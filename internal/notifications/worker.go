package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (s *Service) Test(ctx context.Context, p auth.Principal, requestID, key, id string, version int64) (Change, error) {
	return s.change(ctx, p, requestID, key, "notifications.channel.test", id, version, func(tx *sql.Tx) (Change, error) {
		var enabled bool
		if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='notifications'").Scan(&enabled); err != nil {
			return Change{}, err
		}
		if !enabled {
			return Change{}, fault.Conflict("需先启用外部通知模块")
		}
		c, err := s.scanChannel(tx.QueryRowContext(ctx, "SELECT "+channelColumns+" FROM notification_channels WHERE id=?", id))
		if errors.Is(err, sql.ErrNoRows) {
			return Change{}, fault.NotFound("通知渠道不存在")
		}
		if err != nil {
			return Change{}, err
		}
		if version != c.Version {
			return Change{}, fault.Conflict("渠道已变化，请刷新后重试")
		}
		if !c.Enabled {
			return Change{}, fault.Conflict("需先启用渠道")
		}
		var policy Policy
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT settings FROM notification_settings WHERE id=1").Scan(&raw); err != nil {
			return Change{}, err
		}
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			return Change{}, err
		}
		if err := policy.Validate(); err != nil {
			return Change{}, err
		}
		now := time.Now().Unix()
		event := Event{ID: "test." + secure.ID(), Kind: "notification.test", ResourceKind: "notification_channel", ResourceID: id, Severity: "info", State: "notice", Summary: "通知渠道测试", Occurrences: 1, CreatedAt: now, LastSeenAt: now, ExpiresAt: now + min(int64(3600), policy.TTLHours*3600)}
		if err := insertEvent(ctx, tx, event, event.ID); err != nil {
			return Change{}, err
		}
		deliveryID, err := s.enqueue(ctx, tx, event, c, policy)
		if err != nil {
			return Change{}, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE notification_events SET fanout_at=? WHERE id=?", now, event.ID); err != nil {
			return Change{}, err
		}
		return Change{ID: id, Version: version, DeliveryID: deliveryID}, nil
	})
}
func (s *Service) Retry(ctx context.Context, p auth.Principal, requestID, key, id string) (Change, error) {
	return s.change(ctx, p, requestID, key, "notifications.delivery.retry", id, nil, func(tx *sql.Tx) (Change, error) {
		var enabled bool
		if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='notifications'").Scan(&enabled); err != nil {
			return Change{}, err
		}
		if !enabled {
			return Change{}, fault.Conflict("需先启用外部通知模块")
		}
		var channel, state string
		var version, expires, notBefore int64
		var attempts, maximum int
		err := tx.QueryRowContext(ctx, "SELECT COALESCE(channel_id,''),channel_version,state,attempts,max_attempts,expires_at,retry_not_before FROM notification_deliveries WHERE id=?", id).Scan(&channel, &version, &state, &attempts, &maximum, &expires, &notBefore)
		if errors.Is(err, sql.ErrNoRows) {
			return Change{}, fault.NotFound("投递记录不存在")
		}
		if err != nil {
			return Change{}, err
		}
		if state != "failed" && state != "pending" || attempts >= maximum || expires <= time.Now().Unix() {
			return Change{}, fault.Conflict("该投递不能重试；有效期和最大尝试次数仍适用")
		}
		var valid bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM notification_channels WHERE id=? AND version=? AND enabled=1)", channel, version).Scan(&valid); err != nil {
			return Change{}, err
		}
		if !valid {
			return Change{}, fault.Conflict("渠道已变化或停用")
		}
		_, err = tx.ExecContext(ctx, "UPDATE notification_deliveries SET state='pending',next_attempt_at=?,completed_at=0,last_error='等待重试' WHERE id=?", max(time.Now().Unix(), notBefore), id)
		return Change{ID: id, DeliveryID: id}, err
	})
}
func insertEvent(ctx context.Context, tx *sql.Tx, event Event, dedup string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO notification_events(id,dedup_key,kind,resource_kind,resource_id,severity,state,summary,occurrences,created_at,last_seen_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(dedup_key) DO UPDATE SET occurrences=notification_events.occurrences+1,last_seen_at=excluded.last_seen_at", event.ID, dedup, event.Kind, event.ResourceKind, event.ResourceID, event.Severity, event.State, event.Summary, event.Occurrences, event.CreatedAt, event.LastSeenAt, event.ExpiresAt)
	return err
}
func (s *Service) enqueue(ctx context.Context, tx *sql.Tx, event Event, channel storedChannel, policy Policy) (string, error) {
	event.ExpiresAt = min(event.ExpiresAt, event.CreatedAt+policy.TTLHours*3600)
	raw, err := json.Marshal(Payload{Version: 1, NodeID: s.NodeID, Event: event})
	if err != nil {
		return "", err
	}
	if len(raw) > 8192 {
		return "", errors.New("notification payload exceeds budget")
	}
	id := secure.ID()
	now := time.Now().Unix()
	expires := min(event.ExpiresAt, event.CreatedAt+policy.TTLHours*3600)
	err = tx.QueryRowContext(ctx, "INSERT INTO notification_deliveries(id,event_id,channel_id,channel_name,channel_version,payload,state,max_attempts,next_attempt_at,created_at,expires_at) VALUES(?,?,?,?,?,?,'pending',?,?,?,?) ON CONFLICT(event_id,channel_id) DO NOTHING RETURNING id", id, event.ID, channel.ID, channel.Name, channel.Version, raw, policy.MaxAttempts, now, now, expires).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, "SELECT id FROM notification_deliveries WHERE event_id=? AND channel_id=?", event.ID, channel.ID).Scan(&id)
	}
	return id, err
}
func (s *Service) fanout(ctx context.Context, policy Policy) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	var enabled bool
	if err = tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='notifications'").Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+channelColumns+" FROM notification_channels WHERE enabled=1 ORDER BY created_at,id LIMIT 17")
	if err != nil {
		return err
	}
	channels := []storedChannel{}
	for rows.Next() {
		c, e := s.scanChannel(rows)
		if e != nil {
			rows.Close()
			return e
		}
		channels = append(channels, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(channels) > MaxChannels {
		return errors.New("notification channel budget exceeded")
	}
	if len(channels) == 0 {
		return nil
	}
	rows, err = tx.QueryContext(ctx, "SELECT "+eventColumns+" FROM notification_events WHERE fanout_at=0 AND expires_at>? ORDER BY created_at,id LIMIT 32", now)
	if err != nil {
		return err
	}
	events := []Event{}
	for rows.Next() {
		event, e := scanEvent(rows)
		if e != nil {
			rows.Close()
			return e
		}
		events = append(events, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, event := range events {
		for _, channel := range channels {
			if event.CreatedAt+policy.TTLHours*3600 <= now {
				continue
			}
			for _, kind := range channel.Subscriptions {
				if kind == event.Kind {
					if _, err = s.enqueue(ctx, tx, event, channel, policy); err != nil {
						return err
					}
					break
				}
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE notification_events SET fanout_at=? WHERE id=?", now, event.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Service) cleanup(ctx context.Context) error {
	now := time.Now().Unix()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		query string
		args  []any
	}{
		{"UPDATE notification_deliveries SET state='expired',last_error='事件有效期已过',completed_at=? WHERE state IN ('pending','sending') AND expires_at<=?", []any{now, now}},
		{"UPDATE notification_deliveries SET state='failed',last_error='已达到最大尝试次数',completed_at=? WHERE state='sending' AND lease_until<=? AND attempts>=max_attempts", []any{now, now}},
		{"UPDATE notification_deliveries SET state='pending',next_attempt_at=?,last_error='进程中断，原请求结果不确定' WHERE state='sending' AND lease_until<=? AND attempts<max_attempts", []any{now + 15, now}},
		{"DELETE FROM notification_events WHERE created_at<?", []any{now - 7*24*3600}},
	} {
		if _, err = tx.ExecContext(ctx, q.query, q.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type job struct {
	ID                    string
	Attempts, MaxAttempts int
	ExpiresAt             int64
	Payload               []byte
	Channel               storedChannel
}

func (s *Service) claim(ctx context.Context) (*job, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	var enabled bool
	if err = tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='notifications'").Scan(&enabled); err != nil || !enabled {
		return nil, err
	}
	var out job
	var channelID string
	var version int64
	err = tx.QueryRowContext(ctx, "SELECT d.id,d.attempts,d.max_attempts,d.expires_at,d.payload,d.channel_id,d.channel_version FROM notification_deliveries d JOIN notification_channels c ON c.id=d.channel_id WHERE d.state='pending' AND d.next_attempt_at<=? AND d.expires_at>? AND d.attempts<d.max_attempts AND c.enabled=1 AND c.version=d.channel_version AND c.next_send_at<=? ORDER BY d.next_attempt_at,d.created_at,d.id LIMIT 1", now, now, now).Scan(&out.ID, &out.Attempts, &out.MaxAttempts, &out.ExpiresAt, &out.Payload, &channelID, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out.Channel, err = s.scanChannel(tx.QueryRowContext(ctx, "SELECT "+channelColumns+" FROM notification_channels WHERE id=?", channelID))
	if err != nil {
		return nil, err
	}
	if out.Channel.Version != version {
		return nil, errors.New("notification channel changed during claim")
	}
	if err = out.Channel.Config.validate(out.Channel.Kind, true); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE notification_deliveries SET state='sending',attempts=attempts+1,last_attempt_at=?,lease_until=? WHERE id=? AND state='pending'", now, now+30, out.ID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE notification_channels SET next_send_at=? WHERE id=?", now+10, channelID); err != nil {
		return nil, err
	}
	out.Attempts++
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}
func (s *Service) deliver(ctx context.Context, sender *sender) error {
	s.mu.Lock()
	tooSoon := time.Now().Before(s.nextSend)
	s.mu.Unlock()
	if tooSoon {
		return nil
	}
	job, err := s.claim(ctx)
	if err != nil || job == nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	if expires := time.Unix(job.ExpiresAt, 0); expires.Before(deadline) {
		deadline = expires
	}
	sendCtx, cancel := context.WithDeadline(ctx, deadline)
	s.mu.Lock()
	s.active = job.Channel.ID
	s.cancel = cancel
	s.nextSend = time.Now().Add(5 * time.Second)
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); s.active = ""; s.cancel = nil; s.mu.Unlock() }()
	var active bool
	err = s.DB.QueryRowContext(sendCtx, "SELECT EXISTS(SELECT 1 FROM notification_channels c JOIN module_settings m ON m.id='notifications' WHERE c.id=? AND c.version=? AND c.enabled=1 AND m.enabled=1)", job.Channel.ID, job.Channel.Version).Scan(&active)
	if err != nil {
		return err
	}
	if !active {
		_, err = s.DB.ExecContext(ctx, "UPDATE notification_deliveries SET state='pending',attempts=attempts-1,next_attempt_at=?,lease_until=0,last_error='模块或渠道已停用' WHERE id=? AND state='sending'", time.Now().Unix()+15, job.ID)
		return err
	}
	result := sender.send(sendCtx, job.Channel, job.Payload)
	now := time.Now().Unix()
	state, completed, next := "failed", now, int64(0)
	if result.Success {
		state = "sent"
	} else if result.Retry && job.Attempts < job.MaxAttempts {
		delay := min(int64(3600), 15<<min(job.Attempts-1, 8))
		delay += rand.Int64N(max(int64(1), delay/4))
		delay = max(delay, result.RetryAfter)
		next = now + delay
		if next < job.ExpiresAt {
			state = "pending"
			completed = 0
		} else {
			state = "expired"
			result.Message = "重试时间超出事件有效期"
		}
	}
	if ctx.Err() != nil && !result.Success {
		result.Message = "进程停止，原请求结果不确定"
	}
	finish, cancelFinish := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFinish()
	_, err = s.DB.ExecContext(finish, "UPDATE notification_deliveries SET state=?,completed_at=?,next_attempt_at=?,last_error=?,http_status=?,retry_not_before=?,lease_until=0 WHERE id=? AND state='sending'", state, completed, next, result.Message, result.Status, now+result.RetryAfter, job.ID)
	return err
}
func (s *Service) problem(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.reason = ""
		return
	}
	if s.reason == "" {
		slog.Warn("notification worker failed", "error", err)
	}
	s.reason = "本机通知队列或事件采集异常，等待后续处理恢复"
}
func (s *Service) Run(ctx context.Context) error {
	wake := s.signal()
	sender := newSender()
	defer sender.close()
	var lastSignals time.Time
	var signalErr error
	for {
		if ctx.Err() != nil {
			return nil
		}
		view, err := s.policy(ctx)
		if err != nil {
			return err
		}
		cycle, cancel := context.WithTimeout(ctx, 20*time.Second)
		if lastSignals.IsZero() || time.Since(lastSignals) >= time.Minute {
			signalErr = s.cleanup(cycle)
			if signalErr == nil {
				signalErr = s.collectSignals(cycle, view.Policy)
			}
			lastSignals = time.Now()
		}
		enabled, enabledErr := s.enabled(cycle)
		err = errors.Join(err, signalErr, enabledErr)
		if enabledErr == nil && enabled {
			fanoutErr := s.fanout(cycle, view.Policy)
			err = errors.Join(err, fanoutErr)
			if fanoutErr == nil {
				err = errors.Join(err, s.deliver(cycle, sender))
			}
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		s.problem(err)
		wait := 5 * time.Second
		if !enabled {
			wait = 30 * time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}
