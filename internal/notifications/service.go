package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type Service struct {
	DB              *sql.DB
	Vault           *secure.Vault
	NodeID, DataDir string
	mu              sync.Mutex
	wake            chan struct{}
	active          string
	cancel          context.CancelFunc
	reason          string
	nextSend        time.Time
	disk            *diskProbe
}

func Ensure(ctx context.Context, db *sql.DB) error {
	raw, err := json.Marshal(DefaultPolicy())
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "INSERT INTO notification_settings(id,settings) VALUES(1,?) ON CONFLICT(id) DO NOTHING", string(raw))
	return err
}
func (s *Service) signal() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	return s.wake
}
func (s *Service) changed(id string) {
	s.signal()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil && (id == "*" || id == s.active) {
		s.cancel()
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Service) Pause() { s.changed("*") }
func (s *Service) Wake()  { s.changed("") }
func (s *Service) enabled(ctx context.Context) (bool, error) {
	var enabled bool
	err := s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='notifications'").Scan(&enabled)
	return enabled, err
}
func (s *Service) policy(ctx context.Context) (PolicyView, error) {
	var out PolicyView
	var raw string
	if err := s.DB.QueryRowContext(ctx, "SELECT version,settings FROM notification_settings WHERE id=1").Scan(&out.Version, &raw); err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(raw), &out.Policy); err != nil {
		return out, err
	}
	return out, out.Policy.Validate()
}

type scanner interface{ Scan(...any) error }

const channelColumns = "id,version,name,kind,enabled,subscriptions,config,next_send_at,created_at,updated_at"

func (s *Service) scanChannel(row scanner) (storedChannel, error) {
	var c storedChannel
	var subscriptions string
	var sealed []byte
	if err := row.Scan(&c.ID, &c.Version, &c.Name, &c.Kind, &c.Enabled, &subscriptions, &sealed, &c.NextSendAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	if err := json.Unmarshal([]byte(subscriptions), &c.Subscriptions); err != nil {
		return c, err
	}
	plain, err := s.Vault.Open(sealed, channelAAD(c.ID, c.Version))
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(plain, &c.Config); err != nil {
		return c, err
	}
	return c, c.Config.validate(c.Kind, false)
}
func channelAAD(id string, version int64) string {
	return "notifications:channel:" + id + ":" + strconv.FormatInt(version, 10)
}
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	out := Overview{Channels: []Channel{}, Kinds: Kinds}
	var err error
	if out.Enabled, err = s.enabled(ctx); err != nil {
		return out, err
	}
	if out.Policy, err = s.policy(ctx); err != nil {
		return out, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+channelColumns+" FROM notification_channels ORDER BY created_at,id LIMIT 17")
	if err != nil {
		return out, err
	}
	for rows.Next() {
		c, e := s.scanChannel(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Channels = append(out.Channels, c.view())
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(out.Channels) > MaxChannels {
		return out, errors.New("notification channel budget exceeded")
	}
	err = s.DB.QueryRowContext(ctx, "SELECT evicted_events,dropped_deliveries,(SELECT COUNT(*) FROM notification_deliveries WHERE state IN ('pending','sending')),(SELECT COUNT(*) FROM notification_deliveries WHERE state='failed') FROM notification_health WHERE id=1").Scan(&out.Health.EvictedEvents, &out.Health.DroppedDeliveries, &out.Health.Pending, &out.Health.Failed)
	s.mu.Lock()
	out.Health.Reason = s.reason
	s.mu.Unlock()
	return out, err
}
func (s *Service) change(ctx context.Context, p auth.Principal, requestID, key, action, id string, in any, apply func(*sql.Tx) (Change, error)) (Change, error) {
	var out Change
	if err := p.Require("notifications.write"); err != nil {
		return out, err
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("幂等键无效")
	}
	encoded, err := json.Marshal(struct {
		Action, ID string
		Input      any
	}{action, id, in})
	if err != nil {
		return out, err
	}
	digest := secure.Hash(encoded)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if err == nil {
		if prior != digest {
			return out, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, e := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
		if e != nil {
			return out, e
		}
		err = json.Unmarshal(plain, &out)
		return out, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	out, err = apply(tx)
	if err != nil {
		return out, err
	}
	response, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'saved',?)", secure.ID(), requestID, p.ID, action, out.ID, now); err != nil {
		return out, err
	}
	if err = tx.Commit(); err == nil {
		if action == "notifications.channel.save" || action == "notifications.channel.delete" {
			s.changed(out.ID)
		} else {
			s.changed("")
		}
	}
	return out, err
}
func (s *Service) SetPolicy(ctx context.Context, p auth.Principal, requestID, key string, in PolicyInput) (Change, error) {
	if err := in.Policy.Validate(); err != nil {
		return Change{}, err
	}
	if in.BaseVersion < 1 {
		return Change{}, fault.Invalid("通知策略版本无效")
	}
	return s.change(ctx, p, requestID, key, "notifications.policy", "notifications", in, func(tx *sql.Tx) (Change, error) {
		raw, err := json.Marshal(in.Policy)
		if err != nil {
			return Change{}, err
		}
		result, err := tx.ExecContext(ctx, "UPDATE notification_settings SET version=version+1,settings=? WHERE id=1 AND version=?", string(raw), in.BaseVersion)
		if err != nil {
			return Change{}, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return Change{}, err
		}
		if n != 1 {
			return Change{}, fault.Conflict("通知策略已变化，请刷新后重试")
		}
		return Change{ID: "notifications", Version: in.BaseVersion + 1}, nil
	})
}
func (s *Service) SaveChannel(ctx context.Context, p auth.Principal, requestID, key, id string, in ChannelInput) (Change, error) {
	if !text(in.Name, 128) || strings.TrimSpace(in.Name) == "" || len(in.Subscriptions) > len(Kinds) {
		return Change{}, fault.Invalid("渠道名称或订阅无效")
	}
	seen := map[string]bool{}
	for _, kind := range in.Subscriptions {
		if !validKind(kind) || seen[kind] {
			return Change{}, fault.Invalid("事件订阅无效或重复")
		}
		seen[kind] = true
	}
	if in.Subscriptions == nil {
		in.Subscriptions = []string{}
	}
	return s.change(ctx, p, requestID, key, "notifications.channel.save", id, in, func(tx *sql.Tx) (Change, error) {
		now := time.Now().Unix()
		c := storedChannel{Channel: Channel{ID: secure.ID(), Version: 0, CreatedAt: now}}
		if id != "" {
			var err error
			c, err = s.scanChannel(tx.QueryRowContext(ctx, "SELECT "+channelColumns+" FROM notification_channels WHERE id=?", id))
			if errors.Is(err, sql.ErrNoRows) {
				return Change{}, fault.NotFound("通知渠道不存在")
			}
			if err != nil {
				return Change{}, err
			}
			if c.Version != in.BaseVersion {
				return Change{}, fault.Conflict("渠道已变化，请刷新后重试")
			}
			if c.Kind != in.Kind {
				return Change{}, fault.Invalid("修改渠道类型须创建新渠道")
			}
		} else {
			if in.BaseVersion != 0 {
				return Change{}, fault.Invalid("新渠道基础版本须为 0")
			}
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_channels").Scan(&count); err != nil {
				return Change{}, err
			}
			if count >= MaxChannels {
				return Change{}, fault.Conflict("最多配置 16 个通知渠道")
			}
		}
		c.Name = in.Name
		c.Kind = in.Kind
		c.Enabled = in.Enabled
		c.Subscriptions = in.Subscriptions
		c.Version++
		c.UpdatedAt = now
		if in.URL != nil {
			c.Config.URL = *in.URL
		}
		if in.ChatID != nil {
			c.Config.ChatID = *in.ChatID
		}
		if in.ThreadID != nil {
			c.Config.ThreadID = *in.ThreadID
		}
		if in.BotToken != nil {
			c.Config.BotToken = *in.BotToken
		}
		if in.BearerToken != nil {
			c.Config.BearerToken = *in.BearerToken
		}
		if in.SigningSecret != nil {
			c.Config.SigningSecret = *in.SigningSecret
		}
		if err := c.Config.validate(c.Kind, c.Enabled); err != nil {
			return Change{}, err
		}
		raw, err := json.Marshal(c.Config)
		if err != nil {
			return Change{}, err
		}
		if len(raw) > 8064 {
			return Change{}, fault.Invalid("渠道配置超过容量上限")
		}
		subscriptions, err := json.Marshal(c.Subscriptions)
		if err != nil {
			return Change{}, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE notification_deliveries SET state='cancelled',last_error=CASE state WHEN 'sending' THEN '渠道设置已更新，在途请求结果不确定' ELSE '渠道设置已更新' END,completed_at=? WHERE channel_id=? AND state IN ('pending','sending')", now, c.ID); err != nil {
			return Change{}, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO notification_channels(id,version,name,kind,enabled,subscriptions,config,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,name=excluded.name,enabled=excluded.enabled,subscriptions=excluded.subscriptions,config=excluded.config,updated_at=excluded.updated_at", c.ID, c.Version, c.Name, c.Kind, c.Enabled, string(subscriptions), s.Vault.Seal(raw, channelAAD(c.ID, c.Version)), c.CreatedAt, c.UpdatedAt)
		return Change{ID: c.ID, Version: c.Version}, err
	})
}
func (s *Service) DeleteChannel(ctx context.Context, p auth.Principal, requestID, key, id string, version int64) (Change, error) {
	return s.change(ctx, p, requestID, key, "notifications.channel.delete", id, version, func(tx *sql.Tx) (Change, error) {
		var current int64
		if err := tx.QueryRowContext(ctx, "SELECT version FROM notification_channels WHERE id=?", id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
			return Change{}, fault.NotFound("通知渠道不存在")
		} else if err != nil {
			return Change{}, err
		}
		if current != version {
			return Change{}, fault.Conflict("渠道已变化，请刷新后重试")
		}
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, "UPDATE notification_deliveries SET state='cancelled',last_error=CASE state WHEN 'sending' THEN '渠道已删除，在途请求结果不确定' ELSE '渠道已删除' END,completed_at=? WHERE channel_id=? AND state IN ('pending','sending')", now, id); err != nil {
			return Change{}, err
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM notification_channels WHERE id=?", id)
		return Change{ID: id, Version: version}, err
	})
}

const eventColumns = "id,kind,resource_kind,resource_id,severity,state,summary,occurrences,created_at,last_seen_at,expires_at"

func scanEvent(row scanner) (Event, error) {
	var e Event
	err := row.Scan(&e.ID, &e.Kind, &e.ResourceKind, &e.ResourceID, &e.Severity, &e.State, &e.Summary, &e.Occurrences, &e.CreatedAt, &e.LastSeenAt, &e.ExpiresAt)
	return e, err
}
func (s *Service) Events(ctx context.Context, limit, offset int) ([]Event, error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 2048 {
		return nil, fault.Invalid("事件分页无效")
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+eventColumns+" FROM notification_events ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *Service) Deliveries(ctx context.Context, channel string, limit, offset int) ([]Delivery, error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 8192 || len(channel) > 64 {
		return nil, fault.Invalid("投递分页无效")
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT id,event_id,COALESCE(channel_id,''),channel_name,state,attempts,max_attempts,next_attempt_at,last_error,http_status,created_at,last_attempt_at,completed_at,expires_at FROM notification_deliveries WHERE (?='' OR channel_id=?) ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?", channel, channel, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.EventID, &d.ChannelID, &d.ChannelName, &d.State, &d.Attempts, &d.MaxAttempts, &d.NextAttemptAt, &d.LastError, &d.HTTPStatus, &d.CreatedAt, &d.LastAttemptAt, &d.CompletedAt, &d.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
