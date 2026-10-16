package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type HostReader interface {
	ReadHostMetrics(context.Context, int64) (Sample, error)
}
type Service struct {
	DB         *sql.DB
	Vault      *secure.Vault
	Agent      HostReader
	mu         sync.Mutex
	wake       chan struct{}
	latest     *Sample
	current    *bucket
	conditions map[string]Condition
	pending    []transition
	reason     string
}

func Ensure(ctx context.Context, db *sql.DB) error {
	encoded, err := json.Marshal(DefaultSettings())
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "INSERT INTO monitoring_settings(id,settings) VALUES(1,?) ON CONFLICT(id) DO NOTHING", string(encoded))
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
func (s *Service) Wake() {
	s.signal()
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Service) Settings(ctx context.Context) (SettingsView, error) {
	return s.ReadSettings(ctx, s.DB)
}
func (s *Service) SetSettings(ctx context.Context, p auth.Principal, requestID, key string, in SettingsInput) (SettingsView, error) {
	var out SettingsView
	if err := p.Require("monitoring.write"); err != nil {
		return out, err
	}
	if err := in.Settings.Validate(); err != nil {
		return out, err
	}
	if in.BaseVersion < 1 || key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("配置版本或幂等键无效")
	}
	encoded, err := json.Marshal(struct {
		Action string
		Input  SettingsInput
	}{"monitoring.settings", in})
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
	var pending int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_plans WHERE state IN ('applying','recovery_required')").Scan(&pending); err != nil {
		return out, err
	}
	if pending > 0 {
		return out, fault.Conflict("迁移尚未结束或需要恢复，暂不能修改监控配置")
	}
	out, err = s.StoreSettings(ctx, tx, in.BaseVersion, in.Settings)
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
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,'monitoring.settings','monitoring','saved',?)", secure.ID(), requestID, p.ID, now); err != nil {
		return out, err
	}
	if err = tx.Commit(); err == nil {
		s.Wake()
	}
	return out, err
}
func (s *Service) enabled(ctx context.Context) (bool, error) {
	var enabled bool
	err := s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='monitoring'").Scan(&enabled)
	return enabled, err
}
func (s *Service) loadConditions(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, "SELECT payload FROM monitoring_conditions LIMIT 201")
	if err != nil {
		return err
	}
	defer rows.Close()
	conditions := map[string]Condition{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var c Condition
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return err
		}
		if len(conditions) >= limits.MetricDimensions {
			return errors.New("monitoring conditions exceed budget")
		}
		c.Available = false
		c.PendingAt = 0
		c.RecoveringAt = 0
		conditions[metricKey(c.Kind, c.ID)] = c
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.conditions = conditions
	s.mu.Unlock()
	return nil
}
func policyEnabled(kind string, settings Settings) bool {
	return kind == "cpu" && settings.CPU.Enabled || kind == "memory" && settings.Memory.Enabled || kind == "filesystem" && settings.Disk.Enabled
}
func (s *Service) pause(settings Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, c := range s.conditions {
		if !policyEnabled(c.Kind, settings) {
			delete(s.conditions, key)
			continue
		}
		c.Available = false
		c.PendingAt = 0
		c.RecoveringAt = 0
		s.conditions[key] = c
	}
}
func (s *Service) problem(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.reason = ""
	} else {
		if s.reason == "" {
			slog.Warn("monitoring cycle failed", "error", err)
		}
		var known *fault.Error
		if errors.As(err, &known) {
			s.reason = known.Message
		} else {
			s.reason = "监控存储或采样状态更新失败，等待后续采样恢复"
		}
	}
}
func (s *Service) Run(ctx context.Context) error {
	if err := s.loadConditions(ctx); err != nil {
		return err
	}
	wake := s.signal()
	var last time.Time
	var version int64
	wasEnabled := false
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if view, err := s.Settings(stop); err == nil {
			s.problem(s.persist(stop, view.Settings, true))
		}
	}()
	for {
		view, err := s.Settings(ctx)
		if err != nil {
			return err
		}
		enabled, err := s.enabled(ctx)
		if err != nil {
			return err
		}
		if version != view.Version || enabled != wasEnabled {
			s.pause(view.Settings)
			if err := s.persist(ctx, view.Settings, true); err != nil {
				return err
			}
			version = view.Version
			wasEnabled = enabled
		}
		s.mu.Lock()
		retry := len(s.pending) > 0
		s.mu.Unlock()
		if retry {
			if err := s.persist(ctx, view.Settings, false); err != nil {
				s.problem(err)
				timer := time.NewTimer(30 * time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-wake:
					timer.Stop()
				case <-timer.C:
				}
				continue
			}
		}
		wait := 30 * time.Second
		if enabled {
			wait = time.Until(last.Add(time.Duration(view.Settings.IntervalSeconds) * time.Second))
			if last.IsZero() || wait <= 0 {
				last = time.Now()
				sample := Sample{At: last.Unix(), Source: "host-agent-unavailable", Reason: "宿主机采样不可用", Metrics: []Metric{}, Services: []ServiceState{}, Warnings: []string{}}
				readCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
				if s.Agent != nil {
					observed, readErr := s.Agent.ReadHostMetrics(readCtx, view.Settings.IntervalSeconds)
					if readErr == nil {
						if e := validateSample(observed, last); e == nil {
							sample = observed
						} else {
							sample.Reason = "宿主机样本超限、时间或字段无效"
						}
					} else {
						var known *fault.Error
						if errors.As(readErr, &known) {
							sample.Reason = known.Message
						}
					}
				}
				cancel()
				current, e := s.Settings(ctx)
				active, ae := s.enabled(ctx)
				if e != nil || ae != nil {
					if e != nil {
						return e
					}
					return ae
				}
				if current.Version == view.Version && active {
					if err := s.observe(ctx, sample, view.Settings); err != nil {
						s.problem(err)
					} else {
						s.problem(nil)
					}
				}
				wait = time.Until(last.Add(time.Duration(view.Settings.IntervalSeconds) * time.Second))
			}
		} else {
			if err := s.persist(ctx, view.Settings, false); err != nil {
				s.problem(err)
			}
		}
		if wait < time.Second {
			wait = time.Second
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
func validateSample(s Sample, now time.Time) error {
	if s.Source != "host-agent" || s.At <= 0 || s.At > now.Add(10*time.Second).Unix() || s.At < now.Add(-10*time.Second).Unix() || len(s.Metrics) > limits.MetricDimensions || len(s.Services) > 4 || len(s.Warnings) > 16 {
		return errors.New("invalid sample")
	}
	seen := map[string]bool{}
	for _, m := range s.Metrics {
		key := metricKey(m.Kind, m.ID)
		if len(Fields[m.Kind]) == 0 || m.ID == "" || len(m.ID) > 128 || len(m.Label) > 256 || len(m.Reason) > 512 || seen[key] {
			return errors.New("invalid metric")
		}
		seen[key] = true
		for field, value := range m.Values {
			if !ValidField(m.Kind, field) || value != nil && Number(*value) == nil {
				return errors.New("invalid metric field")
			}
		}
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > limits.MetricSampleBytes {
		return errors.New("sample exceeds budget")
	}
	return nil
}
func (s *Service) observe(ctx context.Context, sample Sample, settings Settings) error {
	s.mu.Lock()
	old := s.current
	if s.latest != nil && sample.At <= s.latest.At {
		s.mu.Unlock()
		return fault.Unavailable("采样时间未递增，等待新样本或校准宿主机时钟")
	}
	flush := old != nil && old.Minute != sample.At/60*60
	s.mu.Unlock()
	if flush {
		if err := s.persist(ctx, settings, true); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if s.current == nil {
		s.current = newBucket(sample.At, settings.IntervalSeconds)
		var raw []byte
		err := s.DB.QueryRowContext(ctx, "SELECT payload FROM metric_samples WHERE minute=?", s.current.Minute).Scan(&raw)
		if err == nil {
			saved, decodeErr := decodeBucket(raw)
			if decodeErr != nil {
				s.current = nil
				s.mu.Unlock()
				return decodeErr
			}
			if saved.Interval != settings.IntervalSeconds {
				saved.Gap = true
				saved.Interval = settings.IntervalSeconds
			}
			s.current = saved
		} else if !errors.Is(err, sql.ErrNoRows) {
			s.current = nil
			s.mu.Unlock()
			return err
		}
	}
	if sample.At <= s.current.LastAt {
		s.mu.Unlock()
		return fault.Unavailable("样本已记录，等待新的宿主机采样")
	}
	s.current.Add(sample)
	s.latest = &sample
	events := s.evaluate(sample, settings)
	s.pending = append(s.pending, events...)
	s.mu.Unlock()
	if len(events) > 0 {
		return s.persist(ctx, settings, false)
	}
	return nil
}

type transition struct {
	Condition
	Summary string
}

func (s *Service) evaluate(sample Sample, settings Settings) []transition {
	if s.conditions == nil {
		s.conditions = map[string]Condition{}
	}
	next := map[string]Condition{}
	events := []transition{}
	for _, metric := range sample.Metrics {
		var threshold Threshold
		switch {
		case metric.Kind == "cpu" && metric.ID == "total":
			threshold = settings.CPU
		case metric.Kind == "memory":
			threshold = settings.Memory
		case metric.Kind == "filesystem":
			threshold = settings.Disk
		default:
			continue
		}
		if !threshold.Enabled {
			continue
		}
		key := metricKey(metric.Kind, metric.ID)
		c := s.conditions[key]
		c.Kind = metric.Kind
		c.ID = metric.ID
		c.Label = metric.Label
		value := metric.Values["used_percent"]
		if metric.Kind == "cpu" {
			value = metric.Values["usage_percent"]
		}
		continuous := c.Available && sample.At > c.LastAt && sample.At-c.LastAt <= 2*settings.IntervalSeconds+5
		if !continuous {
			c.PendingAt = 0
			c.RecoveringAt = 0
		}
		c.Value = value
		c.Available = value != nil
		c.LastAt = sample.At
		if value == nil {
			c.PendingAt = 0
			c.RecoveringAt = 0
		} else if !c.Active {
			if *value >= threshold.High {
				if c.PendingAt == 0 {
					c.PendingAt = sample.At
				}
				if sample.At-c.PendingAt >= threshold.ForSeconds {
					c.Active = true
					c.Since = sample.At
					c.PendingAt = 0
					events = append(events, transition{c, fmt.Sprintf("%s %s：资源使用持续超限（%.1f%%）", c.Kind, c.Label, *value)})
				}
			} else {
				c.PendingAt = 0
			}
		} else {
			if *value <= threshold.Recover {
				if c.RecoveringAt == 0 {
					c.RecoveringAt = sample.At
				}
				if sample.At-c.RecoveringAt >= threshold.RecoverSeconds {
					c.Active = false
					c.Since = 0
					c.RecoveringAt = 0
					events = append(events, transition{c, fmt.Sprintf("%s %s：资源使用恢复（%.1f%%）", c.Kind, c.Label, *value)})
				}
			} else {
				c.RecoveringAt = 0
			}
		}
		next[key] = c
	}
	// A missing disk/sample cannot clear a firing condition. Keep its state
	// unavailable until observed again, or until its threshold is disabled.
	for key, c := range s.conditions {
		if _, ok := next[key]; ok {
			continue
		}
		if policyEnabled(c.Kind, settings) && c.Active && len(next) < limits.MetricDimensions {
			c.Available = false
			c.Value = nil
			c.PendingAt = 0
			c.RecoveringAt = 0
			next[key] = c
		}
	}
	s.conditions = next
	return events
}
func (s *Service) persist(ctx context.Context, settings Settings, finish bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.current != nil {
		if finish && time.Now().Unix()/60*60 > s.current.Minute && s.current.Attempts < int(max(int64(1), 60/s.current.Interval)) {
			s.current.Gap = true
		}
		raw, err := json.Marshal(s.current)
		if err != nil {
			return err
		}
		if len(raw) > limits.MetricBucketBytes {
			return errors.New("minute bucket exceeds budget")
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO metric_samples(minute,payload,bytes) VALUES(?,?,?) ON CONFLICT(minute) DO UPDATE SET payload=excluded.payload,bytes=excluded.bytes", s.current.Minute, raw, len(raw)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM monitoring_conditions"); err != nil {
		return err
	}
	for _, c := range s.conditions {
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO monitoring_conditions(kind,resource_id,payload) VALUES(?,?,?)", c.Kind, c.ID, string(raw)); err != nil {
			return err
		}
	}
	now := time.Now().Unix()
	for _, event := range s.pending {
		eventID := secure.Hash([]byte(fmt.Sprintf("%s:%s:%t:%d", event.Kind, event.ID, event.Active, event.LastAt)))
		if _, err = tx.ExecContext(ctx, "INSERT INTO monitoring_events(id,kind,resource_id,active,summary,created_at,expires_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING", eventID, event.Kind, event.ID, event.Active, event.Summary, event.LastAt, now+24*3600); err != nil {
			return err
		}
	}
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{"DELETE FROM metric_samples WHERE minute<?", []any{now - settings.RetentionHours*3600}},
		{"DELETE FROM metric_samples WHERE minute NOT IN (SELECT minute FROM metric_samples ORDER BY minute DESC LIMIT ?)", []any{limits.MetricHistoryMinutes}},
		{"DELETE FROM metric_samples WHERE minute IN (SELECT minute FROM (SELECT minute,SUM(bytes) OVER (ORDER BY minute DESC) AS total FROM metric_samples) WHERE total>?)", []any{limits.MetricHistoryBytes}},
		{"DELETE FROM monitoring_events WHERE expires_at<=? OR id NOT IN (SELECT id FROM monitoring_events ORDER BY created_at DESC,id DESC LIMIT 1024)", []any{now}},
	} {
		if _, err = tx.ExecContext(ctx, query.sql, query.args...); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.pending = nil
	if finish {
		s.current = nil
	}
	return nil
}
func (s *Service) stats(ctx context.Context) (int64, int64, error) {
	var earliest, bytes int64
	err := s.DB.QueryRowContext(ctx, "SELECT COALESCE(MIN(minute),0),COALESCE(SUM(bytes),0) FROM metric_samples").Scan(&earliest, &bytes)
	return earliest, bytes, err
}
func (s *Service) Latest(ctx context.Context) (Latest, error) {
	view, err := s.Settings(ctx)
	if err != nil {
		return Latest{}, err
	}
	enabled, err := s.enabled(ctx)
	if err != nil {
		return Latest{}, err
	}
	s.mu.Lock()
	out := Latest{Enabled: enabled, Stale: true, Sample: s.latest, Reason: s.reason, Conditions: []Condition{}}
	for _, c := range s.conditions {
		c.Available = c.Available && enabled && s.latest != nil && time.Now().Unix() >= c.LastAt && time.Now().Unix()-c.LastAt <= 2*view.Settings.IntervalSeconds+5
		out.Conditions = append(out.Conditions, c)
	}
	if s.latest != nil {
		out.Stale = !enabled || s.latest.Reason != "" || time.Now().Unix() < s.latest.At || time.Now().Unix()-s.latest.At > 2*view.Settings.IntervalSeconds+5
		if out.Reason == "" {
			out.Reason = s.latest.Reason
		}
	}
	s.mu.Unlock()
	sort.Slice(out.Conditions, func(i, j int) bool {
		return metricKey(out.Conditions[i].Kind, out.Conditions[i].ID) < metricKey(out.Conditions[j].Kind, out.Conditions[j].ID)
	})
	if !enabled {
		out.Reason = "基础监控已停用"
	} else if out.Sample == nil && out.Reason == "" {
		out.Reason = "等待首个宿主机样本"
	}
	out.Earliest, out.StoredBytes, err = s.stats(ctx)
	return out, err
}
func (s *Service) History(ctx context.Context, q HistoryQuery) (History, error) {
	if err := q.Validate(); err != nil {
		return History{}, err
	}
	from := q.From / 60 * 60
	until := q.Until / 60 * 60
	minutes := (until-from)/60 + 1
	step := (minutes + int64(q.Points) - 1) / int64(q.Points) * 60
	count := (until-from)/step + 1
	out := History{From: from, Until: until, StepSeconds: step, Points: make([]Point, count), Notice: "历史按分钟聚合；空档及缺失值不补零，超出保留时间或存储配额的样本不可恢复"}
	stats := make([]Stat, count)
	seen := make([]int64, count)
	missing := make([]bool, count)
	for i := range out.Points {
		out.Points[i] = Point{At: from + int64(i)*step, Gap: true}
	}
	consume := func(b bucket) {
		if b.Minute < from || b.Minute > until {
			return
		}
		index := (b.Minute - from) / step
		entry := b.Metrics[metricKey(q.Kind, q.ID)]
		if entry == nil {
			return
		}
		stat := entry.Values[q.Value]
		stats[index].Merge(stat)
		if stat.Count > 0 {
			seen[index]++
		}
		if b.Gap || stat.Count < b.Attempts {
			missing[index] = true
		}
	}
	// Copy the in-flight minute before querying; ignore the same persisted
	// minute, which may exist after a threshold transition.
	s.mu.Lock()
	var live *bucket
	if s.current != nil {
		raw, e := json.Marshal(s.current)
		if e != nil {
			s.mu.Unlock()
			return out, e
		}
		live = &bucket{}
		if e = json.Unmarshal(raw, live); e != nil {
			s.mu.Unlock()
			return out, e
		}
	}
	s.mu.Unlock()
	rows, err := s.DB.QueryContext(ctx, "SELECT payload FROM metric_samples WHERE minute>=? AND minute<=? ORDER BY minute LIMIT ?", from, until, limits.MetricHistoryMinutes)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return out, err
		}
		b, err := decodeBucket(raw)
		if err != nil {
			rows.Close()
			return out, fmt.Errorf("decode monitoring minute: %w", err)
		}
		if live == nil || live.Minute != b.Minute {
			consume(*b)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if live != nil {
		consume(*live)
	}
	for i, stat := range stats {
		if stat.Count > 0 {
			out.Points[i].Average = Number(stat.Sum / float64(stat.Count))
			out.Points[i].Minimum = Number(stat.Min)
			out.Points[i].Maximum = Number(stat.Max)
			out.Points[i].Count = stat.Count
			expected := min(step/60, (until-out.Points[i].At)/60+1)
			out.Points[i].Gap = missing[i] || seen[i] < expected
		}
	}
	out.Earliest, out.StoredBytes, err = s.stats(ctx)
	return out, err
}
