package monitoring

import (
	"encoding/json"
	"errors"
	"math"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
)

var Fields = map[string][]string{
	"cpu": {"usage_percent"}, "memory": {"total_bytes", "available_bytes", "used_percent"},
	"swap": {"total_bytes", "free_bytes", "used_percent"}, "load": {"one", "five", "fifteen"},
	"uptime": {"seconds"}, "filesystem": {"total_bytes", "available_bytes", "reserved_bytes", "used_percent", "total_inodes", "free_inodes", "used_inode_percent"},
	"network": {"received_bytes", "sent_bytes", "rx_bps", "tx_bps"},
}

func ValidField(kind, value string) bool {
	for _, name := range Fields[kind] {
		if name == value {
			return true
		}
	}
	return false
}
func Number(value float64) *float64 {
	if math.IsInf(value, 0) || math.IsNaN(value) || value < 0 {
		return nil
	}
	return &value
}

type Metric struct {
	Kind   string              `json:"kind"`
	ID     string              `json:"id"`
	Label  string              `json:"label"`
	Values map[string]*float64 `json:"values"`
	Reason string              `json:"reason"`
}
type ServiceState struct {
	ID     string `json:"id"`
	Load   string `json:"load"`
	Active string `json:"active"`
	Sub    string `json:"sub"`
	Reason string `json:"reason"`
}
type Sample struct {
	At       int64          `json:"at"`
	Source   string         `json:"source"`
	BootID   string         `json:"boot_id"`
	Metrics  []Metric       `json:"metrics"`
	Services []ServiceState `json:"services"`
	Warnings []string       `json:"warnings"`
	Reason   string         `json:"reason"`
}
type Threshold struct {
	Enabled        bool    `json:"enabled"`
	High           float64 `json:"high"`
	Recover        float64 `json:"recover"`
	ForSeconds     int64   `json:"for_seconds"`
	RecoverSeconds int64   `json:"recover_seconds"`
}
type Settings struct {
	IntervalSeconds int64     `json:"interval_seconds"`
	RetentionHours  int64     `json:"retention_hours"`
	CPU             Threshold `json:"cpu"`
	Memory          Threshold `json:"memory"`
	Disk            Threshold `json:"disk"`
}

func DefaultSettings() Settings {
	t := Threshold{High: 90, Recover: 80, ForSeconds: 300, RecoverSeconds: 120}
	return Settings{IntervalSeconds: limits.MetricIntervalSeconds, RetentionHours: limits.MetricRetentionHours, CPU: t, Memory: t, Disk: t}
}
func (s Settings) Validate() error {
	if s.IntervalSeconds < 15 || s.IntervalSeconds > 300 || s.RetentionHours < 1 || s.RetentionHours > 24 {
		return fault.Invalid("采样间隔须为 15–300 秒，保留时间须为 1–24 小时")
	}
	for _, t := range []Threshold{s.CPU, s.Memory, s.Disk} {
		if math.IsNaN(t.High) || math.IsNaN(t.Recover) || t.High <= 0 || t.High > 100 || t.Recover < 0 || t.Recover >= t.High || t.ForSeconds < 30 || t.ForSeconds > 3600 || t.RecoverSeconds < 30 || t.RecoverSeconds > 3600 || t.Enabled && (t.ForSeconds < 2*s.IntervalSeconds || t.RecoverSeconds < 2*s.IntervalSeconds) {
			return fault.Invalid("资源阈值须满足 0 ≤ 恢复值 < 超限值 ≤ 100，持续窗口为 30–3600 秒且启用时至少为两个采样间隔")
		}
	}
	return nil
}

type SettingsView struct {
	Version  int64    `json:"version"`
	Settings Settings `json:"settings"`
}
type SettingsInput struct {
	BaseVersion int64    `json:"base_version"`
	Settings    Settings `json:"settings"`
}
type Capability struct {
	Available  bool   `json:"available"`
	Scope      string `json:"scope"`
	Reason     string `json:"reason"`
	CPUs       int    `json:"cpus"`
	Interfaces int    `json:"interfaces"`
	Mounts     int    `json:"mounts"`
}
type Condition struct {
	Kind         string   `json:"kind"`
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Active       bool     `json:"active"`
	Since        int64    `json:"since"`
	LastAt       int64    `json:"last_at"`
	PendingAt    int64    `json:"pending_at"`
	RecoveringAt int64    `json:"recovering_at"`
	Value        *float64 `json:"value"`
	Available    bool     `json:"available"`
}
type Latest struct {
	Enabled     bool        `json:"enabled"`
	Stale       bool        `json:"stale"`
	Sample      *Sample     `json:"sample"`
	Reason      string      `json:"reason"`
	Conditions  []Condition `json:"conditions"`
	StoredBytes int64       `json:"stored_bytes"`
	Earliest    int64       `json:"earliest"`
}
type HistoryQuery struct {
	Kind, ID, Value string
	From, Until     int64
}

func (q HistoryQuery) Validate() error {
	if !ValidField(q.Kind, q.Value) || q.ID == "" || len(q.ID) > 128 || q.From <= 0 || q.Until < q.From || q.Until-q.From > 24*3600 || q.Until > time.Now().Add(time.Minute).Unix() {
		return fault.Invalid("指标、维度或时间范围无效，最多查询 24 小时")
	}
	return nil
}

type Point struct {
	At      int64    `json:"at"`
	Average *float64 `json:"average"`
	Minimum *float64 `json:"minimum"`
	Maximum *float64 `json:"maximum"`
	Count   int      `json:"count"`
	Gap     bool     `json:"gap"`
}
type History struct {
	Points      []Point `json:"points"`
	StepSeconds int64   `json:"step_seconds"`
	From        int64   `json:"from"`
	Until       int64   `json:"until"`
	Earliest    int64   `json:"earliest"`
	StoredBytes int64   `json:"stored_bytes"`
	Notice      string  `json:"notice"`
}

type Stat struct {
	Sum   float64 `json:"sum"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	Count int     `json:"count"`
}

func (s *Stat) Add(value float64) {
	if s.Count == 0 {
		s.Min = value
		s.Max = value
	} else {
		s.Min = min(s.Min, value)
		s.Max = max(s.Max, value)
	}
	s.Sum += value
	s.Count++
}

type aggregateMetric struct {
	Kind, ID, Label string
	Values          map[string]Stat
}
type bucket struct {
	Minute, Interval, LastAt int64
	Attempts                 int
	Gap                      bool
	Metrics                  map[string]*aggregateMetric
}

func decodeBucket(raw []byte) (*bucket, error) {
	var b bucket
	if len(raw) > limits.MetricBucketBytes || json.Unmarshal(raw, &b) != nil || b.Minute <= 0 || b.Minute%60 != 0 || b.Interval < 15 || b.Interval > 300 || b.LastAt < b.Minute || b.LastAt >= b.Minute+60 || b.Attempts < 1 || b.Attempts > 32 || b.Metrics == nil || len(b.Metrics) > limits.MetricDimensions {
		return nil, errors.New("invalid monitoring minute")
	}
	for key, m := range b.Metrics {
		if m == nil || key != metricKey(m.Kind, m.ID) || len(Fields[m.Kind]) == 0 || m.ID == "" || len(m.ID) > 128 || len(m.Label) > 256 || len(m.Values) > len(Fields[m.Kind]) {
			return nil, errors.New("invalid monitoring dimension")
		}
		for field, stat := range m.Values {
			if !ValidField(m.Kind, field) || stat.Count < 0 || stat.Count > b.Attempts || Number(stat.Sum) == nil || Number(stat.Min) == nil || Number(stat.Max) == nil || stat.Min > stat.Max {
				return nil, errors.New("invalid monitoring aggregate")
			}
		}
	}
	return &b, nil
}

func metricKey(kind, id string) string { return kind + ":" + id }
func newBucket(at, interval int64) *bucket {
	return &bucket{Minute: at / 60 * 60, Interval: interval, Metrics: map[string]*aggregateMetric{}}
}
func (b *bucket) Add(sample Sample) {
	if b.LastAt > 0 && sample.At-b.LastAt > 2*b.Interval+5 {
		b.Gap = true
	}
	b.Attempts++
	b.LastAt = sample.At
	if sample.Reason != "" {
		b.Gap = true
	}
	for _, metric := range sample.Metrics {
		key := metricKey(metric.Kind, metric.ID)
		entry := b.Metrics[key]
		if entry == nil {
			if len(b.Metrics) >= limits.MetricDimensions {
				b.Gap = true
				continue
			}
			entry = &aggregateMetric{Kind: metric.Kind, ID: metric.ID, Label: metric.Label, Values: map[string]Stat{}}
			b.Metrics[key] = entry
		}
		for field, value := range metric.Values {
			if !ValidField(metric.Kind, field) {
				continue
			}
			stat := entry.Values[field]
			if value != nil {
				stat.Add(*value)
			}
			entry.Values[field] = stat
		}
	}
}
