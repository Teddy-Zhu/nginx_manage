package monitoring

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/modules"
	"nginxpanel/internal/storage"
)

func monitoringTestService(t *testing.T) *Service {
	t.Helper()
	db, err := storage.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Ensure(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := modules.Init(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "UPDATE module_settings SET enabled=1 WHERE id='monitoring'"); err != nil {
		t.Fatal(err)
	}
	return &Service{DB: db}
}

func cpuSample(at int64, value *float64) Sample {
	return Sample{At: at, Source: "host-agent", Metrics: []Metric{{Kind: "cpu", ID: "total", Values: map[string]*float64{"usage_percent": value}}}}
}

func TestMonitoringHistoryGapsAndRestart(t *testing.T) {
	s := monitoringTestService(t)
	settings := DefaultSettings()
	base := time.Now().Unix()/60*60 - 180
	observe := func(sample Sample) {
		t.Helper()
		if err := s.observe(t.Context(), sample, settings); err != nil {
			t.Fatal(err)
		}
	}
	query := HistoryQuery{Kind: "cpu", ID: "total", Value: "usage_percent", From: base, Until: base + 59}
	check := func(service *Service, count int, average float64, gap bool) {
		t.Helper()
		history, err := service.History(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		p := history.Points[0]
		if p.Count != count || p.Average == nil || *p.Average != average || p.Gap != gap {
			t.Fatalf("unexpected history: %+v", p)
		}
	}
	observe(cpuSample(base+1, Number(40)))
	observe(cpuSample(base+50, Number(80)))
	// An interrupted minute must already show a gap before it is persisted.
	check(s, 2, 60, true)
	if err := s.persist(t.Context(), settings, false); err != nil {
		t.Fatal(err)
	}
	check(s, 2, 60, true) // The live and persisted copy must not double-count.
	if err := s.persist(t.Context(), settings, true); err != nil {
		t.Fatal(err)
	}
	check(&Service{DB: s.DB}, 2, 60, true)

	observe(cpuSample(base+120, nil))
	observe(cpuSample(base+135, Number(0)))
	observe(cpuSample(base+150, Number(60)))
	query.Until = base + 179
	history, err := s.History(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	if history.StepSeconds != 60 || len(history.Points) != 2 || history.Points[0].At != base || history.Points[1].At != base+120 {
		t.Fatalf("expected only the original minute records: %+v", history)
	}
	partial := history.Points[1]
	if !partial.Gap || partial.Count != 2 || partial.Average == nil || *partial.Average != 30 || partial.Minimum == nil || *partial.Minimum != 0 || partial.Maximum == nil || *partial.Maximum != 60 {
		t.Fatalf("null and genuine zero were conflated: %+v", partial)
	}
}

func TestMonitoringThresholdMissingAndInterruptedSamples(t *testing.T) {
	s := monitoringTestService(t)
	settings := DefaultSettings()
	settings.CPU = Threshold{Enabled: true, High: 90, Recover: 80, ForSeconds: 30, RecoverSeconds: 30}
	base := time.Now().Unix()/60*60 - 360
	observe := func(offset int64, value *float64, active, available bool) {
		t.Helper()
		if err := s.observe(t.Context(), cpuSample(base+offset, value), settings); err != nil {
			t.Fatal(err)
		}
		c := s.conditions["cpu:total"]
		if c.Active != active || c.Available != available {
			t.Fatalf("at %d: unexpected condition: %+v", offset, c)
		}
	}
	observe(0, Number(95), false, true)
	observe(45, Number(95), false, true) // An outage cannot satisfy a duration.
	observe(60, Number(95), false, true)
	observe(75, Number(95), true, true)
	observe(90, nil, true, false) // Missing data cannot clear an active alert.
	observe(105, Number(50), true, true)
	observe(120, nil, true, false) // Nor can it count toward recovery.
	observe(135, Number(50), true, true)
	observe(150, Number(50), true, true)
	observe(165, Number(50), false, true)
	var events int
	if err := s.DB.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM monitoring_events").Scan(&events); err != nil || events != 2 {
		t.Fatalf("activation/recovery events: %d, %v", events, err)
	}
}

func TestMonitoringRetentionAndByteQuota(t *testing.T) {
	s := monitoringTestService(t)
	settings := DefaultSettings()
	base := time.Now().Unix()/60*60 - 60
	b := newBucket(base, settings.IntervalSeconds)
	for i := 0; i < limits.MetricDimensions; i++ {
		b.Add(Sample{At: base, Metrics: []Metric{{Kind: "filesystem", ID: fmt.Sprintf("%03d", i) + strings.Repeat("x", 40), Label: strings.Repeat("m", 80), Values: map[string]*float64{"total_bytes": Number(1024), "available_bytes": Number(512), "reserved_bytes": Number(0), "used_percent": Number(50), "total_inodes": Number(100), "free_inodes": Number(50), "used_inode_percent": Number(50)}}}})
	}
	// Reuse one maximum-dimension minute; no services or external fixtures are needed.
	b.Attempts = 4
	b.LastAt = base + 45
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBucket(raw); err != nil {
		t.Fatal(err)
	}
	count := limits.MetricHistoryBytes/len(raw) + 2
	if count >= limits.MetricHistoryMinutes {
		t.Fatal("quota fixture must reach the byte limit before the minute limit")
	}
	tx, err := s.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < count; i++ {
		b.Minute = base - int64(i)*60
		b.LastAt = b.Minute + 45
		raw, err = json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(t.Context(), "INSERT INTO metric_samples(minute,payload,bytes) VALUES(?,?,?)", b.Minute, raw, len(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.persist(t.Context(), settings, true); err != nil {
		t.Fatal(err)
	}
	earliest, bytes, err := s.stats(t.Context())
	if err != nil || bytes <= 0 || bytes > limits.MetricHistoryBytes || earliest <= base-int64(count-1)*60 {
		t.Fatalf("byte quota did not evict oldest samples: earliest=%d bytes=%d err=%v", earliest, bytes, err)
	}
	var newest int64
	if err := s.DB.QueryRowContext(t.Context(), "SELECT MAX(minute) FROM metric_samples").Scan(&newest); err != nil || newest != base {
		t.Fatalf("quota evicted newest data: %d, %v", newest, err)
	}
	settings.RetentionHours = 1
	if err := s.persist(t.Context(), settings, true); err != nil {
		t.Fatal(err)
	}
	earliest, _, err = s.stats(t.Context())
	if err != nil || earliest < time.Now().Add(-time.Hour).Unix() {
		t.Fatalf("retention did not evict expired data: %d, %v", earliest, err)
	}
}
