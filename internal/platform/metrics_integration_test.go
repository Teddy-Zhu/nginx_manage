package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/monitoring"
)

// The test binary runs in a private container chroot containing ordinary fixture
// files at /proc and /sys. Never write to real kernel metric sources.
func TestMetricsCollectorLinuxSources(t *testing.T) {
	if os.Getenv("NGINXPANEL_TEST_METRICS_FIXTURE") != "1" {
		t.Skip("requires the isolated Linux metrics fixture root")
	}
	marker, err := os.ReadFile("/.nginxpanel-metrics-fixture")
	if err != nil || string(marker) != "private-linux-metrics-fixture\n" {
		t.Fatal("refusing to write outside the private metrics fixture root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("fixture must explicitly identify itself as a container")
	}
	write := func(path, value string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(path string) {
		t.Helper()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	cpu := func(user, system, idle uint64, extra string) {
		line := fmt.Sprintf(" %d 0 %d %d 0 0 0 0 %d 0\n", user, system, idle, user*4/5)
		write("/proc/stat", "cpu"+line+"cpu0"+line+extra)
	}
	network := func(rx, tx uint64) {
		write("/proc/net/dev", fmt.Sprintf("Inter-| Receive | Transmit\n lo: %d 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0\n", rx, tx))
	}
	metric := func(s monitoring.Sample, kind, id string) monitoring.Metric {
		t.Helper()
		for _, m := range s.Metrics {
			if m.Kind == kind && m.ID == id {
				return m
			}
		}
		t.Fatalf("missing %s:%s in sample", kind, id)
		return monitoring.Metric{}
	}
	null := func(s monitoring.Sample, kind, id, field string) {
		t.Helper()
		m := metric(s, kind, id)
		if m.Values[field] != nil || m.Reason == "" {
			t.Fatalf("unavailable %s:%s.%s became a value: %+v", kind, id, field, m)
		}
	}
	write("/proc/sys/kernel/random/boot_id", "11111111-2222-3333-4444-555555555555\n")
	write("/proc/meminfo", "MemTotal: 1024 kB\nMemAvailable: 256 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
	write("/proc/loadavg", "1.0 0.5 0.25 1/10 100\n")
	write("/proc/uptime", "100.0 200.0\n")
	write("/sys/class/net/lo/ifindex", "1\n")
	write("/proc/self/mountinfo", "10 1 8:1 / /data rw - ext4 /dev/fixture rw\n11 1 8:1 / /data/bind rw - ext4 /dev/fixture rw\n")
	if err := os.MkdirAll("/data/bind", 0755); err != nil {
		t.Fatal(err)
	}
	c := MetricsCollector{DataDir: "/data"}
	collect := func() monitoring.Sample {
		// Advance the previous observation instead of waiting 15 seconds per case.
		if !c.at.IsZero() {
			c.at = time.Now().Add(-15 * time.Second)
		}
		return c.Collect(15)
	}
	cpu(100, 50, 850, "")
	network(100, 200)
	first := collect()
	null(first, "cpu", "total", "usage_percent")
	null(first, "network", "lo", "rx_bps")
	null(first, "swap", "total", "used_percent")
	if used := metric(first, "memory", "total").Values["used_percent"]; used == nil || *used != 75 {
		t.Fatalf("MemAvailable was not used: %v", used)
	}
	filesystems := 0
	for _, m := range first.Metrics {
		if m.Kind == "filesystem" {
			filesystems++
			if m.Values["total_bytes"] == nil {
				t.Fatal("real statfs failed in private fixture filesystem")
			}
		}
	}
	if filesystems != 1 {
		t.Fatalf("bind mount capacity was counted %d times", filesystems)
	}
	cpu(150, 100, 950, "")
	network(250, 500)
	second := collect()
	if usage := metric(second, "cpu", "total").Values["usage_percent"]; usage == nil || *usage != 50 {
		t.Fatalf("CPU deltas or guest counters were double-counted: %v", usage)
	}
	if rate := metric(second, "network", "lo").Values["rx_bps"]; rate == nil || *rate < 79 || *rate > 81 {
		t.Fatalf("received octets were not converted to bits per second: %v", rate)
	}
	cpu(1, 1, 1, "")
	network(1, 1)
	reset := collect()
	null(reset, "cpu", "total", "usage_percent")
	null(reset, "network", "lo", "rx_bps")
	write("/sys/class/net/lo/ifindex", "2\n")
	network(100, 200)
	null(collect(), "network", "lo", "rx_bps")
	write("/proc/sys/kernel/random/boot_id", "22222222-2222-3333-4444-555555555555\n")
	cpu(100, 50, 850, "")
	reboot := collect()
	null(reboot, "cpu", "total", "usage_percent")
	null(reboot, "network", "lo", "rx_bps")
	c.at = time.Now().Add(-time.Minute)
	gap := c.Collect(15)
	null(gap, "cpu", "total", "usage_percent")
	null(gap, "network", "lo", "rx_bps")
	cpu(150, 100, 950, "cpu1 10 0 10 80 0 0 0 0 0 0\n")
	null(collect(), "cpu", "total", "usage_percent")
	remove("/proc/stat")
	remove("/proc/meminfo")
	remove("/proc/net/dev")
	write("/proc/loadavg", "NaN 0.5 0.25\n")
	missing := collect()
	null(missing, "cpu", "total", "usage_percent")
	null(missing, "memory", "total", "used_percent")
	null(missing, "load", "total", "one")
	if len(missing.Warnings) == 0 {
		t.Fatal("missing interface source was silently ignored")
	}
	cpu(200, 150, 1000, "")
	network(200, 400)
	restored := collect()
	null(restored, "cpu", "total", "usage_percent")
	null(restored, "network", "lo", "rx_bps")
	var many strings.Builder
	many.WriteString("cpu 200 0 150 1000 0 0 0 0\n")
	for i := 0; i < limits.MetricCPUs+10; i++ {
		fmt.Fprintf(&many, "cpu%d 200 0 150 1000 0 0 0 0\n", i)
	}
	write("/proc/stat", many.String())
	bounded := collect()
	cores := 0
	for _, m := range bounded.Metrics {
		if m.Kind == "cpu" && m.ID != "total" {
			cores++
		}
	}
	if cores != limits.MetricCPUs || len(bounded.Warnings) == 0 {
		t.Fatalf("CPU dimensions are not bounded: %d", cores)
	}
	if MetricsCapability("host", false).Available {
		t.Fatal("container namespace was advertised as a host metrics source")
	}
}
