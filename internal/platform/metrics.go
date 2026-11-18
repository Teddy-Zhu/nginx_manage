package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/monitoring"
)

// MetricsCollector is used by one Agent collection job at a time. Counters never
// leave the host; a restart deliberately needs another sample before rates exist.
type MetricsCollector struct {
	DataDir      string
	at           time.Time
	boot, cpuSet string
	cpus         map[string][8]uint64
	network      map[string][2]uint64
}

func readMetricFile(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(b)) > limit {
		return "", fmt.Errorf("metric source exceeds budget")
	}
	return string(b), nil
}

func MetricsCapability(scope string, development bool) monitoring.Capability {
	c := monitoring.Capability{Scope: scope, CPUs: limits.MetricCPUs, Interfaces: limits.MetricInterfaces, Mounts: limits.MetricMounts}
	if development {
		c.Scope = "development"
		c.Reason = "开发 Agent 不采集宿主机指标"
		return c
	}
	if scope != "host" {
		c.Reason = "尚未由本机确认 Agent 运行于宿主机；需设置 --metrics-scope=host"
		return c
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, err := os.Stat(path); err == nil {
			c.Reason = "检测到容器环境，不能将当前命名空间作为宿主机采集"
			return c
		}
	}
	if raw, err := readMetricFile("/proc/1/cgroup", 64<<10); err == nil {
		for _, marker := range []string{"docker", "kubepods", "libpod", "lxc"} {
			if strings.Contains(raw, marker) {
				c.Reason = "检测到容器控制组，不能采集为宿主机指标"
				return c
			}
		}
	}
	c.Available = true
	return c
}

func emptyMetric(kind, id, label, reason string) monitoring.Metric {
	m := monitoring.Metric{Kind: kind, ID: id, Label: label, Reason: reason, Values: map[string]*float64{}}
	for _, field := range monitoring.Fields[kind] {
		m.Values[field] = nil
	}
	return m
}
func (c *MetricsCollector) Collect(interval int64) monitoring.Sample {
	now := time.Now()
	boot, bootErr := readMetricFile("/proc/sys/kernel/random/boot_id", 64)
	boot = strings.TrimSpace(boot)
	if bootErr != nil || len(boot) != 36 {
		boot = ""
	}
	s := monitoring.Sample{At: now.Unix(), Source: "host-agent", BootID: boot, Metrics: []monitoring.Metric{}, Services: []monitoring.ServiceState{}, Warnings: []string{}}
	delta := now.Sub(c.at).Seconds()
	continuous := boot != "" && boot == c.boot && !c.at.IsZero() && now.Unix() > c.at.Unix() && delta > 0 && delta <= float64(2*interval+5)
	c.collectCPU(&s, continuous)
	c.collectMemory(&s)
	c.collectLoad(&s)
	c.collectNetwork(&s, continuous, delta)
	c.collectMounts(&s)
	c.at = now
	c.boot = boot
	return s
}
func warn(s *monitoring.Sample, text string) {
	if len(s.Warnings) < 16 {
		s.Warnings = append(s.Warnings, text)
	}
}
func (c *MetricsCollector) collectCPU(s *monitoring.Sample, continuous bool) {
	raw, err := readMetricFile("/proc/stat", 1<<20)
	if err != nil {
		s.Metrics = append(s.Metrics, emptyMetric("cpu", "total", "CPU 总计", "无法读取 CPU 计数器"))
		c.cpus = nil
		c.cpuSet = ""
		return
	}
	current := map[string][8]uint64{}
	ids := []string{}
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		id := f[0]
		if id != "cpu" {
			if _, err := strconv.ParseUint(strings.TrimPrefix(id, "cpu"), 10, 32); err != nil {
				continue
			}
			ids = append(ids, id)
		}
		if len(current) >= limits.MetricCPUs+1 {
			continue
		}
		var counters [8]uint64
		valid := true
		for i := range counters {
			counters[i], err = strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				valid = false
				break
			}
		}
		if valid {
			current[id] = counters
		}
	}
	sort.Strings(ids)
	set := strings.Join(ids, ",")
	if len(ids) > limits.MetricCPUs {
		warn(s, "CPU 核心超过采集上限，仅展示前 128 个核心")
	}
	keys := make([]string, 0, len(current))
	for id := range current {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		label, metricID := id, id
		if id == "cpu" {
			label = "CPU 总计"
			metricID = "total"
		}
		m := emptyMetric("cpu", metricID, label, "首个样本、计数器重置、核心变化或采样中断，暂无法计算使用率")
		prev, exists := c.cpus[id]
		valid := continuous && exists && c.cpuSet == set
		var total, idle float64
		for i, value := range current[id] {
			if value < prev[i] {
				valid = false
				break
			}
			d := float64(value - prev[i])
			total += d
			if i == 3 || i == 4 {
				idle += d
			}
		}
		// guest/guest_nice are included in user/nice, and must not be added twice.
		if valid && total > 0 && idle <= total {
			m.Values["usage_percent"] = monitoring.Number((total - idle) / total * 100)
			m.Reason = ""
		}
		s.Metrics = append(s.Metrics, m)
	}
	if _, ok := current["cpu"]; !ok {
		s.Metrics = append(s.Metrics, emptyMetric("cpu", "total", "CPU 总计", "CPU 总计数器格式不可用"))
	}
	c.cpus = current
	c.cpuSet = set
}
func (c *MetricsCollector) collectMemory(s *monitoring.Sample) {
	m := emptyMetric("memory", "total", "内存", "无法读取 MemAvailable 与内存总量")
	swap := emptyMetric("swap", "total", "Swap", "无法读取 Swap 计数器")
	raw, err := readMetricFile("/proc/meminfo", 64<<10)
	values := map[string]uint64{}
	if err == nil {
		for _, line := range strings.Split(raw, "\n") {
			f := strings.Fields(line)
			if len(f) != 3 || f[2] != "kB" {
				continue
			}
			n, e := strconv.ParseUint(f[1], 10, 64)
			if e == nil && n <= math.MaxUint64/1024 {
				values[strings.TrimSuffix(f[0], ":")] = n * 1024
			}
		}
	}
	total, ok := values["MemTotal"]
	available, aok := values["MemAvailable"]
	if ok && aok && total > 0 && available <= total {
		m.Values["total_bytes"] = monitoring.Number(float64(total))
		m.Values["available_bytes"] = monitoring.Number(float64(available))
		m.Values["used_percent"] = monitoring.Number(float64(total-available) / float64(total) * 100)
		m.Reason = ""
	}
	total, ok = values["SwapTotal"]
	free, fok := values["SwapFree"]
	if ok && fok && free <= total {
		swap.Values["total_bytes"] = monitoring.Number(float64(total))
		swap.Values["free_bytes"] = monitoring.Number(float64(free))
		swap.Reason = ""
		if total > 0 {
			swap.Values["used_percent"] = monitoring.Number(float64(total-free) / float64(total) * 100)
		} else {
			swap.Reason = "未配置 Swap"
		}
	}
	s.Metrics = append(s.Metrics, m, swap)
}
func (c *MetricsCollector) collectLoad(s *monitoring.Sample) {
	for _, item := range []struct {
		kind, path, label string
		fields            []string
	}{{"load", "/proc/loadavg", "系统负载", []string{"one", "five", "fifteen"}}, {"uptime", "/proc/uptime", "运行时间", []string{"seconds"}}} {
		m := emptyMetric(item.kind, "total", item.label, "内核指标不可用")
		raw, err := readMetricFile(item.path, 256)
		f := strings.Fields(raw)
		if err == nil && len(f) >= len(item.fields) {
			valid := true
			for i, field := range item.fields {
				n, e := strconv.ParseFloat(f[i], 64)
				if e != nil || monitoring.Number(n) == nil {
					valid = false
					break
				}
				m.Values[field] = monitoring.Number(n)
			}
			if valid {
				m.Reason = ""
			} else {
				m = emptyMetric(item.kind, "total", item.label, m.Reason)
			}
		}
		s.Metrics = append(s.Metrics, m)
	}
}
func interfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func (c *MetricsCollector) collectNetwork(s *monitoring.Sample, continuous bool, seconds float64) {
	raw, err := readMetricFile("/proc/net/dev", 256<<10)
	current := map[string][2]uint64{}
	if err != nil {
		warn(s, "网络接口计数器不可用")
		c.network = nil
		return
	}
	type entry struct {
		name   string
		fields []string
	}
	entries := []entry{}
	for _, line := range strings.Split(raw, "\n") {
		left, right, ok := strings.Cut(line, ":")
		name := strings.TrimSpace(left)
		f := strings.Fields(right)
		if ok && interfaceName(name) && len(f) >= 16 {
			entries = append(entries, entry{name, f})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].name == "lo" {
			return false
		}
		if entries[j].name == "lo" {
			return true
		}
		return entries[i].name < entries[j].name
	})
	if len(entries) > limits.MetricInterfaces {
		warn(s, "网络接口超过采集上限，仅展示前 32 个接口")
		entries = entries[:limits.MetricInterfaces]
	}
	for _, e := range entries {
		m := emptyMetric("network", e.name, e.name, "首个样本、接口重建、计数器重置或采样中断，暂无法计算速率")
		rx, rxErr := strconv.ParseUint(e.fields[0], 10, 64)
		tx, txErr := strconv.ParseUint(e.fields[8], 10, 64)
		index, indexErr := readMetricFile(filepath.Join("/sys/class/net", e.name, "ifindex"), 32)
		n, nErr := strconv.ParseUint(strings.TrimSpace(index), 10, 32)
		key := fmt.Sprintf("%s:%d", e.name, n)
		if rxErr == nil && txErr == nil {
			m.Values["received_bytes"] = monitoring.Number(float64(rx))
			m.Values["sent_bytes"] = monitoring.Number(float64(tx))
			if indexErr == nil && nErr == nil && n > 0 {
				prev, exists := c.network[key]
				if continuous && exists && rx >= prev[0] && tx >= prev[1] {
					m.Values["rx_bps"] = monitoring.Number(float64(rx-prev[0]) * 8 / seconds)
					m.Values["tx_bps"] = monitoring.Number(float64(tx-prev[1]) * 8 / seconds)
					m.Reason = ""
				}
				current[key] = [2]uint64{rx, tx}
			}
		}
		s.Metrics = append(s.Metrics, m)
	}
	c.network = current
}

var mountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)

func mountPath(raw string) (string, bool) {
	v := mountEscapes.Replace(raw)
	if !filepath.IsAbs(v) || filepath.Clean(v) != v || len(v) > 256 || strings.ContainsAny(v, "\x00\n\r\t") {
		return "", false
	}
	return v, true
}
func (c *MetricsCollector) collectMounts(s *monitoring.Sample) {
	raw, err := readMetricFile("/proc/self/mountinfo", 1<<20)
	if err != nil {
		warn(s, "本地文件系统列表不可用")
		return
	}
	type mount struct {
		path, device, kind, root string
		priority                 int
	}
	mounts := []mount{}
	for line := range strings.SplitSeq(raw, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		kind, source, ok := strings.Cut(right, " ")
		if !ok || source == "" {
			continue
		}
		switch kind {
		case "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "bcachefs", "ntfs3":
		default:
			continue
		}
		a := strings.Fields(left)
		if len(a) < 6 {
			continue
		}
		path, ok := mountPath(a[4])
		if !ok {
			continue
		}
		priority := 2
		if path == "/" {
			priority = 0
		} else if c.DataDir == path || strings.HasPrefix(c.DataDir, path+"/") {
			priority = 1
		}
		mounts = append(mounts, mount{path, a[2], kind, a[3], priority})
	}
	sort.Slice(mounts, func(i, j int) bool {
		if mounts[i].priority != mounts[j].priority {
			return mounts[i].priority < mounts[j].priority
		}
		if len(mounts[i].path) != len(mounts[j].path) {
			return len(mounts[i].path) < len(mounts[j].path)
		}
		return mounts[i].path < mounts[j].path
	})
	seen := map[string]bool{}
	count := 0
	for _, mount := range mounts {
		// Bind mounts of the same filesystem share capacity. Btrfs subvolumes
		// likewise share capacity rather than creating independent disks.
		if seen[mount.kind+":"+mount.device] {
			continue
		}
		seen[mount.kind+":"+mount.device] = true
		if count >= limits.MetricMounts {
			warn(s, "文件系统超过采集上限，仅展示前 32 个本地文件系统")
			break
		}
		count++
		hash := sha256.Sum256([]byte(mount.kind + ":" + mount.device + ":" + mount.path))
		m := emptyMetric("filesystem", hex.EncodeToString(hash[:12]), mount.path, "文件系统统计不可用")
		var stat unix.Statfs_t
		if unix.Statfs(mount.path, &stat) == nil && stat.Bsize > 0 && stat.Bavail <= stat.Bfree && stat.Bfree <= stat.Blocks && stat.Blocks <= math.MaxUint64/uint64(stat.Bsize) && stat.Ffree <= stat.Files {
			unit := float64(stat.Bsize)
			used := float64(stat.Blocks - stat.Bfree)
			available := float64(stat.Bavail)
			m.Values["total_bytes"] = monitoring.Number(float64(stat.Blocks) * unit)
			m.Values["available_bytes"] = monitoring.Number(available * unit)
			m.Values["reserved_bytes"] = monitoring.Number(float64(stat.Bfree-stat.Bavail) * unit)
			if used+available > 0 {
				m.Values["used_percent"] = monitoring.Number(used / (used + available) * 100)
			}
			m.Values["total_inodes"] = monitoring.Number(float64(stat.Files))
			m.Values["free_inodes"] = monitoring.Number(float64(stat.Ffree))
			if stat.Files > 0 {
				m.Values["used_inode_percent"] = monitoring.Number(float64(stat.Files-stat.Ffree) / float64(stat.Files) * 100)
			}
			m.Reason = ""
		}
		s.Metrics = append(s.Metrics, m)
	}
	if count == 0 {
		warn(s, "没有可采集的本地块文件系统；虚拟、远程及 FUSE 文件系统不参与容量统计")
	}
}
