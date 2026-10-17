package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

// All code is fixed. Only numeric epochs and the previously checked initial
// TZ/TZDIR values are data. Isolated Python cannot import user site packages.
const fail2banExistingClockProbe = "import sys,os,json,time,datetime\nv=json.loads(sys.argv[1])\nfor k,p,s in [('TZ','tz_present','tz'),('TZDIR','dir_present','dir')]:\n if v[p]: os.environ[k]=v[s]\n else: os.environ.pop(k,None)\ntime.tzset()\nprint(json.dumps([datetime.datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S') for t in v['epochs']]))"

func fail2banExistingClockProgram(live fail2banLiveService, started time.Time) (fail2ban.Tool, string, error) {
	var tool fail2ban.Tool
	if live.view.MainPID == nil {
		return tool, "", errors.New("已有实例时钟进程未知")
	}
	proc := "/proc/" + strconv.FormatInt(*live.view.MainPID, 10)
	path, err := os.Readlink(proc + "/exe")
	if err != nil {
		return tool, "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return tool, "", err
	}
	base := filepath.Base(path)
	version, ok := strings.CutPrefix(base, "python3.")
	if filepath.Dir(path) != "/usr/bin" || (!ok || version == "" || strings.Trim(version, "0123456789") != "") && base != "python3" {
		return tool, "", errors.New("已有实例时钟核对仅支持固定系统 Python 入口")
	}
	if err = existingRootDirectory(filepath.Dir(path)); err != nil {
		return tool, "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return tool, "", err
	}
	actual, err := os.Stat(proc + "/exe")
	if err != nil || !os.SameFile(info, actual) {
		return tool, "", errors.New("系统 Python 与已有进程实际程序不同")
	}
	if err = fail2banTimezoneStamp(info, started); err != nil {
		return tool, "", err
	}
	hash, err := secure.HashRootFile(path, 64<<20)
	if err != nil {
		return tool, "", err
	}
	tool = fail2ban.Tool{ID: "python3", Path: path, Resolved: path, Trusted: true}
	return tool, hash, nil
}

// Refuse a replaced/deleted library or a different process-root view. A fresh
// probe using a new libc must not stand in for the old service's cached clock.
func fail2banExistingClockLibraries(live fail2banLiveService, started time.Time) (string, error) {
	if live.view.MainPID == nil {
		return "", errors.New("已有实例时钟进程未知")
	}
	proc := "/proc/" + strconv.FormatInt(*live.view.MainPID, 10)
	raw, err := fail2banReadLimited(proc+"/maps", 512<<10)
	if err != nil {
		return "", err
	}
	files := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return "", errors.New("已有实例的时钟库映射格式未知")
		}
		if !strings.Contains(fields[1], "x") {
			continue
		}
		if len(fields) == 6 && strings.HasPrefix(fields[5], "[") && strings.HasSuffix(fields[5], "]") {
			continue
		}
		if len(fields) != 6 || !filepath.IsAbs(fields[5]) {
			return "", errors.New("已有实例存在无法核对的可执行映射")
		}
		path := fields[5]
		if _, exists := files[path]; exists {
			continue
		}
		if len(files) >= 128 {
			return "", errors.New("已有实例的时钟库映射超过预算")
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(resolved, "/usr/lib/") && !strings.HasPrefix(resolved, "/usr/lib64/") && !strings.HasPrefix(resolved, "/lib/") && !strings.HasPrefix(resolved, "/lib64/") && !strings.HasPrefix(resolved, "/usr/bin/") {
			return "", errors.New("已有实例使用未接管的系统库路径")
		}
		if err = existingRootDirectory(filepath.Dir(resolved)); err != nil {
			return "", err
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return "", err
		}
		if err = fail2banTimezoneStamp(info, started); err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || strconv.FormatUint(stat.Ino, 10) != fields[4] {
			return "", errors.New("已有实例的系统库在启动后被替换或权限未知")
		}
		majorText, minorText, known := strings.Cut(fields[3], ":")
		major, majorErr := strconv.ParseUint(majorText, 16, 32)
		minor, minorErr := strconv.ParseUint(minorText, 16, 32)
		if !known || majorErr != nil || minorErr != nil || uint32(major) != unix.Major(uint64(stat.Dev)) || uint32(minor) != unix.Minor(uint64(stat.Dev)) {
			return "", errors.New("已有实例的系统库设备与宿主机不同")
		}
		remote, err := os.Stat(proc + "/root" + path)
		if err != nil || !os.SameFile(info, remote) {
			return "", errors.New("已有实例与宿主机的系统库视图不同")
		}
		files[path] = resolved + ":" + strconv.FormatUint(uint64(stat.Dev), 10) + ":" + strconv.FormatUint(stat.Ino, 10) + ":" + strconv.FormatInt(info.Size(), 10) + ":" + info.ModTime().UTC().Format(time.RFC3339Nano) + ":" + strconv.FormatInt(stat.Ctim.Sec, 10) + ":" + strconv.FormatInt(stat.Ctim.Nsec, 10)
	}
	if len(files) == 0 {
		return "", errors.New("已有实例的系统时钟库未完整观察")
	}
	data, _ := json.Marshal(files)
	return secure.Hash(data), nil
}

func verifyFail2banExistingNativeClock(ctx context.Context, live fail2banLiveService, zone fail2banExistingTimezone, labels map[string]fail2banHostBanTime, proof map[string]fail2banBanTime) (string, error) {
	started := time.UnixMicro(zone.StartedAt)
	tool, programHash, err := fail2banExistingClockProgram(live, started)
	if err != nil {
		return "", err
	}
	libraries, err := fail2banExistingClockLibraries(live, started)
	if err != nil {
		return "", err
	}
	keys := make([]string, 0, len(labels))
	for ip := range labels {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	epochs, expected := []int64{}, []string{}
	for _, ip := range keys {
		label := labels[ip]
		if label.Duration == -1 {
			continue
		}
		value, ok := proof[ip]
		if !ok || value.Duration != label.Duration {
			return "", errors.New("时钟核对的封禁材料不完整")
		}
		start, err := fail2banExistingCalendar(label.Started, zone.location)
		if err != nil {
			return "", err
		}
		epochs = append(epochs, start.Unix(), value.Expires)
		expected = append(expected, label.Started, label.End)
	}
	input, _ := json.Marshal(struct {
		TZPresent  bool    `json:"tz_present"`
		TZ         string  `json:"tz"`
		DirPresent bool    `json:"dir_present"`
		Dir        string  `json:"dir"`
		Epochs     []int64 `json:"epochs"`
	}{zone.tzPresent, zone.tz, zone.tzDirPresent, zone.tzDir, epochs})
	if len(input) > 64<<10 {
		return "", errors.New("时钟核对输入超过预算")
	}
	raw, err := fail2banManagedExec(ctx, tool, []string{"-I", "-S", "-B", "-c", fail2banExistingClockProbe, string(input)}, 2*time.Second, 128<<10)
	if err != nil {
		return "", err
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) != len(expected) {
		return "", errors.New("系统 Python 时钟核对输出不完整")
	}
	for i, value := range values {
		if value != expected[i] {
			return "", errors.New("系统 Python 与时区数据的封禁时间换算不同")
		}
	}
	after, err := fail2banExistingClockLibraries(live, started)
	if err != nil || after != libraries {
		return "", errors.New("时钟核对期间系统库变化")
	}
	currentTool, currentHash, err := fail2banExistingClockProgram(live, started)
	if err != nil || currentTool.Resolved != tool.Resolved || currentHash != programHash {
		return "", errors.New("时钟核对期间系统 Python 变化")
	}
	data, _ := json.Marshal([]string{programHash, libraries, zone.SHA256})
	return secure.Hash(data), ctx.Err()
}
