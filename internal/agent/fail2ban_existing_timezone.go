package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/secure"
)

type fail2banExistingTimezone struct {
	Name         string `json:"name"`
	Source       string `json:"source"`
	SHA256       string `json:"sha256"`
	StartedAt    int64  `json:"started_at"`
	location     *time.Location
	tz           string
	tzPresent    bool
	tzDir        string
	tzDirPresent bool
}

// systemctl's explicit UTC microsecond format avoids the Agent's local zone.
// The start time also prevents using timezone files changed after Python could
// have cached them at startup.
func fail2banExistingStarted(ctx context.Context, b *fail2banBinding, live fail2banLiveService) (time.Time, error) {
	raw, err := fail2banRun(ctx, fail2banTool("systemctl"), []string{"show", "--all", "--no-pager", "--timestamp=us+utc", "--property=Id,MainPID,InvocationID,ExecMainStartTimestamp", b.Service}, 4096)
	if err != nil {
		return time.Time{}, errors.New("无法读取已有实例的精确 UTC 启动时间")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || len(value) > 256 {
			return time.Time{}, errors.New("已有实例启动时间元数据不完整")
		}
		switch key {
		case "Id", "MainPID", "InvocationID", "ExecMainStartTimestamp":
		default:
			return time.Time{}, errors.New("已有实例启动时间元数据包含未知字段")
		}
		if _, exists := values[key]; exists {
			return time.Time{}, errors.New("已有实例启动时间元数据重复")
		}
		values[key] = value
	}
	if len(values) != 4 || values["Id"] != b.Service || values["InvocationID"] != live.invocation || live.view.MainPID == nil || values["MainPID"] != strconv.FormatInt(*live.view.MainPID, 10) {
		return time.Time{}, errors.New("已有实例在读取启动时间期间变化")
	}
	started, err := time.Parse("Mon 2006-01-02 15:04:05.000000 UTC", values["ExecMainStartTimestamp"])
	if err != nil || started.Unix() <= 0 || started.After(time.Now()) {
		return time.Time{}, errors.New("已有实例的 UTC 启动时间不可核对")
	}
	return started, nil
}

func fail2banTimezoneStamp(info os.FileInfo, started time.Time) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.ModTime().After(started) || time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).After(started) {
		return errors.New("时区材料归属未知或在服务启动后变化，须本机核对")
	}
	return nil
}

func fail2banExistingTimezoneFile(path, procRoot string, started time.Time) ([]byte, []string, error) {
	links := []string{}
	for count := 0; count < 9; count++ {
		if path != "/etc/localtime" && !strings.HasPrefix(path, "/usr/share/zoneinfo/") {
			return nil, nil, errors.New("已有实例时区仅支持系统 localtime 或固定 zoneinfo 数据")
		}
		if filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n\\") {
			return nil, nil, errors.New("时区数据路径无效")
		}
		if err := existingRootDirectory(filepath.Dir(path)); err != nil {
			return nil, nil, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, nil, err
		}
		if err = fail2banTimezoneStamp(info, started); err != nil {
			return nil, nil, err
		}
		remote, err := os.Lstat(procRoot + path)
		if err != nil || !os.SameFile(info, remote) {
			return nil, nil, errors.New("已有实例和宿主机的时区文件视图不同")
		}
		if info.Mode()&os.ModeSymlink == 0 {
			raw, err := secure.ReadRootFile(path, 1<<20)
			if err != nil {
				return nil, nil, err
			}
			latest, err := os.Lstat(path)
			if err != nil || !os.SameFile(info, latest) || latest.ModTime() != info.ModTime() || latest.Size() != info.Size() {
				return nil, nil, errors.New("读取时区文件期间身份变化")
			}
			if err = fail2banTimezoneStamp(latest, started); err != nil {
				return nil, nil, err
			}
			links = append(links, path+":"+secure.Hash(raw))
			return raw, links, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return nil, nil, err
		}
		remoteTarget, err := os.Readlink(procRoot + path)
		if err != nil || remoteTarget != target {
			return nil, nil, errors.New("已有实例时区链接的目标不同")
		}
		links = append(links, path+":"+target)
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = filepath.Clean(target)
	}
	return nil, nil, errors.New("时区链接超过解析预算")
}

func readFail2banExistingTimezone(ctx context.Context, b *fail2banBinding, live fail2banLiveService) (fail2banExistingTimezone, error) {
	var out fail2banExistingTimezone
	started, err := fail2banExistingStarted(ctx, b, live)
	if err != nil {
		return out, err
	}
	procRoot := "/proc/" + strconv.FormatInt(*live.view.MainPID, 10) + "/root"
	raw, err := fail2banReadLimited("/proc/"+strconv.FormatInt(*live.view.MainPID, 10)+"/environ", 64<<10)
	if err != nil || len(raw) > 0 && raw[len(raw)-1] != 0 {
		return out, errors.New("已有实例的初始时区环境不可完整读取")
	}
	zone, found := "", false
	if len(raw) > 0 {
		for _, entry := range strings.Split(string(raw[:len(raw)-1]), "\x00") {
			if value, ok := strings.CutPrefix(entry, "TZDIR="); ok {
				if out.tzDirPresent || value != "/usr/share/zoneinfo" {
					return out, errors.New("已有实例使用未接管的 TZDIR 数据目录")
				}
				out.tzDir, out.tzDirPresent = value, true
			}
			if value, ok := strings.CutPrefix(entry, "TZ="); ok {
				if found || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n\\") {
					return out, errors.New("已有实例时区环境重复或格式未知")
				}
				zone, found = value, true
			}
		}
	}
	out.StartedAt = started.UnixMicro()
	out.tz, out.tzPresent = zone, found
	out.Name, out.Source = "system", "/etc/localtime"
	dependencies := []string{}
	if found && zone == "" {
		out.Name, out.Source, out.location = "UTC", "TZ=", time.UTC
	} else {
		if found {
			name := strings.TrimPrefix(zone, ":")
			if name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-/.") != "" {
				return out, errors.New("已有实例的 POSIX 时区表达式不在接管范围")
			}
			path := name
			if !filepath.IsAbs(path) {
				path = filepath.Join("/usr/share/zoneinfo", path)
			}
			if filepath.Clean(path) != path || filepath.IsAbs(name) && name != "/etc/localtime" && !strings.HasPrefix(name, "/usr/share/zoneinfo/") {
				return out, errors.New("已有实例时区名称或数据路径未知")
			}
			out.Name, out.Source = name, path
		}
		data, links, err := fail2banExistingTimezoneFile(out.Source, procRoot, started)
		if err != nil {
			return out, err
		}
		out.location, err = time.LoadLocationFromTZData(out.Name, data)
		if err != nil {
			return out, errors.New("已有实例时区数据不是有效 TZif")
		}
		dependencies = links
	}
	encoded, _ := json.Marshal(struct {
		Present    bool
		TZ         string
		DirPresent bool
		Dir        string
		Files      []string
	}{found, zone, out.tzDirPresent, out.tzDir, dependencies})
	out.SHA256 = secure.Hash(encoded)
	return out, ctx.Err()
}

// A repeated autumn clock hour has two epochs. Reject it instead of selecting
// one offset and silently changing the remaining protection time.
func fail2banExistingCalendar(label string, location *time.Location) (time.Time, error) {
	const layout = "2006-01-02 15:04:05"
	wall, err := time.Parse(layout, label)
	if err != nil || location == nil {
		return time.Time{}, errors.New("官方封禁日历时间无效")
	}
	at, limit := wall.Add(-48*time.Hour), wall.Add(48*time.Hour)
	matches := map[int64]time.Time{}
	complete := false
	for count := 0; count < 16; count++ {
		local := at.In(location)
		_, offset := local.Zone()
		if offset < -24*3600 || offset > 24*3600 {
			return time.Time{}, errors.New("时区偏移超出已有实例支持范围")
		}
		candidate := wall.Add(-time.Duration(offset) * time.Second)
		if candidate.In(location).Format(layout) == label {
			matches[candidate.Unix()] = candidate
		}
		_, end := local.ZoneBounds()
		if end.IsZero() || !end.Before(limit) {
			complete = true
			break
		}
		if !end.After(at) {
			return time.Time{}, errors.New("时区转换边界未知")
		}
		at = end
	}
	if !complete || len(matches) != 1 {
		return time.Time{}, errors.New("官方封禁时间存在夏令时歧义或超出解析预算")
	}
	for _, value := range matches {
		return value, nil
	}
	return time.Time{}, errors.New("官方封禁时间无法唯一换算")
}

func fail2banExistingBanProof(labels map[string]fail2banHostBanTime, zone fail2banExistingTimezone) (map[string]fail2banBanTime, error) {
	out := map[string]fail2banBanTime{}
	if !fail2banDigest.MatchString(zone.SHA256) || zone.location == nil || len(labels) > 1024 {
		return nil, errors.New("已有实例时区或封禁证明不完整")
	}
	for ip, label := range labels {
		value := fail2banBanTime{Duration: label.Duration}
		if label.Duration != -1 {
			started, err := fail2banExistingCalendar(label.Started, zone.location)
			if err != nil {
				return nil, err
			}
			end, err := fail2banExistingCalendar(label.End, zone.location)
			if err != nil {
				return nil, err
			}
			if started.Unix() <= 0 || end.Unix() <= 0 {
				return nil, errors.New("官方封禁时间超出可持久核对的 Unix 时间范围")
			}
			if delta := end.Unix() - started.Unix() - label.Duration; delta < -1 || delta > 1 {
				return nil, errors.New("官方封禁的起止时间与时长不一致")
			}
			value.Expires = end.Unix()
		}
		out[ip] = value
	}
	return out, nil
}

func verifyFail2banExistingConfigSource(live fail2banLiveService, snapshot fail2banExistingConfigSnapshot) error {
	if live.view.MainPID == nil {
		return errors.New("已有实例进程身份未知")
	}
	procRoot := "/proc/" + strconv.FormatInt(*live.view.MainPID, 10) + "/root"
	entries, files := 0, 0
	err := filepath.WalkDir(fail2banExistingConfig, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 1024 {
			return errors.New("已有实例配置视图核对超过预算")
		}
		if entry.IsDir() {
			if err := existingRootDirectory(path); err != nil {
				return err
			}
		} else {
			name, err := filepath.Rel(fail2banExistingConfig, path)
			if err != nil {
				return err
			}
			if _, exists := snapshot.Files[name]; !exists || !entry.Type().IsRegular() {
				return errors.New("配置视图核对期间文件名单变化")
			}
			files++
		}
		host, err := os.Lstat(path)
		if err != nil {
			return err
		}
		server, err := os.Lstat(procRoot + path)
		if err != nil || !os.SameFile(host, server) {
			return errors.New("已有实例的实际配置文件/目录视图与宿主机不一致")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if files != len(snapshot.Files) {
		return errors.New("配置视图核对期间原文件缺失")
	}
	return nil
}
