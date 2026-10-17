package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/secure"
)

type logRecord struct {
	Definition     logSource `json:"definition"`
	Active         bool      `json:"active"`
	LiveIdentity   string    `json:"live_identity"`
	Generation     string    `json:"generation"`
	OpenedAt       int64     `json:"opened_at"`
	Bytes          int64     `json:"bytes"`
	Warning        string    `json:"warning"`
	Retiring       bool      `json:"retiring"`
	RetiringDevice uint64    `json:"retiring_device"`
	RetiringInode  uint64    `json:"retiring_inode"`
}
type logArchive struct {
	ID           string `json:"id"`
	SourceID     string `json:"source_id"`
	Generation   string `json:"generation"`
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	Size         int64  `json:"size"`
	StoredBytes  int64  `json:"stored_bytes"`
	StoredDevice uint64 `json:"stored_device"`
	StoredInode  uint64 `json:"stored_inode"`
	Compressed   bool   `json:"compressed"`
	Format       string `json:"format"`
	CreatedAt    int64  `json:"created_at"`
	ClosedAt     int64  `json:"closed_at"`
	State        string `json:"state"`
}
type logState struct {
	Version       int64                  `json:"version"`
	Policy        logs.Policy            `json:"policy"`
	LastOperation string                 `json:"last_operation"`
	LastSweepAt   int64                  `json:"last_sweep_at"`
	Warning       string                 `json:"warning"`
	DeliveryGaps  int64                  `json:"delivery_gaps"`
	Sources       map[string]*logRecord  `json:"sources"`
	Archives      map[string]*logArchive `json:"archives"`
}
type managedLogs struct {
	nginx           *Nginx
	dataDir         string
	uid             int
	owner           string
	journal         *Journal
	system          bool
	dir             string
	mu              sync.Mutex
	state           logState
	reader          *logs.Reader
	compression     *logCompression
	nextSource      int
	policyUncertain bool
}

func openManagedLogs(n *Nginx) (*managedLogs, error) {
	if n.LogOwner == "" {
		n.LogOwner = "unconfirmed"
	}
	if n.LogOwner != "agent" && n.LogOwner != "external" && n.LogOwner != "unconfirmed" {
		return nil, errors.New("invalid Nginx log rotation owner")
	}
	return openLogStore(n, n.DataDir, n.uid, n.LogOwner, n.Journal, false)
}

func openLogStore(n *Nginx, dataDir string, uid int, owner string, journal *Journal, system bool) (*managedLogs, error) {
	dir := filepath.Join(dataDir, "agent", "logs")
	if system {
		dir = filepath.Join(dataDir, "agent", "event-logs")
	}
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return nil, err
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	m := &managedLogs{nginx: n, dataDir: dataDir, uid: uid, owner: owner, journal: journal, system: system, dir: dir, state: logState{Version: 1, Policy: logs.DefaultPolicy(), Sources: map[string]*logRecord{}, Archives: map[string]*logArchive{}}}
	name := filepath.Join(dir, "state.json")
	if info, err := os.Lstat(name); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() > 8<<20 {
			return nil, errors.New("untrusted log state")
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		if json.Unmarshal(data, &m.state) != nil || !validLogState(m.state, system) {
			return nil, errors.New("invalid log state")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if !system {
		m.reader = logs.NewReader(m.snapshot, m.openLog)
	}
	if err := m.recoverPolicy(); err != nil {
		return nil, err
	}
	return m, nil
}
func validLogState(state logState, system bool) bool {
	if state.DeliveryGaps < 0 || state.DeliveryGaps > 1 || system && len(state.Sources) > 1024 || state.Version < 1 || state.Policy.Validate() != nil || state.Sources == nil || state.Archives == nil || len(state.Sources) > limits.LogSources || len(state.Archives) > limits.LogArchives || state.LastOperation != "" && !validID(state.LastOperation) {
		return false
	}
	counts := map[string]int{}
	for id, source := range state.Sources {
		if source == nil || id != source.Definition.Source.ID || !validID(source.Generation) || !validStoredLogSource(source.Definition, system) || source.Retiring && (!system || source.Active || source.Definition.Source.Category != "task" || source.RetiringInode == 0) {
			return false
		}
	}
	for id, archive := range state.Archives {
		if archive == nil || !validID(id) || id != archive.ID || state.Sources[archive.SourceID] == nil || archive.Size < 0 || archive.StoredBytes < 0 || archive.CreatedAt <= 0 {
			return false
		}
		if !validID(archive.Generation) || archive.Inode == 0 || archive.Compressed && archive.StoredInode == 0 || archive.State != "planned" && archive.State != "reopening" && archive.ClosedAt <= 0 || archive.Compressed && archive.State != "compressed" && archive.State != "deleting" {
			return false
		}
		switch archive.State {
		case "planned", "reopening", "closed", "compressing", "compressed", "deleting":
		default:
			return false
		}
		if system && archive.Format != logs.EventFormat || !system && archive.Format != "text" && archive.Format != "nginxpanel_http" && archive.Format != "nginxpanel_stream" {
			return false
		}
		counts[archive.SourceID]++
		if counts[archive.SourceID] > limits.LogSourceArchives {
			return false
		}
	}
	return true
}

func (m *managedLogs) saveLocked() error {
	data, err := json.Marshal(m.state)
	if err != nil || len(data) > 8<<20 {
		return errors.New("log state exceeds limit")
	}
	tmp := filepath.Join(m.dir, ".tmp-"+secure.ID())
	defer os.Remove(tmp)
	if err := durableFile(tmp, data, 0600, 0); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(m.dir, "state.json")); err != nil {
		return err
	}
	return syncDir(m.dir)
}

func fileIdentity(stat *syscall.Stat_t) string { return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino) }

func (m *managedLogs) openLog(file logs.File) (*os.File, error) {
	if !filepath.IsAbs(file.Name) || !strings.HasPrefix(file.Name, filepath.Join(m.dataDir, "logs")+string(os.PathSeparator)) || filepath.Clean(file.Name) != file.Name {
		return nil, errors.New("invalid managed log path")
	}
	if err := existingRootDirectory(filepath.Dir(file.Name)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(file.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), file.Name)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || (stat.Uid != 0 && stat.Uid != uint32(m.uid)) || info.Mode().Perm()&0007 != 0 || info.Mode().Perm()&0020 != 0 || file.Inode != 0 && (stat.Ino != file.Inode || uint64(stat.Dev) != file.Device) {
		f.Close()
		return nil, errors.New("untrusted managed log identity or permissions")
	}
	return f, nil
}
func (m *managedLogs) liveFile(source *logRecord) (logs.File, error) {
	name := filepath.Join(m.dataDir, source.Definition.Path)
	f, err := m.openLog(logs.File{Name: name})
	if err != nil {
		return logs.File{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return logs.File{}, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	return logs.File{Name: name, Identity: source.Definition.Source.ID + ":" + source.Generation, Device: uint64(stat.Dev), Inode: stat.Ino, Current: true, Writing: true, Format: source.Definition.Source.Format, Size: info.Size(), CreatedAt: source.OpenedAt}, nil
}
func (m *managedLogs) archiveName(archive *logArchive, compressed bool) string {
	name := filepath.Join(m.dataDir, m.state.Sources[archive.SourceID].Definition.Path) + "." + archive.ID
	if compressed {
		name += ".gz"
	}
	return name
}

func (m *managedLogs) snapshot(id string) (logs.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	source := m.state.Sources[id]
	if source == nil {
		return logs.Snapshot{}, fault.NotFound("受管日志来源不存在")
	}
	out := logs.Snapshot{Source: source.Definition.Source, Files: []logs.File{}, Gap: m.system && m.state.DeliveryGaps > 0}
	archives := []*logArchive{}
	for _, archive := range m.state.Archives {
		if archive.SourceID == id && archive.State != "deleting" {
			archives = append(archives, archive)
		}
	}
	sort.Slice(archives, func(i, j int) bool {
		if archives[i].CreatedAt == archives[j].CreatedAt {
			return archives[i].ID < archives[j].ID
		}
		return archives[i].CreatedAt < archives[j].CreatedAt
	})
	seen := map[string]bool{}
	for _, archive := range archives {
		if archive.Format == "text" {
			out.Source.Sensitive = true
		}
		compressed := archive.Compressed
		file := logs.File{Name: m.archiveName(archive, compressed), Current: false, Writing: archive.State == "planned" || archive.State == "reopening", Format: archive.Format, Compressed: compressed, CreatedAt: archive.CreatedAt, Size: archive.Size}
		if !compressed {
			file.Device = archive.Device
			file.Inode = archive.Inode
		} else {
			file.Device = archive.StoredDevice
			file.Inode = archive.StoredInode
		}
		f, err := m.openLog(file)
		if err != nil {
			if os.IsNotExist(err) {
				if archive.State != "planned" {
					out.Gap = true
				}
				continue
			}
			return out, fault.Unavailable("日志历史文件身份或权限异常")
		}
		info, err := f.Stat()
		f.Close()
		if err != nil {
			return out, err
		}
		stat := info.Sys().(*syscall.Stat_t)
		file.Device = uint64(stat.Dev)
		file.Inode = stat.Ino
		file.Identity = archive.SourceID + ":" + archive.Generation
		out.Files = append(out.Files, file)
		seen[file.Identity] = true
		if archive.Format == "text" {
			out.Source.Sensitive = true
		}
	}
	file, err := m.liveFile(source)
	if err == nil {
		if !seen[file.Identity] {
			out.Files = append(out.Files, file)
		}
	} else if !os.IsNotExist(err) {
		return out, fault.Unavailable("活动日志文件身份或权限异常")
	} else if source.LiveIdentity != "" {
		out.Gap = true
	}
	return out, nil
}

func (m *managedLogs) sources() []logs.Source {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []logs.Source{}
	counts := map[string]int{}
	sizes := map[string]int64{}
	sensitive := map[string]bool{}
	for _, archive := range m.state.Archives {
		counts[archive.SourceID]++
		sizes[archive.SourceID] += archive.StoredBytes
		sensitive[archive.SourceID] = sensitive[archive.SourceID] || archive.Format == "text"
	}
	for _, record := range m.state.Sources {
		source := record.Definition.Source
		source.Active = record.Active
		source.Bytes = record.Bytes
		source.Reason = record.Warning
		source.Archives = counts[source.ID]
		source.Bytes += sizes[source.ID]
		source.Sensitive = source.Sensitive || sensitive[source.ID]
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ResourceID == out[j].ResourceID {
			return out[i].Label < out[j].Label
		}
		return out[i].ResourceID < out[j].ResourceID
	})
	return out
}
func (m *managedLogs) policy() logs.PolicyView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := logs.PolicyView{Version: m.state.Version, Scope: m.scope(), Policy: m.state.Policy, Owner: m.owner, Editable: m.owner == "agent" && !m.policyUncertain, LastSweepAt: m.state.LastSweepAt, Warning: m.state.Warning}
	resources := map[string]int64{}
	for _, source := range m.state.Sources {
		out.Bytes += source.Bytes
		resources[logResourceKey(source)] += source.Bytes
	}
	for _, archive := range m.state.Archives {
		out.Bytes += archive.StoredBytes
		resources[logResourceKey(m.state.Sources[archive.SourceID])] += archive.StoredBytes
	}
	if out.Bytes > m.state.Policy.TotalMiB<<20 {
		out.Warning += " 总占用超过策略配额；活动日志与尚未确认关闭的文件不会被强制删除"
	}
	for _, size := range resources {
		if size > m.state.Policy.ResourceMiB<<20 {
			out.Warning += " 部分资源超过日志配额；仅清理已关闭历史"
			break
		}
	}
	if m.owner != "agent" {
		out.Warning = "日志轮转所有者尚未确认为 Agent，保留外部管理；需本机明确唯一所有者后才能启用受管轮转。 " + out.Warning
	} else if m.policyUncertain {
		out.Warning = "日志状态保存结果不确定，已暂停策略修改与破坏性维护；需本机恢复并重启 Agent"
	}
	return out
}

func logResourceKey(source *logRecord) string {
	if source.Definition.Source.ResourceID != "" {
		return source.Definition.Source.ResourceID
	}
	if source.Definition.Source.Category == "application" || source.Definition.Source.Category == "security" {
		return source.Definition.Source.Category + "-global"
	}
	return "nginx-global"
}

func (m *managedLogs) syncSourcesLocked(sources []logSource) error {
	if !validLogSources(sources) {
		return errors.New("invalid applied log source list")
	}
	for _, source := range m.state.Sources {
		source.Active = false
	}
	for _, definition := range sources {
		source := m.state.Sources[definition.Source.ID]
		if source == nil {
			if len(m.state.Sources) >= limits.LogSources {
				return errors.New("retained log source quota exceeded")
			}
			source = &logRecord{OpenedAt: time.Now().Unix(), Generation: secure.ID()}
			m.state.Sources[definition.Source.ID] = source
		}
		source.Definition = definition
		source.Active = true
	}
	for _, source := range m.state.Sources {
		file, err := m.liveFile(source)
		if err == nil {
			physical := fmt.Sprintf("%d:%d", file.Device, file.Inode)
			if source.LiveIdentity != "" && source.LiveIdentity != physical {
				source.OpenedAt = time.Now().Unix()
				source.Generation = secure.ID()
			}
			source.LiveIdentity = physical
			source.Bytes = file.Size
			source.Warning = ""
		} else if os.IsNotExist(err) {
			source.Bytes = 0
			source.Warning = "日志文件尚未生成或已由外部移除"
		} else {
			source.Warning = "日志路径、文件身份或权限异常，已停止该来源的轮转和读取"
		}
	}
	return m.saveLocked()
}
