package agent

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/secure"
)

type logCompression struct {
	id             string
	source, output *os.File
	writer         *gzip.Writer
}

func (c *logCompression) close() {
	if c.writer != nil {
		c.writer.Close()
	}
	if c.source != nil {
		c.source.Close()
	}
	if c.output != nil {
		c.output.Close()
	}
}

// RunLogs is independent of the Web process and consumes only the root-owned
// applied policy. The caller stops and joins it before releasing Nginx's lock.
func (n *Nginx) RunLogs(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	defer func() {
		if n.logs != nil {
			n.logs.mu.Lock()
			if n.logs.compression != nil {
				n.logs.compression.close()
				n.logs.compression = nil
			}
			n.logs.mu.Unlock()
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		n.logs.reader.Expire()
		n.sweepLogs(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (n *Nginx) sweepLogs(ctx context.Context) {
	n.mu.Lock()
	if n.closed || n.logs == nil {
		n.mu.Unlock()
		return
	}
	m := n.logs
	m.mu.Lock()
	workErr := func() error {
		records, err := n.Journal.List()
		if err != nil {
			return err
		}
		for _, r := range records {
			if strings.HasPrefix(r.Kind, "nginx.") && (r.State == "running" || r.State == "compensating" || r.State == "recovery_required") {
				return errors.New("配置操作未完成，日志轮转等待恢复")
			}
		}
		_, current, err := n.active()
		if err != nil {
			return errors.New("生效配置完整性未确认，日志轮转已暂停")
		}
		observed, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := n.observe(observed, current); err != nil {
			return errors.New("专用 Nginx 运行修订未确认，日志轮转已暂停")
		}
		if err := m.syncSourcesLocked(current.Logs); err != nil {
			return err
		}
		if n.LogOwner != "agent" {
			return nil
		}
		if err := m.recoverArchivesLocked(); err != nil {
			return err
		}
		if err := m.reopenLocked(); err != nil {
			return err
		}
		if err := m.retainLocked(); err != nil {
			return err
		}
		ids := make([]string, 0, len(m.state.Sources))
		for id := range m.state.Sources {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		rotated := 0
		base := m.nextSource
		for count := 0; count < len(ids) && rotated < 4; count++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			index := (base + count) % len(ids)
			source := m.state.Sources[ids[index]]
			file, err := m.liveFile(source)
			if err != nil || file.Size == 0 || source.Warning != "" {
				continue
			}
			if file.Size < m.state.Policy.SizeMiB<<20 && time.Now().Unix()-source.OpenedAt < m.state.Policy.IntervalHours*3600 {
				continue
			}
			pending, total := false, 0
			for _, a := range m.state.Archives {
				if a.SourceID == source.Definition.Source.ID {
					total++
					pending = pending || a.State == "planned" || a.State == "reopening"
				}
			}
			if pending {
				continue
			}
			if total >= limits.LogSourceArchives || len(m.state.Archives) >= limits.LogArchives {
				return errors.New("历史日志数量已达上限，保留策略无法释放足够已关闭文件")
			}
			a := &logArchive{ID: secure.ID(), SourceID: source.Definition.Source.ID, Generation: source.Generation, Device: file.Device, Inode: file.Inode, Size: file.Size, StoredBytes: file.Size, Format: file.Format, CreatedAt: max(source.OpenedAt, 1), State: "planned"}
			m.state.Archives[a.ID] = a
			if err := m.saveLocked(); err != nil {
				return err
			}
			if err := m.renameLocked(a); err != nil {
				return err
			}
			rotated++
			m.nextSource = (index + 1) % len(ids)
		}
		return m.reopenLocked()
	}()
	if workErr != nil {
		m.state.Warning = "日志维护暂停：" + safeLogMaintenanceError(workErr)
	} else {
		m.state.Warning = ""
	}
	m.state.LastSweepAt = time.Now().Unix()
	if n.LogOwner == "agent" {
		var space unix.Statfs_t
		if err := unix.Statfs(n.DataDir, &space); err != nil {
			m.state.Warning += " 无法确认日志磁盘可用空间"
		} else if space.Blocks > 0 && float64(space.Bavail)/float64(space.Blocks) < 0.05 {
			m.state.Warning += " 日志磁盘可用空间不足 5%，请清理或扩容；轮转阈值为定时检查的软阈值"
		}
	}
	if err := m.saveLocked(); err != nil {
		m.state.Warning = "日志维护状态无法持久保存，已暂停后续破坏性操作"
		m.policyUncertain = true
	}
	n.mu.Unlock()
	// Compression performs at most one scan budget per tick. It does not hold
	// the Nginx operation lock while consuming CPU or writing compressed bytes.
	if workErr == nil && n.LogOwner == "agent" && !m.policyUncertain {
		if err := m.compressLocked(ctx); err != nil {
			m.state.Warning = "历史日志压缩失败，原文件保持保留"
			if err := m.saveLocked(); err != nil {
				m.policyUncertain = true
				m.state.Warning = "日志压缩状态保存失败，已暂停破坏性维护；需本机恢复并重启 Agent"
			}
		}
	}
	m.mu.Unlock()
}

func safeLogMaintenanceError(err error) string {
	// Filesystem errors contain host paths; only our bounded semantic errors
	// may cross the IPC boundary.
	if strings.Contains(err.Error(), "日志") || strings.Contains(err.Error(), "Nginx") || strings.Contains(err.Error(), "配置") {
		if len(err.Error()) < 180 {
			return err.Error()
		}
	}
	return "文件身份、权限或持久保存失败，需本机检查"
}

func (m *managedLogs) renameLocked(a *logArchive) error {
	source := m.state.Sources[a.SourceID]
	live, err := m.liveFile(source)
	if err != nil {
		return err
	}
	if live.Inode != a.Inode || live.Device != a.Device {
		return errors.New("日志轮转意图与活动文件身份不一致")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, live.Name, unix.AT_FDCWD, m.archiveName(a, false), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(live.Name)); err != nil {
		return err
	}
	a.State = "reopening"
	source.OpenedAt = time.Now().Unix()
	source.Bytes = 0
	source.LiveIdentity = ""
	source.Generation = secure.ID()
	return m.saveLocked()
}

// A crash can leave a rename or gzip publication between durable state writes.
// Only names derived from the persisted catalog are considered for recovery.
func (m *managedLogs) recoverArchivesLocked() error {
	if m.policyUncertain {
		return errors.New("日志状态保存结果不确定，需 Agent 重启恢复")
	}
	for _, a := range m.state.Archives {
		switch a.State {
		case "planned":
			f, err := m.openLog(logs.File{Name: m.archiveName(a, false), Device: a.Device, Inode: a.Inode})
			if err == nil {
				f.Close()
				a.State = "reopening"
				source := m.state.Sources[a.SourceID]
				source.OpenedAt = time.Now().Unix()
				source.Generation = secure.ID()
				source.LiveIdentity = ""
				if err := m.saveLocked(); err != nil {
					return err
				}
			} else if os.IsNotExist(err) {
				if err := m.renameLocked(a); err != nil {
					return err
				}
			} else {
				return err
			}
		case "compressing":
			if m.compression != nil && m.compression.id == a.ID {
				continue
			}
			original, err := m.openLog(logs.File{Name: m.archiveName(a, false), Device: a.Device, Inode: a.Inode})
			if err != nil {
				return err
			}
			original.Close()
			for _, name := range []string{m.archiveName(a, true) + ".tmp", m.archiveName(a, true)} {
				if err := m.removeKnown(name, 0, 0); err != nil {
					return err
				}
			}
			a.State = "closed"
			if err := m.saveLocked(); err != nil {
				return err
			}
		case "compressed":
			if err := m.removeKnown(m.archiveName(a, false), a.Device, a.Inode); err != nil {
				return err
			}
		case "deleting":
			if err := m.deleteLocked(a); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *managedLogs) reopenLocked() error {
	pending := []*logArchive{}
	definitions := []logSource{}
	for _, a := range m.state.Archives {
		if a.State == "reopening" {
			pending = append(pending, a)
			definitions = append(definitions, m.state.Sources[a.SourceID].Definition)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if err := m.nginx.prepareLogFiles(definitions); err != nil {
		return err
	}
	pid, err := m.nginx.masterPID()
	if err != nil {
		return errors.New("Nginx master 身份未确认，旧日志保持保留")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	confirmed, err := m.nginx.masterPID()
	if err != nil || confirmed != pid {
		return errors.New("Nginx master 已变化，旧日志保持保留")
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGUSR1, nil, 0); err != nil {
		return errors.New("Nginx reopen 信号失败，旧日志保持保留")
	}
	inspect, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	open, err := m.nginx.openLogIdentities(inspect, pid)
	if err != nil {
		return err
	}
	remaining := false
	for _, a := range pending {
		f, err := m.openLog(logs.File{Name: m.archiveName(a, false), Device: a.Device, Inode: a.Inode})
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		a.Size = info.Size()
		a.StoredBytes = info.Size()
		if open[fmt.Sprintf("%d:%d", a.Device, a.Inode)] {
			f.Close()
			remaining = true
			continue
		}
		err = f.Chown(0, 0)
		if err == nil {
			err = f.Chmod(0600)
		}
		f.Close()
		if err != nil {
			return err
		}
		a.Size = info.Size()
		a.StoredBytes = info.Size()
		a.ClosedAt = time.Now().Unix()
		a.State = "closed"
		if err := m.saveLocked(); err != nil {
			return err
		}
	}
	if remaining {
		return errors.New("Nginx 尚未释放旧日志，暂停压缩和清理并等待下一次确认")
	}
	return nil
}

// Read only this verified master's own process tree. Check its descriptors
// first: subsequent workers inherit reopened descriptors once it has closed
// the old ones. Any inaccessible or over-budget tree leaves closure unproven.
func (n *Nginx) openLogIdentities(ctx context.Context, master int) (map[string]bool, error) {
	result := map[string]bool{}
	descriptors := 0
	inspect := func(pid int, child bool) error {
		if err := ctx.Err(); err != nil {
			return errors.New("Nginx 日志关闭确认超过时间预算")
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || exe != n.Binary {
			return errors.New("Nginx 进程树身份无法确认")
		}
		if child {
			data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil || len(data) > 64<<10 {
				return errors.New("Nginx 子进程身份无法确认")
			}
			parent := false
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					parent = strings.TrimSpace(strings.TrimPrefix(line, "PPid:")) == strconv.Itoa(master)
				}
			}
			if !parent {
				return errors.New("Nginx 子进程归属已变化")
			}
		}
		dir, err := os.Open(fmt.Sprintf("/proc/%d/fd", pid))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer dir.Close()
		entries, err := dir.Readdirnames(8193)
		if err != nil && err != io.EOF {
			return err
		}
		if len(entries) > 8192 {
			return errors.New("Nginx 文件描述符超过日志关闭确认预算")
		}
		for _, entry := range entries {
			descriptors++
			if descriptors > 32768 || ctx.Err() != nil {
				return errors.New("Nginx 日志关闭确认超过总预算")
			}
			info, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%s", pid, entry))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && info.Mode().IsRegular() {
				result[fileIdentity(stat)] = true
			}
		}
		return nil
	}
	if err := inspect(master, false); err != nil {
		return nil, err
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/task/%d/children", master, master))
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	file.Close()
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("Nginx 子进程列表超过日志关闭确认预算")
	}
	children := strings.Fields(string(data))
	if len(children) > 1024 {
		return nil, errors.New("Nginx 子进程数量超过日志关闭确认预算")
	}
	for _, child := range children {
		pid, err := strconv.Atoi(child)
		if err != nil || pid <= 1 {
			return nil, errors.New("Nginx 子进程列表无效")
		}
		if err := inspect(pid, true); err != nil {
			return nil, err
		}
	}
	if pid, err := n.masterPID(); err != nil || pid != master {
		return nil, errors.New("Nginx master 已变化，日志关闭尚未确认")
	}
	return result, nil
}

func (m *managedLogs) removeKnown(name string, device, inode uint64) error {
	f, err := m.openLog(logs.File{Name: name, Device: device, Inode: inode})
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	f.Close()
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || info.Mode().Perm() != 0600 {
		return errors.New("历史日志清理对象身份不可信")
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	return syncDir(filepath.Dir(name))
}
func (m *managedLogs) deleteLocked(a *logArchive) error {
	if a.ClosedAt <= 0 {
		return errors.New("日志关闭未经确认，禁止清理")
	}
	if a.State != "deleting" {
		a.State = "deleting"
		if err := m.saveLocked(); err != nil {
			return err
		}
	}
	if err := m.removeKnown(m.archiveName(a, false), a.Device, a.Inode); err != nil {
		return err
	}
	if a.Compressed {
		if err := m.removeKnown(m.archiveName(a, true), a.StoredDevice, a.StoredInode); err != nil {
			return err
		}
	}
	delete(m.state.Archives, a.ID)
	return m.saveLocked()
}

func (m *managedLogs) retainLocked() error {
	archives := []*logArchive{}
	totals := map[string]int64{}
	counts := map[string]int{}
	var total int64
	for _, s := range m.state.Sources {
		totals[logResourceKey(s)] += s.Bytes
		total += s.Bytes
	}
	for _, a := range m.state.Archives {
		counts[a.SourceID]++
		totals[logResourceKey(m.state.Sources[a.SourceID])] += a.StoredBytes
		total += a.StoredBytes
		if a.State == "closed" || a.State == "compressed" {
			archives = append(archives, a)
		}
	}
	sort.Slice(archives, func(i, j int) bool {
		if archives[i].ClosedAt == archives[j].ClosedAt {
			return archives[i].ID < archives[j].ID
		}
		return archives[i].ClosedAt < archives[j].ClosedAt
	})
	deleted := 0
	for _, a := range archives {
		resource := logResourceKey(m.state.Sources[a.SourceID])
		days := m.state.Policy.AccessDays
		if strings.Contains(m.state.Sources[a.SourceID].Definition.Source.Category, "error") {
			days = m.state.Policy.ErrorDays
		}
		if time.Now().Unix()-a.ClosedAt < days*86400 && totals[resource] <= m.state.Policy.ResourceMiB<<20 && total <= m.state.Policy.TotalMiB<<20 && counts[a.SourceID] < limits.LogSourceArchives && len(m.state.Archives) < limits.LogArchives {
			continue
		}
		if err := m.deleteLocked(a); err != nil {
			return err
		}
		total -= a.StoredBytes
		totals[resource] -= a.StoredBytes
		counts[a.SourceID]--
		deleted++
		if deleted >= 32 {
			break
		}
	}
	return nil
}

func (m *managedLogs) compressLocked(ctx context.Context) error {
	if !m.state.Policy.Compress && m.compression == nil {
		return nil
	}
	if m.compression == nil {
		var selected *logArchive
		for _, a := range m.state.Archives {
			if a.State == "closed" && (selected == nil || a.ClosedAt < selected.ClosedAt) {
				selected = a
			}
		}
		if selected == nil {
			return nil
		}
		source, err := m.openLog(logs.File{Name: m.archiveName(selected, false), Device: selected.Device, Inode: selected.Inode})
		if err != nil {
			return err
		}
		selected.State = "compressing"
		if err := m.saveLocked(); err != nil {
			source.Close()
			return err
		}
		output, err := os.OpenFile(m.archiveName(selected, true)+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			source.Close()
			return err
		}
		m.compression = &logCompression{id: selected.ID, source: source, output: output, writer: gzip.NewWriter(output)}
	}
	c := m.compression
	a := m.state.Archives[c.id]
	fail := func(err error) error { c.close(); m.compression = nil; return err }
	buffer := make([]byte, 64<<10)
	var copied int64
	for copied < limits.LogScanBytes {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		n, err := c.source.Read(buffer)
		copied += int64(n)
		if n > 0 {
			if _, writeErr := c.writer.Write(buffer[:n]); writeErr != nil {
				return fail(writeErr)
			}
		}
		if err == nil {
			continue
		}
		if err != io.EOF {
			return fail(err)
		}
		if err := c.writer.Close(); err != nil {
			return fail(err)
		}
		c.writer = nil
		if err := c.output.Sync(); err != nil {
			return fail(err)
		}
		info, err := c.output.Stat()
		if err != nil {
			return fail(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		c.close()
		m.compression = nil
		if err := unix.Renameat2(unix.AT_FDCWD, m.archiveName(a, true)+".tmp", unix.AT_FDCWD, m.archiveName(a, true), unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(m.archiveName(a, true))); err != nil {
			return err
		}
		a.State = "compressed"
		a.Compressed = true
		a.StoredBytes = info.Size()
		a.StoredDevice = uint64(stat.Dev)
		a.StoredInode = stat.Ino
		if err := m.saveLocked(); err != nil {
			m.policyUncertain = true
			return err
		}
		return m.removeKnown(m.archiveName(a, false), a.Device, a.Inode)
	}
	return nil
}
