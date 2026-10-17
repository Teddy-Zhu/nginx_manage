package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/secure"
)

type EventLogRequest struct {
	Protocol int          `json:"protocol"`
	Epoch    string       `json:"epoch"`
	NodeID   string       `json:"node_id"`
	Events   []logs.Event `json:"events"`
}

type eventReceipt struct {
	NodeID string `json:"node_id"`
	Last   int64  `json:"last"`
}

type eventWrite struct {
	Source logSource `json:"source"`
	Device uint64    `json:"device"`
	Inode  uint64    `json:"inode"`
	Offset int64     `json:"offset"`
	Data   []byte    `json:"data"`
	Active bool      `json:"active"`
}

// The intent fixes every byte and file identity before any append. A retry
// completes only an exact existing prefix; it never appends an uncertain line.
type eventIntent struct {
	Request EventLogRequest `json:"request"`
	After   int64           `json:"after"`
	Writes  []eventWrite    `json:"writes"`
}

type eventLogStore struct {
	*managedLogs
	receipts map[string]eventReceipt
	pending  *eventIntent
}

func (m *managedLogs) scope() string {
	if m.system {
		return "system"
	}
	return "nginx"
}

func eventSource(category, taskID string) logSource {
	name, label := "logs/"+category+"/events.jsonl", "应用事件"
	if category == "security" {
		label = "身份与凭据事件"
	}
	if category == "task" {
		name, label = "logs/tasks/"+taskID+"/events.jsonl", "任务 · "+taskID
	}
	return logSource{Path: name, Source: logs.Source{ID: secure.Hash([]byte(name)), ResourceID: taskID, Category: category, Label: label, Format: logs.EventFormat, Active: true}}
}

func validStoredLogSource(source logSource, system bool) bool {
	if !system {
		return validLogSources([]logSource{source})
	}
	if source.Source.Category != "application" && source.Source.Category != "security" && source.Source.Category != "task" {
		return false
	}
	if source.Source.Category == "task" && !validID(source.Source.ResourceID) || source.Source.Category != "task" && source.Source.ResourceID != "" {
		return false
	}
	expected := eventSource(source.Source.Category, source.Source.ResourceID)
	return source.Path == expected.Path && source.Source.ID == expected.Source.ID && source.Source.Format == logs.EventFormat && source.Source.Label == expected.Source.Label && !source.Source.Sensitive && !source.Source.AuthPresence
}

func validEventRequest(in EventLogRequest) bool {
	if in.Protocol != Protocol || len(in.Epoch) != 32 || strings.Trim(in.Epoch, "0123456789abcdef") != "" || !validID(in.NodeID) || len(in.Events) < 1 || len(in.Events) > 64 {
		return false
	}
	var last int64
	for _, event := range in.Events {
		if event.Validate() != nil || event.Sequence <= last {
			return false
		}
		last = event.Sequence
	}
	return true
}

func openEventLogs(s *Server) (*eventLogStore, error) {
	m, err := openLogStore(nil, s.DataDir, 0, "agent", s.Journal, true)
	if err != nil {
		return nil, err
	}
	for _, category := range []string{"application", "security", "tasks"} {
		if err = secure.RootDirectory(filepath.Join(s.DataDir, "logs", category), 0700); err != nil {
			return nil, err
		}
	}
	if err = syncDir(filepath.Join(s.DataDir, "logs")); err != nil {
		return nil, err
	}
	if err = syncDir(s.DataDir); err != nil {
		return nil, err
	}
	e := &eventLogStore{managedLogs: m, receipts: map[string]eventReceipt{}}
	if err = e.load("receipts.json", &e.receipts); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if e.receipts == nil || len(e.receipts) > 32 {
		return nil, errors.New("event log epoch quota exceeded")
	}
	for epoch, r := range e.receipts {
		if len(epoch) != 32 || strings.Trim(epoch, "0123456789abcdef") != "" || !validID(r.NodeID) || r.Last < 1 {
			return nil, errors.New("invalid event log receipt")
		}
	}
	var pending eventIntent
	if err = e.load("pending.json", &pending); err == nil {
		if !validEventRequest(pending.Request) || pending.After < 0 || pending.After >= pending.Request.Events[len(pending.Request.Events)-1].Sequence || len(pending.Writes) < 1 || len(pending.Writes) > 64 {
			return nil, errors.New("invalid event log intent")
		}
		for _, w := range pending.Writes {
			if !validStoredLogSource(w.Source, true) || w.Inode == 0 || w.Offset < 0 || len(w.Data) == 0 || len(w.Data) > 64<<10 {
				return nil, errors.New("invalid event log write")
			}
		}
		if err = e.validateIntent(pending); err != nil {
			return nil, err
		}
		e.pending = &pending
		if err = e.finishLocked(); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err = m.recoverArchivesLocked(); err != nil {
		return nil, err
	}
	if err = m.reopenLocked(); err != nil {
		return nil, err
	}
	for _, category := range []string{"application", "security"} {
		if _, err = e.ensureSourceLocked(eventSource(category, "")); err != nil {
			return nil, err
		}
	}
	if err = m.saveLocked(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *eventLogStore) load(name string, out any) error {
	path := filepath.Join(e.dir, name)
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() > 256<<10 {
		return errors.New("untrusted event log state")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 256<<10+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing event log state")
	}
	return nil
}

func (e *eventLogStore) save(name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 256<<10 {
		return errors.New("event log state exceeds limit")
	}
	tmp := filepath.Join(e.dir, ".tmp-"+secure.ID())
	defer os.Remove(tmp)
	if err = durableFile(tmp, raw, 0600, 0); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(e.dir, name)); err != nil {
		return err
	}
	return syncDir(e.dir)
}

func (e *eventLogStore) ensureSourceLocked(def logSource) (*logRecord, error) {
	if !validStoredLogSource(def, true) {
		return nil, errors.New("invalid event source")
	}
	source := e.state.Sources[def.Source.ID]
	fresh := source == nil
	if fresh {
		if len(e.state.Sources) >= 1024 {
			return nil, fault.Conflict("任务日志来源已达 1024 个保留上限，等待保留策略清理")
		}
		source = &logRecord{Definition: def, Active: def.Source.Category != "task", OpenedAt: time.Now().Unix(), Generation: secure.ID()}
	}
	if source.Retiring {
		return nil, fault.Conflict("任务日志来源正在完成保留清理")
	}
	if err := e.prepareEventFile(def); err != nil {
		return nil, err
	}
	if fresh {
		file, err := e.liveFile(source)
		if err != nil {
			return nil, err
		}
		if file.Size != 0 {
			return nil, errors.New("uncatalogued event file is not empty")
		}
		e.state.Sources[def.Source.ID] = source
	}
	return source, nil
}

func (m *managedLogs) prepareEventFile(def logSource) error {
	name := filepath.Join(m.dataDir, def.Path)
	if err := secure.RootDirectory(filepath.Dir(name), 0700); err != nil {
		return err
	}
	fd, err := unix.Open(name, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm() != 0600 {
			err = errors.New("untrusted event file")
		}
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(name)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(filepath.Dir(name)))
}

func (e *eventLogStore) append(in EventLogRequest) error {
	if !validEventRequest(in) {
		return fault.Invalid("日志批次合同无效")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policyUncertain {
		return fault.Unavailable("日志持久状态不确定，须本机核对并重启 Agent")
	}
	if err := e.finishLocked(); err != nil {
		return err
	}
	if err := e.recoverArchivesLocked(); err != nil {
		return err
	}
	if err := e.reopenLocked(); err != nil {
		return err
	}
	r, exists := e.receipts[in.Epoch]
	if exists && r.NodeID != in.NodeID {
		return fault.Conflict("日志来源身份不一致")
	}
	if !exists && len(e.receipts) >= 32 {
		return fault.Conflict("日志投递代次已达保留上限，须本机维护")
	}
	needed := map[string]bool{}
	for _, event := range in.Events {
		if event.Sequence <= r.Last {
			continue
		}
		id := eventSource(event.Category, event.TaskID).Source.ID
		if source := e.state.Sources[id]; source == nil {
			needed[id] = true
		} else if source.Retiring {
			return fault.Conflict("任务日志来源正在完成保留清理")
		}
	}
	if len(e.state.Sources)+len(needed) > 1024 {
		return fault.Conflict("任务日志来源达到保留上限，等待 Agent 清理已关闭历史")
	}
	intent := &eventIntent{Request: in, After: r.Last}
	groups := map[string]int{}
	for _, event := range in.Events {
		if event.Sequence <= r.Last {
			continue
		}
		def := eventSource(event.Category, event.TaskID)
		index, ok := groups[def.Source.ID]
		if !ok {
			source, err := e.ensureSourceLocked(def)
			if err != nil {
				return err
			}
			file, err := e.liveFile(source)
			if err != nil {
				return err
			}
			index = len(intent.Writes)
			groups[def.Source.ID] = index
			intent.Writes = append(intent.Writes, eventWrite{Source: def, Device: file.Device, Inode: file.Inode, Offset: file.Size})
		}
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		w := &intent.Writes[index]
		w.Data = append(w.Data, append(raw, '\n')...)
		w.Active = event.Category != "task" || event.State != "succeeded" && event.State != "failed" && event.State != "rolled_back" && event.State != "cancelled"
	}
	if len(intent.Writes) == 0 {
		return nil
	}
	// Catalog durability precedes the append intent, so recovery never guesses
	// a source path or recreates the generation associated with written bytes.
	if err := e.saveLocked(); err != nil {
		e.policyUncertain = true
		return err
	}
	if err := e.save("pending.json", intent); err != nil {
		e.policyUncertain = true
		return err
	}
	e.pending = intent
	return e.finishLocked()
}

func (e *eventLogStore) finishLocked() error {
	if e.pending == nil {
		return nil
	}
	intent := e.pending
	for _, w := range intent.Writes {
		name := filepath.Join(e.dataDir, w.Source.Path)
		if err := existingRootDirectory(filepath.Dir(name)); err != nil {
			return err
		}
		fd, err := unix.Open(name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), name)
		err = func() error {
			info, err := f.Stat()
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm() != 0600 || stat.Ino != w.Inode || uint64(stat.Dev) != w.Device || info.Size() < w.Offset || info.Size() > w.Offset+int64(len(w.Data)) {
				return errors.New("event append identity changed")
			}
			present := make([]byte, info.Size()-w.Offset)
			if len(present) > 0 {
				if _, err = f.ReadAt(present, w.Offset); err != nil {
					return err
				}
				if !bytes.Equal(present, w.Data[:len(present)]) {
					return errors.New("event append prefix changed")
				}
			}
			remaining := w.Data[len(present):]
			if len(remaining) > 0 {
				if _, err = f.WriteAt(remaining, info.Size()); err != nil {
					return err
				}
			}
			return f.Sync()
		}()
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		source := e.state.Sources[w.Source.Source.ID]
		if source == nil {
			return errors.New("event source catalog missing")
		}
		source.Active = w.Active
		source.Bytes = w.Offset + int64(len(w.Data))
		source.LiveIdentity = fmt.Sprintf("%d:%d", w.Device, w.Inode)
	}
	// Receipt publication happens only after every file and catalog is durable.
	// The intent remains until both publications are known to have succeeded.
	prior := e.receipts[intent.Request.Epoch]
	last := intent.Request.Events[len(intent.Request.Events)-1].Sequence
	if prior.Last < last {
		for _, event := range intent.Request.Events {
			if event.Sequence > prior.Last && event.Code == "log.delivery_gap" {
				e.state.DeliveryGaps = 1
			}
		}
	}
	if err := e.saveLocked(); err != nil {
		e.policyUncertain = true
		return err
	}
	e.receipts[intent.Request.Epoch] = eventReceipt{NodeID: intent.Request.NodeID, Last: last}
	if err := e.save("receipts.json", e.receipts); err != nil {
		e.policyUncertain = true
		return err
	}
	if err := os.Remove(filepath.Join(e.dir, "pending.json")); err != nil {
		e.policyUncertain = true
		return err
	}
	if err := syncDir(e.dir); err != nil {
		e.policyUncertain = true
		return err
	}
	e.pending = nil
	return nil
}

func (m *managedLogs) closeEventArchivesLocked(pending []*logArchive) error {
	// Event append and maintenance share m.mu; no writer retains a descriptor.
	for _, a := range pending {
		source := m.state.Sources[a.SourceID]
		f, err := m.openLog(logs.File{Name: m.archiveName(a, false), Device: a.Device, Inode: a.Inode})
		if err != nil {
			return err
		}
		info, err := f.Stat()
		f.Close()
		if err != nil {
			return err
		}
		if info.Size() != a.Size {
			return errors.New("closed event log size changed")
		}
		if err := m.prepareEventFile(source.Definition); err != nil {
			return err
		}
		a.State = "closed"
		a.ClosedAt = time.Now().Unix()
		if err := m.saveLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (e *eventLogStore) sweep(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policyUncertain {
		return
	}
	err := func() error {
		if err := e.finishLocked(); err != nil {
			return err
		}
		if err := e.recoverArchivesLocked(); err != nil {
			return err
		}
		if err := e.reopenLocked(); err != nil {
			return err
		}
		for _, source := range e.state.Sources {
			if source.Retiring {
				continue
			}
			f, err := e.liveFile(source)
			if err != nil {
				return err
			}
			source.Bytes = f.Size
		}
		if err := e.retainLocked(); err != nil {
			return err
		}
		if err := e.rotateDueLocked(ctx); err != nil {
			return err
		}
		if err := e.reopenLocked(); err != nil {
			return err
		}
		if err := e.compressLocked(ctx); err != nil {
			return err
		}
		return e.pruneLocked()
	}()
	e.state.Warning = ""
	if err != nil {
		e.state.Warning = "系统日志维护暂停：" + safeLogMaintenanceError(err)
	}
	if e.state.DeliveryGaps > 0 {
		e.state.Warning += " 日志投递曾达到缓冲上限，查询与下载将标记缺口"
	}
	e.state.LastSweepAt = time.Now().Unix()
	if err = e.saveLocked(); err != nil {
		e.policyUncertain = true
	}
}

func (e *eventLogStore) pruneLocked() error {
	ids := make([]string, 0, len(e.state.Sources))
	for id := range e.state.Sources {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return e.state.Sources[ids[i]].OpenedAt < e.state.Sources[ids[j]].OpenedAt })
	deleted := 0
	for _, id := range ids {
		source := e.state.Sources[id]
		if !source.Retiring {
			if source.Active || source.Definition.Source.Category != "task" || source.Bytes != 0 {
				continue
			}
			quota := len(e.state.Sources) > 960
			if !quota && time.Now().Unix()-source.OpenedAt < e.state.Policy.AccessDays*86400 {
				continue
			}
			eligible := true
			for _, a := range e.state.Archives {
				if a.SourceID == id && (!quota || a.State != "closed" && a.State != "compressed") {
					eligible = false
				}
			}
			if !eligible {
				continue
			}
			file, err := e.liveFile(source)
			if err != nil {
				return err
			}
			if file.Size != 0 {
				continue
			}
			source.Retiring = true
			source.RetiringDevice = file.Device
			source.RetiringInode = file.Inode
			if err = e.saveLocked(); err != nil {
				e.policyUncertain = true
				return err
			}
		}
		for _, a := range e.state.Archives {
			if a.SourceID != id {
				continue
			}
			if a.State != "closed" && a.State != "compressed" && a.State != "deleting" {
				return errors.New("retiring task log closure unconfirmed")
			}
			if err := e.deleteLocked(a); err != nil {
				return err
			}
			deleted++
			if deleted >= 32 {
				return nil
			}
		}
		name := filepath.Join(e.dataDir, source.Definition.Path)
		f, err := e.openLog(logs.File{Name: name, Device: source.RetiringDevice, Inode: source.RetiringInode})
		if err == nil {
			info, statErr := f.Stat()
			f.Close()
			if statErr != nil {
				return statErr
			}
			if info.Size() != 0 {
				return errors.New("retiring task log changed")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := e.removeKnown(name, source.RetiringDevice, source.RetiringInode); err != nil {
			return err
		}
		if err := os.Remove(filepath.Dir(name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := syncDir(filepath.Dir(filepath.Dir(name))); err != nil {
			return err
		}
		delete(e.state.Sources, id)
		if err := e.saveLocked(); err != nil {
			e.policyUncertain = true
			return err
		}
		deleted++
		if deleted >= 32 {
			return nil
		}
	}
	return nil
}

func (e *eventLogStore) validateIntent(in eventIntent) error {
	expected := map[string][]byte{}
	active := map[string]bool{}
	for _, event := range in.Request.Events {
		if event.Sequence <= in.After {
			continue
		}
		id := eventSource(event.Category, event.TaskID).Source.ID
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		expected[id] = append(expected[id], append(raw, '\n')...)
		active[id] = event.Category != "task" || event.State != "succeeded" && event.State != "failed" && event.State != "rolled_back" && event.State != "cancelled"
	}
	if len(expected) != len(in.Writes) {
		return errors.New("event intent source mismatch")
	}
	for _, w := range in.Writes {
		id := w.Source.Source.ID
		if e.state.Sources[id] == nil || !bytes.Equal(expected[id], w.Data) || w.Active != active[id] {
			return errors.New("event intent bytes mismatch")
		}
		delete(expected, id)
	}
	if len(expected) != 0 {
		return errors.New("event intent has duplicate sources")
	}
	return nil
}

func (c *Client) AppendEvents(ctx context.Context, in EventLogRequest) error {
	in.Protocol = Protocol
	_, err := logRPC[any](ctx, c, "append-events", in)
	return err
}
