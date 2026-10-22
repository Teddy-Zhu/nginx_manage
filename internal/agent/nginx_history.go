package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/history"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
)

type runtimeHistoryPlan struct {
	Preview   history.RuntimePreview  `json:"preview"`
	Entries   []runtimeHistoryEntry   `json:"entries"`
	Snapshots []snapshotHistoryTarget `json:"snapshots,omitempty"`
}
type runtimeHistoryIntent struct {
	Input history.RuntimeExecuteInput `json:"input"`
	Plan  runtimeHistoryPlan          `json:"plan"`
}

func historyTerminal(r Record) bool {
	return r.State == "succeeded" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
}
func historyRequestHash(in history.RuntimeExecuteInput) string {
	raw, _ := json.Marshal(in)
	return secure.Hash(raw)
}
func historyPlanHash(p runtimeHistoryPlan) string {
	p.Preview.SHA256 = ""
	// Inventory timestamps and bytes are frozen; the time the cleanup plan
	// was assembled does not change a user's approval of that same inventory.
	p.Snapshots = append([]snapshotHistoryTarget(nil), p.Snapshots...)
	for i := range p.Snapshots {
		p.Snapshots[i].Cleanup.CreatedAt = 0
		p.Snapshots[i].Cleanup.SHA256 = ""
	}
	raw, _ := json.Marshal(p)
	return secure.Hash(raw)
}
func historyStatus(r Record) history.RuntimeStatus {
	return history.RuntimeStatus{OperationID: r.OperationID, State: r.State, Stage: r.Stage, Error: r.Error, UpdatedAt: r.UpdatedAt, Preview: r.RuntimeHistory.Plan.Preview}
}

func historyActiveValid(kind, active string) bool {
	switch kind {
	case "agent_program":
		return agentProgramLinkValid(active)
	case "root_receipt":
		return active == "journal"
	case "recovery_snapshot":
		return active == "recovery"
	default:
		return active == "bootstrap" || validID(active)
	}
}

func validRuntimeHistory(r Record) error {
	i := r.RuntimeHistory
	if r.Kind != runtimeHistoryKind || i == nil || !validID(r.OperationID) || i.Input.OperationID != r.OperationID || !validID(i.Input.Filter.MaintenanceID) || !validID(r.MaintenanceEpoch) {
		return errors.New("运行材料清理记录无效")
	}
	f, p := i.Input.Filter, i.Plan.Preview
	if f.ValidateStored() != nil || !historyActiveValid(f.Kind, p.Active) {
		return errors.New("运行清理筛选条件无效")
	}
	if r.RequestHash != historyRequestHash(i.Input) || p.Filter != f || p.SHA256 != i.Input.SHA256 || historyPlanHash(i.Plan) != i.Input.SHA256 {
		return errors.New("运行清理摘要不一致")
	}
	if len(p.Targets) < 1 || len(p.Targets) > 8 || len(i.Plan.Entries) > historyEntryMax || len(i.Plan.Entries) != p.Entries || p.Bytes < 0 || p.Bytes > historyBytesLimit(f.Kind) {
		return errors.New("运行清理清单超出预算")
	}
	if !(r.State == "succeeded" && r.Stage == "cleaned" || r.State == "running" && r.Stage == "approved" || r.State == "recovery_required" && r.Stage == "cleanup_paused") {
		return errors.New("运行清理阶段无效")
	}
	targets := map[string]bool{}
	for _, target := range p.Targets {
		parts := strings.Split(target, "/")
		if targets[target] || !fs.ValidPath(target) {
			return errors.New("运行清理目标无效")
		}
		if f.Kind == "publication" && (len(parts) != 3 || parts[0] != "nginx" || parts[1] != "revisions" || !validID(parts[2])) || f.Kind == "certificate" && (len(parts) != 3 || parts[0] != "certificates" || !validID(parts[1]) || !validID(parts[2])) || f.Kind == "agent_program" && (len(parts) != 2 || parts[0] != "agent-releases" || !validSwitchDigest(parts[1])) {
			return errors.New("运行清理目标无效")
		}
		if f.Kind == "root_receipt" {
			if _, ok := journalReceiptID(target); !ok {
				return errors.New("root 回执归档目标无效")
			}
		}
		if f.Kind == "recovery_snapshot" && (len(parts) != 3 || parts[0] != "agent" || parts[1] != "panel-recovery" || !validID(parts[2])) {
			return errors.New("快照退役目标无效")
		}
		targets[target] = true
	}
	seen := map[string]bool{}
	var bytes int64
	for _, e := range i.Plan.Entries {
		found := false
		owner := ""
		for target := range targets {
			if historyPath(target, e.Path) {
				found, owner = true, target
			}
		}
		if !found || !fs.ValidPath(e.Path) || len(e.Path) > 512 || seen[e.Path] || e.Inode == 0 || e.Size < 0 || e.Size > historyFileLimit(f.Kind) {
			return errors.New("运行清理清单无效")
		}
		if e.Directory {
			if e.Size != 0 || e.Modified != 0 || e.Changed != 0 || e.SHA256 != "" {
				return errors.New("运行清理目录身份无效")
			}
		} else if f.Kind != "root_receipt" && targets[e.Path] || !validSwitchDigest(e.SHA256) {
			return errors.New("运行清理文件身份无效")
		}
		if f.Kind == "root_receipt" && (!targets[e.Path] || e.Directory || e.Size == 0 || e.Mode != 0600) {
			return errors.New("root 回执归档清单无效")
		}
		if f.Kind == "agent_program" && !validAgentHistoryEntry(e, owner) {
			return errors.New("Agent 程序清理清单无效")
		}
		seen[e.Path] = true
		bytes += e.Size
	}
	for target := range targets {
		if !seen[target] {
			return errors.New("运行维护缺少目标身份")
		}
		if f.Kind == "agent_program" && !seen[target+"/nginxpanel"] {
			return errors.New("Agent 程序清理缺少原二进制身份")
		}
	}
	if bytes != p.Bytes {
		return errors.New("运行清理大小不一致")
	}
	return validSnapshotHistoryPlan(i.Plan)
}

// The held maintenance lock and Nginx mutex fence all normal admission; root
// maintenance admission uses the same durable lock across independent workers.
func (s *Server) historyLock(ctx context.Context, id, epoch, kind string) (func(), []Record, error) {
	if s.Dev || s.Nginx == nil || s.Nginx.DataDir != s.DataDir || s.Nginx.maintenance == nil || s.Journal == nil || s.Nginx.Journal == nil || s.Journal.Dir != filepath.Join(s.DataDir, "agent", "operations") || s.Nginx.Journal.Dir != s.Journal.Dir {
		return nil, nil, fault.Unavailable("运行材料清理需要已接入的生产 Nginx Agent")
	}
	programUnlock := func() {}
	if kind == "agent_program" || kind == "root_receipt" || kind == "recovery_snapshot" {
		_, release, err := agentUpgradeLocks(ctx, s.DataDir)
		if err != nil {
			return nil, nil, err
		}
		programUnlock = release
		if kind == "root_receipt" || kind == "recovery_snapshot" {
			// Owners take their locks before the maintenance gate. Try-lock
			// every admitted workflow rather than waiting while holding the
			// installer lock, since image workers acquire these in reverse order.
			releases := []func(){release}
			programUnlock = func() {
				for i := len(releases) - 1; i >= 0; i-- {
					releases[i]()
				}
			}
			for _, name := range []string{".panel-update.lock", ".panel-service.lock", ".panel-image.lock", ".nginx-image.lock", ".panel-select.lock", ".panel-restore.lock"} {
				unlock, err := s.Journal.rootLock(name)
				if err != nil {
					programUnlock()
					return nil, nil, err
				}
				releases = append(releases, unlock)
			}
		}
	}
	g := s.Nginx.maintenance
	if !g.mu.TryLock() {
		programUnlock()
		return nil, nil, fault.New(429, "HISTORY_BUSY", "运行材料维护正在执行")
	}
	fail := func(err error) (func(), []Record, error) { g.mu.Unlock(); programUnlock(); return nil, nil, err }
	if g.scope != "host" || g.poisoned || g.id != id || g.phase != "held" || g.active != 0 || g.epoch != epoch {
		return fail(fault.Conflict("须重新取得已排空的宿主机维护会话"))
	}
	unlock, err := g.journal.maintenanceLock()
	if err != nil {
		return fail(err)
	}
	records, err := g.records()
	if err != nil {
		unlock()
		return fail(err)
	}
	for _, r := range records {
		if r.Kind == runtimeHistoryKind {
			if err = validRuntimeHistory(r); err != nil {
				unlock()
				return fail(err)
			}
			continue
		}
		if r.Kind == "maintenance.lock" || historyTerminal(r) {
			continue
		}
		if r.Kind == fail2banHostSyncKind {
			idle, e := fail2banHostSyncMaintenanceIdle(s.DataDir, r)
			if e == nil && idle {
				continue
			}
		}
		unlock()
		return fail(fault.Conflict("仍有操作或恢复材料待处理，不能清理运行材料"))
	}
	if !s.Nginx.mu.TryLock() {
		unlock()
		return fail(ErrBusy)
	}
	if s.Nginx.closed || s.Nginx.unlock == nil || s.Nginx.http01 != nil && s.Nginx.http01.busy() {
		s.Nginx.mu.Unlock()
		unlock()
		return fail(ErrBusy)
	}
	snapshotUnlock := func() {}
	if kind == "recovery_snapshot" {
		release, e := panelrecovery.LockCleanup(s.DataDir)
		if errors.Is(e, os.ErrNotExist) {
			// An empty store has no capture to race. A future capture still
			// needs the maintenance admission lock held by this operation.
		} else if e != nil {
			s.Nginx.mu.Unlock()
			unlock()
			return fail(e)
		} else {
			snapshotUnlock = release
		}
	}
	return func() { snapshotUnlock(); s.Nginx.mu.Unlock(); unlock(); g.mu.Unlock(); programUnlock() }, records, nil
}

type historyCandidate struct {
	target   string
	at       int64
	manifest manifest
}

func (n *Nginx) historyReferences(records []Record, removed map[string]bool) (string, map[string]bool, map[string]bool, error) {
	active, m, err := n.active()
	if err != nil {
		return "", nil, nil, err
	}
	pinned := map[string]bool{"nginx/revisions/bootstrap": true, "nginx/revisions/" + active: true}
	for _, r := range records {
		// Disaster recovery retains its original physical anchors even after
		// activation; retiring those receipts is a separate explicit operation.
		if !historyTerminal(r) && r.Kind != runtimeHistoryKind || r.DisasterRestoreID != "" || r.AfterDir == active && r.CandidateHash == manifestHash(m) {
			for _, dir := range []string{r.BeforeDir, r.AfterDir} {
				if dir != "" {
					if dir != "bootstrap" && !validID(dir) {
						return "", nil, nil, ErrExternalChange
					}
					pinned["nginx/revisions/"+dir] = true
				}
			}
		}
		if r.NginxSwitch != nil && !historyTerminal(r) {
			pinned["nginx/revisions/"+r.NginxSwitch.Directory] = true
		}
	}
	entries, err := os.ReadDir(filepath.Join(n.DataDir, "nginx", "revisions"))
	if err != nil {
		return "", nil, nil, err
	}
	if len(entries) > limits.PublishedRevisions {
		return "", nil, nil, ErrExternalChange
	}
	dependencies := map[string]bool{}
	for _, e := range entries {
		target := "nginx/revisions/" + e.Name()
		if removed[target] {
			if pinned[target] {
				return "", nil, nil, fault.Conflict("清理目标已成为当前或恢复引用")
			}
			continue
		}
		if e.Name() != "bootstrap" && !validID(e.Name()) {
			return "", nil, nil, ErrExternalChange
		}
		published, err := n.manifestMetadata(e.Name())
		if err != nil {
			return "", nil, nil, err
		}
		for name := range published.Dependencies {
			id, v, _, ok := certificates.Reference(name)
			if ok {
				dependencies["certificates/"+id+"/"+v] = true
			} else if !certificates.IsSystemCA(name) {
				return "", nil, nil, ErrExternalChange
			}
		}
	}
	return active, pinned, dependencies, nil
}

func (n *Nginx) collectRuntimeHistory(ctx context.Context, f history.RuntimeFilter, records []Record) (runtimeHistoryPlan, error) {
	if f.Kind == "recovery_snapshot" {
		return n.collectSnapshotHistory(ctx, f, records)
	}
	p := runtimeHistoryPlan{Preview: history.RuntimePreview{Filter: f, Targets: []string{}}, Entries: []runtimeHistoryEntry{}}
	var active string
	var pinned, deps map[string]bool
	var candidates []historyCandidate
	var err error
	if f.Kind == "agent_program" {
		active, pinned, candidates, err = n.agentProgramHistory(ctx, f.MaintenanceID, records)
	} else if f.Kind == "root_receipt" {
		active = "journal"
		candidates, err = n.journalHistory(ctx, records)
	} else {
		active, pinned, deps, err = n.historyReferences(records, nil)
	}
	if err != nil {
		return p, err
	}
	p.Preview.Active = active
	if f.Kind == "publication" {
		owners := map[string]Record{}
		for _, r := range records {
			if r.Kind == "nginx.apply" || r.Kind == "nginx.validate" || r.Kind == "nginx.restore" {
				owners[r.AfterDir] = r
			}
		}
		entries, err := os.ReadDir(filepath.Join(n.DataDir, "nginx", "revisions"))
		if err != nil {
			return p, err
		}
		for _, e := range entries {
			if e.Name() == "bootstrap" {
				continue
			}
			r, ok := owners[e.Name()]
			if !ok || !historyTerminal(r) {
				continue
			}
			m, err := n.manifestMetadata(e.Name())
			if err != nil || r.CandidateHash != manifestHash(m) || r.OperationID != e.Name() {
				return p, ErrExternalChange
			}
			candidates = append(candidates, historyCandidate{target: "nginx/revisions/" + e.Name(), at: r.UpdatedAt, manifest: m})
		}
	} else if f.Kind == "certificate" {
		root := filepath.Join(n.DataDir, "certificates")
		parents, err := os.ReadDir(root)
		if err != nil {
			return p, err
		}
		if len(parents) > limits.Certificates+1 {
			return p, ErrExternalChange
		}
		for _, parent := range parents {
			if parent.Name() == "ca" {
				continue
			}
			if !validID(parent.Name()) {
				return p, ErrExternalChange
			}
			if err = existingRootDirectory(filepath.Join(root, parent.Name())); err != nil {
				return p, err
			}
			versions, err := os.ReadDir(filepath.Join(root, parent.Name()))
			if err != nil {
				return p, err
			}
			if len(versions) > limits.CertificateVersions {
				return p, ErrExternalChange
			}
			for _, v := range versions {
				if !validID(v.Name()) {
					return p, ErrExternalChange
				}
				info, err := v.Info()
				if err != nil {
					return p, err
				}
				candidates = append(candidates, historyCandidate{target: "certificates/" + parent.Name() + "/" + v.Name(), at: info.ModTime().Unix()})
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].at > candidates[j].at || candidates[i].at == candidates[j].at && candidates[i].target > candidates[j].target
	})
	kept := map[string]int{}
	eligible := []historyCandidate{}
	for _, c := range candidates {
		group := "publication"
		if f.Kind == "certificate" {
			group = strings.Split(c.target, "/")[1]
		}
		kept[group]++
		if kept[group] <= f.Keep || c.at >= f.Before || pinned[c.target] || deps[c.target] {
			continue
		}
		eligible = append(eligible, c)
	}
	archiveUsage := map[string]journalArchiveUsage{}
	archiveFull := false
	for i := len(eligible) - 1; i >= 0; i-- {
		if len(p.Preview.Targets) == 8 {
			p.Preview.More = true
			break
		}
		c := eligible[i]
		wanted := map[string]string{}
		if f.Kind == "publication" || f.Kind == "agent_program" || f.Kind == "root_receipt" {
			for path, hash := range c.manifest.Files {
				wanted[path] = hash
			}
			if f.Kind == "publication" {
				metadata, err := nginxHistoryMetadata(n, c.target)
				if err != nil {
					return p, err
				}
				wanted[".nginxpanel.json"] = metadata
			}
		} else {
			parts := strings.Split(c.target, "/")
			for _, kind := range []string{"fullchain", "privatekey"} {
				b, err := n.certificateFile(certificates.Path(parts[1], parts[2], kind))
				if err != nil {
					return p, err
				}
				name := "fullchain.pem"
				if kind == "privatekey" {
					name = "privatekey.pem"
				}
				wanted[name] = secure.Hash(b)
			}
		}
		files := n.historyFiles(f.Kind)
		entries, size, err := files.inventoryHistory(ctx, c.target, wanted)
		if err != nil {
			return p, err
		}
		if len(p.Entries)+len(entries) > historyEntryMax || p.Preview.Bytes+size > files.bytesLimit {
			p.Preview.More = true
			break
		}
		if f.Kind == "root_receipt" {
			if len(entries) != 1 || entries[0].Directory || entries[0].Mode != 0600 || entries[0].Size <= 0 {
				return p, ErrExternalChange
			}
			room, err := n.receiptArchiveRoom(entries[0], archiveUsage)
			if err != nil {
				return p, err
			}
			if !room {
				p.Preview.More, archiveFull = true, true
				continue
			}
		}
		p.Preview.Targets = append(p.Preview.Targets, c.target)
		p.Entries = append(p.Entries, entries...)
		p.Preview.Bytes += size
	}
	if archiveFull && len(p.Preview.Targets) == 0 {
		return p, fault.Conflict("root 回执归档达到保留预算，原回执继续保留")
	}
	p.Preview.Entries = len(p.Entries)
	p.Preview.SHA256 = historyPlanHash(p)
	raw, _ := json.Marshal(p)
	if len(raw) > 192<<10 {
		return p, errors.New("运行清理清单超出保存预算")
	}
	return p, nil
}

func nginxHistoryMetadata(n *Nginx, target string) (string, error) {
	raw, err := nginxmodules.ReadTrusted(filepath.Join(n.DataDir, filepath.FromSlash(target), ".nginxpanel.json"), 256<<10)
	if err != nil {
		return "", ErrExternalChange
	}
	return secure.Hash(raw), nil
}

func (s *Server) previewRuntimeHistory(ctx context.Context, in history.RuntimeRequest) (history.RuntimePreview, error) {
	if in.Protocol != Protocol || !validID(in.Input.Filter.MaintenanceID) || !validID(in.Epoch) {
		return history.RuntimePreview{}, fault.Invalid("运行清理合同无效")
	}
	if err := in.Input.Filter.Validate(); err != nil {
		return history.RuntimePreview{}, err
	}
	unlock, records, err := s.historyLock(ctx, in.Input.Filter.MaintenanceID, in.Epoch, in.Input.Filter.Kind)
	if err != nil {
		return history.RuntimePreview{}, err
	}
	defer unlock()
	for _, r := range records {
		if r.Kind == runtimeHistoryKind && !historyTerminal(r) {
			return history.RuntimePreview{}, fault.Conflict("须先续办原运行清理操作")
		}
	}
	p, err := s.Nginx.collectRuntimeHistory(ctx, in.Input.Filter, records)
	return p.Preview, err
}

func (s *Server) executeRuntimeHistory(ctx context.Context, in history.RuntimeRequest) (history.RuntimeStatus, error) {
	if in.Protocol != Protocol || !validID(in.Input.OperationID) || !validID(in.Input.Filter.MaintenanceID) || !validID(in.Epoch) || !validSwitchDigest(in.Input.SHA256) {
		return history.RuntimeStatus{}, fault.Invalid("运行清理合同无效")
	}
	if prior, err := s.runtimeHistoryOperation(in.Input.OperationID); err == nil && prior.State == "succeeded" {
		if prior.RequestHash != historyRequestHash(in.Input) {
			return history.RuntimeStatus{}, fault.Conflict("原清理标识已用于不同请求")
		}
		return historyStatus(prior), nil
	} else if err != nil && !os.IsNotExist(err) {
		return history.RuntimeStatus{}, err
	}
	unlock, records, err := s.historyLock(ctx, in.Input.Filter.MaintenanceID, in.Epoch, in.Input.Filter.Kind)
	if err != nil {
		return history.RuntimeStatus{}, err
	}
	defer unlock()
	var r Record
	found := false
	for _, old := range records {
		if old.OperationID == in.Input.OperationID {
			r = old
			found = true
		}
		if old.Kind == runtimeHistoryKind && !historyTerminal(old) && old.OperationID != in.Input.OperationID {
			return history.RuntimeStatus{}, fault.Conflict("须先续办原运行清理操作")
		}
	}
	if found {
		if err = validRuntimeHistory(r); err != nil || r.RequestHash != historyRequestHash(in.Input) {
			return history.RuntimeStatus{}, fault.Conflict("原清理标识或请求不匹配")
		}
		if r.State == "succeeded" {
			return historyStatus(r), nil
		}
	} else {
		if err = in.Input.Filter.Validate(); err != nil {
			return history.RuntimeStatus{}, err
		}
		p, e := s.Nginx.collectRuntimeHistory(ctx, in.Input.Filter, records)
		if e != nil {
			return history.RuntimeStatus{}, e
		}
		if p.Preview.SHA256 != in.Input.SHA256 || len(p.Preview.Targets) == 0 {
			return history.RuntimeStatus{}, fault.Conflict("预览已变化或没有可清理的运行材料")
		}
		r = Record{OperationID: in.Input.OperationID, RequestHash: historyRequestHash(in.Input), Kind: runtimeHistoryKind, State: "running", Stage: "approved", MaintenanceEpoch: in.Epoch, RuntimeHistory: &runtimeHistoryIntent{Input: in.Input, Plan: p}}
		if err = validRuntimeHistory(r); err != nil {
			return history.RuntimeStatus{}, err
		}
		if err = s.Journal.Put(r); err != nil {
			return history.RuntimeStatus{}, err
		}
	}
	r.MaintenanceEpoch = in.Epoch
	removed := map[string]bool{}
	for _, target := range r.RuntimeHistory.Plan.Preview.Targets {
		removed[target] = true
	}
	var pinned, deps map[string]bool
	if in.Input.Filter.Kind == "agent_program" {
		_, pinned, _, err = s.Nginx.agentProgramHistory(ctx, in.Input.Filter.MaintenanceID, records)
	} else if in.Input.Filter.Kind != "root_receipt" && in.Input.Filter.Kind != "recovery_snapshot" {
		_, pinned, deps, err = s.Nginx.historyReferences(records, removed)
	}
	if err == nil {
		for _, target := range r.RuntimeHistory.Plan.Preview.Targets {
			if pinned[target] || deps[target] {
				err = fault.Conflict("原清理目标仍被运行或恢复材料引用")
				break
			}
		}
	}
	if err == nil && r.RuntimeHistory.Input.Filter.Kind == "certificate" {
		for _, target := range r.RuntimeHistory.Plan.Preview.Targets {
			if err = s.Nginx.saveCertificateHistory(target, r.RuntimeHistory.Plan.Entries); err != nil {
				break
			}
		}
	}
	if err == nil {
		if in.Input.Filter.Kind == "root_receipt" {
			err = s.Nginx.archiveJournalHistory(ctx, r.RuntimeHistory.Plan)
		} else if in.Input.Filter.Kind == "recovery_snapshot" {
			err = s.Nginx.removeSnapshotHistory(ctx, r.RuntimeHistory.Plan, records)
		} else {
			err = s.Nginx.removeHistory(ctx, r.RuntimeHistory.Plan)
		}
	}
	if err != nil {
		r.State, r.Stage, r.Error = "recovery_required", "cleanup_paused", "运行材料维护尚未完成，须核对原清单后按原标识续办"
	} else {
		r.State, r.Stage, r.Error = "succeeded", "cleaned", ""
	}
	r.UpdatedAt = time.Now().Unix()
	persist := s.Journal.Put(r)
	return historyStatus(r), errors.Join(err, persist)
}

func (s *Server) runtimeHistoryOperation(id string) (Record, error) {
	if !validID(id) {
		return Record{}, fault.Invalid("运行清理标识无效")
	}
	r, err := readPrivateJournalReceipt(filepath.Join(s.Journal.Dir, id+".json"), id, journalArchiveFileLimit)
	if os.IsNotExist(err) {
		r, err = s.Journal.archivedJournalReceipt(id)
	}
	if err != nil {
		return Record{}, err
	}
	if err = validRuntimeHistory(r); err != nil {
		return Record{}, err
	}
	return r, nil
}

func (s *Server) runtimeHistoryHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/history/runtime/{id}", func(w http.ResponseWriter, r *http.Request) {
		if s.historyReads.Add(1) > 2 {
			s.historyReads.Add(-1)
			maintenanceReply(w, nil, fault.New(429, "HISTORY_BUSY", "运行材料维护已达并发上限"))
			return
		}
		defer s.historyReads.Add(-1)
		record, err := s.runtimeHistoryOperation(r.PathValue("id"))
		if err != nil {
			maintenanceReply(w, nil, err)
			return
		}
		maintenanceReply(w, historyStatus(record), nil)
	})

	for _, action := range []string{"preview", "execute"} {
		mux.HandleFunc("POST /v1/history/runtime/"+action, func(w http.ResponseWriter, r *http.Request) {
			if s.historyReads.Add(1) > 2 {
				s.historyReads.Add(-1)
				maintenanceReply(w, nil, fault.New(429, "HISTORY_BUSY", "运行材料维护已达并发上限"))
				return
			}
			defer s.historyReads.Add(-1)
			var in history.RuntimeRequest
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
				maintenanceReply(w, nil, fault.Invalid("运行清理请求无效"))
				return
			}
			duration := 10 * time.Second
			if in.Input.Filter.Kind == "recovery_snapshot" {
				duration = history.SnapshotRequestTimeout
				if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(duration + 5*time.Second)); err != nil {
					maintenanceReply(w, nil, fault.Unavailable("快照维护连接无法设置响应时限"))
					return
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), duration)
			defer cancel()
			if action == "preview" {
				out, err := s.previewRuntimeHistory(ctx, in)
				maintenanceReply(w, out, err)
			} else {
				out, err := s.executeRuntimeHistory(ctx, in)
				maintenanceReply(w, out, err)
			}
		})
	}
	mux.HandleFunc("GET /v1/history/runtime", func(w http.ResponseWriter, r *http.Request) {
		if s.historyReads.Add(1) > 2 {
			s.historyReads.Add(-1)
			maintenanceReply(w, nil, fault.New(429, "HISTORY_BUSY", "运行材料维护已达并发上限"))
			return
		}
		defer s.historyReads.Add(-1)
		records, err := (&maintenanceGate{journal: s.Journal}).records()
		if err != nil {
			maintenanceReply(w, nil, err)
			return
		}
		out := []history.RuntimeStatus{}
		for _, record := range records {
			if record.Kind != runtimeHistoryKind {
				continue
			}
			if err = validRuntimeHistory(record); err != nil {
				maintenanceReply(w, nil, err)
				return
			}
			out = append(out, historyStatus(record))
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].UpdatedAt > out[j].UpdatedAt || out[i].UpdatedAt == out[j].UpdatedAt && out[i].OperationID > out[j].OperationID
		})
		if len(out) > 16 {
			out = out[:16]
		}
		maintenanceReply(w, out, nil)
	})
}
func (c *Client) PreviewRuntimeHistory(ctx context.Context, in history.RuntimeRequest) (history.RuntimePreview, error) {
	var out history.RuntimePreview
	err := c.runtimeHistoryRequest(ctx, "/v1/history/runtime/preview", in, &out)
	return out, err
}
func (c *Client) ExecuteRuntimeHistory(ctx context.Context, in history.RuntimeRequest) (history.RuntimeStatus, error) {
	var out history.RuntimeStatus
	err := c.runtimeHistoryRequest(ctx, "/v1/history/runtime/execute", in, &out)
	return out, err
}

func (c *Client) runtimeHistoryRequest(ctx context.Context, path string, in history.RuntimeRequest, out any) error {
	client := c
	if in.Input.Filter.Kind == "recovery_snapshot" {
		transport := *c.http
		transport.Timeout = history.SnapshotRequestTimeout + 5*time.Second
		client = &Client{http: &transport}
	}
	return client.envelopeRequest(ctx, http.MethodPost, path, in, out)
}
func (c *Client) RuntimeHistory(ctx context.Context) ([]history.RuntimeStatus, error) {
	var out []history.RuntimeStatus
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/history/runtime", nil, &out)
	return out, err
}

func (c *Client) RuntimeHistoryOperation(ctx context.Context, id string) (history.RuntimeStatus, error) {
	if !validID(id) {
		return history.RuntimeStatus{}, fault.Invalid("运行清理标识无效")
	}
	var out history.RuntimeStatus
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/history/runtime/"+id, nil, &out)
	return out, err
}
