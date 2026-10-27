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
	"nginxpanel/internal/secure"
)

type runtimeHistoryPlan struct {
	Preview history.RuntimePreview `json:"preview"`
	Entries []runtimeHistoryEntry  `json:"entries"`
}
type runtimeHistoryIntent struct {
	Input history.RuntimeExecuteInput `json:"input"`
	Plan  runtimeHistoryPlan          `json:"plan"`
}

func historyTerminal(r Record) bool {
	return r.State == "succeeded" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
}
func historyRequestHash(in history.RuntimeExecuteInput) string {
	in.Filter.MaintenanceID = ""
	raw, _ := json.Marshal(in)
	return secure.Hash(raw)
}
func historyPlanHash(p runtimeHistoryPlan) string {
	p.Preview.SHA256 = ""
	p.Preview.Filter.MaintenanceID = ""
	raw, _ := json.Marshal(p)
	return secure.Hash(raw)
}
func historyStatus(r Record) history.RuntimeStatus {
	return history.RuntimeStatus{OperationID: r.OperationID, State: r.State, Stage: r.Stage, Error: r.Error, UpdatedAt: r.UpdatedAt, Preview: r.RuntimeHistory.Plan.Preview}
}

func validRuntimeHistory(r Record) error {
	i := r.RuntimeHistory
	if r.Kind != runtimeHistoryKind || i == nil || !validID(r.OperationID) || i.Input.OperationID != r.OperationID || !validID(i.Input.Filter.MaintenanceID) || !validID(r.MaintenanceEpoch) {
		return errors.New("运行材料清理记录无效")
	}
	f, p := i.Input.Filter, i.Plan.Preview
	if f.Kind != "publication" && f.Kind != "certificate" || f.Before < 1 || f.Keep < 2 || f.Keep > 32 || p.Active != "bootstrap" && !validID(p.Active) {
		return errors.New("运行清理筛选条件无效")
	}
	if r.RequestHash != historyRequestHash(i.Input) || p.Filter != f || p.SHA256 != i.Input.SHA256 || historyPlanHash(i.Plan) != i.Input.SHA256 {
		return errors.New("运行清理摘要不一致")
	}
	if len(p.Targets) < 1 || len(p.Targets) > 8 || len(i.Plan.Entries) > historyEntryMax || len(i.Plan.Entries) != p.Entries || p.Bytes < 0 || p.Bytes > historyBytesMax {
		return errors.New("运行清理清单超出预算")
	}
	if !(r.State == "succeeded" && r.Stage == "cleaned" || r.State == "running" && r.Stage == "approved" || r.State == "recovery_required" && r.Stage == "cleanup_paused") {
		return errors.New("运行清理阶段无效")
	}
	targets := map[string]bool{}
	for _, target := range p.Targets {
		parts := strings.Split(target, "/")
		if len(parts) != 3 || targets[target] {
			return errors.New("运行清理目标无效")
		}
		if f.Kind == "publication" && (parts[0] != "nginx" || parts[1] != "revisions" || !validID(parts[2])) || f.Kind == "certificate" && (parts[0] != "certificates" || !validID(parts[1]) || !validID(parts[2])) {
			return errors.New("运行清理目标无效")
		}
		targets[target] = true
	}
	seen := map[string]bool{}
	var bytes int64
	for _, e := range i.Plan.Entries {
		found := false
		for target := range targets {
			found = found || historyPath(target, e.Path)
		}
		if !found || !fs.ValidPath(e.Path) || len(e.Path) > 512 || seen[e.Path] || e.Inode == 0 || e.Size < 0 || e.Size > limits.NginxRuntimeFileBytes {
			return errors.New("运行清理清单无效")
		}
		if e.Directory {
			if e.Size != 0 || e.Modified != 0 || e.Changed != 0 || e.SHA256 != "" {
				return errors.New("运行清理目录身份无效")
			}
		} else if targets[e.Path] || !validSwitchDigest(e.SHA256) {
			return errors.New("运行清理文件身份无效")
		}
		seen[e.Path] = true
		bytes += e.Size
	}
	for target := range targets {
		if !seen[target] {
			return errors.New("运行清理缺少目标目录")
		}
	}
	if bytes != p.Bytes {
		return errors.New("运行清理大小不一致")
	}
	return nil
}

// The held maintenance lock and Nginx mutex fence all normal admission; root
// maintenance admission uses the same durable lock across independent workers.
func (s *Server) historyLock(ctx context.Context, id, epoch string) (func(), []Record, error) {
	if s.Dev || s.Nginx == nil || s.Nginx.DataDir != s.DataDir || s.Nginx.maintenance == nil {
		return nil, nil, fault.Unavailable("运行材料清理需要已接入的生产 Nginx Agent")
	}
	g := s.Nginx.maintenance
	if !g.mu.TryLock() {
		return nil, nil, fault.New(429, "HISTORY_BUSY", "运行材料维护正在执行")
	}
	fail := func(err error) (func(), []Record, error) { g.mu.Unlock(); return nil, nil, err }
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
	return func() { s.Nginx.mu.Unlock(); unlock(); g.mu.Unlock() }, records, nil
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
	p := runtimeHistoryPlan{Preview: history.RuntimePreview{Filter: f, Targets: []string{}}, Entries: []runtimeHistoryEntry{}}
	active, pinned, deps, err := n.historyReferences(records, nil)
	if err != nil {
		return p, err
	}
	p.Preview.Active = active
	candidates := []historyCandidate{}
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
	} else {
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
	for i := len(eligible) - 1; i >= 0; i-- {
		if len(p.Preview.Targets) == 8 {
			p.Preview.More = true
			break
		}
		c := eligible[i]
		wanted := map[string]string{}
		if f.Kind == "publication" {
			for path, hash := range c.manifest.Files {
				wanted[path] = hash
			}
			metadata, err := nginxHistoryMetadata(n, c.target)
			if err != nil {
				return p, err
			}
			wanted[".nginxpanel.json"] = metadata
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
		entries, size, err := n.inventoryHistory(ctx, c.target, wanted)
		if err != nil {
			return p, err
		}
		if len(p.Entries)+len(entries) > historyEntryMax || p.Preview.Bytes+size > historyBytesMax {
			p.Preview.More = true
			break
		}
		p.Preview.Targets = append(p.Preview.Targets, c.target)
		p.Entries = append(p.Entries, entries...)
		p.Preview.Bytes += size
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
	unlock, records, err := s.historyLock(ctx, in.Input.Filter.MaintenanceID, in.Epoch)
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
	unlock, records, err := s.historyLock(ctx, in.Input.Filter.MaintenanceID, in.Epoch)
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
		if err = s.Journal.Put(r); err != nil {
			return history.RuntimeStatus{}, err
		}
	}
	r.MaintenanceEpoch = in.Epoch
	removed := map[string]bool{}
	for _, target := range r.RuntimeHistory.Plan.Preview.Targets {
		removed[target] = true
	}
	_, pinned, deps, err := s.Nginx.historyReferences(records, removed)
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
		err = s.Nginx.removeHistory(ctx, r.RuntimeHistory.Plan)
	}
	if err != nil {
		r.State, r.Stage, r.Error = "recovery_required", "cleanup_paused", "清理尚未完成，须核对原清单后按原标识续办"
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
	raw, err := nginxmodules.ReadTrusted(filepath.Join(s.Journal.Dir, id+".json"), 256<<10)
	if err != nil {
		return Record{}, err
	}
	var r Record
	if json.Unmarshal(raw, &r) != nil || r.OperationID != id {
		return Record{}, errors.New("运行清理记录无法读取")
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
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
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
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/history/runtime/preview", in, &out)
	return out, err
}
func (c *Client) ExecuteRuntimeHistory(ctx context.Context, in history.RuntimeRequest) (history.RuntimeStatus, error) {
	var out history.RuntimeStatus
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/history/runtime/execute", in, &out)
	return out, err
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
