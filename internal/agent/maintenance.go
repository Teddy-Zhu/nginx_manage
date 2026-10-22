package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"nginxpanel/internal/protocol"
	"os"
	"path/filepath"
	"sync"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type maintenanceGate struct {
	mu               sync.Mutex
	active           int
	id, phase, epoch string
	poisoned         bool
	journal          *Journal
	scope            string
	dev              bool
	nginx            *Nginx
	components       *components.Manager
	firewall         *hostFirewall
}

func (g *maintenanceGate) open() error {
	g.epoch = secure.ID()
	if g.dev {
		return nil
	}
	unlock, err := g.journal.maintenanceLock()
	if err != nil {
		return err
	}
	defer unlock()
	// Restore the maintenance lease even when a local retirement was
	// interrupted. Admission will verify its proof before granting work.
	records, err := g.rawRecords()
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.Kind != "maintenance.lock" {
			continue
		}
		if r.RequestHash != maintenanceHash(maintenance.RootRequest{Protocol: Protocol, OperationID: r.OperationID}) || !validID(r.MaintenanceEpoch) || !(r.State == "succeeded" && r.Stage == "released" || r.State == "running" && r.Stage == "closing" || r.State == "waiting_confirmation" && r.Stage == "held") {
			return errors.New("独立维护记录无效，须本机恢复")
		}
		if r.State == "succeeded" {
			if err = g.journal.archiveMaintenance(r); err != nil {
				return err
			}
			continue
		}
		if g.id != "" {
			return errors.New("存在多个独立维护锁，须本机恢复")
		}
		g.id, g.phase = r.OperationID, "closing"
		r.State, r.Stage, r.MaintenanceEpoch = "running", "closing", g.epoch
		if err = g.journal.Put(r); err != nil {
			return err
		}
	}
	return nil
}
func (g *maintenanceGate) rawRecords() ([]Record, error) {
	entries, err := os.ReadDir(g.journal.Dir)
	if err != nil {
		return nil, err
	}
	if liveJournalEntries(entries) > journalMaintenanceEntriesMax {
		return nil, errors.New("Agent 记录超出维护扫描预算")
	}
	records := []Record{}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := e.Name()[:len(e.Name())-5]
		if !validID(id) {
			return nil, errors.New("Agent 记录名称无效")
		}
		raw, err := nginxmodules.ReadTrusted(filepath.Join(g.journal.Dir, e.Name()), clientDenyJournalLimit)
		if err != nil {
			return nil, err
		}
		var r Record
		if json.Unmarshal(raw, &r) != nil || r.OperationID != id || r.Kind == "" {
			return nil, errors.New("Agent 记录身份无效")
		}
		if len(raw) > 256<<10 && r.Kind != clientDenyKind {
			return nil, errors.New("Agent 记录超出维护扫描预算")
		}
		if r.Kind == clientDenyKind {
			if _, err := clientDenyCheckpoint([]Record{r}); err != nil {
				return nil, err
			}
		}
		records = append(records, r)
	}
	return records, nil
}

func (g *maintenanceGate) records() ([]Record, error) {
	original, err := g.rawRecords()
	if err != nil {
		return nil, err
	}
	if _, err = fail2banStateRestoreRecords(filepath.Dir(filepath.Dir(g.journal.Dir)), original, ""); err != nil {
		return nil, err
	}
	if _, err = fail2banUpgradeSwitchRecords(filepath.Dir(filepath.Dir(g.journal.Dir)), original, ""); err != nil {
		return nil, err
	}
	upgrade, _, err := pendingFail2banUpgradeRun(filepath.Dir(filepath.Dir(g.journal.Dir)))
	if err != nil {
		return nil, err
	}
	if upgrade != nil {
		found := false
		for _, r := range original {
			found = found || r.Kind == fail2banUpgradeRunKind && r.OperationID == upgrade.Request.OperationID
		}
		if !found {
			return nil, errors.New("整体升级隔离尚无原审计确认，须沿原父任务续办或取消")
		}
	}
	restoring, _, err := pendingFail2banUpgradeRestore(filepath.Dir(filepath.Dir(g.journal.Dir)))
	if err != nil {
		return nil, err
	}
	if restoring != nil {
		found := false
		for _, r := range original {
			found = found || r.Kind == fail2banUpgradeRestoreKind && r.OperationID == restoring.Request.OperationID
		}
		if !found {
			return nil, errors.New("升级恢复隔离尚无原审计确认，须沿原 UUID 续办或取消")
		}
	}
	quiesce, _, err := pendingFail2banUpgradeQuiesce(filepath.Dir(filepath.Dir(g.journal.Dir)))
	if err != nil {
		return nil, err
	}
	if quiesce != nil {
		found := false
		for _, r := range original {
			found = found || r.Kind == fail2banUpgradeQuiesceKind && r.OperationID == quiesce.Request.OperationID
		}
		if !found {
			return nil, errors.New("升级停止隔离尚无原审计确认，须沿原 UUID 续办或取消")
		}
	}
	activation, _, err := pendingFail2banUpgradeActivation(filepath.Dir(filepath.Dir(g.journal.Dir)))
	if err != nil {
		return nil, err
	}
	if activation != nil {
		found := false
		for _, r := range original {
			found = found || r.Kind == fail2banUpgradeActivationKind && r.OperationID == activation.Request.OperationID
		}
		if !found {
			return nil, errors.New("升级启动隔离尚无原审计确认，须沿原 UUID 续办")
		}
	}
	records := make([]Record, 0, len(original))
	for _, r := range original {
		// All independent maintenance workers share this view. Keep the
		// immutable audit on disk, but omit a disposed scope only after its
		// retirement and original receipts have been verified together.
		if r.Kind == firewallOperationKind || r.Kind == iptablesRepairKind {
			retired, err := retiredIPTablesRecord(filepath.Dir(filepath.Dir(g.journal.Dir)), r)
			if err != nil {
				return nil, err
			}
			if retired {
				continue
			}
		}
		if r.Kind == iptablesRetirementKind {
			retirement, err := loadIPTablesRetirement(filepath.Dir(filepath.Dir(g.journal.Dir)), r.RelatedOperationID)
			if err != nil || retirement == nil {
				return nil, errors.Join(errors.New("iptables 退役缺少原本机意图"), err)
			}
			current, _, err := retirement.record(filepath.Dir(filepath.Dir(g.journal.Dir)))
			if err != nil || !sameIPTablesRetirementRecord(current, r) {
				return nil, errors.Join(errors.New("iptables 退役维护回执冲突"), err)
			}
		}
		records = append(records, r)
	}
	return records, nil
}
func (g *maintenanceGate) enter(progress bool) (func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.poisoned || g.id != "" && (!progress || g.phase != "closing") {
		return nil, false
	}
	g.active++
	var once sync.Once
	return func() { once.Do(func() { g.mu.Lock(); g.active--; g.mu.Unlock() }) }, true
}
func (g *maintenanceGate) closing() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.id != "" }
func (g *maintenanceGate) statusLocked(ctx context.Context) (maintenance.RootStatus, error) {
	out := maintenance.RootStatus{Available: !g.dev && g.scope == "host", ID: g.id, Phase: g.phase, Epoch: g.epoch}
	if out.Phase == "" {
		out.Phase = "open"
	}
	if !out.Available {
		out.Reason = "须由本机确认宿主机维护范围"
	}
	if g.poisoned {
		out.Phase, out.Reason = "recovery_required", "维护记录无法持久保存，须本机恢复"
		return out, nil
	}
	if g.dev {
		return out, nil
	}
	out.Busy = g.active
	if g.active != 0 {
		return out, nil
	}
	records, err := g.records()
	if err != nil {
		return out, err
	}
	for _, r := range records {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		if r.Kind == "maintenance.lock" {
			continue
		}
		if r.Kind == runtimeHistoryKind {
			if err := validRuntimeHistory(r); err != nil {
				return out, err
			}
			// The original cleanup can resume after a fresh Agent epoch. Release
			// remains blocked explicitly until all approved unlinks finish.
			if r.RuntimeHistory.Input.Filter.MaintenanceID == g.id {
				continue
			}
		}
		if r.Kind == fail2banHostBootRecoveryKind {
			boot, err := loadFail2banHostBootRecoveryEvent(filepath.Dir(filepath.Dir(g.journal.Dir)), r.OperationID)
			if err != nil {
				return out, err
			}
			if err = boot.validateRecord(r); err != nil {
				return out, err
			}
			// Child registration journals cover uncertain kernel writes. The
			// coordinator may pause before any new grant while maintenance holds.
			continue
		}
		if r.Kind == fail2banHostSyncKind {
			idle, err := fail2banHostSyncMaintenanceIdle(filepath.Dir(filepath.Dir(g.journal.Dir)), r)
			if err != nil {
				return out, err
			}
			if !idle {
				out.Busy++
			}
			continue
		}
		if r.Kind == nginxImageKind {
			if err := validNginxImage(r); err != nil {
				return out, err
			}
			if g.id != "" && r.NginxImage.Intent.Input.MaintenanceID == g.id || nginxImageTerminal(r) {
				continue
			}
		}
		if r.Kind == panelImageKind {
			if err := validPanelImage(r); err != nil {
				return out, err
			}
			if g.id != "" && r.PanelImage.Intent.Input.MaintenanceID == g.id || panelImageTerminal(r) {
				continue
			}
		}
		if r.Kind == agentUpgradeKind {
			if err := validAgentUpgrade(r); err != nil {
				return out, err
			}
			if g.id != "" && r.AgentUpgrade.Intent.Input.MaintenanceID == g.id || agentUpgradeTerminal(r) {
				continue
			}
		}
		if r.Kind == panelUpdateKind {
			if err := validPanelUpdate(r); err != nil {
				return out, err
			}
			if g.id != "" && r.PanelUpdate.Intent.Input.MaintenanceID == g.id {
				if panelUpdateFinalized(r) {
					if out.Completion != nil {
						return out, errors.New("同一维护会话存在多个更新完成授权")
					}
					out.Completion = &maintenance.Completion{OperationID: r.OperationID, RequestSHA256: r.RequestHash, Outcome: panelUpdateOutcome(r)}
				}
				continue
			}
			if panelUpdateFinalized(r) {
				continue
			}
		}
		if r.Kind == panelServiceKind {
			if err := validPanelService(r); err != nil {
				return out, err
			}
			if g.id != "" && r.PanelService.Intent.Input.MaintenanceID == g.id {
				continue
			}
		}
		if r.Kind == panelSelectKind {
			if err := validPanelSelection(r); err != nil {
				return out, err
			}
			if g.id != "" && r.PanelSelection.MaintenanceID == g.id {
				continue
			}
		}
		if r.DisasterRestoreID != "" {
			data := filepath.Dir(filepath.Dir(g.journal.Dir))
			i, err := panelrecovery.ReadDisasterIntent(data, r.DisasterRestoreID)
			if err != nil {
				return out, err
			}
			if err = validDisasterNginxRecord(i, r); err != nil {
				return out, err
			}
			parent, err := readDisasterRestore(data, i.OperationID)
			if err != nil {
				return out, err
			}
			if parent.State == "rolled_back" && r.State != "rolled_back" {
				return out, errors.New("恢复文件补偿与 Nginx 子操作未协调")
			}
			if g.id != "" && i.Stop.MaintenanceID == g.id {
				continue
			}
		}
		if r.Kind == disasterRestoreKind {
			i, err := validDisasterRestore(filepath.Dir(filepath.Dir(g.journal.Dir)), r)
			if err != nil {
				return out, err
			}
			if g.id != "" && i.Stop.MaintenanceID == g.id {
				if disasterActivationFinalized(r) {
					if out.Completion != nil {
						return out, errors.New("同一维护会话存在多个完成授权")
					}
					out.Completion = &maintenance.Completion{OperationID: r.OperationID, RequestSHA256: r.RequestHash, Outcome: "succeeded"}
				}
				continue
			}
			if disasterActivationFinalized(r) {
				continue
			}
		}
		if r.Kind == panelRestoreKind {
			if err := validPanelRestoreRecord(r); err != nil {
				return out, err
			}
			if g.id != "" && r.PanelRestore.Receipt.Manifest.MaintenanceID == g.id {
				continue
			}
		}
		if r.Kind == nginxInstallKind {
			if err := validInstallRecord(r); err != nil {
				return out, err
			}
			// This is work owned by the held maintenance session, rather
			// than ordinary traffic that must drain before it is held.
			if g.id != "" && r.NginxInstall.Input.MaintenanceID == g.id {
				continue
			}
		}
		if r.Kind == nginxSwitchKind {
			if err := validNginxSwitch(r); err != nil {
				return out, err
			}
			if g.id != "" && r.NginxSwitch.Input.MaintenanceID == g.id {
				continue
			}
		}
		if r.Kind == nginxSwitchJobKind {
			if err := validSwitchJob(r); err != nil {
				return out, err
			}
			if g.id != "" && r.NginxSwitchJob.Input.MaintenanceID == g.id {
				continue
			}
		}

		switch r.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		case "queued", "running", "waiting_confirmation", "compensating", "recovery_required":
			out.Busy++
		default:
			return out, errors.New("Agent 存在未知执行状态")
		}
	}
	if g.components != nil {
		busy, err := g.components.Pending()
		if err != nil {
			return out, err
		}
		out.Busy += busy
	}
	if g.firewall != nil && g.firewall.pendingWithLock(g.id != "") {
		out.Busy++
	}
	if g.firewall == nil && dockerRegistrationPending(filepath.Dir(filepath.Dir(g.journal.Dir))) {
		out.Busy++
	}
	if g.nginx != nil {
		if g.nginx.http01 != nil && g.nginx.http01.busy() {
			out.Busy++
		}
		if g.nginx.logs != nil {
			m := g.nginx.logs
			m.mu.Lock()
			if m.policyUncertain {
				out.Busy++
			}
			for _, a := range m.state.Archives {
				if a.State == "planned" || a.State == "reopening" || a.State == "compressing" || a.State == "deleting" {
					out.Busy++
				}
			}
			if m.compression != nil {
				out.Busy++
			}
			m.mu.Unlock()
		}
	}
	return out, nil
}
func (g *maintenanceGate) status(ctx context.Context) (maintenance.RootStatus, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.statusLocked(ctx)
}
func (g *maintenanceGate) acquire(ctx context.Context, in maintenance.RootRequest) (maintenance.RootStatus, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dev || g.scope != "host" {
		return maintenance.RootStatus{}, fault.Unavailable("宿主机维护范围尚未确认")
	}
	unlock, err := g.journal.maintenanceLock()
	if err != nil {
		return maintenance.RootStatus{}, err
	}
	defer unlock()
	if g.id != "" && g.id != in.OperationID {
		return maintenance.RootStatus{}, fault.Conflict("已有其他独立维护锁")
	}
	if err := ctx.Err(); err != nil {
		return maintenance.RootStatus{}, err
	}
	if g.id == "" {
		prior, err := g.journal.Get(in.OperationID)
		if err == nil {
			if prior.Kind != "maintenance.lock" || prior.State == "succeeded" {
				return maintenance.RootStatus{}, fault.Conflict("维护标识不可重用")
			}
		} else if !os.IsNotExist(err) {
			return maintenance.RootStatus{}, err
		}
		g.id, g.phase = in.OperationID, "closing"
		if err = g.journal.Put(Record{OperationID: in.OperationID, RequestHash: maintenanceHash(in), Kind: "maintenance.lock", State: "running", Stage: "closing", MaintenanceEpoch: g.epoch}); err != nil {
			g.poisoned = true
			return maintenance.RootStatus{}, err
		}
	}
	out, err := g.statusLocked(ctx)
	if err != nil {
		return out, err
	}
	if out.Busy == 0 && !g.poisoned && g.phase != "held" {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		r, err := g.journal.Get(g.id)
		if err != nil {
			return out, err
		}
		r.State, r.Stage, r.MaintenanceEpoch = "waiting_confirmation", "held", g.epoch
		if err = g.journal.Put(r); err != nil {
			g.poisoned = true
			return out, err
		}
		g.phase, out.Phase = "held", "held"
	}
	return out, nil
}
func maintenanceHash(in maintenance.RootRequest) string {
	raw, _ := json.Marshal(struct {
		Journal int    `json:"journal"`
		ID      string `json:"operation_id"`
	}{protocol.Journal, in.OperationID})
	return secure.Hash(raw)
}
func (g *maintenanceGate) release(ctx context.Context, in maintenance.RootRequest) (maintenance.RootStatus, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dev || g.scope != "host" {
		return maintenance.RootStatus{}, fault.Unavailable("宿主机维护范围尚未确认")
	}
	unlock, err := g.journal.maintenanceLock()
	if err != nil {
		return maintenance.RootStatus{}, err
	}
	defer unlock()
	if g.id != "" && g.id != in.OperationID {
		return maintenance.RootStatus{}, fault.Conflict("独立维护锁不匹配")
	}
	if err := ctx.Err(); err != nil {
		return maintenance.RootStatus{}, err
	}
	records, err := g.records()
	if err != nil {
		return maintenance.RootStatus{}, err
	}
	data := filepath.Dir(filepath.Dir(g.journal.Dir))
	fenced, err := storage.WriterFenced(data)
	if err != nil {
		return maintenance.RootStatus{}, err
	}
	if fenced {
		return maintenance.RootStatus{}, fault.Conflict("本机恢复标记尚未解除，不能释放维护锁")
	}
	held, err := storage.ServiceHeld(data)
	if err != nil {
		return maintenance.RootStatus{}, err
	}
	if held {
		return maintenance.RootStatus{}, fault.Conflict("面板仍处于持久停机状态，不能释放维护锁")
	}
	for _, record := range records {
		if record.Kind == runtimeHistoryKind {
			if err := validRuntimeHistory(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if !historyTerminal(record) {
				return maintenance.RootStatus{}, fault.Conflict("运行材料清理尚未结束，须先按原标识续办")
			}
		}
		if record.Kind == nginxImageKind {
			if err := validNginxImage(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if !nginxImageTerminal(record) {
				return maintenance.RootStatus{}, fault.Conflict("Nginx 镜像替换尚未确认或完整恢复，须沿原操作续办")
			}
			continue
		}
		if record.Kind == panelImageKind {
			if err := validPanelImage(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if !panelImageTerminal(record) {
				return maintenance.RootStatus{}, fault.Conflict("面板镜像替换尚未确认或完整恢复，须沿原操作续办")
			}
			continue
		}
		if record.Kind == agentUpgradeKind {
			if err := validAgentUpgrade(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if !agentUpgradeTerminal(record) {
				return maintenance.RootStatus{}, fault.Conflict("Agent 升级尚未确认或完整补偿，须沿原操作续办")
			}
			continue
		}
		if record.Kind == panelUpdateKind {
			if err := validPanelUpdate(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if record.PanelUpdate.Intent.Input.MaintenanceID == in.OperationID && !panelUpdateFinalized(record) {
				return maintenance.RootStatus{}, fault.Conflict("独立更新尚未提交或完整补偿，不能释放维护锁")
			}
			continue
		}
		if record.Kind == panelServiceKind {
			if err := validPanelService(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if record.State != "succeeded" && record.PanelService.Intent.Input.MaintenanceID == in.OperationID {
				return maintenance.RootStatus{}, fault.Conflict("面板进程操作尚未完成，不能释放维护锁")
			}
			continue
		}
		if record.Kind == panelSelectKind {
			if err := validPanelSelection(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if record.State != "succeeded" && record.PanelSelection.MaintenanceID == in.OperationID {
				return maintenance.RootStatus{}, fault.Conflict("面板版本选择仍在执行或待恢复，不能释放维护锁")
			}
			continue
		}
		if record.Kind == disasterRestoreKind {
			i, err := validDisasterRestore(filepath.Dir(filepath.Dir(g.journal.Dir)), record)
			if err != nil {
				return maintenance.RootStatus{}, err
			}
			if record.State != "rolled_back" && !disasterActivationFinalized(record) && i.Stop.MaintenanceID == in.OperationID {
				return maintenance.RootStatus{}, fault.Conflict("完整恢复尚待协调或补偿，不能释放维护锁")
			}
			continue
		}
		if record.Kind == panelRestoreKind {
			if err := validPanelRestoreRecord(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if record.State != "succeeded" && record.PanelRestore.Receipt.Manifest.MaintenanceID == in.OperationID {
				return maintenance.RootStatus{}, fault.Conflict("面板恢复仍在执行或待恢复，不能释放维护锁")
			}
			continue
		}
		if record.Kind == nginxSwitchKind {
			if err := validNginxSwitch(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if !nginxSwitchTerminal(record.State) && record.NginxSwitch.Input.MaintenanceID == in.OperationID {
				return maintenance.RootStatus{}, fault.Conflict("Nginx 组件切换仍在执行或待补偿，不能释放维护锁")
			}
			continue
		}
		if record.Kind == nginxSwitchJobKind {
			if err := validSwitchJob(record); err != nil {
				return maintenance.RootStatus{}, err
			}
			if !nginxSwitchTerminal(record.State) && record.NginxSwitchJob.Input.MaintenanceID == in.OperationID {
				return maintenance.RootStatus{}, fault.Conflict("原 Nginx 切换派发仍在执行或待恢复，不能释放维护锁")
			}
			continue
		}
		if record.Kind != nginxInstallKind {
			continue
		}
		if err := validInstallRecord(record); err != nil {
			return maintenance.RootStatus{}, err
		}
		if !installTerminal(record.State) && record.NginxInstall.Input.MaintenanceID == in.OperationID {
			return maintenance.RootStatus{}, fault.Conflict("原 Nginx 安装仍在执行或待恢复，不能释放维护锁")
		}
	}
	prior, err := g.journal.Get(in.OperationID)
	if err == nil && prior.Kind != "maintenance.lock" {
		return maintenance.RootStatus{}, fault.Conflict("维护标识已被其他操作占用")
	}
	if err != nil && !os.IsNotExist(err) {
		return maintenance.RootStatus{}, err
	}
	// A release tombstone also fences an acquire whose response was lost or which
	// arrives after cancellation. Reusing the identifier can never reopen the gate.
	receipt := Record{OperationID: in.OperationID, RequestHash: maintenanceHash(in), Kind: "maintenance.lock", State: "succeeded", Stage: "released", MaintenanceEpoch: g.epoch}
	if err == nil && releasedMaintenance(prior) {
		// A replay after restart must preserve the archived lease's original
		// epoch; the current epoch belongs only to the response and new leases.
		receipt = prior
	}
	if err = g.journal.Put(receipt); err != nil {
		g.poisoned = true
		return maintenance.RootStatus{}, err
	}
	g.id, g.phase, g.poisoned = "", "", false
	return maintenance.RootStatus{Available: true, ID: in.OperationID, Phase: "released", Epoch: g.epoch}, nil
}
func maintenanceReply(w http.ResponseWriter, data any, err error) {
	if err != nil {
		var known *fault.Error
		if !errors.As(err, &known) {
			err = fault.New(http.StatusServiceUnavailable, "MAINTENANCE_UNAVAILABLE", "维护记录或执行器不可用")
		}
	}
	componentReply(w, data, err)
}
func (s *Server) maintenanceHandlers(mux *http.ServeMux, g *maintenanceGate) {
	mux.HandleFunc("GET /v1/maintenance", func(w http.ResponseWriter, r *http.Request) {
		out, err := g.status(r.Context())
		maintenanceReply(w, out, err)
	})
	for _, action := range []string{"acquire", "release"} {
		mux.HandleFunc("POST /v1/maintenance/"+action, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 1024)
			defer r.Body.Close()
			var in maintenance.RootRequest
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Protocol != Protocol || !validID(in.OperationID) {
				maintenanceReply(w, nil, fault.Invalid("维护协议或标识无效"))
				return
			}
			var out maintenance.RootStatus
			var err error
			if action == "acquire" {
				out, err = g.acquire(r.Context(), in)
			} else {
				out, err = g.release(r.Context(), in)
			}
			maintenanceReply(w, out, err)
		})
	}
}
func (g *maintenanceGate) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || (r.URL.Path == "/v1/history/runtime/preview" || r.URL.Path == "/v1/history/runtime/execute") || r.URL.Path == "/v1/maintenance/acquire" || r.URL.Path == "/v1/maintenance/release" || r.Method == http.MethodPost && (r.URL.Path == "/v1/components/nginx-installations" || r.URL.Path == "/v1/panel/updates" || r.URL.Path == "/v1/agent/upgrades" || r.URL.Path == "/v1/panel/images/upgrades" || r.URL.Path == "/v1/nginx/images/upgrades" || r.URL.Path == "/v1/nginx/disaster") {
			next.ServeHTTP(w, r)
			return
		}
		done, ok := g.enter(r.URL.Path == "/v1/management-listener/decide" || r.URL.Path == "/v1/firewall/decide")
		if !ok {
			maintenanceReply(w, nil, fault.New(409, "MAINTENANCE_ACTIVE", "Agent 已关闭配置写入准入"))
			return
		}
		defer done()
		next.ServeHTTP(w, r)
	})
}
func (c *Client) MaintenanceStatus(ctx context.Context) (maintenance.RootStatus, error) {
	var out maintenance.RootStatus
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/maintenance", nil, &out)
	return out, err
}
func (c *Client) AcquireMaintenance(ctx context.Context, in maintenance.RootRequest) (maintenance.RootStatus, error) {
	var out maintenance.RootStatus
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/maintenance/acquire", in, &out)
	return out, err
}
func (c *Client) ReleaseMaintenance(ctx context.Context, in maintenance.RootRequest) (maintenance.RootStatus, error) {
	var out maintenance.RootStatus
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/maintenance/release", in, &out)
	return out, err
}
