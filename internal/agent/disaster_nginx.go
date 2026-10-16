package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type DisasterRuntimeRequest struct {
	Protocol    int    `json:"protocol"`
	OperationID string `json:"operation_id"`
	PlanSHA256  string `json:"plan_sha256"`
	Epoch       string `json:"epoch"`
	Rollback    bool   `json:"rollback"`
}

type DisasterRuntimeStatus struct {
	Restore                Record                                `json:"restore"`
	Nginx                  *Record                               `json:"nginx,omitempty"`
	Reconciliation         *panelrecovery.DisasterReconciliation `json:"reconciliation,omitempty"`
	ReconciliationApproved bool                                  `json:"reconciliation_approved"`
}

func validDisasterNginxRecord(i panelrecovery.DisasterIntent, r Record) error {
	if r.DisasterRestoreID != i.OperationID || r.Kind != "nginx.apply" || r.OperationID != i.PlanID || r.RequestHash != i.NginxRequest.SHA256 || r.BeforeRevision != i.NginxBeforeRevision || r.AfterRevision != i.PlanID || r.BeforeDir != revisionDir(i.NginxBeforeDeployment) || r.AfterDir != i.PlanID || !validID(r.MaintenanceEpoch) || r.RestoreSnapshot != "" || r.PanelRestore != nil || r.PanelUpdate != nil || r.PanelService != nil || r.PanelSelection != nil || r.NginxInstall != nil || r.RemoteListener != nil || r.LogPolicy != nil {
		return errors.New("Nginx 子操作与原完整恢复批准不一致")
	}
	switch r.State {
	case "running", "compensating", "recovery_required", "failed":
	case "succeeded":
		if r.Stage != "runtime_confirmed" || r.ObservedRevision != i.PlanID {
			return errors.New("恢复 Nginx 成功记录缺少运行确认")
		}
	case "rolled_back":
		if r.Stage != "rollback_confirmed" || r.ObservedRevision != i.NginxBeforeRevision {
			return errors.New("恢复 Nginx 补偿记录缺少原运行确认")
		}
	default:
		return errors.New("恢复 Nginx 子操作状态无效")
	}
	return nil
}

func readDisasterNginx(data string, i panelrecovery.DisasterIntent) (Record, error) {
	var r Record
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", i.PlanID+".json"), 64<<10)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || string(raw) != string(canonical) {
		return r, errors.New("恢复 Nginx 子记录不是原规范记录")
	}
	return r, validDisasterNginxRecord(i, r)
}

// DisasterRuntime reads persistent records only; querying does not renew a
// grant, submit work, or assert that the last observed runtime is still current.
func DisasterRuntime(data, id string) (out DisasterRuntimeStatus, err error) {
	out.Restore, err = readDisasterRestore(data, id)
	if err != nil {
		return out, err
	}
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err != nil {
		return out, err
	}
	r, e := panelrecovery.ReadDisasterReconciliation(i)
	if e == nil {
		out.Reconciliation = &r
		if _, e = panelrecovery.ReadDisasterReconciliationProof(i, r); e == nil {
			out.ReconciliationApproved = true
		} else if !os.IsNotExist(e) {
			return out, e
		}
	} else if !os.IsNotExist(e) {
		return out, e
	}
	child, err := readDisasterNginx(data, i)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Nginx = &child
	return out, nil
}

func checkDisasterRecords(j *Journal, i panelrecovery.DisasterIntent, allowChild bool) error {
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.OperationID == i.OperationID || r.Kind == "maintenance.lock" {
			continue
		}
		if r.OperationID == i.PlanID {
			if !allowChild {
				return errors.New("恢复计划标识已被执行记录占用，禁止新建文件安装")
			}
			if err = validDisasterNginxRecord(i, r); err != nil {
				return err
			}
			continue
		}
		settled, e := settledPanelUpdate(r, i.Stop.MaintenanceID)
		if e != nil {
			return e
		}
		if settled {
			continue
		}
		switch r.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		default:
			return errors.New("其他独立副作用操作未结束，停止恢复推进")
		}
	}
	return nil
}

func (n *Nginx) startDisasterRollback(r Record) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.unlock == nil || n.disasterBusy != "" {
		return false
	}
	n.disasterBusy = r.OperationID
	n.workers.Add(1)
	go func() {
		defer n.workers.Done()
		defer func() { n.mu.Lock(); n.disasterBusy = ""; n.mu.Unlock() }()
		n.rollback(r)
	}()
	return true
}

func (n *Nginx) disasterWorking() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.disasterBusy != ""
}

// advanceDisasterRuntime accepts only a fixed root installation intent. The
// immutable request is read locally; ordinary IPC cannot supply restore files.
func (s *Server) advanceDisasterRuntime(ctx context.Context, in DisasterRuntimeRequest) (out DisasterRuntimeStatus, err error) {
	if s.Dev || s.MaintenanceScope != "host" || s.Nginx == nil || s.DataDir != s.Nginx.DataDir || in.Protocol != Protocol || !validID(in.OperationID) || !validID(in.Epoch) || len(in.PlanSHA256) != 64 {
		return out, errors.New("完整恢复运行推进需要本机受管执行器和原批准")
	}
	j := s.Journal
	unlock, err := j.waitRootLock(ctx, ".disaster-restore.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return out, err
	}
	defer access()
	i, err := panelrecovery.ReadDisasterIntent(s.DataDir, in.OperationID)
	if err != nil {
		return out, err
	}
	if i.PlanSHA256 != in.PlanSHA256 {
		return out, errors.New("运行推进指定了不同恢复计划")
	}
	if _, err = panelrecovery.ReadDisasterRuntimeApproval(i, in.Rollback); err != nil {
		return out, errors.Join(errors.New("本机 root 尚未批准本次运行方向"), err)
	}
	if !in.Rollback {
		if _, e := panelrecovery.ReadDisasterRuntimeApproval(i, true); e == nil {
			return out, errors.New("原恢复已明确选择补偿")
		} else if !os.IsNotExist(e) {
			return out, e
		}
	}
	if err = installGrant(j, i.Stop.MaintenanceID, in.Epoch, true); err != nil {
		return out, err
	}
	if err = checkDisasterRuntime(s.DataDir, i); err != nil {
		return out, err
	}
	if err = checkDisasterRecords(j, i, true); err != nil {
		return out, err
	}
	unlockWriter, err := storage.LockWriterForRecovery(s.DataDir, i.Rollback.Manifest.GID)
	if err != nil {
		return out, err
	}
	defer unlockWriter()
	fence, err := storage.ReadWriterFence(s.DataDir)
	if err != nil || fence != i.Fence() {
		return out, errors.Join(err, errors.New("恢复运行推进缺少原写入屏障"))
	}
	out, err = DisasterRuntime(s.DataDir, i.OperationID)
	if err != nil {
		return out, err
	}
	p := &out.Restore
	switch p.Stage {
	case "files_installed", "runtime_preparing", "runtime_applying", "runtime_confirmed", "data_reconciling", "data_reconciled", "runtime_compensating", "runtime_compensated":
	default:
		return out, errors.New("文件安装未完成或已经进入文件补偿，不能推进运行")
	}
	save := func(stage, observed string) error {
		p.Stage, p.State, p.Error, p.ObservedRevision = stage, "recovery_required", "", observed
		p.BeforeRevision, p.AfterRevision, p.MaintenanceEpoch = i.NginxBeforeRevision, i.PlanID, in.Epoch
		if _, e := validDisasterRestore(s.DataDir, *p); e != nil {
			return e
		}
		return j.Put(*p)
	}
	stateMatches := func(revision, deployment string) error {
		state := s.Nginx.State(ctx)
		if !state.Available || !state.Running || !state.Integrity || state.ExternalChange || state.RevisionID != revision || state.DeploymentID != deployment {
			return errors.New("恢复运行状态尚未匹配原批准部署")
		}
		return nil
	}
	if in.Rollback {
		if p.Stage != "runtime_compensating" && p.Stage != "runtime_compensated" {
			if err = save("runtime_compensating", p.ObservedRevision); err != nil {
				return out, err
			}
		}
		if s.Nginx.disasterWorking() {
			return out, nil
		}
		if out.Nginx != nil && out.Nginx.State != "rolled_back" {
			if s.Nginx.startDisasterRollback(*out.Nginx) {
				return out, nil
			}
			return out, ErrBusy
		}
		if err = stateMatches(i.NginxBeforeRevision, i.NginxBeforeDeployment); err != nil {
			return out, err
		}
		err = save("runtime_compensated", i.NginxBeforeRevision)
		return out, err
	}
	if strings.HasPrefix(p.Stage, "runtime_compensat") {
		return out, errors.New("原恢复已选择运行补偿，只能继续原补偿")
	}
	if strings.HasPrefix(p.Stage, "data_") {
		return out, errors.New("原运行已进入数据对账，不能退回应用阶段")
	}
	if out.Nginx == nil {
		if p.Stage == "runtime_applying" || p.Stage == "runtime_confirmed" {
			return out, errors.New("已接受的恢复运行操作记录缺失，禁止重新提交")
		}
		if i.ExpiresAt <= time.Now().Unix() {
			return out, errors.New("原恢复安装授权已到期，可继续原补偿")
		}
		if _, e := os.Lstat(filepath.Join(s.DataDir, "nginx", "revisions", i.PlanID)); e == nil {
			return out, errors.New("原运行记录缺失但已有候选目录，须本机核对")
		} else if !os.IsNotExist(e) {
			return out, e
		}
		if err = panelrecovery.CheckDisasterTarget(ctx, i, true); err != nil {
			return out, err
		}
		if err = stateMatches(i.NginxBeforeRevision, i.NginxBeforeDeployment); err != nil {
			return out, err
		}
		features := s.Nginx.Features(ctx)
		sort.Slice(features.Modules, func(a, b int) bool { return features.Modules[a].Path < features.Modules[b].Path })
		raw, e := json.Marshal(features)
		if e != nil || !features.Available || secure.Hash(raw) != i.NginxCapabilitiesSHA256 {
			return out, errors.New("目标 Nginx 能力偏离原恢复计划，禁止重新推断批准")
		}
		f, _, e := secure.OpenRootFile(filepath.Join(s.DataDir, "agent", "disaster-configs", i.PlanID, "nginx.json"), panelrecovery.DisasterNginxRequestMax)
		if e != nil {
			return out, e
		}
		request, e := ReadDisasterNginxDescriptor(ctx, f, i.NginxRequest)
		f.Close()
		if e != nil {
			return out, e
		}
		if request.OperationID != i.PlanID || request.RevisionID != i.PlanID || request.ExpectedRevision != i.NginxBeforeRevision || request.ValidateOnly || request.RestoreSnapshot != "" || len(request.PreviousFiles) != 0 {
			return out, errors.New("原恢复 Nginx 请求与安装意图不一致")
		}
		if err = save("runtime_preparing", ""); err != nil {
			return out, err
		}
		child, e := s.Nginx.submit(request, i.OperationID, in.Epoch, revisionDir(i.NginxBeforeDeployment))
		if e != nil {
			return out, e
		}
		if err = validDisasterNginxRecord(i, child); err != nil {
			return out, err
		}
		out.Nginx = &child
	}
	if out.Nginx.State == "succeeded" {
		if err = stateMatches(i.PlanID, i.PlanID); err != nil {
			return out, err
		}
		if err = panelrecovery.CheckDisasterTarget(ctx, i, true); err != nil {
			return out, err
		}
		err = save("runtime_confirmed", i.PlanID)
		return out, err
	}
	if out.Nginx.State == "rolled_back" || out.Nginx.State == "failed" || out.Nginx.State == "recovery_required" {
		return out, errors.New("恢复 Nginx 未确认生效，须明确继续原补偿")
	}
	err = save("runtime_applying", "")
	return out, err
}
