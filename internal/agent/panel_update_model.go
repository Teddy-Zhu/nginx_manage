package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/panelupdates"
	"nginxpanel/internal/secure"
)

const panelUpdateKind = "panel.update"

type PanelUpdateInput struct {
	Stage         panelruntime.StageInput `json:"stage"`
	MaintenanceID string                  `json:"maintenance_id"`
}

type PanelUpdateIntent struct {
	Input               PanelUpdateInput        `json:"input"`
	BeforeID            string                  `json:"before_id"`
	TargetID            string                  `json:"target_id"`
	BeforeSchema        int64                   `json:"before_schema"`
	TargetSchema        int64                   `json:"target_schema"`
	BindingSHA256       string                  `json:"binding_sha256"`
	ApprovalSHA256      string                  `json:"approval_sha256"`
	UID                 int                     `json:"uid"`
	GID                 int                     `json:"gid"`
	SnapshotEpoch       string                  `json:"snapshot_epoch"`
	SnapshotID          string                  `json:"snapshot_id"`
	StopID              string                  `json:"stop_id"`
	SelectionID         string                  `json:"selection_id"`
	StartID             string                  `json:"start_id"`
	RollbackStopID      string                  `json:"rollback_stop_id"`
	RollbackSelectionID string                  `json:"rollback_selection_id"`
	RestoreID           string                  `json:"restore_id"`
	RollbackStartID     string                  `json:"rollback_start_id"`
	Before              PanelServiceObservation `json:"before"`
}

// Child operations are embedded so the immutable parent authorization and every
// live-step receipt are published atomically in one independent root journal.
type PanelUpdateAuthorization struct {
	Request    panelupdates.Request `json:"request"`
	AcceptedAt int64                `json:"accepted_at"`
	ClaimedAt  int64                `json:"claimed_at"`
}

type PanelUpdateOperation struct {
	Authorizations      []PanelUpdateAuthorization `json:"authorizations,omitempty"`
	Intent              PanelUpdateIntent          `json:"intent"`
	Snapshot            *panelrecovery.Receipt     `json:"snapshot,omitempty"`
	Stop                *Record                    `json:"stop,omitempty"`
	Start               *Record                    `json:"start,omitempty"`
	RollbackStop        *Record                    `json:"rollback_stop,omitempty"`
	Restore             *Record                    `json:"restore,omitempty"`
	RollbackStart       *Record                    `json:"rollback_start,omitempty"`
	Selected            bool                       `json:"selected"`
	RollbackSelected    bool                       `json:"rollback_selected"`
	Ready               *PanelReadiness            `json:"ready,omitempty"`
	RollbackReady       *PanelReadiness            `json:"rollback_ready,omitempty"`
	AbortObservation    *PanelServiceObservation   `json:"abort_observation,omitempty"`
	Failure             string                     `json:"failure"`
	ReleaseAcknowledged bool                       `json:"release_acknowledged"`
	Cleanup             *PanelUpdateCleanup        `json:"cleanup,omitempty"`
}

type PanelUpdateCleanup struct {
	Status panelupdates.Cleanup       `json:"status"`
	Plan   *panelrecovery.CleanupPlan `json:"plan,omitempty"`
}

func panelUpdateHash(id string, in PanelUpdateIntent) string {
	raw, _ := json.Marshal(struct {
		Protocol int               `json:"protocol"`
		ID       string            `json:"operation_id"`
		Intent   PanelUpdateIntent `json:"intent"`
	}{Protocol, id, in})
	return secure.Hash(raw)
}

func panelUpdateTerminal(r Record) bool {
	return panelUpdateFinalized(r) && r.PanelUpdate.ReleaseAcknowledged && r.State == panelUpdateOutcome(r)
}

func panelUpdateOutcome(r Record) string {
	switch r.Stage {
	case "committed":
		return "succeeded"
	case "compensated":
		return "rolled_back"
	case "aborted":
		return "failed"
	}
	return ""
}

func panelUpdateFinalized(r Record) bool {
	return r.Kind == panelUpdateKind && r.PanelUpdate != nil && panelUpdateOutcome(r) != "" && (r.State == "waiting_confirmation" || r.State == panelUpdateOutcome(r))
}

// A finalized update has no remaining live mutation. Once a different grant is
// held, an uncollected release receipt must not block that later maintenance.
func settledPanelUpdate(r Record, maintenanceID string) (bool, error) {
	if r.Kind != panelUpdateKind {
		return false, nil
	}
	if err := validPanelUpdate(r); err != nil {
		return false, err
	}
	return panelUpdateFinalized(r) && r.PanelUpdate.Intent.Input.MaintenanceID != maintenanceID, nil
}

func validUpdateReadiness(p *PanelReadiness, started *Record, snapshot *panelrecovery.Receipt, in PanelUpdateIntent, schema int64) error {
	if p == nil || started == nil || started.State != "succeeded" || snapshot == nil || p.StartID != started.OperationID || p.StartSHA256 != started.RequestHash || p.SnapshotID != in.SnapshotID || p.SnapshotSHA256 != selectionValueHash(*snapshot) || p.BindingSHA256 != in.BindingSHA256 || p.CheckedAt <= 0 || p.CheckedAt > time.Now().Unix()+300 || p.Process != *started.PanelService.After || p.HTTPS.FrontendFiles <= 0 || !panelSelectionDigest.MatchString(p.HTTPS.CertificateSHA256) {
		return errors.New("更新就绪证据与原子操作或快照不一致")
	}
	if err := p.Application.Validate(); err != nil {
		return err
	}
	a, db := p.Application, snapshot.Manifest.Database
	if a.ReleaseID != started.PanelService.Intent.ReleaseID || a.PID != p.Process.PID || a.Mode != in.Before.Mode || a.DatabaseSchema != schema || a.NodeID != db.NodeID || a.Maintenance.ID != in.Input.MaintenanceID || a.Configuration.DesiredRevision != db.DesiredRevision || a.Configuration.AppliedRevision != db.AppliedRevision || a.Configuration.HeadVersion != db.HeadVersion {
		return errors.New("更新就绪证据的应用或数据库身份无效")
	}
	return nil
}

func validPanelUpdate(r Record) error {
	p := r.PanelUpdate
	if r.Kind != panelUpdateKind || !validID(r.OperationID) || !validID(r.MaintenanceEpoch) || p == nil || r.PanelService != nil || r.PanelSelection != nil || r.PanelRestore != nil || r.NginxInstall != nil {
		return errors.New("面板更新独立记录身份无效")
	}
	i := p.Intent
	s := i.Input.Stage
	if _, err := panelruntime.Root(s.DataDir); err != nil {
		return err
	}
	if !validID(i.Input.MaintenanceID) || !panelSelectionDigest.MatchString(s.PlanID) || !filepath.IsAbs(s.TrustPath) || filepath.Clean(s.TrustPath) != s.TrustPath || len(s.TrustPath) > 512 || !panelSelectionDigest.MatchString(i.BeforeID) || !panelSelectionDigest.MatchString(i.TargetID) || i.BeforeID == i.TargetID || i.BeforeSchema <= 0 || i.TargetSchema < i.BeforeSchema || !panelSelectionDigest.MatchString(i.BindingSHA256) || !panelSelectionDigest.MatchString(i.ApprovalSHA256) || i.UID <= 0 || i.GID <= 0 || i.SnapshotEpoch != r.MaintenanceEpoch || !validServiceObservation(i.Before) || i.Before.State != "running" || i.Before.ReleaseID != i.BeforeID || r.RequestHash != panelUpdateHash(r.OperationID, i) || r.Deadline <= 0 || len(p.Failure) > 1024 || len(r.Error) > 1024 {
		return errors.New("面板更新记录与原批准不一致")
	}
	if len(p.Authorizations) > 32 {
		return errors.New("更新授权记录过多")
	}
	for n, a := range p.Authorizations {
		q := a.Request
		if q.Validate() != nil || q.OperationID != r.OperationID || q.Input != panelUpdateAPIInput(i.Input) || q.Sequence != n+1 || a.AcceptedAt <= 0 || a.AcceptedAt > q.AuthorizationUntil || q.AuthorizationUntil > a.AcceptedAt+305 || a.ClaimedAt != 0 && (a.ClaimedAt < a.AcceptedAt || a.ClaimedAt >= q.AuthorizationUntil) || n == 0 && q.Epoch != i.SnapshotEpoch || n > 0 && a.AcceptedAt < p.Authorizations[n-1].AcceptedAt {
			return errors.New("更新授权历史与原意图不一致")
		}
	}
	if r.State == "queued" && len(p.Authorizations) == 0 {
		return errors.New("排队更新缺少托管授权")
	}
	ids := []string{r.OperationID, i.Input.MaintenanceID, i.SnapshotID, i.StopID, i.SelectionID, i.StartID, i.RollbackStopID, i.RollbackSelectionID, i.RestoreID, i.RollbackStartID}
	for n, id := range ids {
		if !validID(id) {
			return errors.New("面板更新子操作身份无效")
		}
		for k := 0; k < n; k++ {
			if ids[k] == id {
				return errors.New("面板更新子操作标识重复")
			}
		}
	}
	if p.Snapshot != nil {
		if err := p.Snapshot.Validate(s.DataDir, i.SnapshotID); err != nil {
			return err
		}
		m := p.Snapshot.Manifest
		if m.MaintenanceID != i.Input.MaintenanceID || m.Epoch != i.SnapshotEpoch || m.UID != i.UID || m.GID != i.GID || m.Database.SchemaVersion != i.BeforeSchema {
			return errors.New("面板更新快照与原授权不一致")
		}
	}
	for _, child := range []struct {
		r                   *Record
		id, action, release string
	}{{p.Stop, i.StopID, "stop", i.BeforeID}, {p.Start, i.StartID, "start", i.TargetID}, {p.RollbackStop, i.RollbackStopID, "stop", ""}, {p.RollbackStart, i.RollbackStartID, "start", i.BeforeID}} {
		if child.r == nil {
			continue
		}
		c := *child.r
		if c.PanelUpdate != nil || c.PanelSelection != nil || c.PanelRestore != nil || c.NginxInstall != nil {
			return errors.New("更新进程子记录包含其他动作")
		}
		if err := validPanelService(c); err != nil {
			return err
		}
		x := c.PanelService.Intent
		if c.OperationID != child.id || x.Input.DataDir != s.DataDir || x.Input.MaintenanceID != i.Input.MaintenanceID || x.Input.Action != child.action || x.Input.SelectionID != "" || x.BindingSHA256 != i.BindingSHA256 || child.release != "" && x.ReleaseID != child.release || x.ReleaseID != i.BeforeID && x.ReleaseID != i.TargetID {
			return errors.New("更新进程子记录不属于原授权")
		}
	}
	if p.Start != nil && (!p.Selected || p.Stop == nil || p.Stop.State != "succeeded" || p.Start.PanelService.Intent.Input.StopID != p.Stop.OperationID || p.Start.PanelService.Intent.StopSHA256 != p.Stop.RequestHash) {
		return errors.New("更新启动与原停机、版本选择不一致")
	}
	if p.Restore != nil {
		c := *p.Restore
		if c.PanelUpdate != nil || c.PanelService != nil || c.PanelSelection != nil || c.NginxInstall != nil || c.OperationID != i.RestoreID || p.Snapshot == nil {
			return errors.New("更新恢复子记录身份无效")
		}
		if err := validPanelRestoreRecord(c); err != nil {
			return err
		}
		if selectionValueHash(c.PanelRestore.Receipt) != selectionValueHash(*p.Snapshot) {
			return errors.New("更新恢复子记录与原快照不一致")
		}
	}
	if p.RollbackStart != nil {
		stop := p.Stop
		if p.RollbackStop != nil {
			stop = p.RollbackStop
		}
		if !p.RollbackSelected || p.Restore == nil || p.Restore.State != "succeeded" || stop == nil || stop.State != "succeeded" || p.RollbackStart.PanelService.Intent.Input.StopID != stop.OperationID || p.RollbackStart.PanelService.Intent.StopSHA256 != stop.RequestHash {
			return errors.New("补偿启动与匹配程序、数据和停机不一致")
		}
	}
	if p.Ready != nil {
		if err := validUpdateReadiness(p.Ready, p.Start, p.Snapshot, i, i.TargetSchema); err != nil {
			return err
		}
	}
	if p.RollbackReady != nil {
		if err := validUpdateReadiness(p.RollbackReady, p.RollbackStart, p.Snapshot, i, i.BeforeSchema); err != nil {
			return err
		}
	}
	switch r.Stage {
	case "capturing":
		if r.State != "queued" && r.State != "running" && r.State != "recovery_required" {
			return errors.New("更新捕获阶段无效")
		}
	case "stopping", "selecting", "starting", "checking":
		if p.Snapshot == nil || r.State != "running" && r.State != "recovery_required" {
			return errors.New("更新执行阶段无效")
		}
	case "rollback_stopping", "rollback_selecting", "restoring", "rollback_starting", "rollback_checking":
		if p.Snapshot == nil || p.Failure == "" || r.State != "compensating" && r.State != "recovery_required" {
			return errors.New("更新补偿阶段无效")
		}
	case "committed":
		if !panelUpdateFinalized(r) || p.Ready == nil || p.Failure != "" {
			return errors.New("更新提交证据缺失")
		}
	case "compensated":
		if !panelUpdateFinalized(r) || p.RollbackReady == nil || p.Failure == "" {
			return errors.New("更新补偿证据缺失")
		}
	case "aborted":
		if !panelUpdateFinalized(r) || p.Failure == "" || p.AbortObservation == nil || !validServiceObservation(*p.AbortObservation) || p.AbortObservation.State != "running" || p.AbortObservation.ReleaseID != i.BeforeID || p.AbortObservation.Mode != i.Before.Mode || p.Stop != nil || p.Start != nil || p.Selected || p.Restore != nil || p.RollbackStop != nil || p.RollbackStart != nil {
			return errors.New("更新中止的无副作用证据缺失")
		}
	default:
		return errors.New("未知更新阶段")
	}
	if p.ReleaseAcknowledged && (!panelUpdateFinalized(r) || r.State != panelUpdateOutcome(r)) || !p.ReleaseAcknowledged && panelUpdateFinalized(r) && r.State != "waiting_confirmation" {
		return errors.New("更新结果与维护释放回执不一致")
	}
	if err := validPanelUpdateCleanup(r); err != nil {
		return err
	}
	return nil
}

func panelUpdateRecord(data, id string) (Record, error) {
	var r Record
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), 128<<10)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || string(raw) != string(canonical) {
		return r, errors.New("更新记录不是原始规范记录")
	}
	if err = validPanelUpdate(r); err != nil {
		return r, err
	}
	if r.OperationID != id || r.PanelUpdate.Intent.Input.Stage.DataDir != data {
		return r, errors.New("更新记录不属于当前节点")
	}
	return r, nil
}

func PanelUpdateStatus(data, id string) (Record, error) {
	if os.Geteuid() != 0 || !validID(id) {
		return Record{}, errors.New("更新查询需要 root 和原操作标识")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return Record{}, err
	}
	return panelUpdateRecord(data, id)
}
