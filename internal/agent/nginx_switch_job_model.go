package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"

	"nginxpanel/internal/nginxswitch"
	"nginxpanel/internal/secure"
)

const nginxSwitchJobKind = "component.nginx.switch.dispatch"
const nginxSwitchTemplate = "nginxpanel-switch@.service"

type nginxSwitchAuthorization struct {
	Request   nginxswitch.Request `json:"request"`
	ClaimedAt int64               `json:"claimed_at"`
}
type nginxSwitchJob struct {
	Input          nginxswitch.Input          `json:"input"`
	Source         NginxSwitchInput           `json:"source"`
	ChildID        string                     `json:"child_id"`
	Authorizations []nginxSwitchAuthorization `json:"authorizations"`
}

func switchJobHash(id string, j nginxSwitchJob) string {
	j.Authorizations = nil
	raw, _ := json.Marshal(struct {
		Schema int
		ID     string
		Job    nginxSwitchJob
	}{1, id, j})
	return secure.Hash(raw)
}
func validSwitchJob(r Record) error {
	j := r.NginxSwitchJob
	if r.Kind != nginxSwitchJobKind || !validID(r.OperationID) || j == nil || !validID(j.ChildID) || j.ChildID == r.OperationID || r.RequestHash != switchJobHash(r.OperationID, *j) || j.Input.Validate() != nil || j.Source.MaintenanceID != j.Input.MaintenanceID || !j.Source.AllowDowntime || j.Source.Source.Binary != "" || j.Source.Source.Uninstalled || j.Source.Source.PlanID != j.Input.PlanID || j.Source.Source.AssetID != j.Input.AssetID || j.Source.Source.Prerelease != j.Input.Prerelease || len(j.Authorizations) < 1 || len(j.Authorizations) > 32 || r.NginxSwitch != nil || r.NginxInstall != nil || r.PanelUpdate != nil || r.PanelService != nil || r.PanelRestore != nil || r.PanelSelection != nil || r.DisasterRestoreID != "" || r.DisasterActivation != nil {
		return errors.New("组件切换派发记录无效")
	}
	for index, a := range j.Authorizations {
		q := a.Request
		if q.Validate() != nil || q.Input != j.Input || q.OperationID != r.OperationID || index == 0 && q.Sequence != 1 || index > 0 && q.Sequence <= j.Authorizations[index-1].Request.Sequence || a.ClaimedAt < 0 || a.ClaimedAt != 0 && a.ClaimedAt > q.AuthorizationUntil {
			return errors.New("组件切换派发授权与原记录不一致")
		}
	}
	a := j.Authorizations[len(j.Authorizations)-1]
	if r.Deadline != a.Request.AuthorizationUntil || r.MaintenanceEpoch != a.Request.Epoch || r.Stage == "" || len(r.Stage) > 64 {
		return errors.New("组件切换派发进度与授权不一致")
	}
	switch r.State {
	case "queued", "running", "recovery_required", "succeeded", "failed", "rolled_back":
	default:
		return errors.New("组件切换派发状态无效")
	}
	return nil
}

func switchJobRequest(r Record, sequence int) (nginxswitch.Request, bool) {
	for _, a := range r.NginxSwitchJob.Authorizations {
		if a.Request.Sequence == sequence {
			return a.Request, true
		}
	}
	return nginxswitch.Request{}, false
}

func switchJobRecord(data, id string) (Record, error) {
	var r Record
	if !validID(id) {
		return r, errors.New("切换派发标识无效")
	}
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), 64<<10)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) || r.OperationID != id || r.NginxSwitchJob == nil || r.NginxSwitchJob.Source.Source.DataDir != data {
		return r, errors.New("切换派发记录不是本机原规范记录")
	}
	return r, validSwitchJob(r)
}

func switchJobOwns(r Record, opts NginxSwitchOptions) error {
	if validSwitchJob(r) != nil || opts.expected == nil || r.NginxSwitchJob.Input != *opts.expected || r.NginxSwitchJob.ChildID != opts.OperationID || r.NginxSwitchJob.Source != opts.Input || r.State != "running" {
		return errors.New("组件切换不是原派发授权的子操作")
	}
	a := r.NginxSwitchJob.Authorizations[len(r.NginxSwitchJob.Authorizations)-1]
	if a.ClaimedAt == 0 || a.Request.Epoch != opts.Epoch {
		return errors.New("切换启动授权尚未领取")
	}
	return nil
}
