package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/secure"
)

const nginxSwitchKind = "component.nginx.switch"

func validSwitchDigest(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

type NginxSwitchInput struct {
	MaintenanceID string             `json:"maintenance_id"`
	Source        nginxruntime.Input `json:"source"`
	AllowDowntime bool               `json:"allow_downtime"`
}

type NginxSwitchIntent struct {
	Input             NginxSwitchInput         `json:"input"`
	Before            nginxruntime.Binding     `json:"before"`
	Candidate         nginxruntime.Binding     `json:"candidate"`
	Directory         string                   `json:"directory"`
	RevisionID        string                   `json:"revision_id"`
	PublicationSHA256 string                   `json:"publication_sha256"`
	Units             map[string]string        `json:"units"`
	Touched           bool                     `json:"touched"`
	Rollback          bool                     `json:"rollback"`
	Confirmation      *NginxSwitchConfirmation `json:"confirmation,omitempty"`
}

type NginxSwitchConfirmation struct {
	ConfirmedAt  int64      `json:"confirmed_at"`
	BinarySHA256 string     `json:"binary_sha256"`
	Version      string     `json:"version"`
	AgentPID     int        `json:"agent_pid"`
	NginxPID     int        `json:"nginx_pid"`
	Runtime      NginxState `json:"runtime"`
}

type NginxSwitchOptions struct {
	Input                       NginxSwitchInput
	DataDir, OperationID, Epoch string
	Resume, Rollback            bool
}

func nginxSwitchHash(id string, i NginxSwitchIntent) string {
	// Mutable progress is separate from the fixed admission snapshot.
	i.Touched, i.Rollback = false, false
	i.Confirmation = nil
	raw, _ := json.Marshal(struct {
		Schema      int
		OperationID string
		Intent      NginxSwitchIntent
	}{1, id, i})
	return secure.Hash(raw)
}

func nginxSwitchTerminal(state string) bool {
	return state == "succeeded" || state == "rolled_back" || state == "failed"
}

func validNginxSwitch(r Record) error {
	i := r.NginxSwitch
	if r.Kind != nginxSwitchKind || i == nil || !validID(r.OperationID) || !validID(r.MaintenanceEpoch) || !validID(i.Input.MaintenanceID) || !i.Input.AllowDowntime || r.RequestHash != nginxSwitchHash(r.OperationID, *i) || r.Deadline <= 0 || i.Before.DataDir != i.Input.Source.DataDir || i.Candidate.DataDir != i.Input.Source.DataDir || i.Before.Owner != "local" && i.Before.Owner != "managed" || i.Candidate.Owner != "managed" || i.Candidate.Signed == nil || i.Before.SHA256 == i.Candidate.SHA256 || !validSwitchDigest(i.PublicationSHA256) || i.Directory != "bootstrap" && !validID(i.Directory) || len(i.Units) != 2 || r.NginxInstall != nil || r.PanelUpdate != nil || r.PanelRestore != nil || r.PanelService != nil || r.PanelSelection != nil || r.DisasterRestoreID != "" || r.DisasterActivation != nil {
		return errors.New("Nginx 组件切换记录无效")
	}
	for _, unit := range []string{"nginxpanel-nginx.service", "nginxpanel-agent.service"} {
		if !validSwitchDigest(i.Units[unit]) {
			return errors.New("组件切换缺少原生服务摘要")
		}
	}
	if i.Candidate.Signed.PlanID != i.Input.Source.PlanID || i.Candidate.Signed.AssetID != i.Input.Source.AssetID || i.Candidate.Signed.TrustPath != i.Input.Source.TrustPath || i.Candidate.Signed.Prerelease != i.Input.Source.Prerelease {
		return errors.New("组件切换候选与原输入不一致")
	}
	switch r.State {
	case "running", "compensating", "recovery_required", "succeeded", "rolled_back", "failed":
	default:
		return errors.New("组件切换状态无效")
	}
	switch r.Stage {
	case "validated", "stopping_agent", "stopping_nginx", "binding", "starting_nginx", "confirming_nginx", "starting_agent", "confirming_agent", "committed", "rollback_stopping_agent", "rollback_stopping_nginx", "rollback_binding", "rollback_starting_nginx", "rollback_confirming_nginx", "rollback_starting_agent", "rollback_confirming_agent", "rollback_confirmed":
	default:
		return errors.New("组件切换阶段无效")
	}
	if r.State == "succeeded" && (r.Stage != "committed" || !i.Touched || i.Rollback) || r.State == "rolled_back" && (r.Stage != "rollback_confirmed" || !i.Rollback) || r.State == "compensating" && !i.Rollback || r.State == "failed" && i.Touched {
		return errors.New("组件切换终态与持久进度不一致")
	}
	if i.RevisionID != "" && !validID(i.RevisionID) {
		return errors.New("组件切换发布修订无效")
	}
	if r.State == "succeeded" || r.State == "rolled_back" {
		target := i.Candidate
		if i.Rollback {
			target = i.Before
		}
		p := i.Confirmation
		if p == nil || p.ConfirmedAt <= 0 || p.BinarySHA256 != target.SHA256 || p.Version != target.Version || p.AgentPID <= 1 || p.NginxPID <= 1 || !p.Runtime.Available || !p.Runtime.Integrity || !p.Runtime.Running || p.Runtime.ExternalChange || p.Runtime.RevisionID != i.RevisionID || revisionDir(p.Runtime.DeploymentID) != i.Directory {
			return errors.New("组件切换终态缺少实际运行确认")
		}
	}
	return nil
}

// ReadNginxSwitch returns the durable snapshot, without controlling services or
// asserting that a historically confirmed runtime is still running now.
func ReadNginxSwitch(data, id string) (Record, error) {
	var r Record
	if !validID(id) {
		return r, errors.New("组件切换操作标识无效")
	}
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), 64<<10)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) || r.OperationID != id || r.NginxSwitch == nil || r.NginxSwitch.Input.Source.DataDir != data {
		return r, errors.New("组件切换记录不是本机原规范记录")
	}
	return r, validNginxSwitch(r)
}
