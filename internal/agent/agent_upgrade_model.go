package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"nginxpanel/internal/agentupdates"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

const agentUpgradeKind = "agent.upgrade"
const agentUpgradeTemplate = "nginxpanel-agent-upgrade@.service"
const agentBootstrapRoot = "/opt/nginxpanel"

type AgentUpgradeInput struct {
	Stage         panelruntime.StageInput `json:"stage"`
	MaintenanceID string                  `json:"maintenance_id"`
}
type AgentProgram struct {
	Link         string `json:"link"`
	BinarySHA256 string `json:"binary_sha256"`
}
type AgentProcess struct {
	State      string `json:"state"`
	BootID     string `json:"boot_id"`
	Invocation string `json:"invocation"`
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
}
type AgentUpgradeIntent struct {
	Input          AgentUpgradeInput `json:"input"`
	Before         AgentProgram      `json:"before"`
	Target         AgentProgram      `json:"target"`
	BeforeProcess  AgentProcess      `json:"before_process"`
	BindingSHA256  string            `json:"binding_sha256"`
	PanelID        string            `json:"panel_id"`
	TargetVersion  string            `json:"target_version"`
	ApprovalSHA256 string            `json:"approval_sha256"`
	AgentUnit      string            `json:"agent_unit"`
	WorkerUnit     string            `json:"worker_unit"`
	Epoch          string            `json:"epoch"`
	CreatedAt      int64             `json:"created_at"`
	Deadline       int64             `json:"deadline"`
}
type AgentUpgradeOperation struct {
	Authorizations []AgentUpgradeAuthorization `json:"authorizations,omitempty"`
	Intent         AgentUpgradeIntent          `json:"intent"`
	Rollback       bool                        `json:"rollback"`
	Failure        string                      `json:"failure"`
	Ready          *AgentProcess               `json:"ready,omitempty"`
	RollbackReady  *AgentProcess               `json:"rollback_ready,omitempty"`
	ReadyEpoch     string                      `json:"ready_epoch"`
}

type AgentUpgradeAuthorization struct {
	Request    agentupdates.Request `json:"request"`
	AcceptedAt int64                `json:"accepted_at"`
	ClaimedAt  int64                `json:"claimed_at"`
}

func agentUpgradeAPIInput(in AgentUpgradeInput) agentupdates.Input {
	return agentupdates.Input{MaintenanceID: in.MaintenanceID, PlanID: in.Stage.PlanID, Prerelease: in.Stage.AllowPrerelease}
}

func agentProgramLinkValid(link string) bool {
	parts := strings.Split(link, "/")
	return len(parts) == 2 && (parts[0] == "releases" || parts[0] == "agent-releases") && panelSelectionDigest.MatchString(parts[1])
}
func agentProgramValid(p AgentProgram) bool {
	return agentProgramLinkValid(p.Link) && panelSelectionDigest.MatchString(p.BinarySHA256) && (!strings.HasPrefix(p.Link, "agent-releases/") || strings.TrimPrefix(p.Link, "agent-releases/") == p.BinarySHA256)
}
func (p AgentProgram) binary() string { return filepath.Join(agentBootstrapRoot, p.Link, "nginxpanel") }
func agentProcessValid(p AgentProcess) bool {
	return p.State == "running" && validID(p.BootID) && len(p.Invocation) == 32 && strings.Trim(p.Invocation, "0123456789abcdef") == "" && strings.Trim(p.Invocation, "0") != "" && p.PID > 1 && p.StartTicks > 0
}
func agentUpgradeHash(id string, in AgentUpgradeIntent) string {
	raw, _ := json.Marshal(struct {
		Protocol int                `json:"protocol"`
		ID       string             `json:"id"`
		Intent   AgentUpgradeIntent `json:"intent"`
	}{Protocol, id, in})
	return secure.Hash(raw)
}
func agentUpgradeTerminal(r Record) bool {
	return r.Kind == agentUpgradeKind && (r.State == "succeeded" || r.State == "rolled_back")
}
func validAgentUpgrade(r Record) error {
	p := r.AgentUpgrade
	if p == nil || r.Kind != agentUpgradeKind || !validID(r.OperationID) {
		return errors.New("Agent 升级记录身份无效")
	}
	i := p.Intent
	if len(p.Authorizations) > 32 {
		return errors.New("Agent 升级授权超过保留上限")
	}
	for n, a := range p.Authorizations {
		q := a.Request
		if q.Validate() != nil || q.OperationID != r.OperationID || q.Input != agentUpgradeAPIInput(i.Input) || q.Sequence != n+1 || a.AcceptedAt <= 0 || a.AcceptedAt > q.AuthorizationUntil || q.AuthorizationUntil > a.AcceptedAt+305 || a.ClaimedAt != 0 && (a.ClaimedAt < a.AcceptedAt || a.ClaimedAt >= q.AuthorizationUntil) || n == 0 && q.Epoch != i.Epoch || n > 0 && a.AcceptedAt < p.Authorizations[n-1].AcceptedAt {
			return errors.New("Agent 升级持久授权与原操作不一致")
		}
	}
	if agentUpgradeTerminal(r) && len(p.Authorizations) != 0 && p.Authorizations[len(p.Authorizations)-1].ClaimedAt == 0 {
		return errors.New("Agent 升级终态缺少已领取的启动授权")
	}
	if _, err := panelruntime.Root(i.Input.Stage.DataDir); err != nil {
		return err
	}
	if !validID(i.Input.MaintenanceID) || !validID(i.Epoch) || !panelSelectionDigest.MatchString(i.Input.Stage.PlanID) || !filepath.IsAbs(i.Input.Stage.TrustPath) || filepath.Clean(i.Input.Stage.TrustPath) != i.Input.Stage.TrustPath || len(i.Input.Stage.TrustPath) > 512 || !agentProgramValid(i.Before) || !agentProgramValid(i.Target) || i.Target.Link != "agent-releases/"+i.Target.BinarySHA256 || i.Before.BinarySHA256 == i.Target.BinarySHA256 || !agentProcessValid(i.BeforeProcess) || !panelSelectionDigest.MatchString(i.BindingSHA256) || !panelSelectionDigest.MatchString(i.PanelID) || !panelSelectionDigest.MatchString(i.ApprovalSHA256) || !panelSelectionDigest.MatchString(i.AgentUnit) || !panelSelectionDigest.MatchString(i.WorkerUnit) || i.TargetVersion == "" || len(i.TargetVersion) > 96 || i.CreatedAt <= 0 || i.CreatedAt > time.Now().Unix()+300 || i.Deadline != i.CreatedAt+600 || r.RequestHash != agentUpgradeHash(r.OperationID, i) || len(p.Failure) > 4000 {
		return errors.New("Agent 升级意图或恢复身份无效")
	}
	if p.Ready != nil && !agentProcessValid(*p.Ready) || p.RollbackReady != nil && !agentProcessValid(*p.RollbackReady) || p.ReadyEpoch != "" && !validID(p.ReadyEpoch) {
		return errors.New("Agent 升级进程回执无效")
	}
	if r.State == "succeeded" && r.Stage == "committed" && !p.Rollback && p.Ready != nil && *p.Ready != i.BeforeProcess && validID(p.ReadyEpoch) && p.ReadyEpoch != i.Epoch && p.Failure == "" && r.Error == "" || r.State == "rolled_back" && r.Stage == "compensated" && p.Rollback && p.RollbackReady != nil && validID(p.ReadyEpoch) && p.Failure != "" {
		return nil
	}
	if agentUpgradeTerminal(r) {
		return errors.New("Agent 升级终态缺少进程确认")
	}
	if p.Rollback {
		if (r.State != "compensating" && r.State != "recovery_required") || (r.Stage != "rollback_stopping" && r.Stage != "rollback_selecting" && r.Stage != "rollback_starting") || p.Failure == "" {
			return errors.New("Agent 升级补偿状态无效")
		}
	} else if r.State != "running" || !slices.Contains([]string{"authorized", "stopping", "stopped", "selecting", "selected", "starting"}, r.Stage) {
		return errors.New("Agent 升级前进状态无效")
	}
	return nil
}
func AgentUpgradeStatus(data, id string) (Record, error) {
	var r Record
	if os.Geteuid() != 0 || !validID(id) {
		return r, errors.New("Agent 升级查询需要 root 和原操作 UUID")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return r, err
	}
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), 64<<10)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if err := validAgentUpgrade(r); err != nil {
		return r, err
	}
	if r.OperationID != id || r.AgentUpgrade.Intent.Input.Stage.DataDir != data {
		return Record{}, errors.New("Agent 升级记录不属于此节点或原操作")
	}
	return r, nil
}
