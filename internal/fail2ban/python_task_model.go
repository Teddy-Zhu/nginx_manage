package fail2ban

import (
	"context"
	"encoding/json"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

type PythonTaskInput struct {
	Action  string `json:"action"`
	PlanID  string `json:"plan_id"`
	Refresh bool   `json:"refresh"`
}

func (in PythonTaskInput) Validate() error {
	switch in.Action {
	case "plan":
		if in.PlanID != "" {
			return fault.Invalid("生成依赖计划不能指定已有计划")
		}
	case "install":
		if len(in.PlanID) != 64 || strings.Trim(in.PlanID, "0123456789abcdef") != "" || in.Refresh {
			return fault.Invalid("安装须指定原依赖计划，不能同时刷新来源")
		}
	default:
		return fault.Invalid("未知 Python 依赖操作")
	}
	return nil
}

type PythonTaskRequest struct {
	Protocol    int             `json:"protocol"`
	OperationID string          `json:"operation_id"`
	Input       PythonTaskInput `json:"input"`
}

func (in PythonTaskRequest) Valid() bool {
	return in.Protocol == protocol.Agent && policyID.MatchString(in.OperationID) && in.Input.Validate() == nil
}
func (in PythonTaskRequest) Hash() string { raw, _ := json.Marshal(in); return secure.Hash(raw) }

type PythonTaskOperation struct {
	ID          string          `json:"id"`
	RequestHash string          `json:"request_hash"`
	Input       PythonTaskInput `json:"input"`
	State       string          `json:"state"`
	Stage       string          `json:"stage"`
	Submission  string          `json:"submission"`
	At          int64           `json:"at"`
	Plan        *PythonPlan     `json:"plan"`
	Python      Python          `json:"python"`
	Error       string          `json:"error"`
}
type PythonTask = AddressTask
type PythonTaskStatus struct {
	ID          string               `json:"id"`
	OperationID string               `json:"operation_id"`
	State       string               `json:"state"`
	Stage       string               `json:"stage"`
	Error       string               `json:"error"`
	CreatedAt   int64                `json:"created_at"`
	Input       PythonTaskInput      `json:"input"`
	Result      *PythonTaskOperation `json:"result"`
}
type PythonTaskExecutor interface {
	ChangeFail2banPython(context.Context, PythonTaskRequest) (PythonTaskOperation, error)
	Fail2banPythonOperation(context.Context, string) (PythonTaskOperation, error)
}

func ValidPythonPlan(plan PythonPlan) bool {
	if len(plan.ID) != 64 || strings.Trim(plan.ID, "0123456789abcdef") != "" || plan.At <= 0 || plan.ExpiresAt != plan.At+3600 || plan.Manager != "apt" && plan.Manager != "dnf" || plan.Architecture != "amd64" && plan.Architecture != "arm64" || len(plan.Packages) == 0 || len(plan.Packages) > 64 || len(plan.Impacts) == 0 || len(plan.Impacts) > 8 {
		return false
	}
	var download, installed int64
	seen := map[string]bool{}
	for _, pkg := range plan.Packages {
		key := pkg.Name + ":" + pkg.Architecture
		if seen[key] || pkg.Name == "" || len(pkg.Name) > 128 || pkg.Version == "" || len(pkg.Version) > 128 || len(pkg.SHA256) != 64 || strings.Trim(pkg.SHA256, "0123456789abcdef") != "" || pkg.DownloadBytes <= 0 || pkg.DownloadBytes > 128<<20 || pkg.InstalledBytes <= 0 || pkg.InstalledBytes > 1<<30 || len(pkg.Source) > 4096 || len(pkg.Repository) > 256 || len(pkg.Filename) > 512 {
			return false
		}
		seen[key] = true
		download += pkg.DownloadBytes
		installed += pkg.InstalledBytes
	}
	return download == plan.DownloadBytes && installed == plan.InstalledBytes && download <= 1<<30 && installed <= 1<<30
}
func ValidPythonTaskOperation(out PythonTaskOperation) bool {
	if !policyID.MatchString(out.ID) || len(out.RequestHash) != 64 || strings.Trim(out.RequestHash, "0123456789abcdef") != "" || out.Input.Validate() != nil || out.At <= 0 || len(out.Python.Modules) > 16 {
		return false
	}
	if out.State != "running" && out.State != "recovery_required" && out.State != "succeeded" && out.State != "failed" {
		return false
	}
	if out.Submission != "not_sent" && out.Submission != "unknown" && out.Submission != "acknowledged" {
		return false
	}
	if out.Plan != nil && !ValidPythonPlan(*out.Plan) {
		return false
	}
	if out.Input.Action == "install" && (out.Plan == nil || out.Plan.ID != out.Input.PlanID) {
		return false
	}
	if out.State == "succeeded" {
		if out.Submission == "not_sent" || out.Plan == nil {
			return false
		}
		if out.Input.Action == "plan" {
			return out.Stage == "plan_ready" || out.Stage == "plan_ready_receipt_unknown"
		}
		return (out.Stage == "python_confirmed" || out.Stage == "python_confirmed_receipt_unknown") && out.Python.Executable.Trusted && out.Python.Package.Available && out.Python.StandardLibrary != nil && *out.Python.StandardLibrary
	}
	return true
}
