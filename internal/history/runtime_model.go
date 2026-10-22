package history

import (
	"time"

	"nginxpanel/internal/fault"
)

// RuntimeFilter selects a bounded batch of immutable runtime material.
type RuntimeFilter struct {
	MaintenanceID string `json:"maintenance_id"`
	Kind          string `json:"kind"`
	Before        int64  `json:"before"`
	Keep          int    `json:"keep"`
}

func (f RuntimeFilter) Validate() error {
	if err := f.ValidateStored(); err != nil {
		return err
	}
	if f.Before > time.Now().Unix() {
		return fault.Invalid("运行材料清理须选择过去的截止时间")
	}
	return nil
}

// Durable approvals retain their original cutoff if the system clock moves.
func (f RuntimeFilter) ValidateStored() error {
	if f.Kind != "publication" && f.Kind != "certificate" && f.Kind != "agent_program" && f.Kind != "root_receipt" || f.Before < 1 || f.Keep < 2 || f.Keep > 32 || f.Kind == "agent_program" && f.Keep > 8 {
		return fault.Invalid("运行材料须选择发布、证书、Agent 程序或 root 回执、过去的截止时间及保留数量；Agent 程序保留 2–8 份，其余保留 2–32 份")
	}
	return nil
}

type RuntimeExecuteInput struct {
	OperationID string        `json:"operation_id"`
	Filter      RuntimeFilter `json:"filter"`
	SHA256      string        `json:"sha256"`
}

type RuntimePreview struct {
	Filter  RuntimeFilter `json:"filter"`
	Active  string        `json:"active"`
	Targets []string      `json:"targets"`
	Entries int           `json:"entries"`
	Bytes   int64         `json:"bytes"`
	More    bool          `json:"more"`
	SHA256  string        `json:"sha256"`
}

type RuntimeStatus struct {
	OperationID string         `json:"operation_id"`
	State       string         `json:"state"`
	Stage       string         `json:"stage"`
	Error       string         `json:"error"`
	UpdatedAt   int64          `json:"updated_at"`
	Preview     RuntimePreview `json:"preview"`
}

type RuntimeRequest struct {
	Protocol int                 `json:"protocol"`
	Epoch    string              `json:"epoch"`
	Input    RuntimeExecuteInput `json:"input"`
}
