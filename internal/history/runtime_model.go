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
	if f.Kind != "publication" && f.Kind != "certificate" || f.Before < 1 || f.Before > time.Now().Unix() || f.Keep < 2 || f.Keep > 32 {
		return fault.Invalid("运行材料须选择发布或证书类别、过去的截止时间及 2–32 份保留数量")
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
