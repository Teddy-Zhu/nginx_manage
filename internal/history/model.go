package history

import (
	"time"

	"nginxpanel/internal/fault"
)

type Filter struct {
	Before          int64 `json:"before"`
	RevisionKeep    int   `json:"revision_keep"`
	CertificateKeep int   `json:"certificate_keep"`
	OrderKeep       int   `json:"order_keep"`
	MigrationKeep   int   `json:"migration_keep"`
	MaintenanceKeep int   `json:"maintenance_keep"`
	BackupKeep      int   `json:"backup_keep"`
}

func (f Filter) Validate() error {
	if f.Before < 1 || f.Before > time.Now().Unix() || f.RevisionKeep < 2 || f.RevisionKeep > 100 || f.CertificateKeep < 2 || f.CertificateKeep > 16 || f.OrderKeep < 2 || f.OrderKeep > 100 || f.MigrationKeep != 0 && (f.MigrationKeep < 2 || f.MigrationKeep > 100) {
		return fault.Invalid("历史维护须指定过去的截止时间，并至少保留 2 个配置、每证书 2 个版本及每签发配置 2 个订单；上限分别为 100、16、100。迁移计划设为 0 不清理，启用时每个操作者保留 2–100 份")
	}
	if f.MaintenanceKeep != 0 && (f.MaintenanceKeep < 2 || f.MaintenanceKeep > 63) {
		return fault.Invalid("维护会话保留数设为 0 不归档，启用时须为 2–63")
	}
	if f.BackupKeep != 0 && (f.BackupKeep < 2 || f.BackupKeep > 128) {
		return fault.Invalid("备份历史保留数设为 0 不归档，启用时须为 2–128")
	}
	return nil
}

type Item struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	ResourceID string `json:"resource_id"`
	Version    int64  `json:"version"`
	CreatedAt  int64  `json:"created_at"`
	Bytes      int64  `json:"bytes"`
}

type Scope struct {
	Kind     string `json:"kind"`
	Retained int64  `json:"retained"`
	Selected int    `json:"selected"`
	Bytes    int64  `json:"bytes"`
	More     bool   `json:"more"`
}

type Preview struct {
	NodeID      string  `json:"node_id"`
	Filter      Filter  `json:"filter"`
	BaseVersion int64   `json:"base_version"`
	Scopes      []Scope `json:"scopes"`
	Items       []Item  `json:"items"`
	SHA256      string  `json:"sha256"`
	Token       string  `json:"token"`
	ExpiresAt   int64   `json:"expires_at"`
}

type ExecuteInput struct {
	Token string `json:"token"`
}

type Result struct {
	ID          string  `json:"id"`
	NodeID      string  `json:"node_id"`
	SHA256      string  `json:"sha256"`
	CompletedAt int64   `json:"completed_at"`
	Scopes      []Scope `json:"scopes"`
}
