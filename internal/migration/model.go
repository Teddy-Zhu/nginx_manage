// Package migration transfers logical configuration, never host execution state.
package migration

import (
	"context"
	"database/sql"
	"sync"

	"nginxpanel/internal/acme"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/components"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/notifications"
	"nginxpanel/internal/secure"
)

const (
	Schema          = 1
	MaxPackageBytes = 8 << 20
	MaxRequestBytes = 12 << 20
)

type Selection struct {
	Certificates   bool `json:"certificates"`
	DNSCredentials bool `json:"dns_credentials"`
	Automation     bool `json:"automation"`
	Notifications  bool `json:"notifications"`
}
type ExportInput struct {
	Passphrase string    `json:"passphrase"`
	Selection  Selection `json:"selection"`
}
type Package struct {
	Filename string   `json:"filename"`
	Content  []byte   `json:"content"`
	SHA256   string   `json:"sha256"`
	Manifest Manifest `json:"manifest"`
}
type Manifest struct {
	Schema        int               `json:"schema"`
	SourceNode    string            `json:"source_node"`
	SourceVersion string            `json:"source_version"`
	CreatedAt     int64             `json:"created_at"`
	Selection     Selection         `json:"selection"`
	Files         map[string]string `json:"files"`
	Omissions     []string          `json:"omissions"`
}
type Certificate = certificates.Transfer
type Credential = acme.TransferCredential
type Payload struct {
	Files        []nginxconfig.File              `json:"files"`
	Certificates []Certificate                   `json:"certificates"`
	Credentials  []Credential                    `json:"credentials"`
	Automation   acme.TransferAutomation         `json:"automation"`
	Channels     []notifications.TransferChannel `json:"channels"`
}
type ImportInput struct {
	Content     []byte            `json:"content"`
	Passphrase  string            `json:"passphrase"`
	BaseVersion int64             `json:"base_version"`
	Mappings    map[string]string `json:"mappings"`
}
type Remote struct {
	URL         string    `json:"url"`
	APIKey      string    `json:"api_key"`
	Fingerprint string    `json:"fingerprint"`
	NodeID      string    `json:"node_id"`
	Selection   Selection `json:"selection"`
}
type PullInput struct {
	Remote      Remote            `json:"remote"`
	BaseVersion int64             `json:"base_version"`
	Mappings    map[string]string `json:"mappings"`
	Mode        string            `json:"mode"`
	EnableNginx bool              `json:"enable_nginx"`
}
type ExecuteInput struct {
	Mode        string `json:"mode"`
	EnableNginx bool   `json:"enable_nginx"`
}
type Step struct {
	Kind     string `json:"kind"`
	Resource string `json:"resource"`
	State    string `json:"state"`
	Message  string `json:"message"`
}
type Plan struct {
	Dependencies  *DependencyStatus `json:"dependencies,omitempty"`
	PackageSHA256 string            `json:"package_sha256"`
	ID            string            `json:"id"`
	SourceNode    string            `json:"source_node"`
	SourceVersion string            `json:"source_version"`
	BaseVersion   int64             `json:"base_version"`
	ExpiresAt     int64             `json:"expires_at"`
	State         string            `json:"state"`
	Steps         []Step            `json:"steps"`
	Omissions     []string          `json:"omissions"`
	CanSave       bool              `json:"can_save"`
	CanApply      bool              `json:"can_apply"`
	NginxEnabled  bool              `json:"nginx_enabled"`
	RevisionID    string            `json:"revision_id"`
	TaskID        string            `json:"task_id"`
	LastError     string            `json:"last_error"`
}
type storedPlan struct {
	Plan               Plan              `json:"plan"`
	Payload            Payload           `json:"payload"`
	Manifest           Manifest          `json:"manifest"`
	Mappings           map[string]string `json:"mappings"`
	CertificateIDs     map[string]string `json:"certificate_ids"`
	VersionIDs         map[string]string `json:"version_ids"`
	CredentialIDs      map[string]string `json:"credential_ids"`
	ModuleVersion      int64             `json:"module_version"`
	EnabledByMigration bool              `json:"enabled_by_migration"`
}
type Host interface {
	NginxFeatures(context.Context) (agent.NginxFeatures, error)
	NginxState(context.Context) (agent.NginxState, error)
}
type Service struct {
	Components      *components.Service
	Maintenance     *maintenance.Service
	DB              *sql.DB
	Vault           *secure.Vault
	Config          *nginxconfig.Service
	ACME            *acme.Service
	Notifications   *notifications.Service
	Agent           Host
	NodeID, Version string
	mu              sync.Mutex
	pushMu          sync.Mutex
}
