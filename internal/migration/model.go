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
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/monitoring"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxinstall"
	"nginxpanel/internal/notifications"
	"nginxpanel/internal/secure"
)

const (
	Schema          = 6
	MaxPackageBytes = 8 << 20
	MaxRequestBytes = 12 << 20
)

type Selection struct {
	HostDNS        bool `json:"host_dns"`
	Monitoring     bool `json:"monitoring"`
	Fail2ban       bool `json:"fail2ban"`
	Firewall       bool `json:"firewall"`
	Certificates   bool `json:"certificates"`
	DNSCredentials bool `json:"dns_credentials"`
	Automation     bool `json:"automation"`
	Notifications  bool `json:"notifications"`
}
type ExportInput struct {
	Mode       string    `json:"mode"`
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
	Mode          string            `json:"mode"`
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
	HostDNS      *hostdns.Transfer               `json:"host_dns"`
	Monitoring   *monitoring.Settings            `json:"monitoring"`
	Fail2ban     *fail2ban.Transfer              `json:"fail2ban"`
	Firewall     *firewall.Transfer              `json:"firewall"`
	Files        []nginxconfig.File              `json:"files"`
	Certificates []Certificate                   `json:"certificates"`
	Credentials  []Credential                    `json:"credentials"`
	Automation   acme.TransferAutomation         `json:"automation"`
	Channels     []notifications.TransferChannel `json:"channels"`
}
type ImportInput struct {
	HostDNS     HostDNSInput      `json:"host_dns"`
	Monitoring  MonitoringInput   `json:"monitoring"`
	Fail2ban    Fail2banInput     `json:"fail2ban"`
	Firewall    FirewallInput     `json:"firewall"`
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
	Dependencies *DependencyInput  `json:"dependencies,omitempty"`
	HostDNS      HostDNSInput      `json:"host_dns"`
	Monitoring   MonitoringInput   `json:"monitoring"`
	Fail2ban     Fail2banInput     `json:"fail2ban"`
	Firewall     FirewallInput     `json:"firewall"`
	Remote       Remote            `json:"remote"`
	BaseVersion  int64             `json:"base_version"`
	Mappings     map[string]string `json:"mappings"`
	Mode         string            `json:"mode"`
	EnableNginx  bool              `json:"enable_nginx"`
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
	PrunedAt      int64             `json:"pruned_at"`
	Pull          *PullStatus       `json:"pull,omitempty"`
	Mode          string            `json:"mode"`
	HostDNS       *HostDNSPlan      `json:"host_dns,omitempty"`
	Monitoring    *MonitoringPlan   `json:"monitoring,omitempty"`
	Fail2ban      *Fail2banPlan     `json:"fail2ban,omitempty"`
	Firewall      *FirewallPlan     `json:"firewall,omitempty"`
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
	HostDNS            HostDNSInput           `json:"host_dns"`
	Monitoring         *monitoringImportState `json:"monitoring,omitempty"`
	Fail2ban           *fail2banImportState   `json:"fail2ban,omitempty"`
	Firewall           *firewallImportState   `json:"firewall,omitempty"`
	Plan               Plan                   `json:"plan"`
	Payload            Payload                `json:"payload"`
	Manifest           Manifest               `json:"manifest"`
	Mappings           map[string]string      `json:"mappings"`
	CertificateIDs     map[string]string      `json:"certificate_ids"`
	VersionIDs         map[string]string      `json:"version_ids"`
	CredentialIDs      map[string]string      `json:"credential_ids"`
	ModuleVersion      int64                  `json:"module_version"`
	EnabledByMigration bool                   `json:"enabled_by_migration"`
}
type Host interface {
	NginxFeatures(context.Context) (agent.NginxFeatures, error)
	NginxState(context.Context) (agent.NginxState, error)
}
type Service struct {
	HostDNS         *hostdns.Service
	Monitoring      *monitoring.Service
	Fail2ban        *fail2ban.PolicyService
	Firewall        *firewall.Service
	Components      *components.Service
	Installations   *nginxinstall.Service
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
