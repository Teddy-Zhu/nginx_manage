// Package backup manages offline-key disaster archives. Local root maintenance
// snapshots and portable configuration migration have separate formats/keys.
package backup

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/secure"
)

const Schema = 1
const DatabaseMax = int64(512 << 20)
const ArchiveMax = DatabaseMax + (2 << 20)
const StoreMax = int64(2 << 30)
const MaxRecords = 512
const MaxArchives = 16
const WorkspaceLifetime = int64(15 * 60)

var validID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var validHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Host interface {
	NginxFeatures(context.Context) (agent.NginxFeatures, error)
}
type Service struct {
	DB                                           *sql.DB
	Vault                                        *secure.Vault
	Maintenance                                  *maintenance.Service
	Agent                                        Host
	DataDir, NodeID, Version, Runtime, ReleaseID string
	mu                                           sync.Mutex
	passwords                                    map[string]string
	fileLocks                                    sync.Map
	downloadMu                                   sync.Mutex
	downloads                                    int
}
type CreateInput struct {
	Name       string `json:"name"`
	Encryption string `json:"encryption"`
	Recipient  string `json:"recipient"`
	Passphrase string `json:"passphrase"`
}

func (in CreateInput) Validate() error {
	if strings.TrimSpace(in.Name) != in.Name || !utf8.ValidString(in.Name) || len(in.Name) < 1 || len(in.Name) > 100 || strings.ContainsAny(in.Name, "\x00\r\n") {
		return fault.Invalid("备份名称须为 1–100 字节")
	}
	switch in.Encryption {
	case "recipient":
		if in.Passphrase != "" {
			return fault.Invalid("接收方加密不能同时提供口令")
		}
		return recipientValid(in.Recipient)
	case "passphrase":
		if in.Recipient != "" || !passphraseValid(in.Passphrase) {
			return fault.Invalid("备份口令须为 16–256 字节，不能同时提供接收方")
		}
		return nil
	default:
		return fault.Invalid("加密方式须为 recipient 或 passphrase")
	}
}
func recipientValid(value string) error {
	r, err := age.ParseX25519Recipient(value)
	if err != nil || r.String() != value {
		return fault.Invalid("恢复接收方须为规范的 age X25519 公钥")
	}
	return nil
}
func passphraseValid(value string) bool {
	return len(value) >= 16 && len(value) <= 256 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

type Policy struct {
	Version            int64  `json:"version"`
	Enabled            bool   `json:"enabled"`
	Recipient          string `json:"recipient"`
	KeySavedAt         int64  `json:"key_saved_at"`
	IntervalHours      int64  `json:"interval_hours"`
	KeepCount          int    `json:"keep_count"`
	RetentionDays      int64  `json:"retention_days"`
	AuthorizationUntil int64  `json:"authorization_until"`
	NextRunAt          int64  `json:"next_run_at"`
	Error              string `json:"error"`
	UpdatedAt          int64  `json:"updated_at"`
	principal          string
	machine            bool
	epoch              int64
}
type PolicyInput struct {
	BaseVersion        int64  `json:"base_version"`
	Enabled            bool   `json:"enabled"`
	Recipient          string `json:"recipient"`
	KeySaved           bool   `json:"key_saved"`
	IntervalHours      int64  `json:"interval_hours"`
	KeepCount          int    `json:"keep_count"`
	RetentionDays      int64  `json:"retention_days"`
	AuthorizationUntil int64  `json:"authorization_until"`
}

func (in PolicyInput) Validate() error {
	if in.BaseVersion < 1 || in.IntervalHours < 1 || in.IntervalHours > 168 || in.KeepCount < 1 || in.KeepCount >= MaxArchives || in.RetentionDays < 1 || in.RetentionDays > 90 {
		return fault.Invalid("备份周期须为 1–168 小时，保留 1–15 份、1–90 天")
	}
	if in.Enabled || in.Recipient != "" {
		if err := recipientValid(in.Recipient); err != nil {
			return err
		}
		if !in.KeySaved {
			return fault.Invalid("须确认恢复私钥已离线保存")
		}
	}
	if in.Enabled && (in.AuthorizationUntil <= time.Now().Unix() || in.AuthorizationUntil > time.Now().Add(366*24*time.Hour).Unix()) {
		return fault.Invalid("定期备份授权须在未来 366 天内到期")
	}
	return nil
}

type Database struct {
	SchemaVersion   int64  `json:"schema_version"`
	NodeID          string `json:"node_id"`
	DesiredRevision string `json:"desired_revision"`
	AppliedRevision string `json:"applied_revision"`
	HeadVersion     int64  `json:"head_version"`
}
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema               int                 `json:"schema"`
	Mode                 string              `json:"mode"`
	ID                   string              `json:"id"`
	CreatedAt            int64               `json:"created_at"`
	ApplicationVersion   string              `json:"application_version"`
	ApplicationReleaseID string              `json:"application_release_id"`
	Runtime              string              `json:"runtime"`
	AgentProtocol        int                 `json:"agent_protocol"`
	ParserVersion        string              `json:"parser_version"`
	PolicyVersion        string              `json:"policy_version"`
	Database             Database            `json:"database"`
	Nginx                agent.NginxFeatures `json:"nginx"`
	Files                []File              `json:"files"`
	KeyCheck             []byte              `json:"key_check"`
}
type Record struct {
	ID                          string    `json:"id"`
	Name                        string    `json:"name"`
	State                       string    `json:"state"`
	Stage                       string    `json:"stage"`
	Error                       string    `json:"error"`
	Encryption                  string    `json:"encryption"`
	Recipient                   string    `json:"recipient"`
	Scheduled                   bool      `json:"scheduled"`
	MaintenanceID               string    `json:"maintenance_id"`
	ArchiveSize                 int64     `json:"archive_size"`
	ArchiveSHA256               string    `json:"archive_sha256"`
	CapturedAt                  int64     `json:"captured_at"`
	CreatedAt                   int64     `json:"created_at"`
	FinishedAt                  int64     `json:"finished_at"`
	ExpiresAt                   int64     `json:"expires_at"`
	DeletedAt                   int64     `json:"deleted_at"`
	Available                   bool      `json:"available"`
	Database                    *Database `json:"database"`
	principal                   string
	machine                     bool
	epoch, until, policyVersion int64
	requestID                   string
	manifest                    *Manifest
	deleting                    bool
}
type Overview struct {
	Policy     Policy   `json:"policy"`
	Records    []Record `json:"records"`
	ArchiveMax int64    `json:"archive_max"`
	StoreMax   int64    `json:"store_max"`
}
type DownloadTicket struct {
	URL       string `json:"url"`
	ExpiresAt int64  `json:"expires_at"`
}
type InspectCredentials struct {
	Passphrase string `json:"passphrase"`
	Identity   string `json:"identity"`
}
type Inspection struct {
	Manifest         Manifest `json:"manifest"`
	ArchiveSHA256    string   `json:"archive_sha256"`
	FormatCompatible bool     `json:"format_compatible"`
	Issues           []string `json:"issues"`
	ActiveTasks      int64    `json:"active_tasks"`
}
