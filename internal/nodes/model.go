package nodes

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"sync"
	"sync/atomic"

	"nginxpanel/internal/secure"
)

const RemoteHopHeader = "X-Nginxpanel-Remote-Hop"
const TargetNodeHeader = "X-Nginxpanel-Target-Node"

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var pin = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Service struct {
	DB     *sql.DB
	Vault  *secure.Vault
	NodeID string
	locks  sync.Map
	active atomic.Int32
}

type CreateInput struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	APIKey      string `json:"api_key"`
	Fingerprint string `json:"fingerprint"`
}

type Identity struct {
	NodeID         string   `json:"node_id"`
	CredentialID   string   `json:"credential_id"`
	Scopes         []string `json:"scopes"`
	ExpiresAt      int64    `json:"expires_at"`
	APIVersion     int      `json:"api_version"`
	DatabaseSchema int64    `json:"database_schema"`
	AgentProtocol  int      `json:"agent_protocol"`
	ParserVersion  string   `json:"parser_version"`
	PolicyVersion  string   `json:"policy_version"`
}

type Connection struct {
	ID           string          `json:"id"`
	NodeID       string          `json:"node_id"`
	Name         string          `json:"name"`
	URL          string          `json:"url"`
	Fingerprint  string          `json:"fingerprint"`
	CredentialID string          `json:"credential_id"`
	Scopes       []string        `json:"scopes"`
	ExpiresAt    int64           `json:"expires_at"`
	APIVersion   int             `json:"api_version"`
	Capabilities json.RawMessage `json:"capabilities"`
	State        string          `json:"state"`
	Error        string          `json:"error"`
	CheckedAt    int64           `json:"checked_at"`
	CreatedAt    int64           `json:"created_at"`
	UpdatedAt    int64           `json:"updated_at"`
	RemovedAt    int64           `json:"removed_at"`
	Revocation   string          `json:"revocation"`
	Version      int64           `json:"version"`
	token        []byte
}
