package migration

import "regexp"

const maxPushes = 64
const pushGrantSeconds = 3600
const maxPushSummaryBytes = 262144 + 8192

type Receiver struct {
	Schema  int      `json:"schema"`
	NodeID  string   `json:"node_id"`
	Version int64    `json:"version"`
	Scopes  []string `json:"scopes"`
}
type PushInput struct {
	Dependencies *DependencyInput  `json:"dependencies,omitempty"`
	Remote       Remote            `json:"remote"`
	BaseVersion  *int64            `json:"base_version,omitempty"`
	Mappings     map[string]string `json:"mappings"`
	Mode         string            `json:"mode"`
	EnableNginx  bool              `json:"enable_nginx"`
}
type PushResumeInput struct {
	APIKey string `json:"api_key"`
}
type PushTask struct {
	ID                string `json:"id"`
	State             string `json:"state"`
	Stage             string `json:"stage"`
	Mode              string `json:"mode"`
	TargetURL         string `json:"target_url"`
	TargetNode        string `json:"target_node"`
	TargetBound       bool   `json:"target_bound"`
	TargetBaseVersion int64  `json:"target_base_version"`
	PackageSHA256     string `json:"package_sha256"`
	Plan              *Plan  `json:"plan,omitempty"`
	Error             string `json:"error"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
	ExpiresAt         int64  `json:"expires_at"`
}
type pushPayload struct {
	Input       PushInput   `json:"input"`
	Transfer    ImportInput `json:"transfer"`
	ResumeStage string      `json:"resume_stage"`
}
type receiveReservation struct{ ID, Digest, PackageSHA256 string }

var transferID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validTransferID(id string) bool { return transferID.MatchString(id) }
func pushTerminal(state string) bool {
	return state == "succeeded" || state == "failed" || state == "rolled_back" || state == "cancelled"
}
