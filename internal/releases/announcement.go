package releases

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrReceiverIncompatible = errors.New("接收端不满足发行要求")

type Requirements struct {
	APIMajor             int    `json:"api_major"`
	DatabaseSchema       int64  `json:"database_schema"`
	MinimumAgentProtocol int    `json:"minimum_agent_protocol"`
	MinimumLauncher      int    `json:"minimum_launcher"`
	FrontendVersion      string `json:"frontend_version"`
	AutomaticRollback    bool   `json:"automatic_rollback"`
}

// Announcement is authenticated metadata, never an authorization to prepare.
// It deliberately carries no plan ID, assets or private Verified seal.
type Announcement struct {
	Repository         string       `json:"repository"`
	Version            string       `json:"version"`
	Tag                string       `json:"tag"`
	Channel            string       `json:"channel"`
	KeyID              string       `json:"key_id"`
	ManifestSHA256     string       `json:"manifest_sha256"`
	TrustSHA256        string       `json:"trust_sha256"`
	ExpiresAt          int64        `json:"expires_at"`
	Notes              string       `json:"notes"`
	Requirements       Requirements `json:"requirements"`
	Receiver           Receiver     `json:"receiver"`
	ReceiverCompatible bool         `json:"receiver_compatible"`
	Incompatibilities  []string     `json:"incompatibilities"`
}

func ManifestRequirements(m Manifest) Requirements {
	return Requirements{APIMajor: m.APIMajor, DatabaseSchema: m.DatabaseSchema, MinimumAgentProtocol: m.MinimumAgentProtocol, MinimumLauncher: m.MinimumLauncher, FrontendVersion: m.FrontendVersion, AutomaticRollback: m.AutomaticRollback}
}

func ValidNotes(notes string) bool {
	if len(notes) > MaxNotesBytes || !utf8.ValidString(notes) {
		return false
	}
	for _, r := range notes {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	// Component receipts have a fixed budget; HTML escaping can expand text.
	raw, err := json.Marshal(notes)
	return err == nil && len(raw) <= MaxNotesJSONBytes
}

func (r Requirements) Validate() error {
	if r.APIMajor < 1 || r.DatabaseSchema < 1 || r.MinimumAgentProtocol < 1 || r.MinimumLauncher < 1 || !validVersion(r.FrontendVersion) {
		return errors.New("发行要求无效")
	}
	return nil
}

func (r Requirements) Incompatibilities(current Receiver) []string {
	issues := []string{}
	if r.APIMajor != current.APIMajor {
		issues = append(issues, fmt.Sprintf("API 主版本要求 %d，当前为 %d", r.APIMajor, current.APIMajor))
	}
	if r.MinimumAgentProtocol > current.AgentProtocol {
		issues = append(issues, fmt.Sprintf("Agent 协议至少为 %d，当前为 %d", r.MinimumAgentProtocol, current.AgentProtocol))
	}
	if r.MinimumLauncher > current.Launcher {
		issues = append(issues, fmt.Sprintf("launcher 至少为 %d，当前为 %d", r.MinimumLauncher, current.Launcher))
	}
	return issues
}

func (a Announcement) Validate() error {
	issues := a.Requirements.Incompatibilities(a.Receiver)
	if !repository.MatchString(a.Repository) || !validVersion(a.Version) || (a.Tag != "v"+a.Version && a.Tag != "nginx-v"+a.Version) || !identifier.MatchString(a.KeyID) || !validHash(a.ManifestSHA256) || !validHash(a.TrustSHA256) || a.ExpiresAt <= 0 || !ValidNotes(a.Notes) || a.Requirements.Validate() != nil || a.Receiver.APIMajor < 1 || a.Receiver.AgentProtocol < 1 || a.Receiver.Launcher < 1 || a.ReceiverCompatible != (len(issues) == 0) || !slices.Equal(a.Incompatibilities, issues) || !ValidChannel(a.Version, a.Channel) {
		return errors.New("已验签发行说明无效")
	}
	return nil
}

type receiverCompatibilityError struct{ announcement Announcement }

func (e *receiverCompatibilityError) Error() string {
	return ErrReceiverIncompatible.Error() + "：" + strings.Join(e.announcement.Incompatibilities, "；")
}
func (e *receiverCompatibilityError) Unwrap() error { return ErrReceiverIncompatible }
