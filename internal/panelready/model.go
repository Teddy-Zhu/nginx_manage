// Package panelready implements the local, read-only readiness contract used
// by an independent root update process. It never releases maintenance.
package panelready

import (
	"errors"
	"path/filepath"
	"regexp"
)

const Protocol = 1
const ResponseLimit = 16 << 10

var idValue = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digestValue = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Maintenance struct {
	ID        string `json:"id"`
	Phase     string `json:"phase"`
	RootID    string `json:"root_id"`
	RootPhase string `json:"root_phase"`
	Epoch     string `json:"epoch"`
	Busy      int    `json:"busy"`
	Active    int    `json:"active"`
}

type Configuration struct {
	DesiredRevision string `json:"desired_revision"`
	AppliedRevision string `json:"applied_revision"`
	HeadVersion     int64  `json:"head_version"`
	Available       bool   `json:"available"`
	RevisionID      string `json:"revision_id"`
	DeploymentID    string `json:"deployment_id"`
	Integrity       bool   `json:"integrity"`
	Running         bool   `json:"running"`
	ExternalChange  bool   `json:"external_change"`
}

type Status struct {
	Protocol       int           `json:"protocol"`
	PID            int           `json:"pid"`
	ReleaseID      string        `json:"release_id"`
	Version        string        `json:"version"`
	Mode           string        `json:"mode"`
	NodeID         string        `json:"node_id"`
	DatabaseSchema int64         `json:"database_schema"`
	Maintenance    Maintenance   `json:"maintenance"`
	Configuration  Configuration `json:"configuration"`
}

type Envelope struct {
	Code      string  `json:"code"`
	Message   string  `json:"message"`
	Data      *Status `json:"data"`
	RequestID string  `json:"request_id"`
	NodeID    string  `json:"node_id"`
}

func (s Status) Validate() error {
	m, c := s.Maintenance, s.Configuration
	if s.Protocol != Protocol || s.PID <= 1 || !digestValue.MatchString(s.ReleaseID) || s.Version == "" || len(s.Version) > 128 || s.Mode != "native" && s.Mode != "docker" || !idValue.MatchString(s.NodeID) || s.DatabaseSchema <= 0 || !idValue.MatchString(m.ID) || m.Phase != "held" || m.RootID != m.ID || m.RootPhase != "held" || !idValue.MatchString(m.Epoch) || m.Busy != 0 || m.Active != 0 || c.HeadVersion < 0 || c.DesiredRevision != "" && !idValue.MatchString(c.DesiredRevision) || c.AppliedRevision != "" && !idValue.MatchString(c.AppliedRevision) || c.RevisionID != "" && !idValue.MatchString(c.RevisionID) || c.DeploymentID != "" && !idValue.MatchString(c.DeploymentID) {
		return errors.New("面板就绪状态尚未确认")
	}
	return nil
}

func Socket(data string) string { return filepath.Join(data, "app", "readiness.sock") }
