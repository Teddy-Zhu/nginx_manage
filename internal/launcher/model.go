// Package launcher supervises only the root-approved persistent serve release.
package launcher

import (
	"path/filepath"
	"sync"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
)

const Protocol = releases.LauncherVersion

type Request struct {
	Protocol    int    `json:"protocol"`
	BootID      string `json:"boot_id"`
	OperationID string `json:"operation_id"`
	ReleaseID   string `json:"release_id"`
}
type Operation struct {
	Request Request `json:"request"`
	State   string  `json:"state"`
	Error   string  `json:"error"`
	Forced  bool    `json:"forced"`
}

func validOperation(op Operation) bool {
	r := op.Request
	if r.Protocol != Protocol || !idValue.MatchString(r.BootID) || !idValue.MatchString(r.OperationID) || !releaseValue.MatchString(r.ReleaseID) || len(op.Error) > 1024 {
		return false
	}
	switch op.State {
	case "queued", "validating", "stopping", "started":
		return op.Error == ""
	case "failed":
		return op.Error != ""
	default:
		return false
	}
}

type Status struct {
	Protocol  int        `json:"protocol"`
	BootID    string     `json:"boot_id"`
	State     string     `json:"state"`
	PID       int        `json:"pid"`
	ReleaseID string     `json:"release_id"`
	Version   string     `json:"version"`
	LastExit  int        `json:"last_exit"`
	Operation *Operation `json:"operation,omitempty"`
}
type supervisor struct {
	mu         sync.Mutex
	status     Status
	operations map[string]Operation
	queue      chan Request
	data       string
	deployment panelruntime.Deployment
}

func Socket(data string) string { return filepath.Join(data, "run", "launcher", "launcher.sock") }
func (s *supervisor) view() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}
func (s *supervisor) operation(req Request, state, message string, forced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op := Operation{Request: req, State: state, Error: message, Forced: forced}
	s.operations[req.OperationID] = op
	s.status.Operation = &op
}
