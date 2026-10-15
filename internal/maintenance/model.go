// Package maintenance coordinates configuration admission and durable drain.
package maintenance

import (
	"context"
	"database/sql"
	"sync"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type RootRequest struct {
	Protocol    int    `json:"protocol"`
	OperationID string `json:"operation_id"`
}
type RootStatus struct {
	Available bool   `json:"available"`
	ID        string `json:"id"`
	Phase     string `json:"phase"`
	Epoch     string `json:"epoch"`
	Busy      int    `json:"busy"`
	Reason    string `json:"reason"`
}
type Host interface {
	MaintenanceStatus(context.Context) (RootStatus, error)
	AcquireMaintenance(context.Context, RootRequest) (RootStatus, error)
	ReleaseMaintenance(context.Context, RootRequest) (RootStatus, error)
}
type StartInput struct {
	DrainSeconds int64 `json:"drain_seconds"`
}
type Session struct {
	TaskID        string `json:"task_id"`
	Phase         string `json:"phase"`
	Deadline      int64  `json:"deadline"`
	RootRequested bool   `json:"root_requested"`
	RootEpoch     string `json:"root_epoch"`
	Error         string `json:"error"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}
type View struct {
	Phase   string     `json:"phase"`
	Active  int        `json:"active"`
	Session *Session   `json:"session,omitempty"`
	Agent   RootStatus `json:"agent"`
	Reason  string     `json:"reason"`
}
type Service struct {
	DB      *sql.DB
	Vault   *secure.Vault
	Agent   Host
	control sync.Mutex
	mu      sync.Mutex
	phase   string
	active  int
	session *Session
	root    RootStatus
	reason  string
}

// Held serializes maintenance-owned admission with release and reconciliation.
// The caller must release this guard after committing its durable intent.
func (s *Service) Held(id string) (RootStatus, func(), error) {
	if s == nil {
		return RootStatus{}, nil, fault.Unavailable("维护服务未配置")
	}
	s.control.Lock()
	s.mu.Lock()
	r := s.root
	ok := s.phase == "held" && s.session != nil && s.session.TaskID == id && r.ID == id && r.Available && r.Phase == "held" && r.Busy == 0 && validID(r.Epoch) && r.Epoch == s.session.RootEpoch
	s.mu.Unlock()
	if !ok {
		s.control.Unlock()
		return r, nil, fault.Conflict("须等待原维护会话重新进入 held")
	}
	return r, s.control.Unlock, nil
}

// Admit precedes every ordinary mutation. It is acquired before subsystem locks.
func (s *Service) Admit() (func(), bool) {
	if s == nil {
		return func() {}, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "open" {
		return nil, false
	}
	s.active++
	var once sync.Once
	return func() { once.Do(func() { s.mu.Lock(); s.active--; s.mu.Unlock() }) }, true
}

// Progress permits previously accepted work to finish while draining.
func (s *Service) Progress() (func(), bool) {
	if s == nil {
		return func() {}, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "open" && s.phase != "draining" {
		return nil, false
	}
	s.active++
	var once sync.Once
	return func() { once.Do(func() { s.mu.Lock(); s.active--; s.mu.Unlock() }) }, true
}
func (s *Service) View() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := View{Phase: s.phase, Active: s.active, Agent: s.root, Reason: s.reason}
	if s.session != nil {
		copy := *s.session
		out.Session = &copy
	}
	return out
}
