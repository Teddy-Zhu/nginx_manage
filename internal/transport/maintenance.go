package transport

import (
	"net/http"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) maintenanceAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
		parts := strings.Split(path, "/")
		release := len(parts) == 3 && parts[0] == "maintenance" && parts[2] == "release"
		installation := r.Method == http.MethodPost && len(parts) >= 2 && parts[0] == "components" && parts[1] == "installations" && (len(parts) == 2 || len(parts) == 4 && (parts[3] == "resume" || parts[3] == "cancel"))
		switchComponent := r.Method == http.MethodPost && len(parts) >= 2 && parts[0] == "components" && parts[1] == "switches" && (len(parts) == 2 || len(parts) == 4 && (parts[3] == "resume" || parts[3] == "rollback"))
		update := r.Method == http.MethodPost && parts[0] == "panel" && len(parts) >= 2 && parts[1] == "updates" && (len(parts) == 2 || len(parts) == 4 && parts[3] == "resume")
		agentUpgrade := r.Method == http.MethodPost && len(parts) >= 2 && parts[0] == "agent" && parts[1] == "upgrades" && (len(parts) == 2 || len(parts) == 4 && parts[3] == "resume")
		runtimeHistory := r.Method == http.MethodPost && (path == "history/runtime/preview" || path == "history/runtime/execute")
		backupCleanup := r.Method == http.MethodDelete && len(parts) == 2 && parts[0] == "backups"
		if path == "session" || path == "session/reauthenticate" || path == "bootstrap" || path == "maintenance" || release || installation || switchComponent || update || agentUpgrade || backupCleanup || runtimeHistory {
			next.ServeHTTP(w, r)
			return
		}
		if !pairingExchangeRequest(r) {
			if _, ok := s.authorize(w, r, false); !ok {
				return
			}
		}
		var done func()
		var ok bool
		// These callbacks can only decide existing operations and must remain
		// reachable while they drain. Domain services verify ownership and state.
		listenerDecision := r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "management" && parts[1] == "listener" && parts[2] == "operations" && (parts[4] == "confirm" || parts[4] == "rollback")
		firewallDecision := r.Method == http.MethodPost && len(parts) == 4 && parts[0] == "firewall" && parts[1] == "operations" && (parts[3] == "confirm" || parts[3] == "rollback")
		existingJailCancel := r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "fail2ban" && parts[1] == "existing" && parts[2] == "tasks" && parts[4] == "cancel"
		if listenerDecision || firewallDecision || existingJailCancel || r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "host" && parts[1] == "dns" && parts[2] == "tasks" && (parts[4] == "confirm" || parts[4] == "rollback") {
			done, ok = s.Maintenance.Progress()
		} else {
			done, ok = s.Maintenance.Admit()
		}
		if !ok {
			s.fail(w, r, fault.New(http.StatusConflict, "MAINTENANCE_ACTIVE", "维护期间暂停新的配置写入"))
			return
		}
		defer done()
		next.ServeHTTP(w, r)
	})
}
func (s *Server) maintenanceReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Maintenance == nil {
		s.fail(w, r, fault.Unavailable("维护服务未配置"))
		return false
	}
	return true
}
func (s *Server) GetMaintenance(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read", "system.write"); !ok || !s.maintenanceReady(w, r) {
		return
	}
	s.ok(w, r, s.Maintenance.View())
}
func (s *Server) EnterMaintenance(w http.ResponseWriter, r *http.Request, params apigen.EnterMaintenanceParams) {
	p, ok := s.authorize(w, r, true, "system.write")
	if !ok || !s.maintenanceReady(w, r) {
		return
	}
	var in maintenance.StartInput
	if err := decodeLimit(w, r, &in, 1024); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Maintenance.Start(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "维护请求已受理", out)
}
func (s *Server) ReleaseMaintenance(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.ReleaseMaintenanceParams) {
	p, ok := s.authorize(w, r, true, "system.write")
	if !ok || !s.maintenanceReady(w, r) {
		return
	}
	out, err := s.Maintenance.Release(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "恢复写入请求已受理", out)
}
