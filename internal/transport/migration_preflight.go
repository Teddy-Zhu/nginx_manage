package transport

import (
	"net/http"

	"nginxpanel/internal/transport/apigen"
)

func (s *Server) PreflightMigration(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.PreflightMigrationParams) {
	p, ok := s.authorize(w, r, true, "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	out, err := s.Migration.Preflight(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
