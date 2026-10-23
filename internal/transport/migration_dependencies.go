package transport

import (
	"net/http"

	"nginxpanel/internal/migration"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) PrepareMigrationDependencies(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.PrepareMigrationDependenciesParams) {
	p, ok := s.authorize(w, r, "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write", "components.manage")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.DependencyInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.PrepareDependencies(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
