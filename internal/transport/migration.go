package transport

import (
	"net/http"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/migration"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) migrationReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Migration == nil {
		s.fail(w, r, fault.Unavailable("迁移服务未配置"))
		return false
	}
	return true
}
func (s *Server) ExportMigration(w http.ResponseWriter, r *http.Request, _ apigen.ExportMigrationParams) {
	p, ok := s.authorize(w, r, true, "backup.export")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.ExportInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.Export(r.Context(), p, r.Context().Value(requestIDKey).(string), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) PrepareMigration(w http.ResponseWriter, r *http.Request, _ apigen.PrepareMigrationParams) {
	p, ok := s.authorize(w, r, true, "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.ImportInput
	if err := decodeLimit(w, r, &in, migration.MaxRequestBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.Prepare(r.Context(), p, r.Context().Value(requestIDKey).(string), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ExecuteMigration(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ExecuteMigrationParams) {
	p, ok := s.authorize(w, r, true, "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.ExecuteInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.Execute(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) PullMigration(w http.ResponseWriter, r *http.Request, params apigen.PullMigrationParams) {
	p, ok := s.authorize(w, r, true, "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write", "nodes.manage")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.PullInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.Pull(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ListMigrations(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "backup.restore", "backup.secrets")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	out, err := s.Migration.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetMigration(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, false, "backup.restore", "backup.secrets")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	out, err := s.Migration.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
