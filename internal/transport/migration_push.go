package transport

import (
	"net/http"

	"nginxpanel/internal/migration"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) GetMigrationReceiver(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	out, err := s.Migration.Receiver(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ReceiveMigration(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.ReceiveMigrationParams) {
	p, ok := s.authorize(w, r, true, "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.ImportInput
	if err := decodeLimit(w, r, &in, migration.MaxRequestBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.Receive(r.Context(), p, r.Context().Value(requestIDKey).(string), id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) StartMigrationPush(w http.ResponseWriter, r *http.Request, params apigen.StartMigrationPushParams) {
	p, ok := s.authorize(w, r, true, "backup.export", "backup.secrets", "config.secrets", "nodes.manage")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.PushInput
	if err := decodeLimit(w, r, &in, 2<<20); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.StartPush(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "迁出任务已受理", out)
}
func (s *Server) ResumeMigrationPush(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ResumeMigrationPushParams) {
	p, ok := s.authorize(w, r, true, "backup.export", "backup.secrets", "config.secrets", "nodes.manage")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	var in migration.PushResumeInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Migration.ResumePush(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原迁出任务已受理恢复", out)
}
func (s *Server) ListMigrationPushes(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "backup.export", "backup.secrets", "config.secrets", "nodes.manage")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	out, err := s.Migration.ListPushes(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetMigrationPush(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, false, "backup.export", "backup.secrets", "config.secrets", "nodes.manage")
	if !ok || !s.migrationReady(w, r) {
		return
	}
	out, err := s.Migration.GetPush(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
