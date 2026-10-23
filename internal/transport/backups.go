package transport

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/backup"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) backupsReady(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get(remoteapi.HopHeader) != "" {
		s.fail(w, r, fault.Invalid("完整备份须直接连接本节点操作"))
		return false
	}
	if s.Backups == nil {
		s.fail(w, r, fault.Unavailable("备份服务未配置"))
		return false
	}
	return true
}
func (s *Server) ListBackups(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "backup.export")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	out, err := s.Backups.Overview(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateBackup(w http.ResponseWriter, r *http.Request, params apigen.CreateBackupParams) {
	p, ok := s.authorize(w, r, "backup.export", "backup.secrets", "system.write")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	var in backup.CreateInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Backups.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "备份任务已登记", out)
}
func (s *Server) GetBackup(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, "backup.export")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	out, err := s.Backups.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) DeleteBackup(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.DeleteBackupParams) {
	p, ok := s.authorize(w, r, "backup.export", "system.write")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	out, err := s.Backups.Delete(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetBackupPolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "backup.export")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	out, err := s.Backups.Policy(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) SetBackupPolicy(w http.ResponseWriter, r *http.Request, _ apigen.SetBackupPolicyParams) {
	p, ok := s.authorize(w, r, "backup.export", "backup.secrets", "system.write")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	var in backup.PolicyInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Backups.SetPolicy(r.Context(), p, r.Context().Value(requestIDKey).(string), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateBackupDownload(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.CreateBackupDownloadParams) {
	p, ok := s.authorize(w, r, "backup.export", "backup.secrets")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	out, err := s.Backups.Ticket(r.Context(), p, s.Auth.Sessions.Token(r.Context()), r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) DownloadBackup(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DownloadBackupParams) {
	p, ok := s.authorize(w, r, "backup.export", "backup.secrets")
	if !ok || !s.backupsReady(w, r) {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 256 || len(query) > 1 || len(query["ticket"]) > 1 || (len(query) == 1 && len(query["ticket"]) != 1) {
		s.fail(w, r, fault.Invalid("下载参数无效"))
		return
	}
	ticket := ""
	if params.Ticket != nil {
		ticket = *params.Ticket
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	f, record, closeAll, err := s.Backups.OpenDownload(ctx, p, s.Auth.Sessions.Token(r.Context()), ticket, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer closeAll()
	verify := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		live, err := s.Auth.Authenticate(r)
		if err != nil {
			return err
		}
		if live.ID != p.ID || live.Machine != p.Machine {
			return auth.ErrForbidden
		}
		if err = live.Require("backup.export", "backup.secrets"); err != nil {
			return err
		}
		if !live.Machine {
			alive, err := s.Auth.SessionAlive(ctx)
			if err != nil {
				return err
			}
			if !alive {
				return auth.ErrUnauthorized
			}
		}
		return nil
	}
	if err = verify(); err != nil {
		s.fail(w, r, err)
		return
	}
	if err = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+record.ID+`.tar.age"`)
	w.Header().Set("Content-Length", strconv.FormatInt(record.ArchiveSize, 10))
	w.Header().Set("ETag", `"`+record.ArchiveSHA256+`"`)
	w.Header().Set("X-Backup-SHA256", record.ArchiveSHA256)
	reader := &backupStreamReader{reader: f, verify: verify}
	if _, err = io.CopyBuffer(w, reader, make([]byte, 64<<10)); err != nil {
		slog.Warn("备份下载中断", "request_id", r.Context().Value(requestIDKey), "backup_id", id)
	}
}

type backupStreamReader struct {
	reader io.Reader
	verify func() error
	next   time.Time
}

func (r *backupStreamReader) Read(p []byte) (int, error) {
	if time.Now().After(r.next) {
		if err := r.verify(); err != nil {
			return 0, err
		}
		r.next = time.Now().Add(2 * time.Second)
	}
	return r.reader.Read(p)
}
