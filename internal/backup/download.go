package backup

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (s *Service) Ticket(ctx context.Context, p auth.Principal, session, trace, id string) (DownloadTicket, error) {
	if err := p.Require("backup.export", "backup.secrets"); err != nil {
		return DownloadTicket{}, err
	}
	if p.Machine || session == "" {
		return DownloadTicket{}, fault.Invalid("机器凭据须直接请求下载接口")
	}
	r, err := s.Get(ctx, p, id)
	if err != nil {
		return DownloadTicket{}, err
	}
	if !r.Available {
		return DownloadTicket{}, fault.Conflict("备份尚不可下载或已过期")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return DownloadTicket{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "DELETE FROM backup_downloads WHERE expires_at<=? OR used_at IS NOT NULL", now); err != nil {
		return DownloadTicket{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_downloads").Scan(&count); err != nil {
		return DownloadTicket{}, err
	}
	if count >= 64 {
		return DownloadTicket{}, fault.Conflict("下载凭据过多，请稍后重试")
	}
	token := secure.Token()
	expires := now + 60
	if _, err = tx.ExecContext(ctx, "INSERT INTO backup_downloads(token_hash,task_id,principal,session_hash,expires_at) VALUES(?,?,?,?,?)", secure.Hash([]byte(token)), id, p.ID, secure.Hash([]byte(session)), expires); err != nil {
		return DownloadTicket{}, err
	}
	if err = audit(ctx, tx, p.ID, trace, id, "backup.download.ticket", "issued"); err != nil {
		return DownloadTicket{}, err
	}
	if err = tx.Commit(); err != nil {
		return DownloadTicket{}, err
	}
	return DownloadTicket{URL: "/api/v1/backups/" + id + "/download?ticket=" + url.QueryEscape(token), ExpiresAt: expires}, nil
}

// OpenDownload holds the deletion guard and one of two streaming slots until
// the caller closes it. The artifact is checked before any HTTP bytes are sent.
func (s *Service) OpenDownload(ctx context.Context, p auth.Principal, session, ticket, trace, id string) (*os.File, Record, func(), error) {
	noop := func() {}
	if err := p.Require("backup.export", "backup.secrets"); err != nil {
		return nil, Record{}, noop, err
	}
	r, err := s.Get(ctx, p, id)
	if err != nil {
		return nil, r, noop, err
	}
	if !r.Available {
		return nil, r, noop, fault.Conflict("备份尚不可下载或已过期")
	}
	if p.Machine {
		if ticket != "" {
			return nil, r, noop, fault.Invalid("机器凭据不能混用下载票据")
		}
	} else if session == "" || len(ticket) != 43 {
		return nil, r, noop, auth.ErrForbidden
	}
	s.downloadMu.Lock()
	if s.downloads >= 2 {
		s.downloadMu.Unlock()
		return nil, r, noop, fault.Conflict("备份下载并发已满")
	}
	s.downloads++
	s.downloadMu.Unlock()
	lock := s.lock(id)
	lock.RLock()
	var f *os.File
	closeAll := func() {
		if f != nil {
			f.Close()
		}
		lock.RUnlock()
		s.downloadMu.Lock()
		s.downloads--
		s.downloadMu.Unlock()
	}
	r, err = s.Get(ctx, p, id)
	if err != nil || !r.Available {
		closeAll()
		if err == nil {
			err = fault.Conflict("备份正在清理或已过期")
		}
		return nil, r, noop, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		closeAll()
		return nil, r, noop, err
	}
	defer tx.Rollback()
	if !p.Machine {
		result, e := tx.ExecContext(ctx, "UPDATE backup_downloads SET used_at=? WHERE token_hash=? AND task_id=? AND principal=? AND session_hash=? AND expires_at>? AND used_at IS NULL", time.Now().Unix(), secure.Hash([]byte(ticket)), id, p.ID, secure.Hash([]byte(session)), time.Now().Unix())
		if e != nil {
			closeAll()
			return nil, r, noop, e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			closeAll()
			return nil, r, noop, auth.ErrForbidden
		}
	}
	if err = audit(ctx, tx, p.ID, trace, id, "backup.download", "accepted"); err != nil {
		closeAll()
		return nil, r, noop, err
	}
	if err = tx.Commit(); err != nil {
		closeAll()
		return nil, r, noop, err
	}
	f, info, err := openPrivate(s.archivePath(id), ArchiveMax)
	if err != nil {
		closeAll()
		return nil, r, noop, err
	}
	identity, err := digestOpenFile(ctx, f, info, ArchiveMax)
	if err != nil || identity.Size != r.ArchiveSize || identity.SHA256 != r.ArchiveSHA256 || info.Size() != r.ArchiveSize {
		closeAll()
		return nil, r, noop, errors.New("备份文件与原发布身份不一致")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		closeAll()
		return nil, r, noop, err
	}
	return f, r, closeAll, nil
}
