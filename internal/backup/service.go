package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type scanner interface{ Scan(...any) error }
type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const recordColumns = "t.id,b.name,t.state,t.stage,t.last_error,b.encryption,b.recipient,b.policy_version,COALESCE(b.maintenance_id,''),b.archive_size,b.archive_sha256,b.captured_at,t.created_at,b.finished_at,b.expires_at,COALESCE(b.deleted_at,0),b.principal,b.issuer_machine,b.issuer_epoch,b.authorization_until,b.request_id,b.manifest,b.delete_started,b.archived_at"
const recordJoin = " FROM backup_records b JOIN tasks t ON t.id=b.task_id "

func (s *Service) read(row scanner) (Record, error) {
	var r Record
	var raw []byte
	err := row.Scan(&r.ID, &r.Name, &r.State, &r.Stage, &r.Error, &r.Encryption, &r.Recipient, &r.policyVersion, &r.MaintenanceID, &r.ArchiveSize, &r.ArchiveSHA256, &r.CapturedAt, &r.CreatedAt, &r.FinishedAt, &r.ExpiresAt, &r.DeletedAt, &r.principal, &r.machine, &r.epoch, &r.until, &r.requestID, &raw, &r.deleting, &r.ArchivedAt)
	if err != nil {
		return r, err
	}
	r.Scheduled = r.policyVersion != 0
	if len(raw) > 0 {
		plain, err := s.Vault.Open(raw, "backup-manifest:"+r.ID)
		if err != nil {
			return r, err
		}
		var m Manifest
		if decodeStrict(plain, &m) != nil || m.Validate() != nil || m.ID != r.ID {
			return r, errors.New("备份记录的清单身份无效")
		}
		r.manifest = &m
		r.Database = &m.Database
	}
	r.Available = r.State == "succeeded" && r.Stage == "ready" && r.ArchiveSize > 0 && r.DeletedAt == 0 && !r.deleting && r.ExpiresAt > time.Now().Unix()
	return r, nil
}
func (s *Service) get(ctx context.Context, id string) (Record, error) {
	return s.read(s.DB.QueryRowContext(ctx, "SELECT "+recordColumns+recordJoin+"WHERE t.id=?", id))
}
func canRead(p auth.Principal, r Record) error {
	if r.principal != p.ID && !p.Has("auth.manage") {
		return auth.ErrForbidden
	}
	return nil
}
func (s *Service) Get(ctx context.Context, p auth.Principal, id string) (Record, error) {
	if err := p.Require("backup.export"); err != nil {
		return Record{}, err
	}
	if !validID.MatchString(id) {
		return Record{}, fault.Invalid("备份编号无效")
	}
	r, err := s.get(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return r, fault.NotFound("备份记录不存在")
	}
	if err == nil {
		err = canRead(p, r)
	}
	return r, err
}
func (s *Service) List(ctx context.Context, p auth.Principal) ([]Record, error) {
	if err := p.Require("backup.export"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+recordColumns+recordJoin+"WHERE b.principal=? OR ? ORDER BY t.created_at DESC,t.id DESC LIMIT 128", p.ID, p.Has("auth.manage"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		r, err := s.read(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Service) Overview(ctx context.Context, p auth.Principal) (Overview, error) {
	var out Overview
	var err error
	out.ArchiveMax = ArchiveMax
	out.StoreMax = StoreMax
	if out.Records, err = s.List(ctx, p); err != nil {
		return out, err
	}
	out.Policy, err = s.Policy(ctx, p)
	return out, err
}
func audit(ctx context.Context, tx *sql.Tx, actor, trace, id, action, outcome string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", secure.ID(), trace, actor, action, id, outcome, time.Now().Unix())
	return err
}
func checkIssuer(ctx context.Context, q queryer, id string, machine bool, epoch, until int64) (auth.Principal, error) {
	p := auth.Principal{ID: id, Machine: machine, Scopes: auth.AllScopes}
	if machine {
		var raw string
		var expires int64
		if err := q.QueryRowContext(ctx, "SELECT scopes,expires_at FROM api_credentials WHERE id=? AND revoked_at IS NULL AND expires_at>?", id, time.Now().Unix()).Scan(&raw, &expires); err != nil {
			return p, err
		}
		if err := json.Unmarshal([]byte(raw), &p.Scopes); err != nil {
			return p, err
		}
		if expires < until {
			return p, auth.ErrForbidden
		}
	} else {
		var live int64
		if err := q.QueryRowContext(ctx, "SELECT session_epoch FROM users WHERE id=1").Scan(&live); err != nil {
			return p, err
		}
		if live != epoch {
			return p, auth.ErrForbidden
		}
		p.SessionEpoch = epoch
	}
	if err := p.Require("backup.export", "backup.secrets", "system.write"); err != nil {
		return p, err
	}
	return p, nil
}
func (s *Service) Create(ctx context.Context, p auth.Principal, trace, key string, in CreateInput) (Record, error) {
	if err := p.Require("backup.export", "backup.secrets", "system.write"); err != nil {
		return Record{}, err
	}
	if err := in.Validate(); err != nil {
		return Record{}, err
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return Record{}, fault.Invalid("需要 1–128 字节幂等键")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(in)
	if err != nil {
		return Record{}, err
	}
	digest := s.Vault.Digest(raw, "backup.create:"+p.ID)
	var id, prior string
	err = s.DB.QueryRowContext(ctx, "SELECT task_id,request_hash FROM backup_requests WHERE principal=? AND key=?", p.ID, key).Scan(&id, &prior)
	if err == nil {
		if prior != digest {
			return Record{}, fault.Conflict("同一幂等键不能用于不同备份请求")
		}
		return s.get(ctx, id)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Record{}, err
	}
	view := s.Maintenance.View()
	if !view.Agent.Available || view.Phase != "open" {
		return Record{}, fault.Conflict("备份须等待宿主机维护准入就绪")
	}
	policy, err := s.policy(ctx)
	if err != nil {
		return Record{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	until := time.Now().Add(10 * time.Minute).Unix()
	if p.Machine {
		var expires int64
		if err = tx.QueryRowContext(ctx, "SELECT expires_at FROM api_credentials WHERE id=? AND revoked_at IS NULL", p.ID).Scan(&expires); err != nil {
			return Record{}, err
		}
		until = min(until, expires)
	}
	if until <= time.Now().Unix() {
		return Record{}, auth.ErrForbidden
	}
	if _, err = checkIssuer(ctx, tx, p.ID, p.Machine, p.SessionEpoch, until); err != nil {
		return Record{}, fault.Conflict("备份授权不足或即将到期")
	}
	id = secure.ID()
	if err = s.insert(ctx, tx, id, p.ID, p.Machine, p.SessionEpoch, trace, in.Name, in.Encryption, in.Recipient, until, 0, policy.RetentionDays); err != nil {
		return Record{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO backup_requests(principal,key,request_hash,task_id) VALUES(?,?,?,?)", p.ID, key, digest, id); err != nil {
		return Record{}, err
	}
	if err = tx.Commit(); err != nil {
		return Record{}, err
	}
	if in.Encryption == "passphrase" {
		if s.passwords == nil {
			s.passwords = map[string]string{}
		}
		s.passwords[id] = in.Passphrase
	}
	return s.get(ctx, id)
}
func (s *Service) insert(ctx context.Context, tx *sql.Tx, id, actor string, machine bool, epoch int64, trace, name, encryption, recipient string, until, policyVersion, retentionDays int64) error {
	var count, active int
	if err := tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM backup_records WHERE archived_at=0),(SELECT COUNT(*) FROM tasks WHERE kind='backup.create' AND state NOT IN('succeeded','failed','rolled_back','cancelled'))").Scan(&count, &active); err != nil {
		return err
	}
	if active != 0 {
		return fault.Conflict("已有备份正在处理")
	}
	if count >= MaxRecords {
		if err := s.archiveHistoryAtCapacity(ctx, tx, actor, trace); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_records WHERE archived_at=0").Scan(&count); err != nil {
			return err
		}
	}
	if count >= MaxRecords {
		return fault.Conflict("备份历史达到 512 项上限，请先清理旧备份文件或恢复未结束的维护任务")
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'backup.create',?,'queued','queued',?,?,?)", id, id, id, now, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO backup_records(task_id,principal,issuer_machine,issuer_epoch,name,encryption,recipient,authorization_until,policy_version,request_id,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", id, actor, machine, epoch, name, encryption, recipient, until, policyVersion, trace, now+retentionDays*86400); err != nil {
		return err
	}
	return audit(ctx, tx, actor, trace, id, "backup.create", "queued")
}
