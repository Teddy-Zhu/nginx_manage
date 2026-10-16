package nginxconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/secure"
)

// SaveRestoredInTx adds a desired revision to an isolated database. It cannot
// enqueue an operation, mark a revision applied, or release the startup barrier.
func (s *Service) SaveRestoredInTx(ctx context.Context, tx *sql.Tx, restoreID, revisionID string, baseVersion, createdAt int64, files []File) (Tree, error) {
	if restoreID == "" || revisionID == "" || restoreID == revisionID || createdAt <= 0 || baseVersion < 0 || baseVersion >= 1<<62 {
		return Tree{}, errors.New("离线恢复修订身份无效")
	}
	var isolated bool
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)=1 FROM restore_barriers WHERE id=? AND state='prepared'", restoreID).Scan(&isolated); err != nil {
		return Tree{}, err
	}
	if !isolated {
		return Tree{}, errors.New("离线修订只能写入仍隔离的恢复数据库")
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)=1 FROM module_settings WHERE id='nginx-config' AND enabled=1").Scan(&isolated); err != nil {
		return Tree{}, err
	}
	if !isolated {
		return Tree{}, errors.New("恢复数据库的 Nginx 配置模块未启用")
	}
	p, err := Parse(files, s.Policy)
	if err != nil {
		return Tree{}, err
	}
	if len(p.Tree.Diagnostics) != 0 {
		return Tree{}, ErrInvalid
	}
	uses, err := s.validateCertificates(ctx, tx, p)
	if err != nil {
		return Tree{}, err
	}
	var version, highest int64
	var parent, applied sql.NullString
	if err = tx.QueryRowContext(ctx, "SELECT version,desired_revision,applied_revision FROM config_head WHERE id=1").Scan(&version, &parent, &applied); err != nil {
		return Tree{}, err
	}
	if version != baseVersion || applied.Valid {
		return Tree{}, ErrConflict
	}
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM config_revisions").Scan(&highest); err != nil {
		return Tree{}, err
	}
	if highest < 0 || highest >= 1<<62 {
		return Tree{}, errors.New("恢复修订版本超出范围")
	}
	next := max(version, highest) + 1
	if err = insertRevision(ctx, tx, s.Vault, s.Policy.Version, p, revisionID, parent, next, "desired", "restore:"+restoreID, createdAt, uses); err != nil {
		return Tree{}, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE config_head SET desired_revision=?,version=? WHERE id=1 AND version=? AND applied_revision IS NULL", revisionID, next, version)
	if err != nil {
		return Tree{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Tree{}, err
	}
	if count != 1 {
		return Tree{}, ErrConflict
	}
	return p.Tree, nil
}

func insertRevision(ctx context.Context, tx *sql.Tx, vault *secure.Vault, policy string, p *Parsed, id string, parent sql.NullString, version int64, state, principal string, createdAt int64, uses []CertificateUse) error {
	p.Tree.RevisionID, p.Tree.Version, p.Tree.State = id, version, state
	diagnostics, err := json.Marshal(p.Tree.Diagnostics)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO config_revisions(id,parent_id,version,state,parser_version,policy_version,diagnostics,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)", id, parent, version, state, ParserVersion, policy, string(diagnostics), createdAt, principal); err != nil {
		return err
	}
	for _, f := range p.Tree.Files {
		if _, err = tx.ExecContext(ctx, "INSERT INTO nginx_config_files(revision_id,id,path,content,sha256) VALUES(?,?,?,?,?)", id, f.ID, f.Path, vault.Seal([]byte(f.Content), "nginx:"+id+":"+f.ID), f.SHA256); err != nil {
			return err
		}
	}
	for _, use := range uses {
		certificateID, versionID, _, _ := certificates.Reference(use.Path)
		if _, err = tx.ExecContext(ctx, "INSERT INTO nginx_certificate_references(revision_id,file_id,position,resource_id,certificate_id,version_id,purpose) VALUES(?,?,?,?,?,?,?)", id, use.FileID, use.Position, use.ResourceID, certificateID, versionID, use.Purpose); err != nil {
			return err
		}
	}
	// Invalid drafts carry no effective projection and never move config_head.
	if len(p.Tree.Diagnostics) == 0 {
		for _, r := range p.Tree.Resources {
			encoded, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO nginx_resource_bindings(revision_id,resource_id,file_id,block_key,kind,projection) VALUES(?,?,?,?,?,?)", id, r.ID, r.FileID, r.BlockKey, r.Kind, vault.Seal(encoded, "projection:"+id+":"+r.ID)); err != nil {
				return err
			}
		}
	}
	return nil
}
