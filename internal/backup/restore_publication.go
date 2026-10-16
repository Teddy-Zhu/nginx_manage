package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

type RestorePublication struct {
	RevisionID string   `json:"revision_id"`
	Database   Database `json:"database"`
	File       File     `json:"file"`
	CreatedAt  int64    `json:"created_at"`
}

func (p RestorePublication) validate(source Preparation) error {
	if !validID.MatchString(p.RevisionID) || p.RevisionID == source.OperationID || p.Database.NodeID != source.Database.NodeID || p.Database.SchemaVersion != source.Database.SchemaVersion || p.Database.AppliedRevision != "" || p.Database.DesiredRevision != p.RevisionID || p.Database.HeadVersion <= source.Database.HeadVersion || p.Database.HeadVersion > 1<<62 || p.File.Name != resources[0].name || p.File.Size < 1 || p.File.Size > DatabaseMax || !validHash.MatchString(p.File.SHA256) || p.CreatedAt < source.PreparedAt || p.CreatedAt > time.Now().Unix()+300 {
		return errors.New("恢复发布副本与原准备身份不一致")
	}
	return nil
}

func restorePublicationWork(data, id string) string {
	return filepath.Join(data, "staging", "restore-plans", id)
}

// CleanupRestorationWork removes only the fixed, unpublished helper workspace.
// Immutable root approval files and installed business data are never touched.
func CleanupRestorationWork(data, id string) error {
	if os.Geteuid() == 0 || !validID.MatchString(id) {
		return errors.New("恢复发布暂存清理须使用非 root 面板账户和计划标识")
	}
	if err := panelruntime.CheckInit(data); err != nil {
		return err
	}
	for _, parent := range []string{filepath.Join(data, "staging"), filepath.Join(data, "staging", "restore-plans")} {
		if err := privateDir(parent); err != nil {
			return err
		}
	}
	dir := restorePublicationWork(data, id)
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	items, err := boundedEntries(dir, 2)
	if err != nil {
		return err
	}
	for _, item := range items {
		limit := DatabaseMax
		if item.Name() == "panel.db-journal" {
			limit = preparationJournalMax
		} else if item.Name() != "panel.db" {
			return errors.New("恢复发布暂存包含未知文件")
		}
		f, _, e := openPrivate(filepath.Join(dir, item.Name()), limit)
		if e != nil {
			return e
		}
		f.Close()
	}
	for _, item := range items {
		if err = os.Remove(filepath.Join(dir, item.Name())); err != nil {
			return err
		}
	}
	if err = os.Remove(dir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dir))
}

func publishRestorationDatabase(ctx context.Context, data, planID string, p Preparation, source *os.File, vault *secure.Vault, policy nginxconfig.Policy, files []nginxconfig.File, pending []string) (out RestorePublication, err error) {
	if err = CleanupRestorationWork(data, planID); err != nil {
		return out, err
	}
	root := filepath.Dir(restorePublicationWork(data, planID))
	items, err := boundedEntries(root, AdoptionMax)
	if err != nil {
		return out, err
	}
	for _, item := range items {
		if !validID.MatchString(item.Name()) || !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
			return out, errors.New("恢复发布暂存存在未知资源")
		}
	}
	if len(items) >= AdoptionMax {
		return out, errors.New("恢复发布暂存达到保留上限")
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(root, &disk); err != nil {
		return out, err
	}
	reserve := 2*p.Files[0].Size + (128 << 20)
	if disk.Bsize <= 0 || disk.Bavail < uint64((reserve+int64(disk.Bsize)-1)/int64(disk.Bsize)) {
		return out, errors.New("恢复发布副本及事务日志的磁盘余量不足")
	}
	dir := restorePublicationWork(data, planID)
	if err = os.Mkdir(dir, 0700); err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, CleanupRestorationWork(data, planID))
		}
	}()
	path := filepath.Join(dir, "panel.db")
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	dst, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return out, err
	}
	n, copyErr := io.Copy(dst, contextReader{ctx, io.LimitReader(source, p.Files[0].Size+1)})
	err = errors.Join(copyErr, dst.Sync(), dst.Close())
	if err != nil {
		return out, err
	}
	if n != p.Files[0].Size {
		return out, errors.New("恢复发布源数据库大小变化")
	}
	initial, err := digestFile(ctx, path, DatabaseMax)
	if err != nil || initial.SHA256 != p.Files[0].SHA256 {
		return out, errors.Join(err, errors.New("恢复发布源数据库散列不一致"))
	}
	db, err := writableRestoreDatabase(ctx, path)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	if err = verifyPreparedDatabase(ctx, db, vault, p); err != nil {
		return out, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	at := time.Now().Unix()
	service := &nginxconfig.Service{Vault: vault, Policy: policy, Certificates: &certificates.Service{Vault: vault}}
	tree, err := service.SaveRestoredInTx(ctx, tx, p.OperationID, planID, p.Database.HeadVersion, at, files)
	if err != nil {
		return out, err
	}
	candidate, err := adoptionValueHash(tree.Files)
	if err != nil {
		return out, err
	}
	report, err := restorationPublicationReport(p, pending, tree.RevisionID, candidate)
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE restore_barriers SET report=? WHERE id=? AND state='prepared'", string(report), p.OperationID); err != nil {
		return out, err
	}
	if err = audit(ctx, tx, "restore:"+p.OperationID, planID, tree.RevisionID, "backup.restore.revision", "prepared"); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	out.Database, err = databaseMetadata(ctx, db)
	if err != nil {
		return out, err
	}
	if err = db.Close(); err != nil {
		return out, err
	}
	out.File, err = digestFile(ctx, path, DatabaseMax)
	if err != nil {
		return out, err
	}
	out.File.Name, out.RevisionID, out.CreatedAt = resources[0].name, tree.RevisionID, at
	if err = out.validate(p); err != nil {
		return out, err
	}
	err = syncDir(dir)
	return out, err
}

type RestorePublicationInput struct {
	Preparation Preparation       `json:"preparation"`
	Preview     RestorePreview    `json:"preview"`
	Mappings    map[string]string `json:"mappings"`
}

// VerifyRestorationPublication parses only a frozen root projection after the
// writable helper has exited. Its proof binds the new revision to the preview.
func VerifyRestorationPublication(ctx context.Context, data, id string, in RestorePublicationInput, files []*os.File) (MaterialVerification, error) {
	preview, p := in.Preview, in.Preparation
	if !preview.CanInstall || preview.Publication == nil {
		return MaterialVerification{}, errors.New("恢复发布缺少可安装计划")
	}
	hash, err := adoptionValueHash(preview.Policy)
	if err != nil || hash != preview.PolicySHA256 {
		return MaterialVerification{}, errors.New("恢复发布策略与原预览不一致")
	}
	return verifyRestorationDescriptors(ctx, data, id, p, files, preview.Publication, func(call context.Context, db *sql.DB, vault *secure.Vault) error {
		source, err := restoreRevisionFiles(call, db, vault, p.Database.DesiredRevision)
		if err != nil {
			return err
		}
		mapped, err := nginxconfig.RestorationFiles(source, preview.Policy, in.Mappings)
		if err != nil {
			return err
		}
		parsed, err := nginxconfig.Parse(mapped, preview.Policy)
		if err != nil {
			return err
		}
		hash, err := adoptionValueHash(parsed.Tree.Files)
		if err != nil || hash != preview.CandidateSHA256 || len(parsed.Tree.Diagnostics) != 0 {
			return errors.New("恢复发布配置与原映射预览不一致")
		}
		pub := *preview.Publication
		if err = verifyPublicationReferences(call, db, p, pub, parsed, preview.CandidateSHA256, preview.PendingChecks); err != nil {
			return err
		}
		publishedFiles, err := restoreRevisionFiles(call, db, vault, pub.RevisionID)
		if err != nil {
			return err
		}
		if !sameAdoptionValue(publishedFiles, parsed.Tree.Files) {
			return errors.New("恢复发布修订文件或版本不一致")
		}
		if err = verifyPublicationProjections(call, db, vault, pub.RevisionID, parsed.Tree.Resources); err != nil {
			return err
		}
		uses, err := parsed.CertificateUses()
		if err != nil {
			return err
		}
		paths := []string{}
		for _, use := range uses {
			paths = append(paths, use.Path)
		}
		materials, err := (&certificates.Service{Vault: vault}).Materials(call, db, paths)
		if err != nil {
			return err
		}
		hash, err = adoptionValueHash(materials)
		if err != nil || hash != preview.MaterialsSHA256 {
			return errors.New("恢复发布证书材料与原预览不一致")
		}
		if err = parsed.ValidateTLS(materials); err != nil {
			return err
		}
		return nil
	})
}

func verifyPublicationProjections(ctx context.Context, db *sql.DB, vault *secure.Vault, revision string, resources []nginxconfig.Resource) error {
	expected := map[string]nginxconfig.Resource{}
	for _, resource := range resources {
		expected[resource.ID] = resource
	}
	rows, err := db.QueryContext(ctx, "SELECT substr(resource_id,1,129),substr(file_id,1,129),substr(block_key,1,1025),substr(kind,1,33),CASE WHEN length(projection)<=8388672 THEN projection ELSE NULL END FROM nginx_resource_bindings WHERE revision_id=? LIMIT 513", revision)
	if err != nil {
		return err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var id, file, block, kind string
		var cipher []byte
		if err = rows.Scan(&id, &file, &block, &kind, &cipher); err != nil {
			return err
		}
		resource, ok := expected[id]
		if !ok || resource.FileID != file || resource.BlockKey != block || resource.Kind != kind {
			return errors.New("恢复发布资源投影身份不一致")
		}
		plain, err := vault.Open(cipher, "projection:"+revision+":"+id)
		if err != nil {
			return err
		}
		total += len(plain)
		if total > 32<<20 {
			return errors.New("恢复发布资源投影超过容量限制")
		}
		encoded, err := json.Marshal(resource)
		if err != nil {
			return err
		}
		if string(encoded) != string(plain) {
			return errors.New("恢复发布原文与资源投影不一致")
		}
		delete(expected, id)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(expected) != 0 {
		return errors.New("恢复发布缺少资源投影")
	}
	return nil
}

func verifyPublicationReferences(ctx context.Context, db *sql.DB, p Preparation, pub RestorePublication, parsed *nginxconfig.Parsed, candidate string, pending []string) error {
	var matches bool
	err := db.QueryRowContext(ctx, "SELECT COUNT(*)=1 FROM config_revisions WHERE id=? AND COALESCE(parent_id,'')=? AND version=? AND state='desired' AND parser_version=? AND policy_version=? AND diagnostics='[]' AND created_at=? AND created_by=?", pub.RevisionID, p.Database.DesiredRevision, pub.Database.HeadVersion, nginxconfig.ParserVersion, nginxconfig.PolicyVersion, pub.CreatedAt, "restore:"+p.OperationID).Scan(&matches)
	if err != nil {
		return err
	}
	if !matches {
		return errors.New("恢复发布修订来源不一致")
	}
	uses, err := parsed.CertificateUses()
	if err != nil {
		return err
	}
	var count int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM nginx_certificate_references WHERE revision_id=?", pub.RevisionID).Scan(&count); err != nil {
		return err
	}
	if count != len(uses) {
		return errors.New("恢复发布证书引用数量不一致")
	}
	for _, use := range uses {
		id, version, _, _ := certificates.Reference(use.Path)
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*)=1 FROM nginx_certificate_references WHERE revision_id=? AND file_id=? AND position=? AND resource_id=? AND certificate_id=? AND version_id=? AND purpose=?", pub.RevisionID, use.FileID, use.Position, use.ResourceID, id, version, use.Purpose).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return errors.New("恢复发布证书引用不一致")
		}
	}
	report, err := restorationPublicationReport(p, pending, pub.RevisionID, candidate)
	if err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*)=1 FROM restore_barriers WHERE id=? AND state='prepared' AND report=?", p.OperationID, string(report)).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return errors.New("恢复发布报告与原计划不一致")
	}
	return nil
}

func restorationPublicationReport(p Preparation, pending []string, revision, candidate string) ([]byte, error) {
	return json.Marshal(struct {
		Isolation     RestoreIsolation  `json:"isolation"`
		Disabled      []string          `json:"disabled_modules"`
		Pending       []string          `json:"pending_checks"`
		Configuration map[string]string `json:"configuration"`
	}{p.Isolation, p.DisabledModules, pending, map[string]string{"revision_id": revision, "sha256": candidate}})
}
