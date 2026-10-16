package backup

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
	"nginxpanel/migrations"
)

func readDatabase(ctx context.Context, path string) (*sql.DB, error) {
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?mode=ro&_pragma=trusted_schema(OFF)&_pragma=query_only(ON)&_pragma=busy_timeout(5000)&_pragma=cache_size(-16384)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
func databaseMetadata(ctx context.Context, db *sql.DB) (Database, error) {
	var out Database
	var check string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&check); err != nil {
		return out, err
	}
	if check != "ok" {
		return out, errors.New("SQLite 快照完整性检查失败")
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return out, err
	}
	hasViolation := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if hasViolation {
		return out, errors.New("SQLite 快照存在断开的资源引用")
	}
	if err = db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_id),0) FROM goose_db_version WHERE is_applied=1").Scan(&out.SchemaVersion); err != nil {
		return out, err
	}
	if err = db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='node_id' AND typeof(value)='text' AND length(value)=36").Scan(&out.NodeID); err != nil {
		return out, err
	}
	if err = db.QueryRowContext(ctx, "SELECT COALESCE(desired_revision,''),COALESCE(applied_revision,''),version FROM config_head WHERE id=1 AND typeof(version)='integer' AND length(COALESCE(desired_revision,''))<=36 AND length(COALESCE(applied_revision,''))<=36").Scan(&out.DesiredRevision, &out.AppliedRevision, &out.HeadVersion); err != nil {
		return out, err
	}
	if !validID.MatchString(out.NodeID) || out.HeadVersion < 0 || out.DesiredRevision != "" && !validID.MatchString(out.DesiredRevision) || out.AppliedRevision != "" && !validID.MatchString(out.AppliedRevision) {
		return out, errors.New("快照的节点或配置身份无效")
	}
	return out, nil
}

// capture runs only under the coordinator's original held maintenance guard.
// Database and key files become a fixed, private workspace before release.
func (s *Service) capture(ctx context.Context, id string) (Manifest, error) {
	var m Manifest
	if os.Geteuid() == 0 {
		return m, errors.New("业务 SQLite 快照须由非 root 面板账户执行")
	}
	dir := s.workspace(id)
	if err := os.Mkdir(dir, 0700); err != nil {
		return m, err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	source, _, err := openPrivate(filepath.Join(s.DataDir, "app", "panel.db"), DatabaseMax)
	if err != nil {
		return m, err
	}
	source.Close()
	if _, err = s.DB.ExecContext(call, "VACUUM main INTO ?", filepath.Join(dir, "panel.db")); err != nil {
		return m, err
	}
	if err = os.Chmod(filepath.Join(dir, "panel.db"), 0600); err != nil {
		return m, err
	}
	db, err := readDatabase(call, filepath.Join(dir, "panel.db"))
	if err != nil {
		return m, err
	}
	meta, err := databaseMetadata(call, db)
	db.Close()
	if err != nil {
		return m, err
	}
	latest, err := migrations.LatestVersion()
	if err != nil {
		return m, err
	}
	if meta.SchemaVersion != latest || meta.NodeID != s.NodeID {
		return m, errors.New("快照的数据库版本或节点身份与运行实例不一致")
	}
	for _, r := range resources[1:] {
		if err = copyMaterial(call, filepath.Join(s.DataDir, r.source), filepath.Join(dir, r.local), r.limit); err != nil {
			return m, err
		}
	}
	vault, err := secure.LoadKey(filepath.Join(dir, "master.key"))
	if err != nil {
		return m, err
	}
	probe := s.Vault.Seal([]byte("nginxpanel-disaster:"+id), "backup-key-check:"+id)
	plain, err := vault.Open(probe, "backup-key-check:"+id)
	if err != nil || string(plain) != "nginxpanel-disaster:"+id {
		return m, errors.New("捕获的业务密钥与运行实例不匹配")
	}
	if _, err = tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")); err != nil {
		return m, errors.New("捕获的主入口 TLS 材料不匹配")
	}
	features, err := s.Agent.NginxFeatures(call)
	if err != nil {
		return m, err
	}
	m = Manifest{Schema: Schema, Mode: "full", ID: id, CreatedAt: time.Now().Unix(), ApplicationVersion: s.Version, ApplicationReleaseID: s.ReleaseID, Runtime: s.Runtime, AgentProtocol: protocol.Agent, ParserVersion: nginxconfig.ParserVersion, PolicyVersion: nginxconfig.PolicyVersion, Database: meta, Nginx: features, KeyCheck: probe, Files: []File{}}
	for _, r := range resources {
		file, e := digestFile(call, filepath.Join(dir, r.local), r.limit)
		if e != nil {
			return m, e
		}
		file.Name = r.name
		m.Files = append(m.Files, file)
	}
	f, _, err := openPrivate(filepath.Join(dir, "panel.db"), DatabaseMax)
	if err != nil {
		return m, err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return m, err
	}
	if err = writeManifest(filepath.Join(dir, "manifest.json"), m); err != nil {
		return m, err
	}
	if err = syncDir(dir); err != nil {
		return m, err
	}
	return m, syncDir(filepath.Dir(dir))
}
