package backup

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
	"nginxpanel/migrations"
)

// InspectFile never installs a database, executes bundled code or changes a
// live node. Even a malformed SQLite file is opened only as an unprivileged user.
func InspectFile(ctx context.Context, path string, credentials InspectCredentials) (out Inspection, err error) {
	if os.Geteuid() == 0 {
		return out, errors.New("离线检查须由非 root 账户执行")
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return out, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > ArchiveMax {
		return out, errors.New("备份须为容量限制内的普通文件")
	}
	dir, err := os.MkdirTemp("", "nginxpanel-backup-")
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, removeWorkspace(dir)) }()
	hash := sha256.New()
	reader := &countReader{r: io.TeeReader(io.LimitReader(f, ArchiveMax+1), hash)}
	m, err := decryptArchive(call, reader, dir, credentials)
	if err != nil {
		return out, err
	}
	if reader.n != info.Size() || !secure.RootFileUnchanged(f, info) {
		return out, errors.New("备份输入未完整认证或读取期间发生变化")
	}
	out.Manifest = m
	out.ArchiveSHA256 = hex.EncodeToString(hash.Sum(nil))
	out.Issues = []string{}
	vault, err := secure.LoadKey(filepath.Join(dir, "master.key"))
	if err != nil {
		return out, err
	}
	probe, err := vault.Open(m.KeyCheck, "backup-key-check:"+m.ID)
	if err != nil || string(probe) != "nginxpanel-disaster:"+m.ID {
		return out, errors.New("备份业务密钥与清单不匹配")
	}
	if _, err = tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")); err != nil {
		return out, errors.New("备份入口 TLS 材料不匹配")
	}
	db, err := readDatabase(call, filepath.Join(dir, "panel.db"))
	if err != nil {
		return out, err
	}
	defer db.Close()
	meta, err := databaseMetadata(call, db)
	if err != nil {
		return out, err
	}
	if meta != m.Database {
		return out, errors.New("备份数据库与清单不一致")
	}
	latest, err := migrations.LatestVersion()
	if err != nil {
		return out, err
	}
	out.FormatCompatible = meta.SchemaVersion == latest && m.AgentProtocol == protocol.Agent && m.ParserVersion == nginxconfig.ParserVersion && m.PolicyVersion == nginxconfig.PolicyVersion
	if !out.FormatCompatible {
		out.Issues = append(out.Issues, "数据库、Agent 或解析器版本不同，须使用匹配版本离线处理")
		return out, nil
	}
	checked := map[string]bool{}
	for _, revision := range []string{meta.DesiredRevision, meta.AppliedRevision} {
		if revision != "" && !checked[revision] {
			if err = inspectRevision(call, db, vault, revision); err != nil {
				return out, err
			}
			checked[revision] = true
		}
	}
	if err = db.QueryRowContext(call, "SELECT COUNT(*) FROM tasks WHERE state NOT IN('succeeded','failed','rolled_back','cancelled')").Scan(&out.ActiveTasks); err != nil {
		return out, err
	}
	out.Issues = append(out.Issues, "检查仅确认包格式、材料与数据库一致性；目标宿主机依赖须另行预检")
	if out.ActiveTasks > 0 {
		out.Issues = append(out.Issues, "快照含在途任务和维护记录，恢复时必须隔离旧队列并逐项协调")
	}
	out.Issues = append(out.Issues, "迁至新节点须重建节点身份、会话、远程授权及通知准入，不能直接覆盖后启动")
	return out, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (r *countReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}
func inspectRevision(ctx context.Context, db *sql.DB, vault *secure.Vault, id string) error {
	rows, err := db.QueryContext(ctx, "SELECT substr(id,1,128),CASE WHEN length(content)<=262208 THEN content ELSE NULL END,substr(sha256,1,65) FROM nginx_config_files WHERE revision_id=? LIMIT 129", id)
	if err != nil {
		return err
	}
	count := 0
	total := 0
	for rows.Next() {
		count++
		var file, hash string
		var cipher []byte
		if err = rows.Scan(&file, &cipher, &hash); err != nil {
			break
		}
		if count > 128 || len(cipher) > (256<<10)+64 {
			err = errors.New("备份配置树超过容量限制")
			break
		}
		var plain []byte
		plain, err = vault.Open(cipher, "nginx:"+id+":"+file)
		if err != nil {
			break
		}
		total += len(plain)
		if total > 2<<20 || secure.Hash(plain) != hash {
			err = errors.New("备份配置树内容与散列不一致")
			break
		}
	}
	err = errors.Join(err, rows.Err())
	rows.Close()
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("备份配置修订缺少完整文件树")
	}
	rows, err = db.QueryContext(ctx, "SELECT substr(resource_id,1,128),CASE WHEN length(projection)<=8388672 THEN projection ELSE NULL END FROM nginx_resource_bindings WHERE revision_id=? LIMIT 513", id)
	if err != nil {
		return err
	}
	defer rows.Close()
	count = 0
	total = 0
	for rows.Next() {
		count++
		var resource string
		var cipher []byte
		if err = rows.Scan(&resource, &cipher); err != nil {
			return err
		}
		if count > 512 || len(cipher) > (8<<20)+64 {
			return errors.New("备份资源投影超过容量限制")
		}
		plain, err := vault.Open(cipher, "projection:"+id+":"+resource)
		if err != nil {
			return err
		}
		total += len(plain)
		if total > 32<<20 || !json.Valid(plain) {
			return errors.New("备份资源投影无效")
		}
	}
	return rows.Err()
}
