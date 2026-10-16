package backup

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

func preparationRoot(data string) string    { return filepath.Join(data, "staging", "restore") }
func preparationDir(data, id string) string { return filepath.Join(preparationRoot(data), id) }

// PrepareWithFile produces private, startup-fenced material only. It never replaces
// live files, changes a root grant or executes an installation action.
func PrepareWithFile(ctx context.Context, data, id string, input *os.File, in PrepareInput) (out Preparation, err error) {
	if os.Geteuid() == 0 || !validID.MatchString(id) {
		return out, errors.New("恢复准备须使用非 root 面板账户及固定操作标识")
	}
	if err = in.validate(); err != nil {
		return out, err
	}
	if err = panelruntime.CheckInit(data); err != nil {
		return out, err
	}
	running, err := panelruntime.Read(data)
	if err != nil {
		return out, err
	}
	unlock, err := storage.LockWriterForPreparation(data, os.Getegid())
	if err != nil {
		return out, err
	}
	defer unlock()
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err = preparationBudget(data); err != nil {
		return out, err
	}
	now := time.Now().Unix()
	final := preparationDir(data, id)
	work := filepath.Join(preparationRoot(data), ".preparing-"+id)
	if _, e := os.Lstat(final); e == nil {
		return out, errors.New("恢复准备标识已有结果，请查询原报告或清理后使用新标识")
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if err = os.Mkdir(work, 0700); err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, removePreparationDirectory(work))
		}
	}()
	if err = writeManifest(filepath.Join(work, "prepared-at"), now); err != nil {
		return out, err
	}
	m, hash, err := extractArchive(call, input, work, in.Credentials)
	if err != nil {
		return out, err
	}
	if hash != in.ArchiveSHA256 || m.Database.NodeID != in.SourceNodeID {
		return out, errors.New("完整备份与指定的加密文件或源节点身份不一致")
	}
	inspection, err := inspectExtracted(call, work, m, hash)
	if err != nil {
		return out, err
	}
	if !inspection.FormatCompatible || m.ApplicationVersion != running.Release.Version {
		return out, errors.New("恢复须使用相同程序、数据库、Agent 与解析策略版本")
	}
	for _, r := range resources {
		f, _, e := openPrivate(filepath.Join(data, r.source), r.limit)
		if e != nil {
			return out, e
		}
		f.Close()
	}
	target, err := readDatabase(call, filepath.Join(data, "app", "panel.db"))
	if err != nil {
		return out, err
	}
	defer target.Close()
	if err = storage.CheckRestoreBarrier(call, target); err != nil {
		return out, err
	}
	if err = storage.VerifyCurrentSchema(call, target); err != nil {
		return out, err
	}
	meta, err := databaseMetadata(call, target)
	if err != nil {
		return out, err
	}
	if meta.NodeID != in.TargetNodeID || meta.SchemaVersion != m.Database.SchemaVersion {
		return out, errors.New("恢复目标节点或数据库版本已变化")
	}
	admin, err := readRestoreAdmin(call, target)
	if err != nil {
		return out, err
	}
	adminBasis := admin
	adminBasis.Epoch = 0
	adminRaw, err := json.Marshal(adminBasis)
	if err != nil {
		return out, err
	}
	out = Preparation{Schema: 1, OperationID: id, MaintenanceID: in.MaintenanceID, Mode: in.Mode, PreparedAt: now, ExpiresAt: now + PreparationLifetime, ArchiveSHA256: hash, Source: m, Target: RestoreTarget{Database: meta, ReleaseID: running.Release.ID, Runtime: running.Deployment.Mode, AdminSHA256: secure.Hash(adminRaw), SessionEpoch: admin.Epoch, Files: []File{}}, Database: m.Database, PreserveNodeIdentity: in.PreserveNodeIdentity, SourceOfflineConfirmed: in.SourceOfflineConfirmed, Files: []File{}, DisabledModules: []string{}, PendingChecks: []string{
		"独立 root 恢复事务须核对原持久停机、维护会话及当前目标文件身份，并先保留匹配的目标回退快照",
		"须从可信来源核对并准备目标 Nginx/组件及预置镜像能力，重新解析映射路径、监听与证书，生成新的受管发布",
		"源任务已隔离，须逐项与目标 Agent 独立记录及真实资源核对；未知结果禁止重新派发",
		"源 ACME 订单及 DNS 值须核对所有权与远端状态，源节点连接和未确认配对须在原目标核对撤销",
		"须核对目标网络所有者、已有归档和运行接入；防火墙、DNS、自动化及通知保持停用，另行授权",
		"所有安装与补偿完成后方可通过原事务解除启动屏障；当前准备报告不代表恢复成功",
	}}
	if !in.PreserveNodeIdentity {
		out.Database.NodeID = secure.ID()
	}
	out.Database.AppliedRevision = ""
	if err = sanitizeRestore(call, filepath.Join(work, "panel.db"), target, admin, &out); err != nil {
		return out, err
	}
	for _, r := range resources[2:] {
		if err = os.Remove(filepath.Join(work, r.local)); err != nil {
			return out, err
		}
		if err = copyMaterial(call, filepath.Join(data, r.source), filepath.Join(work, r.local), r.limit); err != nil {
			return out, err
		}
	}
	if _, err = tls.LoadX509KeyPair(filepath.Join(work, "cert.pem"), filepath.Join(work, "key.pem")); err != nil {
		return out, errors.New("目标主入口 TLS 材料不匹配")
	}
	for _, r := range resources {
		file, e := digestFile(call, filepath.Join(work, r.local), r.limit)
		if e != nil {
			return out, e
		}
		file.Name = r.name
		out.Files = append(out.Files, file)
		f, _, e := openPrivate(filepath.Join(work, r.local), r.limit)
		if e != nil {
			return out, e
		}
		e = errors.Join(f.Sync(), f.Close())
		if e != nil {
			return out, e
		}
		file, e = digestFile(call, filepath.Join(data, r.source), r.limit)
		if e != nil {
			return out, e
		}
		file.Name = r.name
		out.Target.Files = append(out.Target.Files, file)
	}
	wal, e := digestFile(call, filepath.Join(data, "app", "panel.db-wal"), 2*DatabaseMax)
	if e == nil {
		wal.Name = "database/panel.db-wal"
		out.Target.Files = append(out.Target.Files, wal)
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if err = out.Validate(); err != nil {
		return out, err
	}
	if err = writeManifest(filepath.Join(work, "manifest.json"), out); err != nil {
		return out, err
	}
	if err = syncDir(work); err != nil {
		return out, err
	}
	if err = target.Close(); err != nil {
		return out, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, work, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); err != nil {
		return out, err
	}
	if err = syncDir(preparationRoot(data)); err != nil {
		return out, err
	}
	return out, nil
}
func preparationBudget(data string) error {
	if err := privateDir(filepath.Join(data, "staging")); err != nil {
		return err
	}
	if err := privateDir(preparationRoot(data)); err != nil {
		return err
	}
	items, err := boundedEntries(preparationRoot(data), PreparationMax)
	if err != nil {
		return err
	}
	var used int64
	for _, item := range items {
		if _, _, err = preparationEntry(item); err != nil {
			return err
		}
		_, _, size, e := preparationFiles(filepath.Join(preparationRoot(data), item.Name()))
		if e != nil {
			return e
		}
		used += size
	}
	if len(items) >= PreparationMax || used+2*DatabaseMax+(18<<20) > StoreMax {
		return errors.New("恢复暂存容量或数量达到上限，请先清理原准备材料")
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(preparationRoot(data), &disk); err != nil {
		return err
	}
	if disk.Bsize <= 0 || disk.Bavail < uint64((2*DatabaseMax+(128<<20)+int64(disk.Bsize)-1)/int64(disk.Bsize)) {
		return errors.New("恢复准备可用磁盘空间不足")
	}
	return nil
}
func writableRestoreDatabase(ctx context.Context, path string) (*sql.DB, error) {
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?mode=rw&_pragma=trusted_schema(OFF)&_pragma=foreign_keys(ON)&_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)&_pragma=cache_size(-16384)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var pageSize int64
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		db.Close()
		return nil, err
	}
	if pageSize < 512 || pageSize > 65536 {
		db.Close()
		return nil, errors.New("恢复 SQLite 页大小无效")
	}
	var maxPages int64
	err = db.QueryRowContext(ctx, "PRAGMA max_page_count="+strconv.FormatInt(DatabaseMax/pageSize, 10)).Scan(&maxPages)
	if err != nil || maxPages <= 0 || maxPages > DatabaseMax/pageSize {
		db.Close()
		return nil, errors.Join(err, errors.New("无法约束恢复数据库容量"))
	}
	return db, nil
}
