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
	"net/url"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type MaterialVerification struct {
	OperationID       string   `json:"operation_id"`
	PreparationSHA256 string   `json:"preparation_sha256"`
	Database          Database `json:"database"`
	VerifiedAt        int64    `json:"verified_at"`
}

func preparationHash(p Preparation) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}

func verifyPreparedDatabase(ctx context.Context, db *sql.DB, vault *secure.Vault, p Preparation) error {
	if err := storage.VerifyCurrentSchema(ctx, db); err != nil {
		return err
	}
	meta, err := databaseMetadata(ctx, db)
	if err != nil {
		return err
	}
	if meta != p.Database {
		return errors.New("恢复准备数据库身份不一致")
	}
	var matches bool
	err = db.QueryRowContext(ctx, "SELECT COUNT(*)=1 FROM restore_barriers WHERE id=? AND state='prepared' AND source_node_id=? AND target_node_id=? AND archive_sha256=? AND mode=? AND prepared_at=?", p.OperationID, p.Source.Database.NodeID, p.Database.NodeID, p.ArchiveSHA256, p.Mode, p.PreparedAt).Scan(&matches)
	if err != nil {
		return err
	}
	if !matches {
		return errors.New("恢复准备启动屏障不匹配")
	}
	admin, err := readRestoreAdmin(ctx, db)
	if err != nil {
		return err
	}
	epoch := admin.Epoch
	admin.Epoch = 0
	raw, err := json.Marshal(admin)
	if err != nil {
		return err
	}
	if epoch != p.SessionEpoch || secure.Hash(raw) != p.Target.AdminSHA256 {
		return errors.New("恢复准备管理员身份不一致")
	}
	var unsafe bool
	err = db.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM sessions
 UNION ALL SELECT 1 FROM settings WHERE key='bootstrap_hash'
 UNION ALL SELECT 1 FROM api_credentials WHERE revoked_at IS NULL
 UNION ALL SELECT 1 FROM tasks t WHERE state NOT IN('succeeded','failed','rolled_back','cancelled') AND (state<>'recovery_required' OR stage<>'restore_isolated' OR lease_until IS NOT NULL OR NOT EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=t.id))
 UNION ALL SELECT 1 FROM module_settings WHERE id<>'nginx-config' AND enabled<>0
 UNION ALL SELECT 1 FROM backup_policy WHERE key_saved_at<>0 OR principal<>'' OR issuer_machine<>0 OR issuer_epoch<>0 OR authorization_until<>0 OR next_run_at<>0
 UNION ALL SELECT 1 FROM backup_downloads
 UNION ALL SELECT 1 FROM backup_records WHERE deleted_at IS NULL OR delete_started<>0
 UNION ALL SELECT 1 FROM nodes WHERE token IS NOT NULL OR capabilities IS NOT NULL OR state<>'removed' OR removed_at IS NULL
 UNION ALL SELECT 1 FROM node_pairings WHERE token IS NOT NULL OR state<>'revoked'
 UNION ALL SELECT 1 FROM node_pairing_jobs WHERE material IS NOT NULL OR state<>'abandoned' OR stage<>'finished'
 UNION ALL SELECT 1 FROM notification_channels WHERE enabled<>0
 UNION ALL SELECT 1 FROM notification_deliveries WHERE state IN('pending','sending')
 UNION ALL SELECT 1 FROM notification_events WHERE fanout_at=0 OR expires_at>?
 UNION ALL SELECT 1 FROM notification_signals WHERE active<>0
 UNION ALL SELECT 1 FROM acme_profiles WHERE auto_renew<>0 OR auto_deploy<>0 OR deploy_after<>0 OR deployment_observed_version<>''
 UNION ALL SELECT 1 FROM acme_renewals WHERE paused<>1 OR next_check_at<>0
 UNION ALL SELECT 1 FROM acme_dns_records WHERE state NOT IN('cleaned','blocked')
 UNION ALL SELECT 1 FROM host_dns_plans
 UNION ALL SELECT 1 FROM host_dns_desired
 UNION ALL SELECT 1 FROM migration_plans WHERE expires_at>0
 UNION ALL SELECT 1 FROM migration_pushes WHERE expires_at>0 OR next_attempt_at<>0
 UNION ALL SELECT 1 FROM panel_updates WHERE cleanup_pending<>0
 UNION ALL SELECT 1 FROM maintenance_sessions WHERE phase NOT IN('released','failed')
 )`, p.PreparedAt).Scan(&unsafe)
	if err != nil {
		return err
	}
	if unsafe {
		return errors.New("恢复准备仍含未隔离的旧授权、任务或自动化")
	}
	for _, table := range []string{"idempotency_keys", "backup_requests", "migration_pulls", "node_requests", "node_pairings", "node_pairing_jobs"} {
		err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE substr(principal,1,?)<>?)", len("restore:"+p.OperationID+":"), "restore:"+p.OperationID+":").Scan(&unsafe)
		if err != nil {
			return err
		}
		if unsafe {
			return errors.New("恢复准备仍含未隔离的幂等主体")
		}
	}
	var tasks int64
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state NOT IN('succeeded','failed','rolled_back','cancelled')").Scan(&tasks); err != nil {
		return err
	}
	if tasks != p.Isolation.Tasks {
		return errors.New("恢复准备隔离任务计数不一致")
	}
	checked := map[string]bool{}
	for _, revision := range []string{p.Source.Database.DesiredRevision, p.Source.Database.AppliedRevision} {
		if revision != "" && !checked[revision] {
			if err = inspectRevision(ctx, db, vault, revision); err != nil {
				return err
			}
			checked[revision] = true
		}
	}
	return nil
}

// VerifyAdoptionDescriptors checks inherited root read descriptors and the
// matching root-owned SQLite projection after dropping root credentials.
func VerifyAdoptionDescriptors(ctx context.Context, data, id string, p Preparation, files []*os.File) (out MaterialVerification, err error) {
	return verifyAdoptionDescriptors(ctx, data, id, p, files, nil)
}

func verifyAdoptionDescriptors(ctx context.Context, data, id string, p Preparation, files []*os.File, inspect func(context.Context, *sql.DB, *secure.Vault) error) (out MaterialVerification, err error) {
	if os.Geteuid() == 0 || !validID.MatchString(id) || p.OperationID != id || len(files) != len(resources) {
		return out, errors.New("恢复接入核对助手的身份或描述符无效")
	}
	if err = panelruntime.CheckInit(data); err != nil {
		return out, err
	}
	if err = p.Validate(); err != nil {
		return out, err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for i, f := range files {
		info, e := f.Stat()
		if e != nil {
			return out, e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if e != nil {
			return out, e
		}
		if !ok || st.Uid != 0 || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() != p.Files[i].Size || flags&unix.O_ACCMODE != unix.O_RDONLY {
			return out, errors.New("恢复接入核对只接受 root 只读固定资源")
		}
		hash := sha256.New()
		n, e := io.Copy(hash, contextReader{call, io.LimitReader(f, resources[i].limit+1)})
		if e != nil {
			return out, e
		}
		if n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != p.Files[i].SHA256 || !secure.RootFileUnchanged(f, info) {
			return out, errors.New("恢复接入资源与原准备散列不一致")
		}
		if _, e = f.Seek(0, io.SeekStart); e != nil {
			return out, e
		}
	}
	key, err := io.ReadAll(io.LimitReader(files[1], 33))
	if err != nil {
		return out, err
	}
	defer clear(key)
	vault, err := secure.NewVault(key)
	if err != nil {
		return out, err
	}
	probe, err := vault.Open(p.Source.KeyCheck, "backup-key-check:"+p.Source.ID)
	if err != nil || string(probe) != "nginxpanel-disaster:"+p.Source.ID {
		return out, errors.New("恢复接入主密钥与备份不匹配")
	}
	cert, err := io.ReadAll(io.LimitReader(files[2], (64<<10)+1))
	if err != nil {
		return out, err
	}
	tlsKey, err := io.ReadAll(io.LimitReader(files[3], (64<<10)+1))
	if err != nil {
		return out, err
	}
	defer clear(tlsKey)
	if _, err = tls.X509KeyPair(cert, tlsKey); err != nil {
		return out, errors.New("恢复接入主入口 TLS 材料不匹配")
	}
	databaseFile, databaseInfo, err := openAdoptionCheck(data, id, os.Getegid(), p.Files[0])
	if err != nil {
		return out, err
	}
	defer databaseFile.Close()
	databaseHash := sha256.New()
	n, err := io.Copy(databaseHash, contextReader{call, io.LimitReader(databaseFile, p.Files[0].Size+1)})
	if err != nil {
		return out, err
	}
	if n != p.Files[0].Size || hex.EncodeToString(databaseHash.Sum(nil)) != p.Files[0].SHA256 || !secure.RootFileUnchanged(databaseFile, databaseInfo) {
		return out, errors.New("恢复核对数据库投影与固定副本不一致")
	}
	dsn := (&url.URL{Scheme: "file", Path: databaseFile.Name()}).String() + "?mode=ro&immutable=1&_pragma=trusted_schema(OFF)&_pragma=query_only(ON)&_pragma=busy_timeout(5000)&_pragma=cache_size(-16384)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return out, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err = verifyPreparedDatabase(call, db, vault, p); err != nil {
		return out, err
	}
	if inspect != nil {
		if err = inspect(call, db, vault); err != nil {
			return out, err
		}
	}
	if !secure.RootFileUnchanged(databaseFile, databaseInfo) {
		return out, errors.New("恢复核对数据库投影在解析期间变化")
	}
	hash, err := preparationHash(p)
	if err != nil {
		return out, err
	}
	return MaterialVerification{OperationID: id, PreparationSHA256: hash, Database: p.Database, VerifiedAt: time.Now().Unix()}, nil
}
