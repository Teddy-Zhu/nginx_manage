package panelrecovery

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

func openDatabase(ctx context.Context, name string) (*sql.DB, error) {
	dsn := (&url.URL{Scheme: "file", Path: name}).String() + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=trusted_schema(OFF)&_pragma=synchronous(FULL)"
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

// CaptureDatabase is the fixed, non-root child entry point. SQLite never parses
// the business database with root privileges and never runs schema migrations.
func CaptureDatabase(ctx context.Context, data, id string) (Database, error) {
	var out Database
	if os.Geteuid() == 0 || !idValue.MatchString(id) {
		return out, errors.New("数据库快照助手须以面板专用账户执行")
	}
	if _, err := root(data); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(DatabaseMax), Max: uint64(DatabaseMax)}); err != nil {
		return out, err
	}
	dir := workspace(data, id)
	info, err := os.Lstat(dir)
	if err != nil {
		return out, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid() {
		return out, errors.New("数据库快照助手目录归属无效")
	}
	parent, err := os.Lstat(filepath.Dir(dir))
	if err != nil {
		return out, err
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0711 || parentStat.Uid != 0 {
		return out, errors.New("数据库快照助手须使用 root 分配的工作目录")
	}
	source := filepath.Join(data, "app", "panel.db")
	f, _, err := openOwned(source, os.Geteuid(), os.Getegid(), DatabaseMax)
	if err != nil {
		return out, err
	}
	f.Close()
	target := filepath.Join(dir, "panel.db")
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("数据库快照输出已存在或无法确认")
	}
	db, err := openDatabase(ctx, source)
	if err != nil {
		return out, err
	}
	_, err = db.ExecContext(ctx, "VACUUM main INTO ?", target)
	closed := db.Close()
	if err != nil || closed != nil {
		return out, errors.Join(err, closed)
	}
	if err = os.Chmod(target, 0600); err != nil {
		return out, err
	}
	copy, _, err := openOwned(target, os.Geteuid(), os.Getegid(), DatabaseMax)
	if err != nil {
		return out, err
	}
	if err = copy.Sync(); err != nil {
		copy.Close()
		return out, err
	}
	copy.Close()
	db, err = openDatabase(ctx, target)
	if err != nil {
		return out, err
	}
	defer db.Close()
	var check string
	if err = db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&check); err != nil {
		return out, err
	}
	if check != "ok" {
		return out, errors.New("SQLite 一致性快照检查失败")
	}
	if err = db.QueryRowContext(ctx, "SELECT MAX(version_id) FROM goose_db_version").Scan(&out.SchemaVersion); err != nil {
		return out, err
	}
	if err = db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='node_id'").Scan(&out.NodeID); err != nil {
		return out, err
	}
	if err = db.QueryRowContext(ctx, "SELECT COALESCE(desired_revision,''),COALESCE(applied_revision,''),version FROM config_head WHERE id=1").Scan(&out.DesiredRevision, &out.AppliedRevision, &out.HeadVersion); err != nil {
		return out, err
	}
	if !out.valid() {
		return out, errors.New("数据库快照的节点或配置修订身份无效")
	}
	return out, nil
}
