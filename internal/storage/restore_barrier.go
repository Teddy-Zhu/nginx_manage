package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// CheckRestoreBarrier precedes schema migrations and every application worker.
// Prepared data cannot become live merely by copying its database into place.
func CheckRestoreBarrier(ctx context.Context, db *sql.DB) error {
	var exists bool
	if err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='restore_barriers')").Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	} // An empty database has not run its initial migrations.
	var id string
	err := db.QueryRowContext(ctx, "SELECT substr(id,1,37) FROM restore_barriers WHERE state<>'completed' LIMIT 1").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !writerID.MatchString(id) {
		return errors.New("恢复启动屏障无效，拒绝打开业务数据")
	}
	return fmt.Errorf("恢复 %s 尚未完成独立核对，禁止启动业务进程", id)
}

// LockWriterForPreparation permits only an offline data-copy helper. It never
// clears the root stop marker or the interrupted-install fence.
func LockWriterForPreparation(data string, gid int) (func(), error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("恢复材料准备须由非 root 面板账户执行")
	}
	if err := writerDirectory(data); err != nil {
		return nil, err
	}
	info, err := os.Lstat(serviceHoldPath(data))
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || st.Uid != 0 || st.Nlink != 1 || info.Size() < 1 || info.Size() > 4096 {
		return nil, errors.New("恢复材料准备须处于 root 原事务的持久停机边界")
	}
	return lockWriter(data, gid, false, true)
}
