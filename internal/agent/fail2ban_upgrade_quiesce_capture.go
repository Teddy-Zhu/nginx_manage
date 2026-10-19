package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func (i fail2banUpgradeQuiesceIntent) reserveChildren(p fail2banUpgradePreparation, j *Journal) error {
	for _, id := range []string{i.SnapshotID, i.StoppedPreparationID} {
		if _, err := j.Get(id); !os.IsNotExist(err) {
			return errors.Join(errors.New("升级停止的子材料 UUID 已有审计或无法核对"), err)
		}
	}
	for _, dir := range []string{filepath.Join(fail2banStateDir(i.Request.DataDir), i.SnapshotID), filepath.Join(fail2banUpgradePreparations(i.Request.DataDir), i.StoppedPreparationID)} {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			return errors.Join(errors.New("升级停止的子材料路径已被使用或无法核对"), err)
		}
	}
	records, err := j.List()
	if err != nil {
		return err
	}
	reserve := 2
	for _, r := range records {
		if r.OperationID == i.Request.OperationID {
			reserve = 1
		}
	}
	if len(records)+reserve > 2048 {
		return errors.New("升级停止前须为父操作及停止态准备保留审计容量")
	}
	if err = fail2banUpgradePreparationQuota(fail2banUpgradePreparations(i.Request.DataDir)); err != nil {
		return err
	}
	store := fail2banStateDir(i.Request.DataDir)
	if err = fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	// Reserve archive, prepared plaintext and the disposable official DB read,
	// including bounded SQLite recovery growth. Recheck actual sizes after stop.
	var size int64
	for n, resource := range fail2banStateResources {
		f, info, e := secure.OpenRootFile(filepath.Join(p.Basis.Current.work(), "state", resource.name), resource.limit)
		if os.IsNotExist(e) && n != 0 {
			continue
		}
		if e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		if n == 0 && info.Size() == 0 {
			return errors.New("升级停止前缺少可捕获的官方状态库")
		}
		size += info.Size()
	}
	return fail2banStateQuota(store, 3*size+(128<<20)+(6<<20), true)
}

func (i fail2banUpgradeQuiesceIntent) running(ctx context.Context, p fail2banUpgradePreparation) error {
	b, err := i.observe(ctx, p)
	if err != nil {
		return err
	}
	if b.hash() != p.Basis.hash() {
		return errors.New("升级停止执行前原运行准备已变化")
	}
	before, err := readFail2banLiveService(ctx, b.Current.binding())
	if err != nil {
		return err
	}
	if err = i.matches(before); err != nil {
		return err
	}
	current, err := readFail2banJailRuntime(ctx, &b.Current, b.Bundle)
	if err != nil {
		return err
	}
	if err = checkFail2banQuiesceBans(i.Bans, current, time.Now().Unix()); err != nil {
		return err
	}
	after, err := readFail2banLiveService(ctx, b.Current.binding())
	if err != nil || !sameFail2banLive(before, after) {
		return errors.Join(errors.New("升级停止执行前原运行代次变化"), err)
	}
	return ctx.Err()
}

func (i fail2banUpgradeQuiesceIntent) matches(live fail2banLiveService) error {
	if live.view.MainPID == nil || *live.view.MainPID != i.PID || live.invocation != i.Invocation || live.inode != i.SocketInode {
		return errors.New("升级停止不得操作其他服务或 Socket 代次")
	}
	return nil
}

func (i fail2banUpgradeQuiesceIntent) stop(ctx context.Context, p fail2banUpgradePreparation) (fail2banUpgradeQuiesceStopped, error) {
	var out fail2banUpgradeQuiesceStopped
	b, err := i.observe(ctx, p)
	if err != nil {
		return out, err
	}
	if b.Service.Active == "active" {
		if err = i.running(ctx, p); err != nil {
			return out, err
		}
		// A failed/interrupted stop may only be repeated for the same original
		// invocation, PID and Socket, after confirming there is no pending job.
		if err = fail2banManagedSystemctl(ctx, "stop", fail2banManagedService); err != nil {
			return out, err
		}
		b, err = i.observe(ctx, p)
		if err != nil {
			return out, err
		}
	}
	if !i.stoppedInvocation(b.Invocation) {
		return out, errors.New("停止后的服务代次不属于原实例，保留恢复现场")
	}
	if err = fail2banExistingStopped(b.Current.binding(), b.Service); err != nil {
		return out, err
	}
	directory, files, err := observeFail2banStateDirectory(ctx, filepath.Join(b.Current.work(), "state"))
	if err != nil {
		return out, err
	}
	if directory != i.Directory {
		return out, errors.New("升级停止后的状态目录已被替换")
	}
	out = fail2banUpgradeQuiesceStopped{fail2banUpgradeActivationMarker: i.marker(), At: time.Now().Unix(), Service: b.Service, Invocation: b.Invocation, FilesSHA256: fail2banStateFilesHash(files)}
	return out, ctx.Err()
}

func (i fail2banUpgradeQuiesceIntent) stopped(ctx context.Context, p fail2banUpgradePreparation, stopped fail2banUpgradeQuiesceStopped) (fail2banUpgradeBasis, error) {
	b, err := i.observe(ctx, p)
	if err != nil {
		return b, err
	}
	if !fail2banUpgradeOneOf(b.Service, stopped.Service) || b.Invocation != stopped.Invocation {
		return b, errors.New("升级捕获期间原停止服务状态变化")
	}
	if err = fail2banExistingStopped(b.Current.binding(), b.Service); err != nil {
		return b, err
	}
	directory, files, err := observeFail2banStateDirectory(ctx, filepath.Join(b.Current.work(), "state"))
	if err != nil {
		return b, err
	}
	if directory != i.Directory || fail2banStateFilesHash(files) != stopped.FilesSHA256 {
		return b, errors.New("升级捕获期间原状态目录或数据库字节变化")
	}
	return b, ctx.Err()
}

func checkFail2banQuiesceBans(before, after fail2banBanProof, at int64) error {
	if len(before) != len(after) {
		return errors.New("升级捕获的完整 jail 名单变化")
	}
	for jail := range before {
		if _, ok := after[jail]; !ok {
			return errors.New("升级捕获遗漏原 jail")
		}
	}
	return checkFail2banBanPreservationAt(before, after, at)
}

func (i fail2banUpgradeQuiesceIntent) snapshotBans(ctx context.Context, receipt fail2banStateReceipt, manifest fail2banStateManifest) (out Fail2banUpgradeBans, resultErr error) {
	data := i.Request.DataDir
	if err := fail2banStateQuota(fail2banStateDir(data), receipt.ArchiveSize+(128<<20), false); err != nil {
		return out, err
	}
	dir := filepath.Join(fail2banStateDir(data), i.SnapshotID)
	tmp, err := os.MkdirTemp(dir, ".quiesce-check-")
	if err != nil {
		return out, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(tmp)) }()
	var copied int64
	visit := func(file fail2banStateFile, src io.Reader) (int64, error) {
		copied += file.Size
		if copied > receipt.ArchiveSize {
			return 0, errors.New("升级状态核对副本超过原配额预留")
		}
		f, e := os.OpenFile(filepath.Join(tmp, file.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
		if e != nil {
			return 0, e
		}
		n, e := io.Copy(f, src)
		return n, errors.Join(e, f.Close())
	}
	r, m, err := readFail2banStateArchive(ctx, data, i.SnapshotID, dir, visit)
	if err != nil {
		return out, err
	}
	if !fail2banUpgradeOneOf(r, receipt) || !fail2banUpgradeOneOf(m, manifest) {
		return out, errors.New("升级核对期间原加密快照变化")
	}
	at := time.Now().Unix()
	proof, err := readFail2banStateRecovery(ctx, tmp, m, at)
	if err != nil {
		return out, err
	}
	if err = checkFail2banQuiesceBans(i.Bans, proof, at); err != nil {
		return out, err
	}
	return fail2banRecoveryBanSummary(proof, at), ctx.Err()
}
