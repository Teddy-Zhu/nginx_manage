package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func fail2banStateDirectoryIdentity(dir string) (fail2banStateDirectory, error) {
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return fail2banStateDirectory{}, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fail2banStateDirectory{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return fail2banStateDirectory{}, errors.New("Fail2ban 状态目录身份无法核对")
	}
	label, err := fail2banStateDirectoryLabel(dir, nil)
	if err != nil {
		return fail2banStateDirectory{}, err
	}
	return fail2banStateDirectory{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), SELinux: label}, nil
}

func observeFail2banStateDirectory(ctx context.Context, dir string) (fail2banStateDirectory, []fail2banStateFile, error) {
	identity, err := fail2banStateDirectoryIdentity(dir)
	if err != nil {
		return identity, nil, err
	}
	sources, err := openFail2banStateSources(ctx, dir)
	if err != nil {
		return identity, nil, err
	}
	defer closeFail2banStateSources(sources)
	files := make([]fail2banStateFile, len(sources))
	for index, source := range sources {
		files[index] = source.meta
	}
	if err = unchangedFail2banStateSources(dir, sources); err != nil {
		return identity, nil, err
	}
	after, err := fail2banStateDirectoryIdentity(dir)
	if err != nil || identity != after {
		return identity, nil, errors.Join(errors.New("Fail2ban 状态目录在核对期间变化"), err)
	}
	return identity, files, ctx.Err()
}

func sameFail2banStateRestoreControl(a, b fail2banStateBasis) bool {
	// A fresh root invocation may resume after reboot or a fenced failed start.
	// Code, installation event and configuration remain pinned; the caller
	// independently proves the current loaded service stopped with no job/socket.
	a.Service = b.Service
	a.Invocation, b.Invocation = "", ""
	a.BootID, b.BootID = "", ""
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func compatibleFail2banStateSnapshot(current, snapshot fail2banStateBasis) bool {
	if fail2banUpgradeComponent(&current.Managed) != fail2banUpgradeComponent(&snapshot.Managed) || current.Managed.DataDir != snapshot.Managed.DataDir || current.Managed.PythonVersion != snapshot.Managed.PythonVersion || current.Managed.ManagerPath != snapshot.Managed.ManagerPath || current.Managed.ManagerSHA256 != snapshot.Managed.ManagerSHA256 || current.MachineID != snapshot.MachineID || current.Managed.JailSelection != snapshot.Managed.JailSelection || current.StateLabel != snapshot.StateLabel {
		return false
	}
	x, _ := json.Marshal(struct {
		Bundle        *fail2banJailBundle
		Configuration map[string]string
	}{current.Bundle, current.Configuration})
	y, _ := json.Marshal(struct {
		Bundle        *fail2banJailBundle
		Configuration map[string]string
	}{snapshot.Bundle, snapshot.Configuration})
	return bytes.Equal(x, y)
}

func (i fail2banStateRestoreIntent) observe(ctx context.Context, ready *fail2banStateRestoreReady) (bool, error) {
	state := filepath.Join(i.Input.Basis.Managed.work(), "state")
	identity, files, err := observeFail2banStateDirectory(ctx, state)
	if err != nil {
		return false, err
	}
	before := identity == i.Input.Directory && fail2banStateFilesHash(files) == fail2banStateFilesHash(i.Input.Before)
	if ready == nil {
		if !before {
			return false, errors.New("Fail2ban 状态在恢复暂存完成前偏离原目录，停止覆盖")
		}
		return false, nil
	}
	otherID, otherFiles, err := observeFail2banStateDirectory(ctx, filepath.Join(i.dir(), "exchange"))
	if err != nil {
		return false, err
	}
	if before && otherID == ready.Directory && fail2banStateFilesHash(otherFiles) == fail2banStateFilesHash(i.After) {
		return false, nil
	}
	if identity == ready.Directory && fail2banStateFilesHash(files) == fail2banStateFilesHash(i.After) && otherID == i.Input.Directory && fail2banStateFilesHash(otherFiles) == fail2banStateFilesHash(i.Input.Before) {
		return true, nil
	}
	return false, errors.New("Fail2ban 状态目录或保留副本偏离原状态及批准目标，停止交换")
}

func (i fail2banStateRestoreIntent) stage(ctx context.Context, r fail2banStateReceipt, m fail2banStateManifest) (*fail2banStateRestoreReady, error) {
	if _, err := i.observe(ctx, nil); err != nil {
		return nil, err
	}
	prepared := filepath.Join(fail2banStateDir(i.DataDir), r.OperationID, "prepared")
	if err := verifyFail2banStatePrepared(ctx, prepared, r, m); err != nil {
		return nil, err
	}
	dir := filepath.Join(i.dir(), "exchange")
	if _, err := os.Lstat(dir); err == nil {
		// No ready proof means exchange was never authorized. Remove only this
		// operation's bounded regular scratch files, while the original remains.
		if err = fail2banStateSourceDirectory(dir); err != nil {
			return nil, err
		}
		identity, err := fail2banStateDirectoryIdentity(dir)
		if err != nil || identity == i.Input.Directory {
			return nil, errors.Join(errors.New("Fail2ban 恢复暂存不能占用原状态目录"), err)
		}
		for _, resource := range fail2banStateResources {
			name := filepath.Join(dir, resource.name)
			f, _, e := secure.OpenRootFile(name, resource.limit)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return nil, e
			}
			if e = f.Close(); e != nil {
				return nil, e
			}
			if e = os.Remove(name); e != nil {
				return nil, e
			}
		}
		if err = os.Remove(dir); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	if _, err := fail2banStateDirectoryLabel(dir, &i.Input.Basis.StateLabel); err != nil {
		return nil, err
	}
	identity, err := fail2banStateDirectoryIdentity(dir)
	if err != nil || identity.Device != i.Input.Directory.Device || identity == i.Input.Directory {
		return nil, errors.Join(errors.New("Fail2ban 状态恢复仅允许同一文件系统的独立目录交换"), err)
	}
	for _, file := range i.After {
		if !file.Present {
			continue
		}
		src, info, err := secure.OpenRootFile(filepath.Join(prepared, file.Name), file.Size)
		if err != nil {
			return nil, err
		}
		err = copyFail2banRestoreFile(ctx, filepath.Join(dir, file.Name), src, file)
		unchanged := secure.RootFileUnchanged(src, info)
		closed := src.Close()
		if err != nil || !unchanged || closed != nil {
			return nil, errors.Join(errors.New("Fail2ban 恢复暂存复制未完成或源文件变化"), err, closed)
		}
	}
	if err = syncDir(dir); err != nil {
		return nil, err
	}
	if err = syncDir(i.dir()); err != nil {
		return nil, err
	}
	actualID, files, err := observeFail2banStateDirectory(ctx, dir)
	if err != nil || actualID != identity || fail2banStateFilesHash(files) != fail2banStateFilesHash(i.After) {
		return nil, errors.Join(errors.New("Fail2ban 恢复暂存未完整匹配批准目标"), err)
	}
	ready := &fail2banStateRestoreReady{fail2banStateRestoreMarker: i.marker(), Directory: identity}
	raw, err := fail2banStateJSON(ready)
	if err != nil {
		return nil, err
	}
	if err = writeFail2banJailImmutable(filepath.Join(i.dir(), "ready.json"), raw, 4096); err != nil {
		return nil, err
	}
	return ready, nil
}

func copyFail2banRestoreFile(ctx context.Context, target string, source io.Reader, file fail2banStateFile) error {
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), fail2banStateReader{ctx, io.LimitReader(source, file.Size+1)})
	if err != nil || n != file.Size || hex.EncodeToString(h.Sum(nil)) != file.SHA256 {
		return errors.Join(errors.New("Fail2ban 恢复文件复制不完整"), err)
	}
	if err = f.Chown(0, 0); err != nil {
		return err
	}
	if err = f.Chmod(os.FileMode(file.Mode)); err != nil {
		return err
	}
	if err = setFail2banStateLabel(int(f.Fd()), file.SELinux); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func syncFail2banRestoreDirectory(ctx context.Context, dir string) error {
	if err := fail2banStateSourceDirectory(dir); err != nil {
		return err
	}
	for _, resource := range fail2banStateResources {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, _, err := secure.OpenRootFile(filepath.Join(dir, resource.name), resource.limit)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		synced := f.Sync()
		closed := f.Close()
		if err = errors.Join(synced, closed); err != nil {
			return err
		}
	}
	return syncDir(dir)
}
