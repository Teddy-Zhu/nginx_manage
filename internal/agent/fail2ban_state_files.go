package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type fail2banStateReader struct {
	ctx context.Context
	r   io.Reader
}

func (r fail2banStateReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func fail2banStatePrivateDir(name string, create bool) error {
	var err error
	if create {
		err = secure.RootDirectory(name, 0700)
	} else {
		err = existingRootDirectory(name)
	}
	if err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 {
		return errors.New("Fail2ban 状态快照目录须为 root 专用的 0700 目录")
	}
	return nil
}

func fail2banStateWrite(name string, raw []byte) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, written := f.Write(raw)
	synced := f.Sync()
	closed := f.Close()
	return errors.Join(written, synced, closed)
}

// Both published snapshots and abandoned temporary material count toward the
// quota. No expiry or quota pressure may delete the only recovery evidence.
func fail2banStateQuota(store string, reserve int64, addSnapshot bool) error {
	if err := fail2banStatePrivateDir(store, false); err != nil {
		return err
	}
	var used int64
	entries, snapshots := 0, 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > 3 {
			return errors.New("Fail2ban 状态快照材料层级超过限制")
		}
		if err := fail2banStatePrivateDir(dir, false); err != nil {
			return err
		}
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		children, readErr := f.ReadDir(257 - entries)
		closeErr := f.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		for _, child := range children {
			entries++
			if entries > 256 {
				return errors.New("Fail2ban 状态快照材料数量超过限制")
			}
			name := filepath.Join(dir, child.Name())
			if child.IsDir() {
				if depth == 0 {
					snapshots++
				}
				if err = walk(name, depth+1); err != nil {
					return err
				}
				continue
			}
			file, info, err := secure.OpenRootFile(name, fail2banStateArchiveLimit)
			if err != nil {
				return err
			}
			if err = file.Close(); err != nil {
				return err
			}
			used += info.Size()
			if used > fail2banStateStoreLimit {
				return errors.New("Fail2ban 状态快照存储已超过容量限制")
			}
		}
		return nil
	}
	if err := walk(store, 0); err != nil {
		return err
	}
	if reserve < 0 || reserve > fail2banStateStoreLimit || used > fail2banStateStoreLimit-reserve || addSnapshot && snapshots >= fail2banStateSnapshotLimit {
		return errors.New("Fail2ban 状态快照配额不足，保留已有恢复材料")
	}
	return nil
}

func fail2banStateKey(store string, create bool) (*age.X25519Identity, error) {
	name := filepath.Join(store, "recovery.key")
	raw, err := secure.ReadRootFile(name, 256)
	if os.IsNotExist(err) && create {
		dir, e := os.Open(store)
		if e != nil {
			return nil, e
		}
		entries, readErr := dir.ReadDir(1)
		closeErr := dir.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		if len(entries) != 0 {
			return nil, errors.New("已有 Fail2ban 状态材料但恢复密钥缺失，不生成替代密钥")
		}
		identity, e := age.GenerateX25519Identity()
		if e != nil {
			return nil, e
		}
		if e = fail2banStateWrite(name, []byte(identity.String()+"\n")); e != nil {
			return nil, e
		}
		if e = syncDir(store); e != nil {
			return nil, e
		}
		return identity, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		return nil, errors.Join(errors.New("Fail2ban 状态恢复密钥权限无效"), err)
	}
	return age.ParseX25519Identity(strings.TrimSuffix(string(raw), "\n"))
}

type fail2banStateSource struct {
	file *os.File
	info os.FileInfo
	meta fail2banStateFile
}

func closeFail2banStateSources(sources []fail2banStateSource) {
	for _, source := range sources {
		if source.file != nil {
			source.file.Close()
		}
	}
}

func fail2banStateSourceDirectory(dir string) error {
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := f.ReadDir(len(fail2banStateResources) + 1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > len(fail2banStateResources) {
		return errors.New("受管 Fail2ban 状态目录含额外材料，不能完整捕获")
	}
	for _, entry := range entries {
		known := false
		for _, resource := range fail2banStateResources {
			known = known || entry.Name() == resource.name
		}
		if !known {
			return errors.New("受管 Fail2ban 状态目录含未知材料，不能遗漏捕获")
		}
	}
	return nil
}

func openFail2banStateSources(ctx context.Context, dir string) ([]fail2banStateSource, error) {
	if err := fail2banStateSourceDirectory(dir); err != nil {
		return nil, err
	}
	sources := make([]fail2banStateSource, 0, len(fail2banStateResources))
	fail := func(err error) ([]fail2banStateSource, error) {
		closeFail2banStateSources(sources)
		return nil, err
	}
	for _, resource := range fail2banStateResources {
		source := fail2banStateSource{meta: fail2banStateFile{Name: resource.name}}
		f, info, err := secure.OpenRootFile(filepath.Join(dir, resource.name), resource.limit)
		if os.IsNotExist(err) {
			sources = append(sources, source)
			continue
		}
		if err != nil {
			return fail(err)
		}
		source.file, source.info = f, info
		sources = append(sources, source)
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Gid != 0 {
			return fail(errors.New("受管 Fail2ban 状态文件须归属 root 组"))
		}
		h := sha256.New()
		n, err := io.Copy(h, fail2banStateReader{ctx, io.LimitReader(f, resource.limit+1)})
		if err != nil || n != info.Size() || !secure.RootFileUnchanged(f, info) {
			return fail(errors.Join(errors.New("Fail2ban 状态文件在读取期间变化"), err))
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return fail(err)
		}
		label, err := fail2banStateLabel(int(f.Fd()))
		if err != nil || !secure.RootFileUnchanged(f, info) {
			return fail(errors.Join(errors.New("Fail2ban 状态安全标签无法核对"), err))
		}
		sources[len(sources)-1].meta = fail2banStateFile{Name: resource.name, Present: true, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: uint32(info.Mode().Perm()), SELinux: label}
	}
	return sources, nil
}

func hashFail2banStateFile(ctx context.Context, name string, limit int64) (string, error) {
	f, info, err := secure.OpenRootFile(name, limit)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, fail2banStateReader{ctx, io.LimitReader(f, limit+1)})
	if err != nil || n != info.Size() || !secure.RootFileUnchanged(f, info) {
		return "", errors.Join(errors.New("Fail2ban 状态文件在核对期间变化"), err)
	}
	return hex.EncodeToString(h.Sum(nil)), ctx.Err()
}

func unchangedFail2banStateSources(dir string, sources []fail2banStateSource) error {
	if err := fail2banStateSourceDirectory(dir); err != nil {
		return err
	}
	for _, source := range sources {
		current, err := os.Lstat(filepath.Join(dir, source.meta.Name))
		if !source.meta.Present {
			if !os.IsNotExist(err) {
				return errors.New("Fail2ban 状态捕获期间出现原缺失文件")
			}
			continue
		}
		if err != nil || !os.SameFile(source.info, current) || !secure.RootFileUnchanged(source.file, source.info) {
			return errors.Join(errors.New("Fail2ban 状态文件在捕获期间变化"), err)
		}
	}
	return nil
}
