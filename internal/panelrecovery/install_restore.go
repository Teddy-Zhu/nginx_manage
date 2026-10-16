package panelrecovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type Original struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// WAL/SHM must be removed before the restored main database can be opened.
// Install the database last, after its matching vault and node TLS material.
var restoreFiles = []struct {
	name   string
	limit  int64
	target int
}{
	{"app/panel.db-wal", DatabaseMax * 2, -1},
	{"app/panel.db-shm", 16 << 20, -1},
	{"secrets/master.key", materialMax, 1},
	{"secrets/node-tls/cert.pem", materialMax, 2},
	{"secrets/node-tls/key.pem", materialMax, 3},
	{"app/panel.db", DatabaseMax * 2, 0},
}

func ValidateOriginals(in []Original) error {
	if len(in) != len(restoreFiles) {
		return errors.New("恢复前资源清单不完整")
	}
	var total int64
	for i, f := range in {
		if f.Name != restoreFiles[i].name || f.Size < 0 || f.Size > restoreFiles[i].limit || f.Present && !hashValue.MatchString(f.SHA256) || !f.Present && (f.Size != 0 || f.SHA256 != "") {
			return errors.New("恢复前资源清单无效")
		}
		total += f.Size
	}
	if total > StoreMax {
		return errors.New("恢复前资源超过 2 GiB 保留预算")
	}
	return nil
}

func observe(ctx context.Context, m Manifest, name string, limit int64) (Original, *os.File, os.FileInfo, error) {
	out := Original{Name: name}
	f, info, err := openBusinessFile(filepath.Join(m.DataDir, name), m.UID, m.GID, limit, true)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil, nil, nil
	}
	if err != nil {
		return out, nil, nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, limit+1)})
	if err == nil && (n != info.Size() || !secure.RootFileUnchanged(f, info)) {
		err = errors.New("恢复前资源在检查期间变化")
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return out, nil, nil, err
	}
	out.Present, out.Size, out.SHA256 = true, n, hex.EncodeToString(h.Sum(nil))
	return out, f, info, nil
}

// ObserveTarget hashes only the fixed business resources of an approved
// snapshot. It neither parses SQLite nor changes or preserves live files.
func ObserveTarget(ctx context.Context, receipt Receipt) ([]Original, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("恢复目标资源核对需要 root")
	}
	m := receipt.Manifest
	if err := receipt.Validate(m.DataDir, m.OperationID); err != nil {
		return nil, err
	}
	var out []Original
	for _, spec := range restoreFiles {
		original, f, _, err := observe(ctx, m, spec.name, spec.limit)
		if f != nil {
			f.Close()
		}
		if err != nil {
			return nil, err
		}
		out = append(out, original)
	}
	if err := ValidateOriginals(out); err != nil {
		return nil, err
	}
	return out, nil
}

// PreserveOriginals does not alter business files. The caller must durably save
// the returned inventory before Install may make its first live change.
func PreserveOriginals(ctx context.Context, p Prepared) ([]Original, error) {
	if os.Geteuid() != 0 || p.dir == "" {
		return nil, errors.New("恢复前保留需要已认证的 root 暂存")
	}
	return preserveOriginals(ctx, p.Receipt.Manifest, filepath.Join(p.dir, "before"))
}

func preserveOriginals(ctx context.Context, m Manifest, dir string) ([]Original, error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > len(restoreFiles)*2 {
		return nil, errors.New("恢复前暂存超过中断保留上限，须本机处理")
	}
	var out []Original
	var total int64
	for i, spec := range restoreFiles {
		original, f, info, err := observe(ctx, m, spec.name, spec.limit)
		if err != nil {
			return nil, err
		}
		out = append(out, original)
		total += original.Size
		if total > StoreMax {
			if f != nil {
				f.Close()
			}
			return nil, errors.New("恢复前资源超过 2 GiB 保留预算")
		}
		name := filepath.Join(dir, fmt.Sprintf("%02d", i))
		if !original.Present {
			if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("缺失资源已有不同的恢复前副本")
			}
			continue
		}
		err = preserve(ctx, f, info, name, original)
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	if err = ValidateOriginals(out); err != nil {
		return nil, err
	}
	return out, syncDir(dir)
}

func preserve(ctx context.Context, src *os.File, info os.FileInfo, name string, expected Original) error {
	if hash, n, err := rootFileHash(ctx, name, expected.Size, 0400); err == nil {
		if hash != expected.SHA256 || n != expected.Size {
			return errors.New("已保留的恢复前资源与当前状态不同")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".before-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), contextReader{ctx, io.LimitReader(src, expected.Size+1)})
	if err != nil {
		return err
	}
	if n != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 || !secure.RootFileUnchanged(src, info) {
		return errors.New("恢复前资源在保留期间变化")
	}
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, name, unix.RENAME_NOREPLACE)
}

func businessDirectory(data, relative string, uid, gid int, create bool) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, data, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(fd), data)
	for _, part := range strings.Split(relative, "/") {
		if part == "" || part == "." || part == ".." {
			parent.Close()
			return nil, errors.New("恢复资源目录无效")
		}
		childFD, err := unix.Openat2(int(parent.Fd()), part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		created := false
		if errors.Is(err, unix.ENOENT) && create {
			if err = unix.Mkdirat(int(parent.Fd()), part, 0700); err == nil {
				created = true
				childFD, err = unix.Openat2(int(parent.Fd()), part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
			}
		}
		if err != nil {
			parent.Close()
			return nil, err
		}
		child := os.NewFile(uintptr(childFD), part)
		if created {
			err = child.Chown(uid, gid)
			if err == nil {
				err = child.Chmod(0700)
			}
			if err == nil {
				err = child.Sync()
			}
			if err == nil {
				err = parent.Sync()
			}
		}
		info, e := child.Stat()
		if err == nil {
			err = e
		}
		if err == nil {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.IsDir() || st.Uid != 0 && int(st.Uid) != uid || info.Mode().Perm()&0022 != 0 {
				err = errors.New("恢复资源目录归属或权限无效")
			}
		}
		parent.Close()
		if err != nil {
			child.Close()
			return nil, err
		}
		parent = child
	}
	return parent, nil
}

// Install requires the caller's writer lock and durable startup fence. Replays
// accept only the preserved original or the approved target at each live path.
func Install(ctx context.Context, p Prepared, before []Original) error {
	if os.Geteuid() != 0 || p.dir == "" {
		return errors.New("资源恢复需要 root 和已认证暂存")
	}
	if err := ValidateOriginals(before); err != nil {
		return err
	}
	if err := preparedFiles(ctx, filepath.Join(p.dir, "after"), p.Receipt); err != nil {
		return err
	}
	for i, original := range before {
		if original.Present {
			h, n, err := rootFileHash(ctx, filepath.Join(p.dir, "before", fmt.Sprintf("%02d", i)), original.Size, 0400)
			if err != nil {
				return err
			}
			if h != original.SHA256 || n != original.Size {
				return errors.New("恢复前副本不完整或已变化")
			}
		}
	}
	for i, spec := range restoreFiles {
		source := ""
		if spec.target >= 0 {
			source = filepath.Join(p.dir, "after", fmt.Sprintf("%02d", spec.target))
		}
		if err := installOne(ctx, p.Receipt.Manifest, filepath.Base(p.dir), before[i], targetOriginal(p.Receipt, i), i, source); err != nil {
			return err
		}
	}
	for i, spec := range restoreFiles {
		actual, f, _, err := observe(ctx, p.Receipt.Manifest, spec.name, spec.limit)
		if f != nil {
			f.Close()
		}
		if err != nil {
			return err
		}
		if actual != targetOriginal(p.Receipt, i) {
			return errors.New("恢复后资源未全部匹配批准清单")
		}
	}
	synced := map[string]bool{}
	for _, spec := range restoreFiles {
		name := filepath.Dir(spec.name)
		if synced[name] {
			continue
		}
		dir, err := businessDirectory(p.Receipt.Manifest.DataDir, name, p.Receipt.Manifest.UID, p.Receipt.Manifest.GID, false)
		if err != nil {
			return err
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return err
		}
		synced[name] = true
	}
	return nil
}

func targetOriginal(r Receipt, index int) Original {
	spec := restoreFiles[index]
	if spec.target < 0 {
		return Original{Name: spec.name}
	}
	f := r.Manifest.Files[spec.target]
	return Original{Name: spec.name, Present: true, Size: f.Size, SHA256: f.SHA256}
}

func installOne(ctx context.Context, m Manifest, operation string, before, target Original, index int, source string) error {
	spec := restoreFiles[index]
	actual, f, _, err := observe(ctx, m, spec.name, spec.limit)
	if f != nil {
		f.Close()
	}
	if err != nil {
		return err
	}
	if actual == target {
		return nil
	}
	if actual != before {
		return errors.New("恢复资源已偏离原状态及批准目标，停止覆盖")
	}
	dir, err := businessDirectory(m.DataDir, filepath.Dir(spec.name), m.UID, m.GID, target.Present)
	if err != nil {
		return err
	}
	defer dir.Close()
	base := filepath.Base(spec.name)
	if !target.Present {
		if err = unix.Unlinkat(int(dir.Fd()), base, 0); err != nil {
			return err
		}
		return dir.Sync()
	}
	src, _, err := secure.OpenRootFile(source, target.Size)
	if err != nil {
		return err
	}
	defer src.Close()
	// One reserved scratch name per resource bounds crash leftovers. It is
	// unapproved copy output, so a replay may unlink it without following it.
	name := fmt.Sprintf(".panel-restore-%s-%02d", operation, index)
	if err = unix.Unlinkat(int(dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	tmp := os.NewFile(uintptr(fd), name)
	defer tmp.Close()
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), contextReader{ctx, io.LimitReader(src, target.Size+1)})
	if err != nil {
		return err
	}
	if n != target.Size || hex.EncodeToString(hash.Sum(nil)) != target.SHA256 {
		return errors.New("安装中的恢复资源散列不匹配")
	}
	if err = tmp.Chown(m.UID, m.GID); err != nil {
		return err
	}
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	// Recheck drift after the copy, before replacing the live basename.
	current, opened, _, err := observe(ctx, m, spec.name, spec.limit)
	if opened != nil {
		opened.Close()
	}
	if err != nil {
		return err
	}
	if current != before {
		return errors.New("恢复资源在安装期间变化")
	}
	var st unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	info, err := tmp.Stat()
	if err != nil {
		return err
	}
	actualStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Ino != actualStat.Ino || st.Dev != uint64(actualStat.Dev) || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("恢复临时文件身份变化")
	}
	if err = unix.Renameat2(int(dir.Fd()), name, int(dir.Fd()), base, 0); err != nil {
		return err
	}
	return dir.Sync()
}
