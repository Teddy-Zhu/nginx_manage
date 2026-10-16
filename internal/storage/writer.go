package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

var writerID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var writerHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// WriterFence survives an interrupted restore. Serve must not open its vault or
// database until the original recovery transaction has installed every resource.
type WriterFence struct {
	Schema        int    `json:"schema"`
	OperationID   string `json:"operation_id"`
	SnapshotID    string `json:"snapshot_id"`
	MaintenanceID string `json:"maintenance_id"`
	RequestSHA256 string `json:"request_sha256"`
}

func WriterFencePath(data string) string {
	return filepath.Join(data, "run", "panel-writer-fence.json")
}

func writerDirectory(data string) error {
	if !filepath.IsAbs(data) || filepath.Clean(data) != data {
		return errors.New("正式面板写锁需要规范绝对目录")
	}
	name := filepath.Join(data, "run")
	// Validate without creating directories from a non-root startup path.
	for dir := name; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("正式面板写锁上层须由 root 持有且不可被其他账户写入")
		}
		if dir == "/" {
			break
		}
	}
	return nil
}

func writerFile(data string, gid int) (*os.File, error) {
	if !filepath.IsAbs(data) || filepath.Clean(data) != data || gid <= 0 || uint64(gid) > uint64(^uint32(0)) {
		return nil, errors.New("正式面板写锁的目录或专用组无效")
	}
	if err := writerDirectory(data); err != nil {
		return nil, err
	}
	name := filepath.Join(data, "run", "panel-writer.lock")
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Open(name, flags, 0660)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, e := f.Stat()
	if err == nil {
		err = e
	}
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0660 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Uid != 0 || int(st.Gid) != gid || st.Nlink != 1 {
			err = errors.New("正式面板写锁的归属、类型或权限无效")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// BindWriter creates a stable root-owned inode in the root-owned run directory.
// The serve group may flock it, but cannot replace it by unlinking its pathname.
func BindWriter(data string, gid int) error {
	if os.Geteuid() != 0 {
		return errors.New("正式面板写锁初始化需要 root")
	}
	f, err := writerFile(data, gid)
	if err == nil {
		if err = f.Close(); err != nil {
			return err
		}
		return syncWriterDirectory(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err = os.CreateTemp(filepath.Join(data, "run"), ".panel-writer-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chown(0, gid); err != nil {
		return err
	}
	if err = f.Chmod(0660); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	err = unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, filepath.Join(data, "run", "panel-writer.lock"), unix.RENAME_NOREPLACE)
	if errors.Is(err, os.ErrExist) {
		var existing *os.File
		existing, err = writerFile(data, gid)
		if err == nil {
			err = existing.Close()
		}
	}
	if err != nil {
		return err
	}
	return syncWriterDirectory(data)
}

func LockWriter(data string, gid int) (func(), error) { return lockWriter(data, gid, false) }

func LockWriterForRecovery(data string, gid int) (func(), error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("恢复写锁仅允许 root 使用")
	}
	return lockWriter(data, gid, true)
}

func lockWriter(data string, gid int, recovery bool) (func(), error) {
	f, err := writerFile(data, gid)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("已有面板进程或恢复执行器持有写锁")
	}
	if !recovery {
		present, e := WriterFenced(data)
		if e != nil || present {
			f.Close()
			return nil, errors.Join(e, errors.New("本机恢复尚未完成，须继续原恢复操作"))
		}
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

func WriterFenced(data string) (bool, error) {
	if err := writerDirectory(data); err != nil {
		return false, err
	}
	_, err := os.Lstat(WriterFencePath(data))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (f WriterFence) valid() bool {
	return f.Schema == 1 && writerID.MatchString(f.OperationID) && writerID.MatchString(f.SnapshotID) && writerID.MatchString(f.MaintenanceID) && writerHash.MatchString(f.RequestSHA256)
}

func ReadWriterFence(data string) (WriterFence, error) {
	var out WriterFence
	if err := writerDirectory(data); err != nil {
		return out, err
	}
	f, info, err := secure.OpenRootFile(WriterFencePath(data), 4096)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if info.Mode().Perm() != 0400 {
		return out, errors.New("恢复标记须为 root 只读文件")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return out, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || !out.valid() || !secure.RootFileUnchanged(f, info) {
		return out, errors.New("恢复标记内容无效")
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return out, errors.New("恢复标记不是原始规范记录")
	}
	return out, nil
}

func BindWriterFence(data string, expected WriterFence) error {
	if os.Geteuid() != 0 || !expected.valid() {
		return errors.New("恢复标记需要 root 和有效的原操作身份")
	}
	if prior, err := ReadWriterFence(data); err == nil {
		if prior != expected {
			return errors.New("已有其他恢复操作的持久标记")
		}
		return syncWriterDirectory(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Join(data, "run"), ".panel-fence-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
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
	if err = unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, WriterFencePath(data), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncWriterDirectory(data)
}

func ClearWriterFence(data string, expected WriterFence) error {
	if os.Geteuid() != 0 || !expected.valid() {
		return errors.New("解除恢复标记需要 root 和原操作身份")
	}
	prior, err := ReadWriterFence(data)
	if errors.Is(err, os.ErrNotExist) {
		return syncWriterDirectory(data)
	}
	if err != nil {
		return err
	}
	if prior != expected {
		return errors.New("不能解除其他操作的恢复标记")
	}
	if err = os.Remove(WriterFencePath(data)); err != nil {
		return err
	}
	return syncWriterDirectory(data)
}

func syncWriterDirectory(data string) error {
	f, err := os.Open(filepath.Join(data, "run"))
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return err
	}
	parent, err := os.Open(data)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
