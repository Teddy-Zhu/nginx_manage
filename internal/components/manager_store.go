package components

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (m *Manager) entries() ([]os.DirEntry, int, error) {
	// Public history queries are bounded separately. Retaining completed receipts
	// must not exhaust an execution quota for everyday software operations.
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		return nil, 0, err
	}
	count := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, 0, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 || info.Size() > 64<<10 {
			return nil, 0, errors.New("组件操作目录存在不受信任的条目")
		}
		if strings.HasSuffix(entry.Name(), ".json") && ValidID(strings.TrimSuffix(entry.Name(), ".json")) {
			count++
		} else if entry.Name() != ".manager.lock" && !strings.HasPrefix(entry.Name(), ".tmp-") {
			return nil, 0, errors.New("组件操作目录存在未知文件")
		}
	}
	return entries, count, nil
}

func (m *Manager) read(id string) (Operation, error) {
	if !ValidID(id) {
		return Operation{}, errors.New("组件操作标识无效")
	}
	fd, err := unix.Open(filepath.Join(m.Dir, id+".json"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return Operation{}, err
	}
	f := os.NewFile(uintptr(fd), id)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Operation{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 || info.Size() > 64<<10 {
		return Operation{}, errors.New("组件操作记录归属、权限或长度无效")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return Operation{}, errors.New("组件操作记录读取不完整")
	}
	var out Operation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return Operation{}, errors.New("组件操作记录格式无效")
	}
	if err := out.Validate(Request{Protocol: out.Protocol, OperationID: id, Input: out.Input}); err != nil {
		return Operation{}, err
	}
	return out, nil
}
func containsState(state string) bool {
	return state == "queued" || state == "running" || state == "succeeded" || state == "failed" || state == "recovery_required"
}

func (m *Manager) write(out *Operation) error {
	if _, _, err := m.entries(); err != nil {
		return err
	}
	out.UpdatedAt = time.Now().Unix()
	if err := out.Validate(Request{Protocol: out.Protocol, OperationID: out.ID, Input: out.Input}); err != nil {
		return err
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if len(raw) > 64<<10 {
		return errors.New("组件操作记录超过 64 KiB")
	}
	f, err := os.CreateTemp(m.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil && !os.IsNotExist(err) {
			slog.Error("组件记录暂存清理失败", "error", err)
		}
	}()
	err = f.Chmod(0600)
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), filepath.Join(m.Dir, out.ID+".json")); err != nil {
		return err
	}
	dir, err := os.Open(m.Dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
