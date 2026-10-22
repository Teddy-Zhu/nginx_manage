package panelrecovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

const retirementFileLimit = manifestMax + 2048
const retirementShardCount = 128
const retirementShardBytes = 1 << 20

// Retirement receipts are immutable fences, not proof that deletion finished.
// The owning root operation retains that outcome and its original inventory.
func retirementPath(data, id string, create bool) (string, error) {
	if os.Geteuid() != 0 || !idValue.MatchString(id) {
		return "", errors.New("快照退役凭据需要 root 和原快照标识")
	}
	store, err := root(data)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(store), "panel-recovery-history")
	for _, name := range []string{filepath.Dir(dir), dir, filepath.Join(dir, id[:2])} {
		if create && name != filepath.Dir(dir) {
			err = privateDir(name)
		} else {
			err = checkPrivateDir(name)
		}
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, id[:2], id+".json"), nil
}

// CheckRetirement also rejects partial publication: no new capture or restore
// may pass a durable retirement intent while its owner resumes deletion.
func CheckRetirement(data, id string) error {
	name, err := retirementPath(data, id, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = os.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("原快照已提交退役，不能重新捕获或恢复；须查询原维护操作")
}

func RetirementReceipt(data, id string) (Receipt, error) {
	var r Receipt
	name, err := retirementPath(data, id, false)
	if err != nil {
		return r, err
	}
	f, info, err := secure.OpenRootFile(name, retirementFileLimit)
	if err != nil {
		return r, err
	}
	defer f.Close()
	if info.Mode().Perm() != 0400 {
		return r, errors.New("快照退役凭据须为 root 只读")
	}
	raw, err := io.ReadAll(io.LimitReader(f, retirementFileLimit+1))
	if err != nil || !secure.RootFileUnchanged(f, info) {
		return r, errors.Join(err, errors.New("快照退役凭据读取期间变化"))
	}
	if err = decode(bytes.NewReader(raw), &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return r, errors.New("快照退役凭据不是原始规范记录")
	}
	return r, r.Validate(data, id)
}

// RetirementRoom accounts for the complete receipt before any payload unlink.
// Each of the 256 UUID shards has independent bounded reads and byte quotas.
func RetirementRoom(r Receipt) (bool, error) {
	if err := r.Validate(r.Manifest.DataDir, r.Manifest.OperationID); err != nil {
		return false, err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > retirementFileLimit {
		return false, errors.New("快照退役凭据超过单项预算")
	}
	name, err := retirementPath(r.Manifest.DataDir, r.Manifest.OperationID, false)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(name))
	if err != nil {
		return false, err
	}
	entries, readErr := dir.Readdir(retirementShardCount + 1)
	closeErr := dir.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err = errors.Join(readErr, closeErr); err != nil {
		return false, err
	}
	if len(entries) > retirementShardCount {
		return false, errors.New("快照退役分片超过数量预算")
	}
	count, total := len(entries), int64(0)
	found := false
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		st, ok := entry.Sys().(*syscall.Stat_t)
		if !strings.HasSuffix(entry.Name(), ".json") || !idValue.MatchString(id) || id[:2] != r.Manifest.OperationID[:2] || !ok || !entry.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || entry.Mode().Perm() != 0400 && entry.Mode().Perm() != 0600 || entry.Size() < 0 || entry.Size() > retirementFileLimit {
			return false, errors.New("快照退役分片包含不可信材料")
		}
		if id == r.Manifest.OperationID {
			found = true
		} else {
			total += entry.Size()
		}
	}
	if !found {
		count++
	}
	return count <= retirementShardCount && total+int64(len(raw)) <= retirementShardBytes, nil
}

// SaveRetirement is called under LockCleanup, after the complete frozen source
// inventory has been approved. An interrupted write can only be completed with
// the same original bytes; it never grants permission to replace another fence.
func SaveRetirement(r Receipt) error {
	if r.Manifest.ExpiresAt > time.Now().Unix() {
		return errors.New("快照尚未过期，不能提交退役")
	}
	room, err := RetirementRoom(r)
	if err != nil {
		return err
	}
	if !room {
		return errors.New("快照退役凭据达到保留预算，原材料继续保留")
	}
	name, err := retirementPath(r.Manifest.DataDir, r.Manifest.OperationID, true)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(r)
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0400)
	if errors.Is(err, os.ErrExist) {
		f, err = os.OpenFile(name, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 || info.Size() > int64(len(raw)) {
		return errors.New("原快照退役凭据身份不可信")
	}
	old, err := io.ReadAll(io.LimitReader(f, int64(len(raw))+1))
	if err != nil || int64(len(old)) != info.Size() || !secure.RootFileUnchanged(f, info) || !bytes.HasPrefix(raw, old) {
		return errors.Join(err, errors.New("原快照退役凭据与批准不同"))
	}
	if _, err = f.Write(raw[len(old):]); err != nil {
		return err
	}
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	for _, dir := range []string{filepath.Dir(name), filepath.Dir(filepath.Dir(name)), filepath.Dir(filepath.Dir(filepath.Dir(name)))} {
		if err = syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// SnapshotReceipts reads only the bounded live inventory, not ciphertext or any
// retired payload. Unknown or incomplete live material requires its own recovery.
func SnapshotReceipts(data string) ([]Receipt, error) {
	store, err := root(data)
	if err != nil {
		return nil, err
	}
	if err = checkPrivateDir(store); errors.Is(err, os.ErrNotExist) {
		return []Receipt{}, nil
	} else if err != nil {
		return nil, err
	}
	f, err := os.Open(store)
	if err != nil {
		return nil, err
	}
	entries, readErr := f.Readdirnames(SnapshotMax + 3)
	closeErr := f.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err = errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(entries) > SnapshotMax+2 {
		return nil, errors.New("本机恢复存储超过快照数量预算")
	}
	out := []Receipt{}
	for _, id := range entries {
		if id == ".capture.lock" || id == "recovery.key" {
			continue
		}
		if !idValue.MatchString(id) {
			return nil, errors.New("本机恢复存储包含未知材料")
		}
		r, err := ReceiptFor(data, id)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
