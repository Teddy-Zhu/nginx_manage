package panelrecovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// Prepared contains only authenticated private source files, never live paths.
type Prepared struct {
	Receipt Receipt
	dir     string
}

func ReceiptFor(data, id string) (Receipt, error) {
	if os.Geteuid() != 0 || !idValue.MatchString(id) {
		return Receipt{}, errors.New("快照批准记录需要 root 和原快照标识")
	}
	store, err := root(data)
	if err != nil {
		return Receipt{}, err
	}
	if err = checkPrivateDir(store); err != nil {
		return Receipt{}, err
	}
	if err = checkPrivateDir(filepath.Join(store, id)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RetirementReceipt(data, id)
		}
		return Receipt{}, err
	}
	r, err := readReceipt(store, id)
	if errors.Is(err, os.ErrNotExist) {
		return RetirementReceipt(data, id)
	}
	if err == nil {
		err = r.Validate(data, id)
	}
	return r, err
}

func restoreDirectory(r Receipt, operation string) (string, error) {
	if !idValue.MatchString(operation) {
		return "", errors.New("恢复操作标识无效")
	}
	store, err := root(r.Manifest.DataDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(store, r.Manifest.OperationID, "restores", operation), nil
}

func rootFileHash(ctx context.Context, name string, limit int64, mode os.FileMode) (string, int64, error) {
	f, info, err := secure.OpenRootFile(name, limit)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if info.Mode().Perm() != mode {
		return "", 0, errors.New("恢复暂存资源权限无效")
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, limit+1)})
	if err != nil {
		return "", 0, err
	}
	if n != info.Size() || !secure.RootFileUnchanged(f, info) {
		return "", 0, errors.New("恢复暂存资源在读取期间变化")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func preparedFiles(ctx context.Context, dir string, r Receipt) error {
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Join(dir, "receipt.json"))
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0400 {
		return errors.New("恢复暂存批准记录权限无效")
	}
	raw, err := secure.ReadRootFile(filepath.Join(dir, "receipt.json"), manifestMax+2048)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, expected) {
		return errors.New("恢复暂存与快照批准记录不一致")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != len(r.Manifest.Files)+1 {
		return errors.New("恢复暂存资源数量不一致")
	}
	for i, file := range r.Manifest.Files {
		h, size, err := rootFileHash(ctx, filepath.Join(dir, fmt.Sprintf("%02d", i)), file.Size, 0400)
		if err != nil {
			return err
		}
		if h != file.SHA256 || size != file.Size {
			return errors.New("恢复暂存资源散列不一致")
		}
	}
	return nil
}

// PrepareRestore requires the caller's root transaction lock. The encrypted
// stream is fully authenticated before a complete cleartext generation is
// published. A previously approved generation can survive local-key loss.
func PrepareRestore(ctx context.Context, data, snapshot, operation string) (Prepared, error) {
	r, err := ReceiptFor(data, snapshot)
	if err != nil {
		return Prepared{}, err
	}
	return PrepareApprovedRestore(ctx, r, operation)
}

// PrepareApprovedRestore also accepts the immutable receipt saved by a root
// recovery transaction, so a complete approved source generation remains usable
// if the original encrypted input is later lost. It cannot invent source files.
func PrepareApprovedRestore(ctx context.Context, r Receipt, operation string) (Prepared, error) {
	var out Prepared
	if os.Geteuid() != 0 {
		return out, errors.New("恢复准备需要 root")
	}
	if err := r.Validate(r.Manifest.DataDir, r.Manifest.OperationID); err != nil {
		return out, err
	}
	data, snapshot := r.Manifest.DataDir, r.Manifest.OperationID
	if err := CheckRetirement(data, snapshot); err != nil {
		return out, err
	}
	dir, err := restoreDirectory(r, operation)
	if err != nil {
		return out, err
	}
	if err = privateDir(filepath.Dir(dir)); err != nil {
		return out, err
	}
	operations, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		return out, err
	}
	if len(operations) > SnapshotMax {
		return out, errors.New("快照恢复记录超过保留上限，须本机处理")
	}
	exists := false
	for _, entry := range operations {
		if !idValue.MatchString(entry.Name()) || !entry.IsDir() {
			return out, errors.New("快照恢复目录包含未知资源，须本机处理")
		}
		if err = checkPrivateDir(filepath.Join(filepath.Dir(dir), entry.Name())); err != nil {
			return out, err
		}
		if entry.Name() == operation {
			exists = true
		}
	}
	if !exists && len(operations) >= SnapshotMax {
		return out, errors.New("快照恢复记录已达保留上限，须本机处理")
	}
	if err = privateDir(dir); err != nil {
		return out, err
	}
	after := filepath.Join(dir, "after")
	if _, err = os.Lstat(after); err == nil {
		if err = preparedFiles(ctx, after, r); err != nil {
			return out, err
		}
		return Prepared{Receipt: r, dir: dir}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, err
	}
	if len(entries) >= SnapshotMax+1 {
		return out, errors.New("恢复暂存已达中断保留上限，须本机处理")
	}
	tmp, err := os.MkdirTemp(dir, ".after-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(tmp)
	index := 0
	result, err := inspect(ctx, data, snapshot, func(file File, src io.Reader) (int64, error) {
		f, err := os.OpenFile(filepath.Join(tmp, fmt.Sprintf("%02d", index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		n, err := io.Copy(f, src)
		if err != nil {
			return n, err
		}
		if err = f.Chmod(0400); err != nil {
			return n, err
		}
		if err = f.Sync(); err != nil {
			return n, err
		}
		index++
		return n, f.Close()
	})
	if err != nil {
		return out, err
	}
	expected, err := json.Marshal(r)
	if err != nil {
		return out, err
	}
	actual, err := json.Marshal(result.Receipt)
	if err != nil || !bytes.Equal(actual, expected) {
		return out, errors.New("快照批准记录在准备期间变化")
	}
	if err = writeFile(filepath.Join(tmp, "receipt.json"), expected, 0400); err != nil {
		return out, err
	}
	if err = syncDir(tmp); err != nil {
		return out, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, after, unix.RENAME_NOREPLACE); err != nil {
		return out, err
	}
	if err = syncDir(dir); err != nil {
		return out, err
	}
	// Only unapproved source scratch is disposable; before-images are retained.
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".after-") {
			if err = os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return out, err
			}
		}
	}
	return Prepared{Receipt: r, dir: dir}, nil
}
