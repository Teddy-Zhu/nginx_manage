package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type fail2banStatePrepared struct {
	Schema         int    `json:"schema"`
	OperationID    string `json:"operation_id"`
	ReceiptSHA256  string `json:"receipt_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func fail2banStatePreparation(r fail2banStateReceipt) (fail2banStatePrepared, error) {
	raw, err := fail2banStateJSON(r)
	if err != nil {
		return fail2banStatePrepared{}, err
	}
	return fail2banStatePrepared{Schema: 1, OperationID: r.OperationID, ReceiptSHA256: secure.Hash(raw), ManifestSHA256: r.ManifestSHA256}, nil
}

func verifyFail2banStatePrepared(ctx context.Context, dir string, r fail2banStateReceipt, m fail2banStateManifest) error {
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return err
	}
	want, err := fail2banStatePreparation(r)
	if err != nil {
		return err
	}
	var proof fail2banStatePrepared
	if err = readFail2banNginxJSON(filepath.Join(dir, "proof.json"), &proof, 4096); err != nil {
		return err
	}
	if proof != want {
		return errors.New("Fail2ban 状态恢复暂存与原快照回执不匹配")
	}
	raw, err := secure.ReadRootFile(filepath.Join(dir, "manifest.json"), fail2banStateManifestLimit)
	if err != nil {
		return err
	}
	manifest, err := fail2banStateJSON(m)
	if err != nil || !bytes.Equal(raw, manifest) {
		return errors.Join(errors.New("Fail2ban 状态恢复暂存清单不匹配"), err)
	}
	expected := map[string]bool{"proof.json": true, "manifest.json": true}
	for _, file := range m.Files {
		if !file.Present {
			continue
		}
		expected[file.Name] = true
		f, info, err := secure.OpenRootFile(filepath.Join(dir, file.Name), file.Size)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if info.Mode().Perm() != 0600 || info.Size() != file.Size {
			return errors.New("Fail2ban 状态恢复暂存文件权限或长度不匹配")
		}
		digest, err := hashFail2banStateFile(ctx, filepath.Join(dir, file.Name), file.Size)
		if err != nil || digest != file.SHA256 {
			return errors.Join(errors.New("Fail2ban 状态恢复暂存文件已变化"), err)
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := f.ReadDir(len(expected) + 1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) != len(expected) {
		return errors.New("Fail2ban 状态恢复暂存包含缺失或额外材料")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return errors.New("Fail2ban 状态恢复暂存包含未知材料")
		}
	}
	return ctx.Err()
}

// Preparing is a quarantine-only operation. It never opens SQLite, replaces a
// live file, selects historical grants or starts a service. The later upgrade
// coordinator must separately fence, preserve its before-image and reconcile.
func prepareFail2banState(ctx context.Context, in Fail2banStateSnapshotOptions) (out Fail2banStateSnapshot, resultErr error) {
	store := fail2banStateDir(in.DataDir)
	dir := filepath.Join(store, in.OperationID)
	prepared := filepath.Join(dir, "prepared")
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return out, err
	}
	if _, err := os.Lstat(prepared); err == nil {
		r, m, e := readFail2banStateArchive(ctx, in.DataDir, in.OperationID, dir, nil)
		if e != nil {
			return out, e
		}
		if e = verifyFail2banStatePrepared(ctx, prepared, r, m); e != nil {
			return out, e
		}
		return r.result("prepared", m), nil
	} else if !os.IsNotExist(err) {
		return out, err
	}
	// The uncompressed age/tar archive is larger than its plaintext files and
	// manifest. Its checked length plus the proof bounds staging without a
	// second decryption solely to learn resource sizes.
	var receipt fail2banStateReceipt
	if err := readFail2banNginxJSON(filepath.Join(dir, "receipt.json"), &receipt, 16<<10); err != nil {
		return out, err
	}
	if err := receipt.validate(in.DataDir, in.OperationID); err != nil {
		return out, err
	}
	if err := fail2banStateQuota(store, receipt.ArchiveSize+4096, false); err != nil {
		return out, err
	}
	tmp, err := os.MkdirTemp(dir, ".prepare-")
	if err != nil {
		return out, err
	}
	published := false
	defer func() {
		if !published {
			resultErr = errors.Join(resultErr, os.RemoveAll(tmp))
		}
	}()
	visit := func(file fail2banStateFile, src io.Reader) (int64, error) {
		f, err := os.OpenFile(filepath.Join(tmp, file.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return 0, err
		}
		n, copied := io.Copy(f, src)
		synced := f.Sync()
		closed := f.Close()
		return n, errors.Join(copied, synced, closed)
	}
	r, m, err := readFail2banStateArchive(ctx, in.DataDir, in.OperationID, dir, visit)
	if err != nil {
		return out, err
	}
	raw, err := fail2banStateJSON(m)
	if err != nil {
		return out, err
	}
	if err = fail2banStateWrite(filepath.Join(tmp, "manifest.json"), raw); err != nil {
		return out, err
	}
	proof, err := fail2banStatePreparation(r)
	if err != nil {
		return out, err
	}
	raw, err = fail2banStateJSON(proof)
	if err != nil {
		return out, err
	}
	if err = fail2banStateWrite(filepath.Join(tmp, "proof.json"), raw); err != nil {
		return out, err
	}
	if err = syncDir(tmp); err != nil {
		return out, err
	}
	if err = verifyFail2banStatePrepared(ctx, tmp, r, m); err != nil {
		return out, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, prepared, unix.RENAME_NOREPLACE); err != nil {
		return out, err
	}
	published = true
	if err = syncDir(dir); err != nil {
		return out, err
	}
	return r.result("prepared", m), nil
}
