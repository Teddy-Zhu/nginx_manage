package panelrecovery

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"nginxpanel/internal/secure"
)

func (r Receipt) validate(data, id string) error {
	m := r.Manifest
	if err := Validate(Input{DataDir: m.DataDir, OperationID: m.OperationID, MaintenanceID: m.MaintenanceID, Epoch: m.Epoch, UID: m.UID, GID: m.GID}); err != nil {
		return err
	}
	if m.Schema != Schema || m.DataDir != data || m.OperationID != id || !m.Database.valid() || !hashValue.MatchString(m.CaptureBinarySHA256) || m.CreatedAt <= 0 || m.CreatedAt > time.Now().Unix()+300 || m.ExpiresAt != m.CreatedAt+Lifetime || len(m.Files) != len(resources) || !hashValue.MatchString(r.ManifestSHA256) || !hashValue.MatchString(r.ArchiveSHA256) || !hashValue.MatchString(r.KeyID) || r.ArchiveSize <= 0 || r.ArchiveSize > ArchiveMax {
		return errors.New("本机恢复快照批准身份无效")
	}
	for i, file := range m.Files {
		if file.Name != resources[i].name || file.Size <= 0 || file.Size > resources[i].limit || !hashValue.MatchString(file.SHA256) {
			return errors.New("本机恢复快照资源清单无效")
		}
	}
	if m.Files[1].Size != 32 {
		return errors.New("本机恢复快照主密钥长度无效")
	}
	raw, err := json.Marshal(m)
	if err != nil || secure.Hash(raw) != r.ManifestSHA256 {
		return errors.New("本机恢复快照清单散列不匹配")
	}
	return nil
}

func validHeader(h *tar.Header, name string, size int64) bool {
	return h != nil && h.Name == name && h.Typeflag == tar.TypeReg && h.Mode == 0600 && h.Size == size && h.Uid == 0 && h.Gid == 0 && h.Linkname == "" && len(h.PAXRecords) == 0 && len(h.Xattrs) == 0
}

// Inspect fully authenticates ciphertext, encrypted inventory and every file.
// Expiry is reported, never used to delete the only surviving recovery evidence.
// It creates no files and does not open the business database or business key.
func Inspect(ctx context.Context, data, id string) (Result, error) {
	var out Result
	if os.Geteuid() != 0 || !idValue.MatchString(id) {
		return out, errors.New("本机恢复快照检查需要 root 和原操作标识")
	}
	store, err := root(data)
	if err != nil {
		return out, err
	}
	if err = checkPrivateDir(store); err != nil {
		return out, err
	}
	if err = checkPrivateDir(filepath.Join(store, id)); err != nil {
		return out, err
	}
	r, err := readReceipt(store, id)
	if err != nil {
		return out, err
	}
	if err = r.validate(data, id); err != nil {
		return out, err
	}
	identity, err := key(store, false)
	if err != nil {
		return out, err
	}
	if secure.Hash([]byte(identity.Recipient().String())) != r.KeyID {
		return out, errors.New("快照与本机恢复密钥不匹配")
	}
	f, info, err := secure.OpenRootFile(filepath.Join(store, id, "snapshot.age"), ArchiveMax)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if info.Mode().Perm() != 0600 || info.Size() != r.ArchiveSize {
		return out, errors.New("加密快照权限或长度已变化")
	}
	cipherHash := sha256.New()
	source := io.TeeReader(contextReader{ctx, io.LimitReader(f, ArchiveMax+1)}, cipherHash)
	plain, err := age.Decrypt(source, identity)
	if err != nil {
		return out, err
	}
	bounded := io.LimitReader(plain, ArchiveMax+1)
	tr := tar.NewReader(bounded)
	raw, err := json.Marshal(r.Manifest)
	if err != nil {
		return out, err
	}
	h, err := tr.Next()
	if err != nil || !validHeader(h, "manifest.json", int64(len(raw))) {
		return out, errors.New("加密快照缺少原始清单")
	}
	manifest, err := io.ReadAll(io.LimitReader(tr, manifestMax+1))
	if err != nil || !bytes.Equal(manifest, raw) {
		return out, errors.New("加密快照与 root 批准清单不匹配")
	}
	for _, file := range r.Manifest.Files {
		h, err = tr.Next()
		if err != nil || !validHeader(h, file.Name, file.Size) {
			return out, errors.New("加密快照资源头无效")
		}
		hash := sha256.New()
		n, err := io.Copy(hash, contextReader{ctx, io.LimitReader(tr, file.Size+1)})
		if err != nil || n != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
			return out, errors.New("加密快照资源不完整或散列不匹配")
		}
	}
	if _, err = tr.Next(); err != io.EOF {
		return out, errors.New("加密快照包含额外资源或无效尾部")
	}
	// Reach the authenticated stream terminator; a valid tar prefix is not proof
	// that age's final chunk or the entire ciphertext has been received.
	if n, err := io.Copy(io.Discard, bounded); err != nil || n != 0 {
		return out, errors.New("加密快照尾部认证失败")
	}
	if n, err := io.Copy(io.Discard, source); err != nil || n != 0 || !secure.RootFileUnchanged(f, info) || hex.EncodeToString(cipherHash.Sum(nil)) != r.ArchiveSHA256 {
		return out, errors.New("加密快照密文已变化或包含额外数据")
	}
	return Result{State: "verified", Receipt: r, Expired: time.Now().Unix() >= r.Manifest.ExpiresAt}, nil
}
