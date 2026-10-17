package agent

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
	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func captureFail2banState(ctx context.Context, in Fail2banStateSnapshotOptions, j *Journal) (out Fail2banStateSnapshot, resultErr error) {
	basis, err := readFail2banStateBasis(ctx, in.DataDir)
	if err != nil {
		return out, err
	}
	stateDir := filepath.Join(basis.Managed.work(), "state")
	sources, err := openFail2banStateSources(ctx, stateDir)
	if err != nil {
		return out, err
	}
	defer closeFail2banStateSources(sources)
	m := fail2banStateManifest{Schema: 1, OperationID: in.OperationID, DataDir: in.DataDir, CreatedAt: time.Now().Unix(), Basis: basis, Files: make([]fail2banStateFile, len(sources))}
	var reserve int64 = 2 << 20
	for i, source := range sources {
		m.Files[i] = source.meta
		reserve += source.meta.Size
	}
	if err = m.validate(in.DataDir, in.OperationID); err != nil {
		return out, err
	}
	raw, err := fail2banStateJSON(m)
	if err != nil {
		return out, err
	}
	store := fail2banStateDir(in.DataDir)
	if err = fail2banStatePrivateDir(store, true); err != nil {
		return out, err
	}
	if err = syncDir(filepath.Dir(store)); err != nil {
		return out, err
	}
	if err = fail2banStateQuota(store, reserve, true); err != nil {
		return out, err
	}
	identity, err := fail2banStateKey(store, true)
	if err != nil {
		return out, err
	}
	tmp, err := os.MkdirTemp(store, ".capture-")
	if err != nil {
		return out, err
	}
	published := false
	defer func() {
		if !published {
			resultErr = errors.Join(resultErr, os.RemoveAll(tmp))
		}
	}()
	r, err := sealFail2banState(ctx, tmp, m, raw, sources, identity)
	if err != nil {
		return out, err
	}
	if _, _, err = readFail2banStateArchive(ctx, in.DataDir, in.OperationID, tmp, nil); err != nil {
		return out, err
	}
	after, err := readFail2banStateBasis(ctx, in.DataDir)
	if err != nil {
		return out, err
	}
	beforeRaw, err := fail2banStateJSON(basis)
	if err != nil {
		return out, err
	}
	afterRaw, err := fail2banStateJSON(after)
	if err != nil || !bytes.Equal(beforeRaw, afterRaw) {
		return out, errors.Join(errors.New("状态捕获期间实例、配置或服务发生变化"), err)
	}
	if err = fail2banUpgradeIdle(j); err != nil {
		return out, err
	}
	if err = unchangedFail2banStateSources(stateDir, sources); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, filepath.Join(store, in.OperationID), unix.RENAME_NOREPLACE); err != nil {
		return out, err
	}
	published = true
	if err = syncDir(store); err != nil {
		return out, err
	}
	return r.result("captured", m), nil
}

func sealFail2banState(ctx context.Context, dir string, m fail2banStateManifest, raw []byte, sources []fail2banStateSource, identity *age.X25519Identity) (fail2banStateReceipt, error) {
	var out fail2banStateReceipt
	f, err := os.OpenFile(filepath.Join(dir, "snapshot.age"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return out, err
	}
	defer f.Close()
	digest := sha256.New()
	w, err := age.Encrypt(io.MultiWriter(f, digest), identity.Recipient())
	if err != nil {
		return out, err
	}
	tw := tar.NewWriter(w)
	if err = tw.WriteHeader(fail2banStateHeader("manifest.json", int64(len(raw)))); err != nil {
		return out, err
	}
	if _, err = tw.Write(raw); err != nil {
		return out, err
	}
	for _, source := range sources {
		if !source.meta.Present {
			continue
		}
		if err = tw.WriteHeader(fail2banStateHeader(source.meta.Name, source.meta.Size)); err != nil {
			return out, err
		}
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(tw, h), fail2banStateReader{ctx, io.LimitReader(source.file, source.meta.Size+1)})
		if e != nil || n != source.meta.Size || hex.EncodeToString(h.Sum(nil)) != source.meta.SHA256 || !secure.RootFileUnchanged(source.file, source.info) {
			return out, errors.Join(errors.New("Fail2ban 状态在加密期间变化"), e)
		}
	}
	if err = tw.Close(); err != nil {
		return out, err
	}
	if err = w.Close(); err != nil {
		return out, err
	}
	if err = f.Sync(); err != nil {
		return out, err
	}
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	if info.Size() <= 0 || info.Size() > fail2banStateArchiveLimit {
		return out, errors.New("Fail2ban 加密状态快照超过容量限制")
	}
	if err = f.Close(); err != nil {
		return out, err
	}
	out = fail2banStateReceipt{Schema: 1, OperationID: m.OperationID, DataDir: m.DataDir, CreatedAt: m.CreatedAt, InstallationID: m.Basis.Managed.OperationID, EventID: m.Basis.Managed.EventID, Component: fail2banUpgradeComponent(&m.Basis.Managed), MachineID: m.Basis.MachineID, ManifestSHA256: secure.Hash(raw), ArchiveSHA256: hex.EncodeToString(digest.Sum(nil)), ArchiveSize: info.Size(), KeyID: secure.Hash([]byte(identity.Recipient().String()))}
	if err = out.validate(m.DataDir, m.OperationID); err != nil {
		return fail2banStateReceipt{}, err
	}
	receipt, err := fail2banStateJSON(out)
	if err != nil {
		return fail2banStateReceipt{}, err
	}
	if err = fail2banStateWrite(filepath.Join(dir, "receipt.json"), receipt); err != nil {
		return fail2banStateReceipt{}, err
	}
	if err = syncDir(dir); err != nil {
		return fail2banStateReceipt{}, err
	}
	return out, nil
}

func fail2banStateHeader(name string, size int64) *tar.Header {
	return &tar.Header{Name: name, Mode: 0600, Size: size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
}

func validFail2banStateHeader(h *tar.Header, name string, size int64) bool {
	return h != nil && h.Name == name && h.Typeflag == tar.TypeReg && h.Mode == 0600 && h.Size == size && h.Uid == 0 && h.Gid == 0 && h.Linkname == "" && len(h.PAXRecords) == 0 && len(h.Xattrs) == 0
}

// A visitor writes only to a private, unpublished quarantine. Its output must
// not be used until the complete age stream, ciphertext and inventory pass.
func readFail2banStateArchive(ctx context.Context, data, id, dir string, visit func(fail2banStateFile, io.Reader) (int64, error)) (fail2banStateReceipt, fail2banStateManifest, error) {
	var r fail2banStateReceipt
	var m fail2banStateManifest
	fail := func(err error) (fail2banStateReceipt, fail2banStateManifest, error) {
		return fail2banStateReceipt{}, fail2banStateManifest{}, err
	}
	store := fail2banStateDir(data)
	if err := fail2banStatePrivateDir(store, false); err != nil {
		return fail(err)
	}
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return fail(err)
	}
	if err := readFail2banNginxJSON(filepath.Join(dir, "receipt.json"), &r, 16<<10); err != nil {
		return fail(err)
	}
	if err := r.validate(data, id); err != nil {
		return fail(err)
	}
	machine, _, err := hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil || machine != r.MachineID {
		return fail(errors.Join(errors.New("Fail2ban 状态快照不属于当前宿主机"), err))
	}
	identity, err := fail2banStateKey(store, false)
	if err != nil {
		return fail(err)
	}
	if secure.Hash([]byte(identity.Recipient().String())) != r.KeyID {
		return fail(errors.New("Fail2ban 状态快照与本机密钥不匹配"))
	}
	f, info, err := secure.OpenRootFile(filepath.Join(dir, "snapshot.age"), fail2banStateArchiveLimit)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	if info.Mode().Perm() != 0600 || info.Size() != r.ArchiveSize {
		return fail(errors.New("Fail2ban 加密状态快照权限或长度不匹配"))
	}
	cipherHash := sha256.New()
	source := io.TeeReader(fail2banStateReader{ctx, io.LimitReader(f, fail2banStateArchiveLimit+1)}, cipherHash)
	plain, err := age.Decrypt(source, identity)
	if err != nil {
		return fail(err)
	}
	bounded := io.LimitReader(plain, fail2banStateArchiveLimit+1)
	tr := tar.NewReader(bounded)
	header, err := tr.Next()
	if err != nil || header.Size < 0 || header.Size > fail2banStateManifestLimit || !validFail2banStateHeader(header, "manifest.json", header.Size) {
		return fail(errors.New("Fail2ban 加密状态快照清单头无效"))
	}
	raw, err := io.ReadAll(io.LimitReader(tr, fail2banStateManifestLimit+1))
	if err != nil || secure.Hash(raw) != r.ManifestSHA256 {
		return fail(errors.Join(errors.New("Fail2ban 加密状态快照清单不匹配"), err))
	}
	if err = decodeFail2banNginxJSON(raw, &m); err != nil {
		return fail(err)
	}
	if err = m.validate(data, id); err != nil {
		return fail(err)
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, raw) || r.CreatedAt != m.CreatedAt || r.MachineID != m.Basis.MachineID || r.InstallationID != m.Basis.Managed.OperationID || r.EventID != m.Basis.Managed.EventID || r.Component != fail2banUpgradeComponent(&m.Basis.Managed) {
		return fail(errors.Join(errors.New("Fail2ban 状态快照原始身份不匹配"), err))
	}
	for _, file := range m.Files {
		if !file.Present {
			continue
		}
		header, err = tr.Next()
		if err != nil || !validFail2banStateHeader(header, file.Name, file.Size) {
			return fail(errors.New("Fail2ban 加密状态文件头不匹配"))
		}
		h := sha256.New()
		reader := io.TeeReader(fail2banStateReader{ctx, io.LimitReader(tr, file.Size+1)}, h)
		var n int64
		if visit == nil {
			n, err = io.Copy(io.Discard, reader)
		} else {
			n, err = visit(file, reader)
		}
		if err != nil || n != file.Size || hex.EncodeToString(h.Sum(nil)) != file.SHA256 {
			return fail(errors.Join(errors.New("Fail2ban 加密状态文件不完整"), err))
		}
	}
	if _, err = tr.Next(); err != io.EOF {
		return fail(errors.New("Fail2ban 加密状态快照包含额外或无效资源"))
	}
	if n, e := io.Copy(io.Discard, bounded); e != nil || n != 0 {
		return fail(errors.Join(errors.New("Fail2ban 加密状态快照尾部认证失败"), e))
	}
	if n, e := io.Copy(io.Discard, source); e != nil || n != 0 || !secure.RootFileUnchanged(f, info) || hex.EncodeToString(cipherHash.Sum(nil)) != r.ArchiveSHA256 {
		return fail(errors.Join(errors.New("Fail2ban 状态密文变化或包含额外数据"), e))
	}
	return r, m, ctx.Err()
}
