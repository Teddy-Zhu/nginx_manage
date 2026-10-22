package panelrecovery

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type boundedOutput struct{ raw []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.raw)+len(p) > 4096 {
		return 0, errors.New("快照助手输出超过限制")
	}
	b.raw = append(b.raw, p...)
	return len(p), nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func captureLock(store string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(store, ".capture.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	checked, info, err := secure.OpenRootFile(f.Name(), 0)
	if err == nil {
		checked.Close()
		opened, e := f.Stat()
		if e != nil || !os.SameFile(info, opened) || info.Mode().Perm() != 0600 {
			err = errors.New("本机恢复存储锁不可信")
		}
	}
	if err == nil {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

func storeUsage(store string) (int64, int, error) {
	entries, err := os.ReadDir(store)
	if err != nil {
		return 0, 0, err
	}
	var total int64
	count := 0
	for _, entry := range entries {
		if entry.Name() == ".capture.lock" || entry.Name() == "recovery.key" {
			continue
		}
		if !entry.IsDir() {
			return 0, 0, errors.New("本机恢复存储存在未知文件")
		}
		count++
		name := filepath.Join(store, entry.Name(), "snapshot.age")
		f, info, e := secure.OpenRootFile(name, ArchiveMax)
		if e != nil {
			return 0, 0, errors.New("本机恢复存储存在不完整快照，须本机处理")
		}
		f.Close()
		total += info.Size()
	}
	return total, count, nil
}

func databaseChild(ctx context.Context, in Input) (Database, string, error) {
	var meta Database
	binary, err := os.Executable()
	if err != nil {
		return meta, "", err
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return meta, "", err
	}
	hash, err := secure.HashRootFile(binary, 192<<20)
	if err != nil {
		return meta, "", err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(call, binary, "panel-snapshot-db", "--data-dir", in.DataDir, "--recovery-operation", in.OperationID)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=" + workspace(in.DataDir, in.OperationID)}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(in.UID), Gid: uint32(in.GID), Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	var out, diagnostic boundedOutput
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err = cmd.Run(); err != nil {
		return meta, "", fmt.Errorf("非 root SQLite 快照助手失败：%w；%s", err, strings.TrimSpace(string(diagnostic.raw)))
	}
	if err = decode(bytes.NewReader(out.raw), &meta); err != nil || !meta.valid() {
		return meta, "", errors.New("SQLite 快照助手返回无效身份")
	}
	if after, err := secure.HashRootFile(binary, 192<<20); err != nil || after != hash {
		return meta, "", errors.New("快照助手程序在执行期间变化")
	}
	return meta, hash, nil
}

// Capture requires the caller to hold independent maintenance admission for
// the entire call. It never releases that admission or changes live files.
func Capture(ctx context.Context, in Input) (out Result, retErr error) {
	if os.Geteuid() != 0 {
		return out, errors.New("本机恢复快照需要 root")
	}
	if err := Validate(in); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	store, _ := root(in.DataDir)
	if err := privateDir(store); err != nil {
		return out, err
	}
	unlock, err := captureLock(store)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = CheckRetirement(in.DataDir, in.OperationID); err != nil {
		return out, err
	}
	if _, err = os.Lstat(filepath.Join(store, in.OperationID)); err == nil {
		out, err = Inspect(ctx, in.DataDir, in.OperationID)
		if err == nil {
			m := out.Receipt.Manifest
			if m.MaintenanceID != in.MaintenanceID || m.Epoch != in.Epoch || m.UID != in.UID || m.GID != in.GID {
				return Result{}, errors.New("快照标识已有不同维护授权")
			}
			if _, e := os.Lstat(workspace(in.DataDir, in.OperationID)); !errors.Is(e, os.ErrNotExist) {
				return Result{}, errors.New("已批准快照仍有未清理的助手暂存，须本机处理")
			}
			err = syncDir(store)
		}
		return out, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	usage, count, err := storeUsage(store)
	if err != nil {
		return out, err
	}
	if count >= SnapshotMax || usage+ArchiveMax > StoreMax {
		return out, errors.New("本机恢复快照已达容量上限，不自动清理救援依据")
	}
	identity, err := key(store, count == 0)
	if err != nil {
		return out, err
	}
	parent := filepath.Dir(workspace(in.DataDir, in.OperationID))
	if err = secure.RootDirectory(parent, 0711); err != nil {
		return out, err
	}
	info, err := os.Lstat(parent)
	if err != nil || info.Mode().Perm() != 0711 && info.Mode().Perm() != 0700 {
		return out, errors.New("快照助手父目录权限无效")
	}
	if err = os.Chmod(parent, 0711); err != nil {
		return out, err
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return out, err
	}
	if len(entries) >= SnapshotMax {
		return out, errors.New("快照助手暂存目录已达上限，须本机处理")
	}
	dir := workspace(in.DataDir, in.OperationID)
	if err = os.Mkdir(dir, 0700); err != nil {
		return out, errors.New("快照助手目录已存在或无法创建，拒绝重复执行未知捕获")
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			out = Result{}
			retErr = errors.Join(retErr, fmt.Errorf("清理快照助手暂存失败：%w", err))
		}
	}()
	if err = os.Chown(dir, in.UID, in.GID); err != nil {
		return out, err
	}
	meta, binaryHash, err := databaseChild(ctx, in)
	if err != nil {
		return out, err
	}
	m := Manifest{Schema: Schema, DataDir: in.DataDir, OperationID: in.OperationID, MaintenanceID: in.MaintenanceID, Epoch: in.Epoch, UID: in.UID, GID: in.GID, CreatedAt: time.Now().Unix(), CaptureBinarySHA256: binaryHash, Database: meta}
	m.ExpiresAt = m.CreatedAt + Lifetime
	return seal(ctx, store, dir, m, identity)
}

func seal(ctx context.Context, store, sourceDir string, m Manifest, identity *age.X25519Identity) (Result, error) {
	var out Result
	files := make([]*os.File, 0, len(resources))
	infos := make([]os.FileInfo, 0, len(resources))
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	material := map[string][]byte{}
	for i, resource := range resources {
		name := filepath.Join(m.DataDir, resource.name)
		if i == 0 {
			name = filepath.Join(sourceDir, "panel.db")
		}
		f, info, err := openOwned(name, m.UID, m.GID, resource.limit)
		if err != nil {
			return out, err
		}
		files, infos = append(files, f), append(infos, info)
		h := sha256.New()
		var target io.Writer = h
		var buf bytes.Buffer
		if i != 0 {
			target = io.MultiWriter(h, &buf)
		}
		n, err := io.Copy(target, contextReader{ctx, io.LimitReader(f, resource.limit+1)})
		if err != nil || n != info.Size() || !secure.RootFileUnchanged(f, info) {
			return out, errors.Join(err, errors.New("快照资源在捕获期间变化或读取失败"))
		}
		m.Files = append(m.Files, File{Name: resource.name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
		material[resource.name] = buf.Bytes()
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return out, err
		}
	}
	if len(material["secrets/master.key"]) != 32 {
		return out, errors.New("业务主密钥长度无效")
	}
	if _, err := tls.X509KeyPair(material["secrets/node-tls/cert.pem"], material["secrets/node-tls/key.pem"]); err != nil {
		return out, errors.New("节点 TLS 证书与私钥不匹配")
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > manifestMax {
		return out, errors.New("恢复快照清单超过上限")
	}
	tmp, err := os.MkdirTemp(store, ".snapshot-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(tmp)
	f, err := os.OpenFile(filepath.Join(tmp, "snapshot.age"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	w, err := age.Encrypt(io.MultiWriter(f, h), identity.Recipient())
	if err != nil {
		return out, err
	}
	tw := tar.NewWriter(w)
	if err = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err == nil {
		_, err = tw.Write(raw)
	}
	for i, file := range m.Files {
		if err != nil {
			break
		}
		if err = tw.WriteHeader(&tar.Header{Name: file.Name, Mode: 0600, Size: file.Size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			break
		}
		digest := sha256.New()
		var n int64
		n, err = io.Copy(io.MultiWriter(tw, digest), contextReader{ctx, io.LimitReader(files[i], file.Size+1)})
		if err == nil && (n != file.Size || hex.EncodeToString(digest.Sum(nil)) != file.SHA256 || !secure.RootFileUnchanged(files[i], infos[i])) {
			err = errors.New("快照资源在加密期间变化")
		}
	}
	if err != nil {
		return out, err
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
	if info.Size() <= 0 || info.Size() > ArchiveMax {
		return out, errors.New("加密快照超过容量限制")
	}
	if err = f.Close(); err != nil {
		return out, err
	}
	r := Receipt{Manifest: m, ManifestSHA256: secure.Hash(raw), ArchiveSize: info.Size(), ArchiveSHA256: hex.EncodeToString(h.Sum(nil)), KeyID: secure.Hash([]byte(identity.Recipient().String()))}
	if err = r.Validate(m.DataDir, m.OperationID); err != nil {
		return out, err
	}
	receipt, err := json.Marshal(r)
	if err != nil {
		return out, err
	}
	if err = writeFile(filepath.Join(tmp, "receipt.json"), receipt, 0400); err != nil {
		return out, err
	}
	if err = syncDir(tmp); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, filepath.Join(store, m.OperationID), unix.RENAME_NOREPLACE); err != nil {
		return out, err
	}
	if err = syncDir(store); err != nil {
		return out, err
	}
	return Result{State: "captured", Receipt: r}, nil
}
