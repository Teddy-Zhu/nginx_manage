package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

var resources = []struct {
	name, source, local string
	limit               int64
}{
	{"database/panel.db", "app/panel.db", "panel.db", DatabaseMax},
	{"secrets/master.key", "secrets/master.key", "master.key", 32},
	{"secrets/node-tls/cert.pem", "secrets/node-tls/cert.pem", "cert.pem", 64 << 10},
	{"secrets/node-tls/key.pem", "secrets/node-tls/key.pem", "key.pem", 64 << 10},
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
func privateDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || int(st.Uid) != os.Geteuid() {
		return errors.New("备份目录须由面板账户持有且权限为 0700")
	}
	return nil
}
func openPrivate(path string, max int64) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || info.Size() < 0 || info.Size() > max {
			err = errors.New("备份文件的类型、归属、权限或大小无效")
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *Service) root() string                 { return filepath.Join(s.DataDir, "backups") }
func (s *Service) workspace(id string) string   { return filepath.Join(s.root(), ".work", id) }
func (s *Service) archivePath(id string) string { return filepath.Join(s.root(), id+".tar.age") }
func (s *Service) openStore() error {
	if !filepath.IsAbs(s.DataDir) || filepath.Clean(s.DataDir) != s.DataDir {
		return errors.New("备份需要规范的绝对数据目录")
	}
	if err := privateDir(s.root()); err != nil {
		return err
	}
	if err := privateDir(filepath.Join(s.root(), ".work")); err != nil {
		return err
	}
	return syncDir(s.root())
}
func removeWorkspace(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || int(st.Uid) != os.Geteuid() || info.Mode().Perm() != 0700 {
		return errors.New("备份暂存目录归属发生变化")
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	items, err := f.ReadDir(8)
	f.Close()
	if err != nil && err != io.EOF {
		return err
	}
	if len(items) > 5 {
		return errors.New("备份暂存存在未知资源")
	}
	allowed := map[string]bool{"manifest.json": true}
	for _, r := range resources {
		allowed[r.local] = true
	}
	for _, item := range items {
		if !allowed[item.Name()] || !item.Type().IsRegular() {
			return errors.New("备份暂存包含未知文件或链接")
		}
	}
	for _, item := range items {
		if err = os.Remove(filepath.Join(dir, item.Name())); err != nil {
			return err
		}
	}
	if err = os.Remove(dir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dir))
}
func digestFile(ctx context.Context, path string, max int64) (File, error) {
	f, info, err := openPrivate(path, max)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	return digestOpenFile(ctx, f, info, max)
}
func digestOpenFile(ctx context.Context, f *os.File, info os.FileInfo, max int64) (File, error) {
	hash := sha256.New()
	n, err := io.Copy(hash, contextReader{ctx, io.LimitReader(f, max+1)})
	if err != nil {
		return File{}, err
	}
	if n != info.Size() || n > max || !secure.RootFileUnchanged(f, info) {
		return File{}, errors.New("备份文件在读取时变化")
	}
	return File{Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}
func copyMaterial(ctx context.Context, source, target string, max int64) error {
	f, info, err := openPrivate(source, max)
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, contextReader{ctx, io.LimitReader(f, max+1)})
	if err == nil && (n != info.Size() || n > max || !secure.RootFileUnchanged(f, info)) {
		err = errors.New("密钥材料在快照期间变化")
	}
	if err == nil {
		err = out.Sync()
	}
	return errors.Join(err, out.Close())
}
func writeManifest(path string, m any) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(raw) > 128<<10 {
		return errors.New("备份清单超出限制")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
