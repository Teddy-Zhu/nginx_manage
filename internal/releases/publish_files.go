package releases

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Publication inputs belong to the publishing account, not necessarily root.
// Receiving hosts retain their separate root-only trust and preparation policy.
func openPublicationFile(name string, maximum int64) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 0 || info.Size() > maximum {
			err = errors.New("发布输入的类型、归属、权限、链接或长度无效")
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func publicationParents(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errors.New("发布路径须为规范绝对路径")
	}
	for parent := filepath.Dir(name); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || info.Mode().Perm()&0022 != 0 {
			return errors.New("发布目录及上层须由发布账户或 root 持有且不可被其他账户写入")
		}
		if parent == "/" {
			return nil
		}
	}
}

func readPublicationFile(name string, maximum int64) ([]byte, error) {
	if err := publicationParents(name); err != nil {
		return nil, err
	}
	f, before, err := openPublicationFile(name, maximum)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != before.Size() || !unchanged(f, before) {
		return nil, errors.New("发布输入读取期间发生变化")
	}
	return raw, nil
}

func signingKey(name string) (ed25519.PrivateKey, error) {
	if err := publicationParents(name); err != nil {
		return nil, err
	}
	f, before, err := openPublicationFile(name, 128)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if before.Mode().Perm() != 0600 {
		return nil, errors.New("发布私钥文件须为 0600")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if int64(len(raw)) != before.Size() || !unchanged(f, before) {
		return nil, errors.New("发布私钥读取期间发生变化")
	}
	encoded := strings.TrimSuffix(string(raw), "\n")
	seed, err := base64.StdEncoding.Strict().DecodeString(encoded)
	defer clear(seed)
	if err != nil || len(seed) != ed25519.SeedSize || base64.StdEncoding.EncodeToString(seed) != encoded {
		return nil, errors.New("发布私钥须为规范 Base64 的 32 字节 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func publicationFiles(ctx context.Context, directory string, executable []string) ([]File, int64, error) {
	if err := publicationParents(filepath.Join(directory, ".inspect")); err != nil {
		return nil, 0, err
	}
	exec := map[string]bool{}
	for _, name := range executable {
		if !safePath(name) || exec[name] {
			return nil, 0, errors.New("可执行文件清单无效或重复")
		}
		exec[name] = true
	}
	files := []File{}
	var total int64
	entries := 0
	err := filepath.WalkDir(directory, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > MaxEntries {
			return errors.New("发布输入目录条目超过上限")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("发布输入包含链接或不受信任的归属、权限")
		}
		if name == directory {
			return nil
		}
		rel, err := filepath.Rel(directory, name)
		if err != nil || !safePath(rel) {
			return errors.New("发布输入路径不满足接收端合同")
		}
		if entry.IsDir() {
			return nil
		}
		if len(files) >= MaxFiles || info.Size() > 192<<20 {
			return errors.New("发布文件数量或单文件长度超过上限")
		}
		total += info.Size()
		if total > MaxUnpackedBytes {
			return errors.New("发布资产展开长度超过 256 MiB")
		}
		f, before, err := openPublicationFile(name, 192<<20)
		if err != nil {
			return err
		}
		h := sha256.New()
		copied, copyErr := io.Copy(h, io.LimitReader(contextReader{ctx: ctx, reader: f}, before.Size()+1))
		stable := unchanged(f, before)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if copied != info.Size() || !stable {
			return errors.New("发布文件扫描期间发生变化")
		}
		mode := uint32(0644)
		if exec[rel] {
			mode = 0755
			delete(exec, rel)
		}
		files = append(files, File{Path: rel, SHA256: hex.EncodeToString(h.Sum(nil)), Size: copied, Mode: mode})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if len(exec) != 0 {
		return nil, 0, errors.New("指定的可执行文件缺失")
	}
	slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	return files, total, nil
}

type archiveBudget struct {
	writer    io.Writer
	remaining int64
}

func (w *archiveBudget) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("发布归档超过 128 MiB")
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func packPublication(ctx context.Context, destination, source string, asset Asset) (int64, string, error) {
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	if err := f.Chmod(0644); err != nil {
		return 0, "", err
	}
	h := sha256.New()
	budget := &archiveBudget{writer: io.MultiWriter(f, h), remaining: MaxArchiveBytes}
	z, err := gzip.NewWriterLevel(budget, gzip.BestCompression)
	if err != nil {
		return 0, "", err
	}
	defer z.Close()
	t := tar.NewWriter(z)
	defer t.Close()
	for _, file := range asset.Files {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		if err := t.WriteHeader(&tar.Header{Name: file.Path, Typeflag: tar.TypeReg, Mode: int64(file.Mode), Size: file.Size, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			return 0, "", err
		}
		input, before, err := openPublicationFile(filepath.Join(source, file.Path), file.Size)
		if err != nil {
			return 0, "", err
		}
		digest := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(t, digest), io.LimitReader(contextReader{ctx: ctx, reader: input}, file.Size+1))
		stable := unchanged(input, before)
		closeErr := input.Close()
		if copyErr != nil {
			return 0, "", copyErr
		}
		if closeErr != nil {
			return 0, "", closeErr
		}
		if n != file.Size || !stable || hex.EncodeToString(digest.Sum(nil)) != file.SHA256 {
			return 0, "", fmt.Errorf("发布文件 %s 在打包期间发生变化", file.Path)
		}
	}
	if err := t.Close(); err != nil {
		return 0, "", err
	}
	if err := z.Close(); err != nil {
		return 0, "", err
	}
	if err := f.Sync(); err != nil {
		return 0, "", err
	}
	if err := f.Close(); err != nil {
		return 0, "", err
	}
	return MaxArchiveBytes - budget.remaining, hex.EncodeToString(h.Sum(nil)), nil
}

func writePublicationFile(name string, raw []byte) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	err = f.Chmod(0644)
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
	return closeErr
}
