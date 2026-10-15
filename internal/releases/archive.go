package releases

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func zeros(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}

// Parse physical USTAR headers so even trailing PAX/GNU metadata cannot be
// silently consumed by archive/tar's logical-entry reader. archive/tar still
// validates each header checksum and numeric representation.
func extract(ctx context.Context, archive, destination string, asset Asset) error {
	f, before, err := openRoot(archive, asset.Size)
	if err != nil {
		return err
	}
	defer f.Close()
	if before.Size() != asset.Size {
		return errors.New("归档长度与签名清单不一致")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, contextReader{ctx, io.LimitReader(f, asset.Size+1)}); err != nil {
		return err
	}
	if hex.EncodeToString(digest.Sum(nil)) != asset.SHA256 || !unchanged(f, before) {
		return errors.New("归档散列不匹配或源文件变化")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest.Reset()
	compressed := bufio.NewReader(io.TeeReader(contextReader{ctx, f}, digest))
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	defer gz.Close()
	gz.Multistream(false)
	stream := &io.LimitedReader{R: gz, N: asset.UnpackedBytes + MaxEntries*1024 + (64 << 10) + 1024}
	wanted := map[string]File{}
	directories := map[string]bool{}
	for _, file := range asset.Files {
		wanted[file.Path] = file
		for dir := path.Dir(file.Path); dir != "."; dir = path.Dir(dir) {
			directories[dir] = true
		}
	}
	seen := map[string]bool{}
	seenDirs := map[string]bool{}
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		block := make([]byte, 512)
		if _, err := io.ReadFull(stream, block); err != nil {
			return fmt.Errorf("归档头不完整：%w", err)
		}
		if zeros(block) {
			second := make([]byte, 512)
			if _, err := io.ReadFull(stream, second); err != nil || !zeros(second) {
				return errors.New("归档缺少连续结束块")
			}
			break
		}
		entries++
		if entries > MaxEntries {
			return errors.New("归档条目超过上限")
		}
		if block[156] != tar.TypeReg && block[156] != tar.TypeRegA && block[156] != tar.TypeDir {
			return errors.New("归档不允许链接、设备或扩展元数据")
		}
		h, err := tar.NewReader(bytes.NewReader(block)).Next()
		if err != nil || h.Format != tar.FormatUSTAR || h.Uid != 0 || h.Gid != 0 || h.Mode&^int64(0777) != 0 || h.Linkname != "" {
			return errors.New("归档不是受支持的 root USTAR 格式")
		}
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
			if !safePath(name) || !directories[name] || seenDirs[name] || h.Size != 0 || h.Mode&0022 != 0 {
				return errors.New("归档目录不在签名文件清单内或重复")
			}
			seenDirs[name] = true
			continue
		}
		file, ok := wanted[name]
		if !ok || seen[name] || h.Size != file.Size || h.Mode != int64(file.Mode) {
			return errors.New("归档文件与签名清单不一致")
		}
		seen[name] = true
		full := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		if err := writeEntry(ctx, stream, full, file); err != nil {
			return err
		}
		padding := (512 - file.Size%512) % 512
		pad := make([]byte, padding)
		if _, err := io.ReadFull(stream, pad); err != nil || !zeros(pad) {
			return errors.New("归档文件填充无效")
		}
	}
	if len(seen) != len(wanted) {
		return errors.New("归档缺少清单文件")
	}
	tail, err := io.ReadAll(io.LimitReader(stream, (64<<10)+1))
	if err != nil || len(tail) > 64<<10 || !zeros(tail) || stream.N == 0 {
		return errors.New("归档尾随内容、gzip 校验或展开预算无效")
	}
	if _, err := compressed.Peek(1); err != io.EOF {
		return errors.New("归档存在额外 gzip 流或压缩尾随内容")
	}
	if hex.EncodeToString(digest.Sum(nil)) != asset.SHA256 || !unchanged(f, before) {
		return errors.New("归档在解包期间变化")
	}
	return inspectEntry(destination, asset)
}
func writeEntry(ctx context.Context, r io.Reader, name string, file File) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.CopyN(io.MultiWriter(f, h), contextReader{ctx, r}, file.Size)
	if err == nil && hex.EncodeToString(h.Sum(nil)) != file.SHA256 {
		err = errors.New("展开文件散列不匹配")
	}
	if err == nil {
		err = f.Chmod(os.FileMode(file.Mode))
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
func inspectEntry(dir string, a Asset) error {
	if a.Component == "web" {
		return nil
	}
	if a.Component == "fail2ban" {
		for _, file := range a.Files {
			f, err := os.Open(filepath.Join(dir, file.Path))
			if err != nil {
				return err
			}
			magic := make([]byte, 4)
			n, err := io.ReadFull(f, magic)
			closeErr := f.Close()
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if n == 4 && bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) {
				return errors.New("Fail2ban 代码包不得携带 Python 解释器或原生二进制")
			}
		}
		return nil
	}
	entry := "nginxpanel"
	if a.Component == "nginx" {
		entry = "bin/nginx"
	}
	binary, err := elf.Open(filepath.Join(dir, entry))
	if err != nil {
		return err
	}
	defer binary.Close()
	want := elf.EM_X86_64
	if a.Architecture == "arm64" {
		want = elf.EM_AARCH64
	}
	if binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Machine != want {
		return errors.New("程序 ELF 架构与签名资产不一致")
	}
	if binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN || binary.Entry == 0 {
		return errors.New("资产入口不是可执行 ELF")
	}
	interpreter := ""
	for _, prog := range binary.Progs {
		if prog.Type == elf.PT_INTERP {
			if interpreter != "" || prog.Filesz > 512 {
				return errors.New("ELF 解释器无效")
			}
			raw, err := io.ReadAll(io.LimitReader(prog.Open(), 513))
			if err != nil {
				return err
			}
			if len(raw) == 0 || raw[len(raw)-1] != 0 || bytes.IndexByte(raw[:len(raw)-1], 0) >= 0 {
				return errors.New("ELF 解释器格式无效")
			}
			interpreter = string(raw[:len(raw)-1])
		}
	}
	if a.ABI == "static" && interpreter != "" {
		return errors.New("静态 ABI 资产包含动态解释器")
	}
	libraries, err := binary.ImportedLibraries()
	if err != nil {
		return err
	}
	if len(libraries) > 64 || a.ABI == "static" && len(libraries) != 0 {
		return errors.New("静态 ABI 或动态库数量不满足约束")
	}
	known := map[string]bool{}
	for _, runtime := range a.RuntimeFiles {
		known[path.Base(runtime.Path)] = true
	}
	for _, file := range a.Files {
		if strings.HasPrefix(file.Path, "lib/") {
			known[path.Base(file.Path)] = true
		}
	}
	for _, library := range libraries {
		if strings.Contains(library, "/") || !known[library] {
			return errors.New("ELF 直接依赖未纳入受管文件约束")
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		paths, err := binary.DynString(tag)
		if err != nil {
			return err
		}
		for _, list := range paths {
			for _, search := range strings.Split(list, ":") {
				allowed := "$ORIGIN/lib"
				if a.Component == "nginx" {
					allowed = "$ORIGIN/../lib"
				}
				if search != allowed {
					return errors.New("ELF 库搜索路径不在固定受管目录")
				}
			}
		}
	}
	if interpreter != "" {
		found := false
		for _, runtime := range a.RuntimeFiles {
			if runtime.Path == interpreter {
				found = true
			}
		}
		if !found {
			return errors.New("动态解释器未纳入系统文件约束")
		}
	}
	return nil
}
