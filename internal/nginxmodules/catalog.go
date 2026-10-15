// Package nginxmodules describes locally approved native Nginx modules. The
// catalog is a root-owned startup input, never an HTTP request or business data.
package nginxmodules

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type Approval struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Source       string `json:"source"`
	SHA256       string `json:"sha256"`
	BinarySHA256 string `json:"binary_sha256"`
}

func (a Approval) Path() string { return "modules/" + a.ID + "/" + a.SHA256 + ".so" }
func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}
func validID(value string) bool {
	return len(value) > 0 && len(value) <= 48 && strings.Trim(value, "abcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}
func Reference(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 3 && parts[0] == "modules" && validID(parts[1]) && strings.HasSuffix(parts[2], ".so") && validHash(strings.TrimSuffix(parts[2], ".so"))
}
func ReadCatalog(name string) ([]Approval, error) {
	if name == "" {
		return []Approval{}, nil
	}
	data, err := ReadTrusted(name, 64<<10)
	if err != nil {
		return nil, err
	}
	var catalog struct {
		Version int         `json:"version"`
		Modules *[]Approval `json:"modules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&catalog) != nil || decoder.Decode(new(any)) != io.EOF || catalog.Version != 1 || catalog.Modules == nil || len(*catalog.Modules) > limits.NginxModules {
		return nil, errors.New("invalid native module catalog")
	}
	seen := map[string]bool{}
	for _, item := range *catalog.Modules {
		if !validID(item.ID) || item.Name == "" || len(item.Name) > 128 || strings.ContainsAny(item.Name, "\x00\r\n") || !filepath.IsAbs(item.Source) || filepath.Clean(item.Source) != item.Source || !validHash(item.SHA256) || !validHash(item.BinarySHA256) || seen[item.Path()] {
			return nil, errors.New("invalid or duplicate native module approval")
		}
		seen[item.Path()] = true
	}
	// Preserve catalog order: it also supplies the native module dependency order.
	return *catalog.Modules, nil
}
func Paths(catalog []Approval) []string {
	out := []string{}
	for _, item := range catalog {
		out = append(out, item.Path())
	}
	return out
}

// The descriptor is opened without following links after all parents have been
// checked. Reads are bounded and reject replaced or concurrently edited files.
func openTrusted(name string, max int64) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, nil, errors.New("trusted file path must be canonical and absolute")
	}
	for parent := filepath.Dir(name); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return nil, nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, nil, errors.New("untrusted module parent directory")
		}
		if parent == "/" {
			break
		}
	}
	info, err := os.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Size() > max {
		return nil, nil, errors.New("untrusted or oversized module file")
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	opened, err := file.Stat()
	if err != nil || !os.SameFile(opened, info) {
		file.Close()
		return nil, nil, errors.New("trusted file changed while opening")
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || !opened.Mode().IsRegular() || openedStat.Uid != 0 || openedStat.Nlink != 1 || opened.Mode().Perm()&0022 != 0 || opened.Size() > max {
		file.Close()
		return nil, nil, errors.New("trusted file permissions changed while opening")
	}
	return file, opened, nil
}
func unchanged(file *os.File, before os.FileInfo) bool {
	after, err := file.Stat()
	a, aok := before.Sys().(*syscall.Stat_t)
	if err != nil {
		return false
	}
	b, bok := after.Sys().(*syscall.Stat_t)
	return aok && bok && os.SameFile(before, after) && a.Nlink == b.Nlink && before.Mode() == after.Mode() && before.Size() == after.Size() && a.Ctim == b.Ctim && before.ModTime().Equal(after.ModTime())
}
func ReadTrusted(name string, max int64) ([]byte, error) {
	file, info, err := openTrusted(name, max)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max || !unchanged(file, info) {
		return nil, errors.New("trusted file changed or exceeds read budget")
	}
	return data, nil
}
func HashTrusted(name string, max int64) (string, error) {
	file, info, err := openTrusted(name, max)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(file, max+1))
	if err != nil || count > max || !unchanged(file, info) {
		return "", errors.New("trusted file changed or exceeds hash budget")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
func Inspect(data []byte) ([]string, error) {
	image, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("native module is not an ELF image")
	}
	defer image.Close()
	if image.Type != elf.ET_DYN {
		return nil, errors.New("native module must be a shared ELF image")
	}
	symbols, err := image.DynamicSymbols()
	if err != nil {
		return nil, errors.New("native module symbols are unavailable")
	}
	names := map[string]bool{}
	for _, symbol := range symbols {
		if symbol.Section != elf.SHN_UNDEF {
			names[symbol.Name] = true
		}
		if strings.HasPrefix(symbol.Name, "ngx_") && strings.HasSuffix(symbol.Name, "_module") && (strings.Contains(symbol.Name, "lua") || strings.Contains(symbol.Name, "_js_") || strings.Contains(symbol.Name, "perl")) {
			return nil, errors.New("script modules are outside the native module policy")
		}
	}
	if !names["ngx_modules"] || !names["ngx_module_names"] || !names["ngx_module_order"] {
		return nil, errors.New("ELF image is not a native Nginx module")
	}
	features := []string{}
	for symbol, feature := range map[string]string{"ngx_stream_module": "stream", "ngx_stream_ssl_module": "stream_tls", "ngx_stream_realip_module": "stream_real_ip", "ngx_stream_ssl_preread_module": "stream_ssl_preread"} {
		if names[symbol] {
			features = append(features, feature)
		}
	}
	sort.Strings(features)
	return features, nil
}
func Material(item Approval, binaryHash string) ([]byte, []string, error) {
	if binaryHash != item.BinarySHA256 {
		return nil, nil, errors.New("module approval targets another Nginx binary")
	}
	data, err := ReadTrusted(item.Source, limits.NginxModuleBytes)
	if err != nil {
		return nil, nil, err
	}
	if secure.Hash(data) != item.SHA256 {
		return nil, nil, errors.New("approved module digest changed")
	}
	features, err := Inspect(data)
	return data, features, err
}
