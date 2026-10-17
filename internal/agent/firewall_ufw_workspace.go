package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// The official --datadir relocates configuration reads. Only dry-run output
// may update this disposable copy; no caller-supplied path or command enters it.
type ufwDryRunWorkspace struct {
	root     string
	contents map[string][]byte
	code     map[string][]byte
}

func ufwWorkspacePath(root, source string) (string, error) {
	for _, item := range ufwConfigurationSources("", false) {
		if source != "" && source == item.path {
			return filepath.Join(root, strings.TrimPrefix(source, "/")), nil
		}
	}
	return "", errors.New("UFW 私有预演不接受未知配置路径")
}

func newUFWDryRunWorkspace(ctx context.Context, root string, baseline ufwConfigurationSnapshot) (*ufwDryRunWorkspace, error) {
	out := &ufwDryRunWorkspace{root: root, contents: map[string][]byte{}, code: map[string][]byte{}}
	files := map[string]ufwFileSnapshot{}
	for _, file := range baseline.Files {
		files[file.Path] = file
	}
	for _, source := range ufwConfigurationSources("", false) {
		if source.path == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, known := files[source.path]
		raw, present := baseline.Contents[source.path]
		if !known || present != file.Present || present && (int64(len(raw)) != file.Bytes || secure.Hash(raw) != file.Hash) {
			return nil, errors.New("UFW 私有配置与受信源快照不一致")
		}
		if !present {
			continue
		}
		target, err := ufwWorkspacePath(root, source.path)
		if err != nil {
			return nil, err
		}
		if err = secure.RootDirectory(filepath.Dir(target), 0700); err != nil {
			return nil, err
		}
		if err = writeUFWWorkspaceFile(target, raw); err != nil {
			return nil, err
		}
		out.contents[source.path] = raw
	}
	// Generated rules use explicit numeric selectors, never application profiles.
	// Existing profile tuples still have to survive byte-for-byte in each result.
	for _, dir := range []string{"etc/ufw/applications.d", "tmp", "lib/ufw"} {
		if err := secure.RootDirectory(filepath.Join(root, dir), 0700); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (w *ufwDryRunWorkspace) installUFWTools(binding *ufwToolBinding) error {
	if len(w.code) != 0 {
		return errors.New("UFW 私有源程序已经固定")
	}
	for _, file := range binding.Files {
		name := "ufw-cli.py"
		if file.Role != "cli" {
			if !slices.Contains(ufwSourceModules, file.Role) {
				continue
			}
			name = filepath.Join("lib", "ufw", ufwSourceLeaf(file.Role))
		}
		if int64(len(file.Raw)) != file.File.Bytes || secure.Hash(file.Raw) != file.File.Hash {
			return errors.New("UFW 私有源码与原受信读取不匹配")
		}
		if err := writeUFWWorkspaceFile(filepath.Join(w.root, name), file.Raw); err != nil {
			return err
		}
		w.code[name] = file.Raw
	}
	if len(w.code) != len(ufwSourceModules)+1 {
		return errors.New("UFW 私有源码清单不完整")
	}
	return nil
}

// A private temporary file plus rename makes the next CLI invocation see the
// complete verified candidate. The outer workspace owner handles all cleanup.
// This material is disposable and is not a persistent operation receipt.
func writeUFWWorkspaceFile(path string, raw []byte) error {
	if len(raw) > firewall.UFWReadBytes {
		return errors.New("UFW 私有配置文件超过 2 MiB")
	}
	temp := path + "." + secure.ID() + ".tmp"
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func (w *ufwDryRunWorkspace) replace(family string, candidate []byte) error {
	source := "/etc/ufw/user.rules"
	if family == "ipv6" {
		source = "/etc/ufw/user6.rules"
	} else if family != "ipv4" {
		return errors.New("UFW 私有候选地址族无效")
	}
	path, err := ufwWorkspacePath(w.root, source)
	if err != nil {
		return err
	}
	expected, present := w.contents[source]
	if !present {
		return errors.New("UFW 私有候选缺少原生源文件")
	}
	current, err := listenerRead(path, firewall.UFWReadBytes)
	if err != nil || !bytes.Equal(current, expected) {
		return errors.New("UFW 私有原生配置在 dry-run 期间被意外改写")
	}
	if err = writeUFWWorkspaceFile(path, candidate); err != nil {
		return err
	}
	w.contents[source] = candidate
	return nil
}

// Enumerate a bounded, closed directory tree, including the empty profiles and
// temporary directories. Unexpected files cannot silently become batch input.
func (w *ufwDryRunWorkspace) verify(ctx context.Context) error {
	directories := []string{".", "etc", "etc/default", "etc/ufw", "etc/ufw/applications.d", "tmp", "lib", "lib/ufw"}
	allowed := map[string]bool{}
	for _, dir := range directories {
		allowed[dir] = true
	}
	for source := range w.contents {
		allowed[strings.TrimPrefix(source, "/")] = false
	}
	for source := range w.code {
		allowed[source] = false
	}
	for _, dir := range directories {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(w.root, dir)
		if err := existingRootDirectory(path); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		items, readErr := f.ReadDir(64)
		if readErr == nil && len(items) < 64 {
			extra, err := f.ReadDir(1)
			if len(extra) == 0 {
				readErr = err
			}
		}
		closeErr := f.Close()
		if closeErr != nil {
			return closeErr
		}
		if readErr != io.EOF {
			if readErr != nil {
				return readErr
			}
			return errors.New("UFW 私有预演目录清单不完整或超过预算")
		}
		for _, item := range items {
			isDir, known := allowed[filepath.Join(dir, item.Name())]
			if !known || item.Type()&os.ModeSymlink != 0 || isDir != item.IsDir() || !isDir && !item.Type().IsRegular() {
				return errors.New("UFW 私有预演存在未知文件或目录")
			}
		}
	}
	for source, expected := range w.code {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := listenerRead(filepath.Join(w.root, source), firewall.UFWReadBytes)
		if err != nil || !bytes.Equal(current, expected) {
			return errors.New("UFW 私有源码在预演期间变化")
		}
	}
	for _, source := range ufwConfigurationSources("", false) {
		if source.path == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		path, err := ufwWorkspacePath(w.root, source.path)
		if err != nil {
			return err
		}
		expected, present := w.contents[source.path]
		current, err := listenerRead(path, firewall.UFWReadBytes)
		if !present && os.IsNotExist(err) {
			continue
		}
		if !present || err != nil || !bytes.Equal(current, expected) {
			return errors.New("UFW 私有批次完成后配置内容或存在性不匹配")
		}
	}
	return nil
}

func verifyUFWBatchOrder(before, after map[string]*ufwNativeFile, expected []ufwNativeRule) error {
	for _, family := range []string{"ipv4", "ipv6"} {
		source := before[family]
		if source == nil {
			if after[family] != nil {
				return errors.New("UFW 私有批次新增了未授权地址族")
			}
			continue
		}
		rules := []ufwNativeRule{}
		for _, rule := range expected {
			if rule.Family == family {
				rules = append(rules, rule)
			}
		}
		rules = append(rules, source.Rules...)
		candidate := after[family]
		if candidate == nil || len(candidate.Rules) != len(rules) {
			return errors.New("UFW 私有批次最终规则数量不匹配")
		}
		for index, rule := range rules {
			if !ufwNativeRuleEqual(rule, candidate.Rules[index]) {
				return errors.New("UFW 私有批次最终顺序或既有规则保留不匹配")
			}
		}
	}
	return nil
}

type ufwBatchFile struct {
	Path, Hash string
	Bytes      int
}

func (w *ufwDryRunWorkspace) digest(baseline, native, steps, tools string) (string, error) {
	files := []ufwBatchFile{}
	for _, path := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		if raw, present := w.contents[path]; present {
			files = append(files, ufwBatchFile{path, secure.Hash(raw), len(raw)})
		}
	}
	return ufwBatchDigest(baseline, native, steps, tools, files)
}

func ufwBatchDigest(baseline, native, steps, tools string, files []ufwBatchFile) (string, error) {
	raw, err := json.Marshal(struct {
		Baseline, Native, Steps, Tools string
		Files                          []ufwBatchFile
	}{baseline, native, steps, tools, files})
	if err != nil {
		return "", err
	}
	return secure.Hash(append([]byte("ufw:dry-run-batch:v3:\x00"), raw...)), nil
}
