package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/hostdns"
)

type netplanTool struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type netplanOutput struct {
	Mode fs.FileMode
	Link string
	Data []byte
}

func readNetplanTool() (netplanTool, error) {
	for _, candidate := range []string{"/usr/libexec/netplan/generate", "/usr/lib/netplan/generate", "/lib/netplan/generate"} {
		path, err := trustedFile(candidate, true)
		if err != nil {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return netplanTool{}, errors.New("无法读取 netplan 原生生成器")
		}
		prefix := make([]byte, 4)
		_, err = io.ReadFull(f, prefix)
		if err == nil && !bytes.Equal(prefix, []byte{0x7f, 'E', 'L', 'F'}) {
			err = errors.New("not a native ELF generator")
		}
		h := sha256.New()
		if err == nil {
			_, err = f.Seek(0, io.SeekStart)
		}
		var size int64
		if err == nil {
			size, err = io.Copy(h, io.LimitReader(f, (32<<20)+1))
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil || size > 32<<20 {
			return netplanTool{}, errors.New("netplan 原生生成器不受支持或超过容量限制")
		}
		return netplanTool{Path: path, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
	}
	return netplanTool{}, errors.New("未发现安全的 netplan 原生生成器")
}

func netplanGenerate(ctx context.Context, tool netplanTool, root string) error {
	current, err := readNetplanTool()
	if err != nil || current != tool {
		return errors.New("netplan 原生生成器已变化")
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, tool.Path, "--root-dir", root)
	// A systemd-generator argv[0] changes error handling and service behaviour.
	// Offline mode also fences the native generator's boot-time systemctl path.
	cmd.Args[0] = "nginxpanel-netplan-generate"
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "SYSTEMD_OFFLINE=1", "SYSTEMD_IN_CHROOT=1", "NETPLAN_PARSER_IGNORE_ERRORS=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	out, diagnostic := firewallOutput{limit: 4096}, firewallOutput{limit: 8192}
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err = cmd.Run()
	if err != nil || out.exceeded || diagnostic.exceeded {
		return errors.New("netplan 原生候选生成失败、超时或超限；未修改系统配置")
	}
	current, err = readNetplanTool()
	if err != nil || current != tool {
		return errors.New("netplan 生成期间程序发生变化")
	}
	return nil
}

func netplanStageInputs(root string, s *netplanSnapshot, edited string, after *dnsFile) error {
	if err := os.MkdirAll(filepath.Join(root, "etc", "netplan"), 0700); err != nil {
		return err
	}
	for _, file := range s.files {
		raw := file.File.Data
		if file.Path == edited && after != nil {
			raw = after.Data
		}
		path := filepath.Join(root, "etc", "netplan", filepath.Base(file.Path))
		if err := os.WriteFile(path, raw, 0600); err != nil {
			return err
		}
	}
	return nil
}

func netplanOutputs(root string) (map[string]netplanOutput, error) {
	out := map[string]netplanOutput{}
	count, budget := 0, 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		rel, err := filepath.Rel(root, path)
		if err != nil || count > 512 || len(rel) > 512 || strings.Count(rel, string(filepath.Separator)) > 8 {
			return errors.New("netplan 生成树超过读取上限")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		file := netplanOutput{Mode: info.Mode()}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			file.Link, err = os.Readlink(path)
			if len(file.Link) > 512 {
				return errors.New("netplan 生成链接超限")
			}
		case info.Mode().IsRegular():
			if info.Size() > 128<<10 {
				return errors.New("netplan 生成文件超限")
			}
			var f *os.File
			f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			file.Data, err = io.ReadAll(io.LimitReader(f, (128<<10)+1))
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
		default:
			return errors.New("netplan 生成树包含未知文件类型")
		}
		if err != nil {
			return err
		}
		budget += len(file.Data) + len(file.Link) + len(rel)
		if len(file.Data) > 128<<10 || budget > 2<<20 {
			return errors.New("netplan 生成总量超过读取上限")
		}
		out[filepath.ToSlash(rel)] = file
		return nil
	})
	return out, err
}

// Both native generations use the same private root and fresh files. Only the
// selected YAML input and that interface's DNS lines may differ in the output.
func (d *HostDNS) netplanNativeCandidate(ctx context.Context, s *netplanSnapshot, tool netplanTool, source networkSource, after dnsFile, generated networkSource, want hostdns.Config, routes []string) (dnsFile, error) {
	root, err := os.MkdirTemp(d.Dir, ".netplan-")
	if err != nil {
		return dnsFile{}, err
	}
	defer os.RemoveAll(root)
	if err = netplanStageInputs(root, s, "", nil); err != nil {
		return dnsFile{}, err
	}
	if err = netplanGenerate(ctx, tool, root); err != nil {
		return dnsFile{}, err
	}
	before, err := netplanOutputs(root)
	if err != nil {
		return dnsFile{}, err
	}
	// The synchronous native generator has exited before replacing its inputs.
	if err = os.RemoveAll(root); err != nil {
		return dnsFile{}, err
	}
	if err = netplanStageInputs(root, s, source.Path, &after); err != nil {
		return dnsFile{}, err
	}
	if err = netplanGenerate(ctx, tool, root); err != nil {
		return dnsFile{}, err
	}
	next, err := netplanOutputs(root)
	if err != nil {
		return dnsFile{}, err
	}
	key := strings.TrimPrefix(generated.Path, "/")
	original, found := before[key]
	candidate, exists := next[key]
	if !found || !exists || !original.Mode.IsRegular() || !candidate.Mode.IsRegular() || !bytes.Equal(original.Data, generated.File.Data) || len(candidate.Data) > hostdns.SourceLimit {
		return dnsFile{}, errors.New("netplan 源的原生生成结果与当前已加载文件不一致")
	}
	_, nm := netplanGeneratedID("NetworkManager", generated.Path)
	left, e1 := stripNetworkDNS(original.Data)
	right, e2 := stripNetworkDNS(candidate.Data)
	if nm {
		left, right, e1, e2 = stripNetplanNMDNS(original.Data), stripNetplanNMDNS(candidate.Data), nil, nil
	}
	if e1 != nil || e2 != nil || !bytes.Equal(left, right) || original.Mode != candidate.Mode {
		return dnsFile{}, errors.New("netplan 候选改变了目标 DNS 以外的生成配置")
	}
	delete(before, key)
	delete(next, key)
	input := "etc/netplan/" + filepath.Base(source.Path)
	oldInput, oldOK := before[input]
	newInput, newOK := next[input]
	if !oldOK || !newOK || !bytes.Equal(oldInput.Data, source.File.Data) || !bytes.Equal(newInput.Data, after.Data) {
		return dnsFile{}, errors.New("netplan 原生生成改变了暂存源文件")
	}
	delete(before, input)
	delete(next, input)
	if !reflect.DeepEqual(before, next) {
		return dnsFile{}, errors.New("netplan 候选影响其他接口或非 DNS 生成材料")
	}
	file := generated.File
	file.Data = candidate.Data
	if nm {
		config, domains, err := netplanNMFile(file.Data)
		if err != nil || !reflect.DeepEqual(config, want) || !reflect.DeepEqual(domains, routes) {
			return dnsFile{}, errors.New("netplan 候选连接 DNS 与确认的期望值不一致")
		}
	} else {
		projection, err := networkDNSProjection([]networkSource{{Path: generated.Path, File: file}})
		expected := networkConfigState(want, routes)
		if err != nil || projection == nil || !networkSame(&expected, ptrNetworkConfigState(projection)) {
			return dnsFile{}, errors.New("netplan 候选 DNS 与确认的期望值不一致")
		}
	}
	if !s.stable() {
		return dnsFile{}, errors.New("netplan 源在生成期间变化")
	}
	return file, nil
}

func ptrNetworkConfigState(p *hostdns.NetworkDNS) *hostdns.LinkDNS {
	value := networkConfigState(networkConfig(p), p.RoutingDomains)
	return &value
}
