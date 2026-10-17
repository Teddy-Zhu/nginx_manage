package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

func validIPTablesBackend(backend string) bool {
	return backend == "iptables-nft" || backend == "iptables-legacy"
}

type iptablesRegistrationSnapshot struct {
	Hash     string
	ToolHash string
	Observed firewall.Observation
	Images   []iptablesImage
}

// Registration binds diagnostics, not an executable write capability. A future
// policy plan must independently pin the complete execution toolchain again.
func iptablesRegistrationTools(ctx context.Context, backend string) (string, error) {
	tools := []struct{ Name, Path, Hash, Version string }{}
	for _, family := range []string{"ipv4", "ipv6"} {
		name := backend
		if family == "ipv6" {
			name = "ip6tables-" + strings.TrimPrefix(backend, "iptables-")
		}
		for _, role := range []string{name, name + "-save"} {
			var path string
			for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
				candidate := filepath.Join(dir, role)
				if resolved, err := trustedFile(candidate, true); err == nil {
					path = resolved
					break
				}
			}
			if path == "" {
				return "", errors.New("显式 iptables 诊断工具不可用")
			}
			before, err := os.Stat(path)
			if err != nil {
				return "", err
			}
			raw, err := nginxmodules.ReadTrusted(path, 32<<20)
			if err != nil {
				return "", err
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
				return "", errors.New("iptables 工具在授权核对期间变化")
			}
			version, err := firewallRead(ctx, role, "version", 1024)
			if err != nil {
				return "", err
			}
			kind, text, err := firewallVersion(version)
			wanted := "nftables"
			if backend == "iptables-legacy" {
				wanted = "legacy"
			}
			if err != nil || kind != wanted {
				return "", errors.New("显式 iptables 诊断工具后端不一致")
			}
			tools = append(tools, struct{ Name, Path, Hash, Version string }{role, path, secure.Hash(raw), text})
		}
	}
	raw, err := json.Marshal(tools)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}

func inspectIPTablesRegistration(ctx context.Context, dataDir, backend string, admit bool) (iptablesRegistrationSnapshot, error) {
	var out iptablesRegistrationSnapshot
	if !validIPTablesBackend(backend) {
		return out, errors.New("必须显式选择 iptables-nft 或 iptables-legacy")
	}
	if admit {
		if err := forbidUFWRegistration(); err != nil {
			return out, err
		}
		nftState, err := loadFirewallState(dataDir)
		if err != nil {
			return out, err
		}
		fwState, err := loadFirewalldState(dataDir)
		if err != nil {
			return out, err
		}
		nft, err := loadNFTRegistration(dataDir)
		if err != nil {
			return out, err
		}
		fw, err := loadFirewalldRegistration(dataDir)
		if err != nil {
			return out, err
		}
		ufw, err := loadUFWRegistration(dataDir)
		if err != nil {
			return out, err
		}
		if nftState != nil || fwState != nil || ufwRegistrationPending(dataDir) || ufw != nil && ufw.State != "released" || nft != nil && nft.State != "released" || fw != nil && fw.State != "released" {
			return out, errors.New("其他防火墙登记或恢复材料尚未释放，禁止 iptables 新授权")
		}
	}
	// Skip this backend's projection: it calls this inspector itself.
	call, cancel := context.WithTimeout(ctx, 6*time.Second)
	observed := (&firewallObserver{scope: "host", dataDir: dataDir, skipIPTablesRegistration: true}).collect(call)
	cancel()
	return snapshotIPTablesRegistration(ctx, backend, observed)
}

func snapshotIPTablesRegistration(ctx context.Context, backend string, observed firewall.Observation) (iptablesRegistrationSnapshot, error) {
	var out iptablesRegistrationSnapshot
	if !observed.Kernel.Available || observed.Kernel.TableExists {
		return out, errors.New("直接 nftables 目标表不存在的状态无法确认")
	}
	if problems, _ := firewall.IPTablesEnvironment(observed, &firewall.IPTablesProgram{Backend: backend}); len(problems) != 0 {
		return out, errors.New(strings.Join(problems, "；"))
	}
	// Inspect all explicit backends, including unused families. Summaries alone
	// cannot detect a reserved jump/comment hidden among foreign rules.
	names := []string{"iptables-nft-save", "ip6tables-nft-save", "iptables-legacy-save", "ip6tables-legacy-save"}
	hashes, errs := make([]string, len(names)), make([]error, len(names))
	images := make([]iptablesImage, len(names))
	var wg sync.WaitGroup
	for index, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := firewallRead(ctx, name, "rules", iptablesExportBytes)
			if err == nil {
				family := "ipv4"
				if strings.HasPrefix(name, "ip6tables") {
					family = "ipv6"
				}
				images[index], err = parseIPTablesImage(raw, family)
				if err == nil {
					err = proveIPTablesGeneration(images[index], nil)
					hashes[index] = images[index].hash()
				}
			}
			errs[index] = err
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return out, err
	}
	var err error
	out.ToolHash, err = iptablesRegistrationTools(ctx, backend)
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(struct {
		Backend, NamespaceID, ToolHash string
		Rules                          []string
	}{backend, observed.Kernel.NamespaceID, out.ToolHash, hashes})
	if err != nil {
		return out, err
	}
	out.Hash = secure.Hash(raw)
	out.Observed = observed
	for index, name := range names {
		if strings.Contains(name, strings.TrimPrefix(backend, "iptables-")+"-save") {
			out.Images = append(out.Images, images[index])
		}
	}
	return out, ctx.Err()
}
