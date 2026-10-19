package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/secure"
)

func fail2banUpgradeNginxEntries(b *fail2banJailBundle, proof fail2banBanProof, bindings map[string][]string) (map[string][]string, int, error) {
	sets := map[string]map[string]bool{}
	if b != nil {
		for _, jail := range b.Policy.Jails {
			if !jail.Enabled || jail.Action != "nginx-client" {
				continue
			}
			if len(bindings[jail.ResourceID]) == 0 || !sameFail2banHostJails(bindings[jail.ResourceID], b.Proxies[jail.ResourceID]) {
				return nil, 0, errors.New("升级 Nginx 动作的活动资源或代理保护范围变化")
			}
			bans, ok := proof[fail2banJailNameFor(jail.ID)]
			if !ok || bans == nil {
				return nil, 0, errors.New("升级 Nginx 动作缺少完整官方 jail 封禁")
			}
			if sets[jail.ResourceID] == nil {
				sets[jail.ResourceID] = map[string]bool{}
			}
			for address := range bans {
				sets[jail.ResourceID][address] = true
			}
		}
	}
	entries, excluded := map[string][]string{}, 0
	for resource, set := range sets {
		entries[resource] = []string{}
		for address := range set {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.Zone() != "" || ip.Unmap().String() != address {
				return nil, 0, errors.New("升级 Nginx 动作包含非规范单 IP 封禁")
			}
			protected, err := fail2banNginxProtectedAddress(ip, bindings[resource])
			if err != nil {
				return nil, 0, err
			}
			if protected {
				excluded++
			} else {
				entries[resource] = append(entries[resource], address)
			}
		}
		sort.Strings(entries[resource])
	}
	return entries, excluded, nil
}

func fail2banUpgradeNginxSourceKey(registry, invocation, socket string) string {
	raw, _ := json.Marshal(struct{ Registry, Invocation, Socket string }{registry, invocation, socket})
	return secure.Hash(raw)
}

func validateFail2banUpgradeNginxVerification(i fail2banUpgradeSwitch, proof fail2banBanProof, invocation string, h fail2banUpgradeNginxVerification) error {
	b := i.Prepared.Material.Bundle
	if b == nil || h.Directory != b.NginxDir || manifestHash(h.Manifest) != b.NginxHash || h.PID < 2 || h.StartTicks == 0 || h.BootID != i.Manifest.Basis.BootID || h.UID < 1 || h.GID < 1 || !fail2banDigest.MatchString(h.BinarySHA256) || !fail2banDigest.MatchString(h.RuntimeSHA256) {
		return errors.New("升级 Nginx 运行证明缺少原修订、完整内容或进程身份")
	}
	if h.Container && h.Binary != "" || !h.Container && (!filepath.IsAbs(h.Binary) || filepath.Clean(h.Binary) != h.Binary) {
		return errors.New("升级 Nginx 运行来源无效")
	}
	inode, err := strconv.ParseUint(h.SocketInode, 10, 64)
	if err != nil || inode == 0 {
		return errors.New("升级 Nginx 动作缺少候选 Socket 身份")
	}
	registry, _, _ := fail2banUpgradeVerificationGrants(i)
	if h.Snapshot.SourceKey != fail2banUpgradeNginxSourceKey(registry.ID, invocation, h.SocketInode) || h.Snapshot.ObservedAt <= 0 || h.Snapshot.ObservedAt > time.Now().Unix()+300 {
		return errors.New("升级 Nginx 拒绝集合并非来自候选的当前运行代次")
	}
	wanted, _, err := fail2banUpgradeNginxEntries(b, proof, h.Manifest.ClientDeny)
	if err != nil {
		return err
	}
	for resource, addresses := range wanted {
		actual, present := h.Snapshot.Entries[resource]
		if !present || actual == nil || !sameFail2banHostJails(actual, addresses) {
			return errors.New("升级 Nginx 拒绝集合与完整官方封禁不一致")
		}
	}
	selected := map[string]string{}
	for _, jail := range b.Policy.Jails {
		if jail.Enabled && jail.Action == "nginx-client" {
			selected[fail2banJailNameFor(jail.ID)] = jail.ResourceID
		}
	}
	seen := map[string]bool{}
	for _, grant := range registry.Grants {
		if _, owned := wanted[grant.ResourceID]; !owned {
			continue
		}
		if selected[grant.Jail] != grant.ResourceID || grant.EngineKey != fail2banNginxEngineKey(i.After.binding()) {
			return errors.New("升级 Nginx 资源存在其他来源的合并批准，无法证明候选完整集合")
		}
		seen[grant.Jail] = true
	}
	if len(seen) != len(selected) {
		return errors.New("升级 Nginx 动作缺少候选 jail 批准")
	}
	checkpoint, err := clientDenyCheckpoint([]Record{h.Checkpoint})
	if err != nil {
		return err
	}
	if checkpoint == nil || checkpoint.State != "succeeded" || checkpoint.Stage != "runtime_confirmed" || checkpoint.BeforeDir != h.Directory || checkpoint.AfterDir != h.Directory || checkpoint.ObservedRevision != h.Manifest.RevisionID || checkpoint.ClientDeny.ManifestHash != manifestHash(h.Manifest) || !fail2banUpgradeOneOf(checkpoint.ClientDeny.After, h.Snapshot) {
		return errors.New("升级 Nginx 动作缺少与活动集合一致的成功审计")
	}
	_, _, err = renderClientDenySnapshot(h.Snapshot)
	return err
}

// Prepare only an observer. Open/setup would create directories and acquire
// ownership; verification must never initialize or repair an Nginx instance.
func fail2banUpgradeNginxObserver(in Fail2banUpgradeVerificationOptions) (*Nginx, string, string, error) {
	n := &Nginx{DataDir: in.DataDir, Journal: &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}, observationOnly: true}
	identity, err := user.Lookup(in.NginxWorker)
	if err != nil {
		return nil, "", "", err
	}
	n.uid, err = strconv.Atoi(identity.Uid)
	if err != nil {
		return nil, "", "", err
	}
	n.gid, err = strconv.Atoi(identity.Gid)
	if err != nil {
		return nil, "", "", err
	}
	if n.uid < 1 || n.gid < 1 {
		return nil, "", "", errors.New("Nginx 保护核对须指定原专用非 root worker")
	}
	if in.NginxContainer {
		if in.NginxBinary != "" {
			return nil, "", "", errors.New("Nginx 保护核对不能混用容器与原生程序")
		}
		binding, err := nginxcontainer.Read(in.DataDir)
		if err != nil {
			return nil, "", "", err
		}
		if binding.UID != n.uid || binding.GID != n.gid {
			return nil, "", "", errors.New("原专用 worker 与容器登记不匹配")
		}
		if _, err = containerFeatures(binding); err != nil {
			return nil, "", "", err
		}
		n.Container = &nginxcontainer.Runtime{Binding: binding}
		return n, binding.Capabilities.BinaryDigest, fail2banUpgradeGrantHash("verification-container", binding), nil
	}
	n.Binary, err = trustedFile(in.NginxBinary, true)
	if err != nil {
		return nil, "", "", err
	}
	hash, err := secure.HashRootFile(n.Binary, limits.NginxBinaryBytes)
	if err != nil {
		return nil, "", "", err
	}
	return n, hash, fail2banUpgradeGrantHash("verification-native", struct{ Binary, SHA256 string }{n.Binary, hash}), nil
}

func fail2banUpgradeNginxProcess(pid int) (string, uint64, error) {
	boot, err := fail2banReadLimited("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return "", 0, err
	}
	if !validID(strings.TrimSpace(string(boot))) || pid < 2 {
		return "", 0, errors.New("Nginx 运行启动身份无效")
	}
	raw, err := fail2banReadLimited("/proc/"+strconv.Itoa(pid)+"/stat", 4096)
	if err != nil {
		return "", 0, err
	}
	at := strings.LastIndex(string(raw), ") ")
	if at < 0 {
		return "", 0, errors.New("Nginx 进程身份不可核对")
	}
	fields := strings.Fields(string(raw)[at+2:])
	if len(fields) < 20 {
		return "", 0, errors.New("Nginx 进程启动身份不完整")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", 0, errors.New("Nginx 进程启动身份无效")
	}
	return strings.TrimSpace(string(boot)), start, nil
}

func readFail2banUpgradeNginxVerification(ctx context.Context, in Fail2banUpgradeVerificationOptions, i fail2banUpgradeSwitch, o fail2banStateRecoveryObservation) (*fail2banUpgradeNginxVerification, error) {
	if !fail2banJailNeedsNginx(o.Bundle) {
		return nil, nil
	}
	n, binaryHash, runtimeHash, err := fail2banUpgradeNginxObserver(in)
	if err != nil {
		return nil, err
	}
	dir, m, err := n.active()
	if err != nil {
		return nil, err
	}
	snapshot, _, err := n.readClientDenySnapshot()
	if err != nil {
		return nil, err
	}
	records, err := n.Journal.List()
	if err != nil {
		return nil, err
	}
	checkpoint, err := clientDenyCheckpoint(records)
	if err != nil {
		return nil, err
	}
	if checkpoint == nil {
		return nil, errors.New("Nginx 动态拒绝集合尚无独立运行回执")
	}
	pid, err := n.masterPID()
	if err != nil {
		return nil, err
	}
	boot, started, err := fail2banUpgradeNginxProcess(pid)
	if err != nil {
		return nil, err
	}
	h := &fail2banUpgradeNginxVerification{Binary: n.Binary, BinarySHA256: binaryHash, RuntimeSHA256: runtimeHash, Container: in.NginxContainer, UID: n.uid, GID: n.gid, SocketInode: o.Live.inode, PID: pid, BootID: boot, StartTicks: started, Directory: dir, Manifest: m, Snapshot: snapshot, Checkpoint: *checkpoint}
	if err = validateFail2banUpgradeNginxVerification(i, o.Actual, o.Live.invocation, *h); err != nil {
		return nil, err
	}
	if err = n.observe(ctx, m); err != nil {
		return nil, err
	}
	afterPID, err := n.masterPID()
	if err != nil {
		return nil, err
	}
	afterBoot, afterStart, err := fail2banUpgradeNginxProcess(afterPID)
	if err != nil {
		return nil, err
	}
	if pid != afterPID || boot != afterBoot || started != afterStart {
		return nil, errors.New("Nginx 动作核对期间进程代次变化")
	}
	return h, ctx.Err()
}
