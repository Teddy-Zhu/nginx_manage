package agent

import (
	"context"
	"errors"
	"sort"

	"nginxpanel/internal/firewall"
)

func fail2banUpgradeHostAddresses(b *fail2banJailBundle, proof fail2banBanProof, protected []string) ([]string, int, error) {
	union := map[string]bool{}
	if b != nil {
		for _, jail := range b.Policy.Jails {
			if !jail.Enabled || jail.Action != "host-input" {
				continue
			}
			bans, ok := proof[fail2banJailNameFor(jail.ID)]
			if !ok || bans == nil {
				return nil, 0, errors.New("升级保护核对缺少宿主机 jail 的完整官方封禁")
			}
			for address := range bans {
				union[address] = true
			}
		}
	}
	return filterFail2banHostUnion(union, protected)
}

func fail2banUpgradeVerificationGrants(i fail2banUpgradeSwitch) (fail2banNginxRegistry, *fail2banHostSourcesEvent, *fail2banHostSyncEvent) {
	p := i.Prepared
	registry, sources, sync := p.Basis.Registry, p.Basis.HostSources, p.Basis.HostSync
	if p.Material.Nginx != nil {
		registry = *p.Material.Nginx
	}
	if p.Material.Sources != nil {
		sources = p.Material.Sources
	}
	if p.Material.Sync != nil {
		sync = p.Material.Sync
	}
	return registry, sources, sync
}

func checkFail2banUpgradeVerificationGrants(data string, i fail2banUpgradeSelection) error {
	registry, sources, sync := i.Registry, i.Sources, i.Sync
	actualRegistry, err := loadFail2banNginxRegistry(data)
	if err != nil {
		return err
	}
	actualSources, err := loadFail2banHostSources(data)
	if err != nil {
		return err
	}
	actualSync, err := loadFail2banHostSync(data)
	if err != nil {
		return err
	}
	root, err := loadFail2banHostRegistration(data)
	if err != nil {
		return err
	}
	protection, err := loadFail2banHostProtection(data)
	if err != nil {
		return err
	}
	if !fail2banUpgradeOneOf(registry, actualRegistry) || !fail2banUpgradeOneOf(sources, actualSources) || !fail2banUpgradeOneOf(sync, actualSync) || !fail2banUpgradeOneOf(root, i.Registration) || !fail2banUpgradeOneOf(protection, i.Protection) {
		return errors.New("升级保护核对的动作批准、保护或本机登记已超出原切换范围")
	}
	stopping, err := loadFail2banHostSyncStop(data, actualSync)
	if err != nil {
		return err
	}
	if stopping != nil {
		return errors.New("升级保护核对期间存在未完成的持续停用")
	}
	return nil
}

func validateFail2banUpgradeHostVerification(i fail2banUpgradeSelection, proof fail2banBanProof, h fail2banUpgradeHostVerification) error {
	b := i.Bundle
	sources, sync := i.Sources, i.Sync
	root := i.Registration
	if root == nil || root.State != "registered" || sources == nil || sources.Action != "approve" || sync == nil || sync.Action != "enable" || sources.EngineKey != fail2banNginxEngineKey(i.Managed.binding()) || sync.SourcesID != sources.ID || sync.EngineKey != sources.EngineKey || sync.ProtectionID != b.HostProtectionID {
		return errors.New("升级宿主机动作缺少候选来源、持续会话或原保护批准")
	}
	if !sameFail2banHostJails(h.Protected, b.HostProtected) {
		return errors.New("当前宿主机保护范围与候选完整配置不同")
	}
	names := []string{}
	for _, jail := range b.Policy.Jails {
		if jail.Enabled && jail.Action == "host-input" {
			names = append(names, fail2banJailNameFor(jail.ID))
		}
	}
	sort.Strings(names)
	if !sources.Policy.Managed && !sameFail2banHostJails(sources.Policy.Jails, names) {
		return errors.New("升级官方来源未精确覆盖候选宿主机 jail")
	}
	wanted, _, err := fail2banUpgradeHostAddresses(b, proof, h.Protected)
	if err != nil {
		return err
	}
	v := h.Runtime
	if !v.valid() || v.State != "succeeded" || v.Intent.Action != "apply" || !fail2banHostRuntimeMatches(&v, root) || v.effective().Set == nil {
		return errors.New("升级宿主机动作尚无成功且匹配归属的运行规则")
	}
	expected := firewall.NFTBanSet{Addresses: wanted, Protected: h.Protected}
	if !fail2banUpgradeOneOf(v.effective().Set, expected) || !fail2banHostProgramShape(v.effective(), h.Kernel) || h.Kernel.NamespaceID != v.Confirmed.NamespaceID || h.Kernel.Fingerprint != v.Confirmed.Fingerprint {
		return errors.New("升级宿主机内核规则与官方完整封禁或当前保护范围不一致")
	}
	return nil
}

func readFail2banUpgradeHostVerification(ctx context.Context, i fail2banUpgradeSelection, proof fail2banBanProof) (*fail2banUpgradeHostVerification, error) {
	if !fail2banJailNeedsHost(i.Bundle) {
		return nil, nil
	}
	data := i.DataDir
	basis, err := loadFail2banHostSourcesBasis(ctx, data)
	if err != nil {
		return nil, err
	}
	v, err := loadFail2banHostRuntime(data)
	if err != nil {
		return nil, err
	}
	if v == nil || !fail2banHostRuntimeReceipt(data, v) {
		return nil, errors.New("升级宿主机动作缺少当前运行检查点及独立审计")
	}
	kernel, err := v.effective().snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := &fail2banUpgradeHostVerification{Runtime: *v, Kernel: kernel, Protected: basis.protected}
	if err = validateFail2banUpgradeHostVerification(i, proof, *out); err != nil {
		return nil, err
	}
	return out, nil
}

func (h fail2banUpgradeHostVerification) unchanged(ctx context.Context, data string) error {
	v, err := loadFail2banHostRuntime(data)
	if err != nil {
		return err
	}
	if v == nil || !fail2banUpgradeOneOf(v, h.Runtime) || !fail2banHostRuntimeReceipt(data, v) {
		return errors.New("核对期间宿主机动作运行检查点或审计变化")
	}
	current, err := v.effective().snapshot(ctx)
	if err != nil {
		return err
	}
	if !fail2banHostProgramShape(v.effective(), current) || current.NamespaceID != h.Kernel.NamespaceID || current.Fingerprint != h.Kernel.Fingerprint {
		return errors.New("核对期间宿主机内核规则缺失或漂移")
	}
	protected, err := loadFail2banHostSourcesBasis(ctx, data)
	if err != nil {
		return err
	}
	if !sameFail2banHostJails(protected.protected, h.Protected) {
		return errors.New("核对期间宿主机保护范围变化")
	}
	return ctx.Err()
}
