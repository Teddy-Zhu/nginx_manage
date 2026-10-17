package agent

import (
	"context"
	"errors"

	"nginxpanel/internal/firewall"
)

// This is a read-only registration observation, also used by manager probes.
// Do not call the full observer or reconciler here: they collect this view.
func verifyUFWConfirmedRegistration(ctx context.Context, dataDir, owner string, configuration ufwConfigurationSnapshot, observed firewall.UFW) (bool, error) {
	source, err := loadUFWChange(dataDir)
	if err != nil || source == nil {
		return false, err
	}
	if source.Confirmed == nil || source.Confirmed.Action != "apply" {
		return false, nil
	}
	if observed.Enabled == nil || !*observed.Enabled || observed.Active == nil || !*observed.Active || observed.IPv6 == nil || *observed.IPv6 != source.Transition.IPv6 || source.Transition.Owner != owner || len(configuration.Files) == 0 || configuration.Files[0] != source.Transition.Tools.Files[0].File {
		return true, errors.New("UFW 原确认登记、启用状态或工具不一致")
	}
	manager, err := lockUFWManager()
	if err != nil {
		return true, err
	}
	defer manager.Close()
	enabled, enabledErr := ufwConfigured()
	ipv6, ipv6Err := ufwConfigurationFlag("/etc/default/ufw", "IPV6")
	if enabledErr != nil || ipv6Err != nil || enabled == nil || !*enabled || ipv6 == nil || *ipv6 != source.Transition.IPv6 {
		return true, errors.New("UFW 启用状态或地址族在登记观察期间变化")
	}
	if err = checkUFWConfirmedAnchor(dataDir, source); err != nil {
		return true, err
	}
	if err = source.Transition.Tools.verify(ctx); err != nil {
		return true, err
	}
	program, err := ufwPolicyProgram(source.Confirmed, owner)
	if err != nil {
		return true, err
	}
	owned, err := ufwNativeProgram(program)
	if err != nil {
		return true, err
	}
	if err = verifyUFWOwnedConfiguration(configuration, source.Transition.IPv6, owned); err != nil {
		return true, err
	}
	families := []string{"ipv4"}
	if source.Transition.IPv6 {
		families = append(families, "ipv6")
	}
	count := 0
	for _, family := range families {
		image, err := readUFWTransitionKernel(ctx, &source.Transition, family, dataDir)
		if err != nil {
			return true, err
		}
		_, payload, err := ufwRepairProjection(configuration.Contents[ufwRepairUserPath(family)], family, image, owned)
		if err != nil || len(payload) != 0 {
			return true, errors.Join(err, errors.New("UFW 原确认运行规则尚未恢复"))
		}
		for _, chain := range image {
			count += len(chain.Rules)
		}
		if count > firewall.MaxEntries {
			return true, errors.New("UFW 登记核对范围合计超过 8192 条")
		}
	}
	after, err := readUFWConfiguration(ctx, configuration.Files[0].Path, source.Transition.IPv6)
	if err != nil || after.Hash != configuration.Hash {
		return true, errors.New("UFW 配置在确认登记观察期间变化")
	}
	if err = source.Transition.Tools.verify(ctx); err != nil {
		return true, err
	}
	binary, err := ufwTool()
	if err != nil || binary != configuration.Files[0].Path {
		return true, errors.New("UFW CLI 选择在登记观察期间变化")
	}
	if err = checkUFWConfirmedAnchor(dataDir, source); err != nil {
		return true, err
	}
	if err = verifyUFWManagerLock(manager); err != nil {
		return true, err
	}
	return true, ctx.Err()
}
