package agent

import (
	"context"
	"errors"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

func verifyDockerPolicyAuthority(dataDir string, parent *iptablesRegistrationCheckpoint, record *dockerIPTablesPolicyRecord) error {
	if record == nil {
		return nil
	}
	expected := &record.Registration
	if !validDockerRegistration(expected) || expected.DataDir != dataDir {
		return errors.New("Docker 原业务授权不属于本机数据目录")
	}
	current, err := dockerRegistrationAuthority(dataDir, parent, expected.EngineHash)
	if err != nil {
		return err
	}
	if dockerRegistrationReceiptHash(current) != dockerRegistrationReceiptHash(expected) {
		return errors.New("Docker 原业务的独立本机授权已变化")
	}
	return nil
}

func dockerTargetFamilies(targets firewall.DockerTargets) []string {
	out := []string{}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, binding := range targets.Bindings {
			if binding.Family == family {
				out = append(out, family)
				break
			}
		}
	}
	return out
}

// A replacement must leave its frozen rollback target usable before any
// candidate write. This proves the original binding, never a new default.
func verifyIPTablesPreviousDockerRuntime(ctx context.Context, dataDir string, transition *iptablesTransition, current iptablesRegistrationSnapshot) error {
	previous := iptablesPreviousDocker(transition)
	if previous == nil {
		return nil
	}
	return verifyDockerPolicyRuntime(ctx, dataDir, transition.Previous.Policy.Policy, previous, current, transition.Tools)
}

// Planning and live verification use exactly the same mapping, route and
// ordered DNAT proof. These reads cannot adopt new endpoints into an old intent.
func resolveDockerPolicyBindings(ctx context.Context, reader *dockerRouteReader, routing dockerRoutingSnapshot, snapshot *dockerFirewallSnapshot, host dockerTargetHost, images []iptablesImage, policy firewall.Policy, targets firewall.DockerTargets) ([]firewall.DockerResolvedBinding, error) {
	bindings := []firewall.DockerResolvedBinding{}
	natBudget := 65536
	for _, binding := range targets.Bindings {
		resolved, err := resolveDockerTarget(snapshot, host, binding)
		if err != nil {
			return nil, fault.Conflict(err.Error())
		}
		resolved.Path, err = reader.prove(ctx, routing, resolved, host.Interfaces[binding.InputInterface].Index, host.Interfaces[resolved.OutputInterface].Index)
		if err != nil {
			return nil, fault.Unavailable(boundedIPTablesError(err))
		}
		found := false
		for _, image := range images {
			if image.Family != binding.Family {
				continue
			}
			if found {
				return nil, fault.Unavailable("Docker 路径核对出现重复地址族规则")
			}
			found = true
			resolved.Path.DNATHash, resolved.Path.DNATRules, err = proveDockerDNAT(ctx, image, resolved, dockerRuleSources(policy, binding), &natBudget)
			if err != nil {
				return nil, fault.Unavailable(boundedIPTablesError(err))
			}
		}
		if !found {
			return nil, fault.Unavailable("Docker 路径核对缺少当前地址族完整规则")
		}
		bindings = append(bindings, resolved)
	}
	return bindings, ctx.Err()
}

// A removal may inspect owned objects while Docker is offline. Installing or
// confirming a generation additionally requires these fresh environment proofs.
func verifyDockerPolicyRuntime(ctx context.Context, dataDir string, policy firewall.Policy, record *dockerIPTablesPolicyRecord, current iptablesRegistrationSnapshot, tools *iptablesToolBinding) error {
	if record == nil {
		return nil
	}
	if record.Program == nil || !tools.valid() || tools.Backend != record.Program.Backend || current.Observed.Docker.BackendHint != "iptables" {
		return errors.New("Docker 原代际、固定工具或转发后端无法核对")
	}
	parent, err := iptablesRegistrationAuthority(dataDir)
	if err != nil {
		return err
	}
	if err = verifyDockerPolicyAuthority(dataDir, parent, record); err != nil {
		return err
	}
	runtime, snapshot := readDockerFirewallState(ctx)
	if !runtime.Available || snapshot == nil {
		return errors.New("Docker 原业务实例无法读取：" + runtime.Reason)
	}
	if runtime.Rootless || runtime.Swarm != "inactive" || runtime.EngineHash != record.Targets.EngineHash || runtime.SnapshotHash != record.Targets.SnapshotHash {
		return errors.New("Docker 原业务实例、网络或发布映射已变化")
	}
	host, err := readDockerTargetHost(ctx)
	if err != nil {
		return err
	}
	reader, err := openDockerRouteRead()
	if err != nil {
		return err
	}
	defer reader.close()
	families := dockerTargetFamilies(record.Targets)
	routing, err := reader.snapshot(ctx, families)
	if err != nil {
		return err
	}
	for _, family := range families {
		found := false
		for _, image := range current.Images {
			if image.Family == family {
				if !observeDockerFirewallHook(image).Observed {
					return errors.New("Docker 原始转发挂接已变化")
				}
				found = true
			}
		}
		if !found {
			return errors.New("Docker 原始转发地址族未完整读取")
		}
	}
	bindings, err := resolveDockerPolicyBindings(ctx, reader, routing, snapshot, host, current.Images, policy, record.Targets)
	if err != nil {
		return err
	}
	program, err := firewall.CompileDockerIPTablesRuntime(policy, record.Targets, bindings, record.Registration.Owner, record.Program.PlanID)
	if err != nil || !sameIPTablesValue(program, record.Program) {
		return errors.New("Docker 当前映射、接口、DNAT 或内核路由不再匹配原完整代际")
	}
	afterRuntime, _ := readDockerFirewallState(ctx)
	if !afterRuntime.Available || afterRuntime.EngineHash != runtime.EngineHash || afterRuntime.SnapshotHash != runtime.SnapshotHash {
		return errors.New("Docker 实例或映射在原代际核对期间变化")
	}
	afterHost, err := readDockerTargetHost(ctx)
	if err != nil || afterHost.Hash != host.Hash {
		return errors.New("Docker 主机接口在原代际核对期间变化")
	}
	afterRouting, err := reader.snapshot(ctx, families)
	if err != nil || afterRouting.Hash != routing.Hash {
		return errors.New("Docker 内核路由在原代际核对期间变化")
	}
	for _, image := range current.Images {
		after, err := tools.image(ctx, image.Family)
		if err != nil || after.hash() != image.hash() {
			return errors.New("iptables 完整规则在 Docker 原代际核对期间变化")
		}
	}
	if err = tools.verify(ctx); err != nil {
		return err
	}
	parent, err = iptablesRegistrationAuthority(dataDir)
	if err != nil {
		return err
	}
	if err = verifyDockerPolicyAuthority(dataDir, parent, record); err != nil {
		return err
	}
	return ctx.Err()
}
