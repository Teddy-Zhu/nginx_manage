package agent

import (
	"context"
	"errors"

	"nginxpanel/internal/firewall"
)

// Initial, update and removal plans share the same material and readback
// admission. Projected After images never supply kernel execution receipts.
func prepareIPTablesTransition(ctx context.Context, before iptablesRegistrationSnapshot, v *iptablesTransition) (*firewall.DockerTransitionPlan, *firewall.IPTablesPlan, error) {
	if v == nil || v.Program == nil || len(v.Materials) != 0 || !v.Tools.valid() || v.Tools.Backend != v.Program.Backend || v.ConfigurationHash != before.Hash || v.ToolHash != before.ToolHash || !firewalldDigest(before.Hash) || !firewalldDigest(before.ToolHash) {
		return nil, nil, errors.New("iptables 计划缺少完整代际、基线或固定工具")
	}
	var summary *firewall.DockerTransitionPlan
	if v.Docker != nil {
		grant, program := &v.Docker.Registration, v.Docker.Program
		if !validDockerRegistration(grant) || grant.State != "registered" || program == nil || program.Owner != grant.Owner || program.Backend != v.Program.Backend || program.PlanID != v.Program.PlanID {
			return nil, nil, errors.New("Docker 联合计划的独立代际身份无效")
		}
		summary = &firewall.DockerTransitionPlan{Owner: grant.Owner, HostOwner: v.Owner, HostRuntimeHash: v.Program.Hash, HostRuntimeBytes: v.Program.Bytes, RegistrationOperationID: grant.OperationID, ParentOperationID: grant.ParentOperationID, RegistrationHash: grant.RequestHash, ToolHash: before.ToolHash, HookChain: "DOCKER-USER", EntryChain: firewall.IPTablesDockerChain, RuntimeHash: program.Hash, RuntimeBytes: program.Bytes, GeneratedRules: program.GeneratedRules, Families: []firewall.IPTablesFamilyPlan{}}
	}
	host := &firewall.IPTablesPlan{RegistrationOperationID: v.RegistrationOperationID, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, LogicalHash: v.Program.LogicalHash, ProtectionRules: v.Program.ProtectionRules, Families: []firewall.IPTablesFamilyPlan{}, Warnings: []string{"IPv4/IPv6 分别处理，不保证跨地址族原子性"}, Reason: "主机入站计划已准备，应用后须通过新连接确认"}
	if v.Docker != nil || iptablesPreviousDocker(v) != nil {
		host.Warnings = append(host.Warnings, "INPUT 的 ACCEPT 可能结束后续判断；Docker 允许规则使用 RETURN 交还后续过滤")
		host.Reason = "主机入站与 Docker 转发的联合预览，尚不支持执行"
		if iptablesPreviousDocker(v) != nil {
			host.Warnings = append(host.Warnings, "撤回或修复原 Docker 规则仍须核对原目标及路径；本次预览不证明原目标仍可恢复")
		}
		if v.Docker == nil {
			host.Warnings = append(host.Warnings, "此计划同时移除原已确认的 Docker 转发规则；不移除 Docker 本机授权")
		}
	}
	prior := iptablesPreviousProgram(v)
	for _, family := range iptablesTransitionFamilies(v) {
		var image *iptablesImage
		for index := range before.Images {
			if before.Images[index].Family == family {
				image = &before.Images[index]
			}
		}
		if image == nil {
			return nil, nil, errors.New("iptables 计划缺少完整地址族规则")
		}
		material, err := makeIPTablesTransitionMaterial(*image, v)
		if err != nil {
			return nil, nil, err
		}
		foreign, err := iptablesCombinedForeignImage(*image, iptablesGeneration(prior, family), dockerIPTablesGeneration(iptablesPreviousDocker(v), family))
		if err != nil {
			return nil, nil, err
		}
		preserved := 0
		for _, table := range foreign.Tables {
			for _, chain := range table.Chains {
				preserved += len(chain.Rules)
			}
		}
		base := firewall.IPTablesFamilyPlan{Family: family, Binary: material.Binary, PreservedRules: preserved, BeforeHash: material.BeforeHash, AfterHash: material.AfterHash, CandidateHash: material.CandidateHash, PreviousHash: material.PreviousHash, CandidateBytes: len(material.Candidate), PreviousBytes: len(material.Previous)}
		hostFamily := base
		if next := iptablesGeneration(v.Program, family); next != nil {
			hostFamily.Chain, hostFamily.HookPosition, hostFamily.GeneratedRules = next.Chain, 1, len(next.Rules)+2
		} else if old := iptablesGeneration(prior, family); old != nil {
			hostFamily.Chain = old.Chain
		}
		host.Families = append(host.Families, hostFamily)
		if next := dockerIPTablesGeneration(v.Docker, family); next != nil {
			dockerFamily := base
			dockerFamily.Chain, dockerFamily.HookPosition, dockerFamily.GeneratedRules = next.Chain, 1, len(next.Rules)+2
			summary.Families = append(summary.Families, dockerFamily)
		}
		v.Materials = append(v.Materials, material)
		if summary != nil {
			summary.TransactionBytes += len(material.Candidate)
		}
	}
	if err := before.admitTransitionReadback(v); err != nil {
		return nil, nil, err
	}
	proof, err := preflightIPTables(ctx, v)
	if err != nil {
		return nil, nil, err
	}
	v.DryRun = proof
	if summary != nil {
		summary.ToolchainHash, summary.DryRunHash, summary.DryRunCommands = v.Tools.Hash, proof.Hash, len(proof.Calls)
	}
	host.ToolchainHash, host.DryRunHash, host.DryRunCommands = v.Tools.Hash, proof.Hash, len(proof.Calls)
	return summary, host, nil
}
