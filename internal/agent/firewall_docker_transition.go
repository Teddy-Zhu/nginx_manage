package agent

import (
	"context"
	"errors"

	"nginxpanel/internal/firewall"
)

// Both scopes use the same bounded business-intent representation. The plan
// remains volatile and non-writable until live authority and recovery support
// the combined scope; projected After images are never kernel receipts.
func prepareDockerInitialTransition(ctx context.Context, before iptablesRegistrationSnapshot, v *iptablesTransition) (*firewall.DockerTransitionPlan, *firewall.IPTablesPlan, error) {
	if v == nil || v.Docker == nil || v.Program == nil || len(v.Materials) != 0 || !v.Tools.valid() || v.Tools.Backend != v.Program.Backend || v.ConfigurationHash != before.Hash || v.ToolHash != before.ToolHash || !firewalldDigest(before.Hash) || !firewalldDigest(before.ToolHash) || iptablesPreviousDocker(v) != nil {
		return nil, nil, errors.New("Docker 联合初始计划缺少父子授权、完整基线或固定工具")
	}
	grant, program := &v.Docker.Registration, v.Docker.Program
	if !validDockerRegistration(grant) || grant.State != "registered" || program == nil || program.Owner != grant.Owner || program.Backend != v.Program.Backend || program.PlanID != v.Program.PlanID {
		return nil, nil, errors.New("Docker 联合初始计划的独立代际身份无效")
	}
	summary := &firewall.DockerTransitionPlan{Owner: grant.Owner, HostOwner: v.Owner, HostRuntimeHash: v.Program.Hash, HostRuntimeBytes: v.Program.Bytes, RegistrationOperationID: grant.OperationID, ParentOperationID: grant.ParentOperationID, RegistrationHash: grant.RequestHash, ToolHash: before.ToolHash, HookChain: "DOCKER-USER", EntryChain: firewall.IPTablesDockerChain, RuntimeHash: program.Hash, RuntimeBytes: program.Bytes, GeneratedRules: program.GeneratedRules, Families: []firewall.IPTablesFamilyPlan{}}
	host := &firewall.IPTablesPlan{RegistrationOperationID: v.RegistrationOperationID, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, LogicalHash: v.Program.LogicalHash, ProtectionRules: v.Program.ProtectionRules, Families: []firewall.IPTablesFamilyPlan{}, Warnings: []string{"IPv4/IPv6 分别处理，不保证跨地址族原子性", "INPUT 的 ACCEPT 可能结束后续判断；Docker 允许规则使用 RETURN 交还后续过滤"}, Reason: "主机入站与 Docker 转发的联合预览"}
	prior := iptablesPreviousProgram(v)
	for _, family := range iptablesTransitionFamilies(v) {
		var image *iptablesImage
		for index := range before.Images {
			if before.Images[index].Family == family {
				image = &before.Images[index]
			}
		}
		if image == nil {
			return nil, nil, errors.New("Docker 联合计划缺少完整地址族规则")
		}
		material, err := makeIPTablesTransitionMaterial(*image, v)
		if err != nil {
			return nil, nil, err
		}
		foreign, err := iptablesCombinedForeignImage(*image, iptablesGeneration(prior, family), nil)
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
		summary.TransactionBytes += len(material.Candidate)
	}
	if err := before.admitTransitionReadback(v); err != nil {
		return nil, nil, err
	}
	proof, err := preflightIPTables(ctx, v)
	if err != nil {
		return nil, nil, err
	}
	v.DryRun = proof
	summary.ToolchainHash, summary.DryRunHash, summary.DryRunCommands = v.Tools.Hash, proof.Hash, len(proof.Calls)
	host.ToolchainHash, host.DryRunHash, host.DryRunCommands = v.Tools.Hash, proof.Hash, len(proof.Calls)
	return summary, host, nil
}
