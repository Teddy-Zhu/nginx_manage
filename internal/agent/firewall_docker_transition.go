package agent

import (
	"context"
	"encoding/json"
	"errors"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// This is an initial empty-namespace preview, never an execution checkpoint.
// In particular its projected After image is not a kernel read-back receipt.
type dockerInitialTransition struct {
	Registration      dockerRegistrationCheckpoint
	ConfigurationHash string
	ToolHash          string
	Program           *firewall.DockerIPTablesRuntimeProgram
	Materials         []iptablesChangeMaterial
	Tools             *iptablesToolBinding
	DryRun            *iptablesDryRunProof
}

func prepareDockerInitialTransition(ctx context.Context, before iptablesRegistrationSnapshot, grant *dockerRegistrationCheckpoint, program *firewall.DockerIPTablesRuntimeProgram, tools *iptablesToolBinding) (*dockerInitialTransition, *firewall.DockerTransitionPlan, error) {
	if !validDockerRegistration(grant) || grant.State != "registered" || program == nil || program.Owner != grant.Owner || program.Backend != grant.Backend || program.PlanID == grant.OperationID || program.PlanID == grant.ParentOperationID || !firewalldDigest(before.Hash) || !firewalldDigest(before.ToolHash) || !tools.valid() || tools.Backend != program.Backend {
		return nil, nil, errors.New("Docker 初始代际缺少独立本机授权、当前完整基线或固定工具")
	}
	v := &dockerInitialTransition{Registration: *grant, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, Program: program, Materials: []iptablesChangeMaterial{}, Tools: tools}
	summary := &firewall.DockerTransitionPlan{Owner: grant.Owner, RegistrationOperationID: grant.OperationID, ParentOperationID: grant.ParentOperationID, RegistrationHash: grant.RequestHash, ToolHash: before.ToolHash, HookChain: "DOCKER-USER", EntryChain: firewall.IPTablesDockerChain, RuntimeHash: program.Hash, RuntimeBytes: program.Bytes, GeneratedRules: program.GeneratedRules, Families: []firewall.IPTablesFamilyPlan{}}
	for _, generation := range program.Families {
		var image *iptablesImage
		for i := range before.Images {
			if before.Images[i].Family == generation.Family {
				image = &before.Images[i]
			}
		}
		if image == nil {
			return nil, nil, errors.New("Docker 初始代际缺少完整地址族规则")
		}
		material, err := makeDockerIPTablesChangeMaterial(*image, nil, &generation)
		if err != nil {
			return nil, nil, err
		}
		preserved := 0
		for _, table := range image.Tables {
			for _, chain := range table.Chains {
				preserved += len(chain.Rules)
			}
		}
		v.Materials = append(v.Materials, material)
		summary.Families = append(summary.Families, firewall.IPTablesFamilyPlan{Family: generation.Family, Binary: generation.Binary, Chain: generation.Chain, HookPosition: 1, GeneratedRules: len(generation.Rules) + 2, PreservedRules: preserved, BeforeHash: material.BeforeHash, AfterHash: material.AfterHash, CandidateHash: material.CandidateHash, PreviousHash: material.PreviousHash, CandidateBytes: len(material.Candidate), PreviousBytes: len(material.Previous)})
		summary.TransactionBytes += len(material.Candidate)
	}
	if err := admitDockerInitialReadback(before, program); err != nil {
		return nil, nil, err
	}
	proof, err := preflightIPTablesMaterials(ctx, tools, before.Hash, program.Hash, v.Materials, func(image iptablesImage) error {
		if err := proveEmptyDockerNamespace(image); err != nil {
			return err
		}
		if hook := observeDockerFirewallHook(image); !hook.Observed {
			return errors.New("Docker 官方预演的原始挂接无法核对：" + hook.Reason)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	v.DryRun = proof
	summary.ToolchainHash, summary.DryRunHash, summary.DryRunCommands = tools.Hash, proof.Hash, len(proof.Calls)
	// Hash typed summaries rather than serializing foreign rules into the public
	// view. The full images and batches remain solely in the root private plan.
	raw, err := json.Marshal(struct {
		RegistrationReceiptHash, ConfigurationHash string
		Summary                                    firewall.DockerTransitionPlan
	}{dockerRegistrationReceiptHash(grant), before.Hash, *summary})
	if err != nil {
		return nil, nil, err
	}
	summary.TransactionHash = secure.Hash(append([]byte("iptables:docker-initial-transition:v2:\x00"), raw...))
	return v, summary, nil
}
