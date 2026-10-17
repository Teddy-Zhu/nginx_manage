package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

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

func makeDockerInitialMaterial(before iptablesImage, generation firewall.IPTablesGeneration) (iptablesChangeMaterial, error) {
	var out iptablesChangeMaterial
	if before.Family != generation.Family || len(generation.Rules) == 0 {
		return out, errors.New("Docker 初始代际的地址族或规则无效")
	}
	if err := proveEmptyDockerNamespace(before); err != nil {
		return out, err
	}
	if hook := observeDockerFirewallHook(before); !hook.Observed {
		return out, errors.New("Docker 初始代际挂接无法核对：" + hook.Reason)
	}
	// Render only compiler-owned tokens. No declaration, policy, flush or rule
	// text from the existing image enters either restore batch.
	var candidate, previous bytes.Buffer
	candidate.WriteString("*filter\n-N " + generation.Chain + "\n")
	previous.WriteString("*filter\n")
	write := func(buffer *bytes.Buffer, command, chain string, args []string) error {
		text, err := firewall.IPTablesRuleText(args)
		if err != nil {
			return err
		}
		buffer.WriteString(command + " " + chain + " " + text + "\n")
		return nil
	}
	for _, rule := range generation.Rules {
		if err := write(&candidate, "-A", generation.Chain, rule.Arguments); err != nil {
			return out, err
		}
	}
	candidate.WriteString("-N " + firewall.IPTablesDockerChain + "\n")
	for _, step := range []struct {
		Buffer         *bytes.Buffer
		Command, Chain string
		Args           []string
	}{
		{&candidate, "-A", firewall.IPTablesDockerChain, generation.Pointer},
		{&candidate, "-I", "DOCKER-USER 1", generation.Hook},
		{&previous, "-D", "DOCKER-USER", generation.Hook},
		{&previous, "-D", firewall.IPTablesDockerChain, generation.Pointer},
	} {
		if err := write(step.Buffer, step.Command, step.Chain, step.Args); err != nil {
			return out, err
		}
	}
	candidate.WriteString("COMMIT\n")
	previous.WriteString("-X " + firewall.IPTablesDockerChain + "\n")
	for _, rule := range generation.Rules {
		if err := write(&previous, "-D", generation.Chain, rule.Arguments); err != nil {
			return out, err
		}
	}
	previous.WriteString("-X " + generation.Chain + "\nCOMMIT\n")
	if candidate.Len() > firewall.IPTablesProgramBytes || previous.Len() > firewall.IPTablesProgramBytes {
		return out, errors.New("Docker 候选或补偿批次超过 2 MiB")
	}
	raw, err := json.Marshal(before)
	if err != nil {
		return out, err
	}
	var after iptablesImage
	if err = json.Unmarshal(raw, &after); err != nil {
		return out, err
	}
	for ti := range after.Tables {
		table := &after.Tables[ti]
		if table.Name != "filter" {
			continue
		}
		for ci := range table.Chains {
			if table.Chains[ci].Name == "DOCKER-USER" {
				table.Chains[ci].Rules = append([][]string{slices.Clone(generation.Hook)}, table.Chains[ci].Rules...)
			}
		}
		rules := [][]string{}
		for _, rule := range generation.Rules {
			rules = append(rules, slices.Clone(rule.Arguments))
		}
		table.Chains = append(table.Chains, iptablesImageChain{Name: firewall.IPTablesDockerChain, Policy: "-", Rules: [][]string{slices.Clone(generation.Pointer)}}, iptablesImageChain{Name: generation.Chain, Policy: "-", Rules: rules})
	}
	if err = after.readbackBudget(); err != nil {
		return out, err
	}
	// Reverse the modeled insertion and require the complete original image,
	// including INPUT, Docker and every third-party table and ordered rule.
	raw, err = json.Marshal(after)
	if err != nil {
		return out, err
	}
	var restored iptablesImage
	if err = json.Unmarshal(raw, &restored); err != nil {
		return out, err
	}
	for ti := range restored.Tables {
		table := &restored.Tables[ti]
		if table.Name != "filter" {
			continue
		}
		chains := []iptablesImageChain{}
		for _, chain := range table.Chains {
			if chain.Name == generation.Chain || chain.Name == firewall.IPTablesDockerChain {
				continue
			}
			if chain.Name == "DOCKER-USER" {
				if len(chain.Rules) == 0 || !slices.Equal(chain.Rules[0], generation.Hook) {
					return out, errors.New("Docker 补偿投影的首位入口不一致")
				}
				chain.Rules = chain.Rules[1:]
			}
			chains = append(chains, chain)
		}
		table.Chains = chains
	}
	if err = proveEmptyDockerNamespace(restored); err != nil {
		return out, err
	}
	if restored.hash() != before.hash() {
		return out, errors.New("Docker 候选与补偿投影未完整还原原规则")
	}
	return iptablesChangeMaterial{Family: before.Family, Binary: generation.Binary, BeforeHash: before.hash(), AfterHash: after.hash(), CandidateHash: secure.Hash(candidate.Bytes()), PreviousHash: secure.Hash(previous.Bytes()), Before: before, After: after, Candidate: candidate.Bytes(), Previous: previous.Bytes()}, nil
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
		material, err := makeDockerInitialMaterial(*image, generation)
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
