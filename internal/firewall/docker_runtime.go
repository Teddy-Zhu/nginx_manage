package firewall

import (
	"encoding/json"
	"slices"
	"strconv"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// Docker's forwarding generation has its own owner and grammar. It cannot be
// passed to the host INPUT executor, even when both use the same backend.
type DockerIPTablesRuntimeProgram struct {
	Backend, Owner, PlanID, LogicalHash, BindingsHash, Marker, Hash string
	Families                                                        []IPTablesGeneration
	Entries                                                         []PreviewEntry
	Bytes, GeneratedRules                                           int
}

type DockerTransitionPlan struct {
	Owner                   string               `json:"owner"`
	RegistrationOperationID string               `json:"registration_operation_id"`
	ParentOperationID       string               `json:"parent_operation_id"`
	RegistrationHash        string               `json:"registration_hash"`
	ToolHash                string               `json:"tool_hash"`
	ToolchainHash           string               `json:"toolchain_hash"`
	DryRunHash              string               `json:"dry_run_hash"`
	DryRunCommands          int                  `json:"dry_run_commands"`
	HookChain               string               `json:"hook_chain"`
	EntryChain              string               `json:"entry_chain"`
	RuntimeHash             string               `json:"runtime_hash"`
	RuntimeBytes            int                  `json:"runtime_bytes"`
	GeneratedRules          int                  `json:"generated_rules"`
	TransactionHash         string               `json:"transaction_hash"`
	TransactionBytes        int                  `json:"transaction_bytes"`
	Families                []IPTablesFamilyPlan `json:"families"`
}

func CompileDockerIPTablesRuntime(policy Policy, targets DockerTargets, resolved []DockerResolvedBinding, owner, planID string) (*DockerIPTablesRuntimeProgram, error) {
	const zero = "00000000-0000-0000-0000-000000000000"
	if !ruleIDPattern.MatchString(owner) || !ruleIDPattern.MatchString(planID) || owner == zero || planID == zero || owner == planID {
		return nil, fault.Invalid("Docker 代际的独立所有者或计划标识无效")
	}
	logical, err := CompileDockerIPTables(policy, targets, resolved)
	if err != nil {
		return nil, err
	}
	// Keep the complete chain name within 28 bytes for both explicit backends.
	// The full digest and independent authority remain in every rule marker.
	name := IPTablesDockerChain + "-" + secure.Hash([]byte(owner + ":" + planID + ":" + logical.Hash))[:10]
	marker := "nginxpanel:docker:generation:v1:" + owner + ":" + planID + ":" + logical.Hash
	out := &DockerIPTablesRuntimeProgram{Backend: logical.Backend, Owner: owner, PlanID: planID, LogicalHash: logical.Hash, BindingsHash: logical.BindingsHash, Marker: marker, Families: []IPTablesGeneration{}, Entries: []PreviewEntry{}}
	ordinal := 0
	for _, family := range logical.Families {
		generation := IPTablesGeneration{Family: family.Family, Binary: family.Binary, Chain: name, Hook: []string{"-m", "comment", "--comment", "nginxpanel:docker:hook:v1:" + owner, "-j", IPTablesDockerChain}, Pointer: []string{"-m", "comment", "--comment", marker, "-j", name}, Rules: []IPTablesRule{}}
		for _, rule := range family.Rules {
			args := slices.Clone(rule.Arguments)
			comment := slices.Index(args, "--comment")
			if comment < 0 || comment+1 >= len(args) {
				return nil, fault.Invalid("Docker 规则缺少完整代际标记位置")
			}
			args[comment+1] = marker + ":" + strconv.Itoa(ordinal)
			text, err := IPTablesRuleText(args)
			if err != nil {
				return nil, err
			}
			generation.Rules = append(generation.Rules, IPTablesRule{Arguments: args})
			entry := logical.Entries[ordinal]
			entry.Expression = family.Binary + " -t filter -A " + name + " " + text
			out.Entries = append(out.Entries, entry)
			ordinal++
		}
		out.Families = append(out.Families, generation)
	}
	out.GeneratedRules = ordinal + 2*len(out.Families)
	if len(out.Families) == 0 || out.GeneratedRules > MaxEntries {
		return nil, fault.Invalid("包含入口及代际指针的 Docker 程序为空或超过 8192 条")
	}
	raw, err := json.Marshal(struct {
		Backend, Owner, PlanID, LogicalHash, BindingsHash string
		Families                                          []IPTablesGeneration
	}{out.Backend, owner, planID, out.LogicalHash, out.BindingsHash, out.Families})
	if err != nil {
		return nil, err
	}
	if len(raw) > IPTablesProgramBytes {
		return nil, fault.Invalid("包含完整代际身份的 Docker 程序超过 2 MiB")
	}
	out.Bytes, out.Hash = len(raw), secure.Hash(append([]byte("iptables:docker-runtime:v1:\x00"), raw...))
	return out, nil
}
