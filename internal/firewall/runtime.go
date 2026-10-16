package firewall

import (
	"encoding/json"
	"sort"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const ConfirmationSeconds = 120

type Protection struct {
	Service string   `json:"service"`
	Family  string   `json:"family"`
	Port    int      `json:"port"`
	Sources []string `json:"sources"`
}
type PlanInput struct {
	Action  string `json:"action"`
	Version int64  `json:"version"`
}
type ApplyInput struct {
	Action  string `json:"action"`
	PlanID  string `json:"plan_id"`
	Version int64  `json:"version"`
}
type RuntimeInput struct {
	Action  string `json:"action"`
	Version int64  `json:"version"`
	Policy  Policy `json:"policy"`
}
type Plan struct {
	Action              string       `json:"action"`
	ID                  string       `json:"id"`
	Version             int64        `json:"version"`
	PolicyHash          string       `json:"policy_hash"`
	ProgramHash         string       `json:"program_hash"`
	Baseline            KernelView   `json:"baseline"`
	Protections         []Protection `json:"protections"`
	SSHProfile          string       `json:"ssh_profile"`
	SSHListeners        []string     `json:"ssh_listeners"`
	ListenerVersion     int64        `json:"listener_version"`
	Listener            string       `json:"listener"`
	ControlSource       string       `json:"control_source"`
	ConfirmationSeconds int          `json:"confirmation_seconds"`
	ExpiresAt           int64        `json:"expires_at"`
	TransactionHash     string       `json:"transaction_hash"`
	TransactionBytes    int          `json:"transaction_bytes"`
	GeneratedRules      int          `json:"generated_rules"`
}
type Operation struct {
	Action            string `json:"action"`
	ID                string `json:"id"`
	PlanID            string `json:"plan_id"`
	Version           int64  `json:"version"`
	PolicyHash        string `json:"policy_hash"`
	ProgramHash       string `json:"program_hash"`
	State             string `json:"state"`
	Stage             string `json:"stage"`
	Deadline          int64  `json:"deadline"`
	UpdatedAt         int64  `json:"updated_at"`
	ConfirmedSource   string `json:"confirmed_source"`
	VerificationScope string `json:"verification_scope"`
	Error             string `json:"error"`
}

// ProtectionObservation compares the current host inputs with one confirmed
// root plan. It neither proves external reachability nor changes any rules.
type ProtectionObservation struct {
	State        string       `json:"state"`
	PlanID       string       `json:"plan_id"`
	ObservedAt   int64        `json:"observed_at"`
	SSHProfile   string       `json:"ssh_profile"`
	SSHListeners []string     `json:"ssh_listeners"`
	Protections  []Protection `json:"protections"`
	Reason       string       `json:"reason"`
}
type RuntimeView struct {
	ProtectionObservation ProtectionObservation `json:"protection_observation"`
	ConfirmedAction       string                `json:"confirmed_action"`
	ConfirmedPlanID       string                `json:"confirmed_plan_id"`
	ConfirmedOperationID  string                `json:"confirmed_operation_id"`
	Available             bool                  `json:"available"`
	Reason                string                `json:"reason"`
	ConfirmedVersion      int64                 `json:"confirmed_version"`
	ConfirmedPolicyHash   string                `json:"confirmed_policy_hash"`
	Kernel                KernelView            `json:"kernel"`
	Protections           []Protection          `json:"protections"`
	Operation             *Operation            `json:"operation"`
}

func PolicyDigest(policy Policy) (string, error) {
	normalized, err := policy.Normalize()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}

func CompileNFTProtected(policy Policy, protections []Protection) (*NFTProgram, error) {
	base, err := CompileNFT(policy)
	if err != nil {
		return nil, err
	}
	if len(protections) > 128 {
		return nil, fault.Invalid("保护项超过限制")
	}
	guards := Policy{Backend: "direct-nftables", Rules: []Rule{}}
	for _, p := range protections {
		if p.Service != "ssh" && p.Service != "management" || p.Family != "ipv4" && p.Family != "ipv6" || len(p.Sources) == 0 {
			return nil, fault.Invalid("防火墙保护项无效")
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		hash := secure.Hash(encoded)
		id := hash[:8] + "-" + hash[8:12] + "-" + hash[12:16] + "-" + hash[16:20] + "-" + hash[20:32]
		sources := append([]string{}, p.Sources...)
		sort.Strings(sources)
		guards.Rules = append(guards.Rules, Rule{ID: id, Name: p.Service, Enabled: true, Scope: "host_input", Family: p.Family, Protocol: "tcp", Sources: sources, Ports: []PortRange{{From: p.Port, To: p.Port}}, Action: "allow"})
	}
	protected, err := CompileNFT(guards)
	if err != nil {
		return nil, err
	}
	rules := append(base.Rules[:2:2], protected.Rules[2:]...)
	for _, rule := range rules[2:] {
		rule.Table, rule.Chain = base.Table, base.Chain
	}
	rules = append(rules, base.Rules[2:]...)
	if len(rules) > MaxEntries {
		return nil, fault.Invalid("包含保护项的内核规则超过 8192 条")
	}
	base.Rules = rules
	return finishNFT(base)
}

// Removal leaves an owned empty table with no chain, hook or filtering rules.
// The previous confirmed record remains the rollback target until confirmation.
func CompileRuntime(policy Policy, protections []Protection, action string) (*NFTProgram, error) {
	if action == "apply" {
		return CompileNFTProtected(policy, protections)
	}
	if action != "remove" {
		return nil, fault.Invalid("防火墙动作须为 apply 或 remove")
	}
	normalized, err := policy.Normalize()
	if err != nil {
		return nil, err
	}
	if normalized.Backend != "direct-nftables" {
		return nil, fault.Unavailable("当前移除执行器仅支持 direct-nftables")
	}
	if _, err = CompileNFTProtected(DefaultPolicy(), protections); err != nil {
		return nil, err
	}
	return nil, nil
}
func RuntimeProgramHash(program *NFTProgram) string {
	if program == nil {
		return secure.Hash([]byte("nginxpanel:firewall:empty:v2"))
	}
	return program.Hash
}
