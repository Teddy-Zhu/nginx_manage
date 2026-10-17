package firewall

// KernelView identifies one coherent read of the fixed inet target table.
// Its fingerprint is a change detector, not proof of ownership or permission.
type KernelView struct {
	Available   bool   `json:"available"`
	TableExists bool   `json:"table_exists"`
	Generation  uint32 `json:"generation"`
	NamespaceID string `json:"namespace_id"`
	Fingerprint string `json:"fingerprint"`
	Chains      int    `json:"chains"`
	Rules       int    `json:"rules"`
	Bytes       int    `json:"bytes"`
	ObservedAt  int64  `json:"observed_at"`
	Reason      string `json:"reason"`
}

// RegistrationView is based on an independent root record and an exact
// coherent kernel fingerprint. Verification never grants policy write access.
type RegistrationView struct {
	State       string `json:"state"`
	Verified    bool   `json:"verified"`
	OperationID string `json:"operation_id"`
	ObservedAt  int64  `json:"observed_at"`
	Reason      string `json:"reason"`
}

// Observation describes independent, bounded reads. It does not certify rule
// ownership or reachability and must never be used as authorization to write.
type Observation struct {
	Registration RegistrationView `json:"registration"`
	Kernel       KernelView       `json:"kernel"`
	At           int64            `json:"at"`
	Source       string           `json:"source"`
	Scope        string           `json:"scope"`
	Available    bool             `json:"available"`
	Writable     bool             `json:"writable"`
	Manager      string           `json:"manager"`
	Backend      string           `json:"backend"`
	Reason       string           `json:"reason"`
	Firewalld    Firewalld        `json:"firewalld"`
	UFW          UFW              `json:"ufw"`
	Iptables     []Iptables       `json:"iptables"`
	Rulesets     []Ruleset        `json:"rulesets"`
	Docker       Docker           `json:"docker"`
	Warnings     []string         `json:"warnings"`
	Interfaces   []string         `json:"interfaces"`
}
type Firewalld struct {
	Registration      RegistrationView         `json:"registration"`
	Running           *bool                    `json:"running"`
	ConfiguredBackend string                   `json:"configured_backend"`
	DefaultZone       string                   `json:"default_zone"`
	Panic             *bool                    `json:"panic"`
	Zones             []Zone                   `json:"zones"`
	PolicyInventory   FirewalldPolicyInventory `json:"policy_inventory"`
	Reason            string                   `json:"reason"`
}

// The two settings documents are independent observations, not a kernel or
// ownership proof. Nil means the policy was absent from that configuration.
type FirewalldPolicyInventory struct {
	Available bool              `json:"available"`
	Policies  []FirewalldPolicy `json:"policies"`
	Reason    string            `json:"reason"`
}
type FirewalldPolicy struct {
	Name               string                   `json:"name"`
	Active             bool                     `json:"active"`
	ActiveIngressZones []string                 `json:"active_ingress_zones"`
	ActiveEgressZones  []string                 `json:"active_egress_zones"`
	Runtime            *FirewalldPolicySettings `json:"runtime"`
	Permanent          *FirewalldPolicySettings `json:"permanent"`
}
type FirewalldPolicySettings struct {
	Hash         string   `json:"hash"`
	Target       string   `json:"target"`
	Priority     *int32   `json:"priority"`
	IngressZones []string `json:"ingress_zones"`
	EgressZones  []string `json:"egress_zones"`
	RichRules    int      `json:"rich_rules"`
	Entries      int      `json:"entries"`
	Masquerade   *bool    `json:"masquerade"`
}

func EmptyFirewalldPolicies(reason string) FirewalldPolicyInventory {
	return FirewalldPolicyInventory{Policies: []FirewalldPolicy{}, Reason: reason}
}

type Zone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
	Sources    []string `json:"sources"`
}
type UFW struct {
	RuleInventory UFWRuleInventory `json:"rule_inventory"`
	IPv6          *bool            `json:"ipv6"`
	Installed     bool             `json:"installed"`
	Enabled       *bool            `json:"enabled"`
	Active        *bool            `json:"active"`
	Reason        string           `json:"reason"`
}
type UFWRuleInventory struct {
	Available bool     `json:"available"`
	Hash      string   `json:"hash"`
	Rules     int      `json:"rules"`
	Commands  []string `json:"commands"`
	Truncated bool     `json:"truncated"`
	Reason    string   `json:"reason"`
}

func EmptyUFWRules(reason string) UFWRuleInventory {
	return UFWRuleInventory{Commands: []string{}, Reason: reason}
}

type Iptables struct {
	Family  string `json:"family"`
	Backend string `json:"backend"`
	Version string `json:"version"`
	Reason  string `json:"reason"`
}
type Ruleset struct {
	ID        string  `json:"id"`
	Backend   string  `json:"backend"`
	Family    string  `json:"family"`
	Available bool    `json:"available"`
	Tables    []Table `json:"tables"`
	Reason    string  `json:"reason"`
}
type Table struct {
	Family string  `json:"family"`
	Name   string  `json:"name"`
	Chains []Chain `json:"chains"`
}
type Chain struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Hook           string `json:"hook"`
	Priority       *int64 `json:"priority"`
	Policy         string `json:"policy"`
	Rules          int    `json:"rules"`
	DockerUserJump bool   `json:"docker_user_jump"`
}
type Docker struct {
	BackendHint string   `json:"backend_hint"`
	Evidence    []string `json:"evidence"`
	Writable    bool     `json:"writable"`
	Reason      string   `json:"reason"`
}

func Empty(scope, reason string) Observation {
	return Observation{Registration: RegistrationView{State: "unavailable", Reason: "尚未核对 root 独立登记"}, Source: "host-agent", Kernel: KernelView{Reason: "尚未读取受管目标表的内核快照"}, Scope: scope, Manager: "unknown", Backend: "unknown", Reason: reason, Interfaces: []string{},
		Firewalld: Firewalld{Registration: RegistrationView{State: "unavailable", Reason: "尚未核对 firewalld root 登记"}, Zones: []Zone{}, PolicyInventory: EmptyFirewalldPolicies("尚未读取"), Reason: "尚未读取"}, UFW: UFW{RuleInventory: EmptyUFWRules("尚未读取"), Reason: "尚未读取"},
		Iptables: []Iptables{}, Rulesets: []Ruleset{}, Docker: Docker{BackendHint: "unknown", Evidence: []string{}, Reason: "尚未核对 Docker 转发路径"}, Warnings: []string{}}
}
