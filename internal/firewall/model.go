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
	Running           *bool  `json:"running"`
	ConfiguredBackend string `json:"configured_backend"`
	DefaultZone       string `json:"default_zone"`
	Panic             *bool  `json:"panic"`
	Zones             []Zone `json:"zones"`
	Reason            string `json:"reason"`
}
type Zone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
	Sources    []string `json:"sources"`
}
type UFW struct {
	Installed bool   `json:"installed"`
	Enabled   *bool  `json:"enabled"`
	Active    *bool  `json:"active"`
	Reason    string `json:"reason"`
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
		Firewalld: Firewalld{Zones: []Zone{}, Reason: "尚未读取"}, UFW: UFW{Reason: "尚未读取"},
		Iptables: []Iptables{}, Rulesets: []Ruleset{}, Docker: Docker{BackendHint: "unknown", Evidence: []string{}, Reason: "尚未核对 Docker 转发路径"}, Warnings: []string{}}
}
