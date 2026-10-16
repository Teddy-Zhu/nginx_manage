package fail2ban

type BindingView struct {
	Engine        EngineIdentity `json:"engine"`
	State         string         `json:"state"`
	ID            string         `json:"id"`
	Service       string         `json:"service"`
	Socket        string         `json:"socket"`
	ClientPath    string         `json:"client_path"`
	ClientVersion string         `json:"client_version"`
	ApprovedAt    int64          `json:"approved_at"`
	Reason        string         `json:"reason"`
}

func ValidBindingView(v BindingView) bool {
	if !ValidEngineIdentity(v.Engine) {
		return false
	}
	switch v.State {
	case "bound":
		return v.Engine.Owner == "existing" || v.Engine.Owner == "managed"
	case "unbound":
		return v.Engine.Owner == "none"
	case "unavailable":
		return v.Engine.Owner == "unavailable"
	default:
		return false
	}
}

type JailSummary struct {
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}
type Instance struct {
	At            int64         `json:"at"`
	Source        string        `json:"source"`
	Scope         string        `json:"scope"`
	Available     bool          `json:"available"`
	Writable      bool          `json:"writable"`
	Binding       BindingView   `json:"binding"`
	ServerVersion string        `json:"server_version"`
	Service       Service       `json:"service"`
	Jails         []JailSummary `json:"jails"`
	Reason        string        `json:"reason"`
}
type Jail struct {
	At            int64    `json:"at"`
	Source        string   `json:"source"`
	Scope         string   `json:"scope"`
	Available     bool     `json:"available"`
	Writable      bool     `json:"writable"`
	BindingID     string   `json:"binding_id"`
	Name          string   `json:"name"`
	Managed       bool     `json:"managed"`
	ServerVersion string   `json:"server_version"`
	CurrentFailed *int64   `json:"current_failed"`
	TotalFailed   *int64   `json:"total_failed"`
	CurrentBanned *int64   `json:"current_banned"`
	TotalBanned   *int64   `json:"total_banned"`
	Banned        []string `json:"banned"`
	Reason        string   `json:"reason"`
}

func UnknownBinding() BindingView {
	return BindingView{Engine: EngineIdentity{Owner: "unavailable"}, State: "unavailable", Reason: "实例接入登记尚未读取"}
}
func EmptyInstance(scope, reason string) Instance {
	return Instance{Source: "host-agent", Scope: scope, Binding: UnknownBinding(), Jails: []JailSummary{}, Reason: reason}
}
func EmptyJail(scope, name, reason string) Jail {
	return Jail{Source: "host-agent", Scope: scope, Name: name, Banned: []string{}, Reason: reason}
}
