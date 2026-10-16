package fail2ban

// Observation is inventory, not approval to start an engine or manage a jail.
// Presence, service state and complete engine readiness remain separate.
type Observation struct {
	At            int64       `json:"at"`
	Source        string      `json:"source"`
	Scope         string      `json:"scope"`
	Available     bool        `json:"available"`
	Writable      bool        `json:"writable"`
	Reason        string      `json:"reason"`
	Tools         []Tool      `json:"tools"`
	ClientVersion string      `json:"client_version"`
	Python        Python      `json:"python"`
	Services      []Service   `json:"services"`
	Socket        Socket      `json:"socket"`
	Missing       []string    `json:"missing"`
	Warnings      []string    `json:"warnings"`
	Binding       BindingView `json:"binding"`
}
type Tool struct {
	ID       string `json:"id"`
	Present  *bool  `json:"present"`
	Trusted  bool   `json:"trusted"`
	Path     string `json:"path"`
	Resolved string `json:"resolved"`
	Reason   string `json:"reason"`
}
type Python struct {
	Executable      Tool     `json:"executable"`
	Version         string   `json:"version"`
	StandardLibrary *bool    `json:"standard_library"`
	SQLiteVersion   string   `json:"sqlite_version"`
	Modules         []Module `json:"modules"`
	Package         Package  `json:"package"`
	Reason          string   `json:"reason"`
}
type Module struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}
type Package struct {
	Available bool   `json:"available"`
	Manager   string `json:"manager"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Reason    string `json:"reason"`
}
type Service struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Load      string `json:"load"`
	Active    string `json:"active"`
	Sub       string `json:"sub"`
	UnitFile  string `json:"unit_file"`
	MainPID   *int64 `json:"main_pid"`
	Reason    string `json:"reason"`
}
type Socket struct {
	Path          string `json:"path"`
	Present       *bool  `json:"present"`
	RootProtected bool   `json:"root_protected"`
	Reason        string `json:"reason"`
}

func Empty(scope, reason string) Observation {
	return Observation{Source: "host-agent", Scope: scope, Reason: reason, Tools: []Tool{}, Python: Python{Executable: Tool{ID: "python3", Reason: "尚未读取"}, Modules: []Module{}, Package: Package{Reason: "尚未核对软件包归属"}, Reason: "尚未读取"}, Services: []Service{}, Socket: Socket{Path: "/run/fail2ban/fail2ban.sock", Reason: "尚未读取；文件状态不代表实例健康"}, Missing: []string{}, Warnings: []string{}, Binding: UnknownBinding()}
}
