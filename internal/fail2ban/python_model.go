package fail2ban

// PythonPackage is one exact addition proposed by the native package solver.
// Source contains only the repository origin, never a path or credentials.
type PythonPackage struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Architecture   string `json:"architecture"`
	Source         string `json:"source"`
	Repository     string `json:"repository"`
	Filename       string `json:"filename"`
	SHA256         string `json:"sha256"`
	DownloadBytes  int64  `json:"download_bytes"`
	InstalledBytes int64  `json:"installed_bytes"`
}

type PythonPlan struct {
	ID             string          `json:"id"`
	At             int64           `json:"at"`
	ExpiresAt      int64           `json:"expires_at"`
	OS             string          `json:"os"`
	Version        string          `json:"version"`
	Architecture   string          `json:"architecture"`
	Manager        string          `json:"manager"`
	Packages       []PythonPackage `json:"packages"`
	DownloadBytes  int64           `json:"download_bytes"`
	InstalledBytes int64           `json:"installed_bytes"`
	Impacts        []string        `json:"impacts"`
}

type PythonOperation struct {
	ID         string `json:"id"`
	PlanID     string `json:"plan_id"`
	State      string `json:"state"`
	Stage      string `json:"stage"`
	Submission string `json:"submission"`
	At         int64  `json:"at"`
	Python     Python `json:"python"`
	Error      string `json:"error"`
}
