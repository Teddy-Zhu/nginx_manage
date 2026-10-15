// Package releases verifies publisher-authenticated assets before they enter a
// root-owned preparation store. Preparation never activates or executes assets.
package releases

import "slices"

const (
	Schema            = 1
	LauncherVersion   = 1
	SignatureDomain   = "nginxpanel-release-manifest-v1\n"
	Store             = "/opt/nginxpanel/prepared"
	MaxManifestBytes  = 2 << 20
	MaxPlanBytes      = 4 << 20
	MaxArchiveBytes   = 128 << 20
	MaxUnpackedBytes  = 256 << 20
	MaxSelectionBytes = 512 << 20
	MaxStoreBytes     = 2 << 30
	MaxFiles          = 4096
	MaxEntries        = 8192
	MaxReleaseAssets  = 64
)

type Key struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}
type Trust struct {
	Schema     int    `json:"schema"`
	Repository string `json:"repository"`
	Keys       []Key  `json:"keys"`
}
type Signature struct {
	Schema    int    `json:"schema"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}
type Asset struct {
	ID                  string   `json:"id"`
	Component           string   `json:"component"`
	Version             string   `json:"version"`
	OS                  string   `json:"os"`
	Architecture        string   `json:"architecture"`
	Distribution        string   `json:"distribution"`
	DistributionVersion string   `json:"distribution_version"`
	ABI                 string   `json:"abi"`
	RuntimeFiles        []File   `json:"runtime_files"`
	Archive             string   `json:"archive"`
	SHA256              string   `json:"sha256"`
	Size                int64    `json:"size"`
	UnpackedBytes       int64    `json:"unpacked_bytes"`
	Files               []File   `json:"files"`
	Dependencies        []string `json:"dependencies"`
	License             string   `json:"license"`
	LicenseFiles        []string `json:"license_files"`
	SourceURL           string   `json:"source_url"`
	Maintenance         string   `json:"maintenance"`
	Features            []string `json:"features"`
}
type Manifest struct {
	Schema               int     `json:"schema"`
	Repository           string  `json:"repository"`
	Version              string  `json:"version"`
	Channel              string  `json:"channel"`
	CreatedAt            int64   `json:"created_at"`
	ExpiresAt            int64   `json:"expires_at"`
	APIMajor             int     `json:"api_major"`
	DatabaseSchema       int64   `json:"database_schema"`
	MinimumAgentProtocol int     `json:"minimum_agent_protocol"`
	MinimumLauncher      int     `json:"minimum_launcher"`
	FrontendVersion      string  `json:"frontend_version"`
	AutomaticRollback    bool    `json:"automatic_rollback"`
	Assets               []Asset `json:"assets"`
}
type Host struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
}
type Receiver struct {
	APIMajor      int `json:"api_major"`
	AgentProtocol int `json:"agent_protocol"`
	Launcher      int `json:"launcher"`
}
type Input struct {
	TrustPath, ManifestPath, SignaturePath string
	Assets                                 []string
	AllowPrerelease                        bool
	Host                                   Host
	Receiver                               Receiver
}
type Plan struct {
	State          string   `json:"state"`
	ID             string   `json:"id"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	TrustSHA256    string   `json:"trust_sha256"`
	KeyID          string   `json:"key_id"`
	Manifest       Manifest `json:"manifest"`
	Host           Host     `json:"host"`
	Receiver       Receiver `json:"receiver"`
	Selected       []string `json:"selected"`
	Assets         []Asset  `json:"assets"`
	ArchiveBytes   int64    `json:"archive_bytes"`
	UnpackedBytes  int64    `json:"unpacked_bytes"`
}

// Private state prevents callers from manufacturing an unsigned preparation.
type Verified struct {
	plan                Plan
	manifest, signature []byte
	seal                string
	trustPath           string
}

func (v *Verified) Plan() Plan {
	// The returned plan must not share slices with the authenticated state.
	out := v.plan
	out.Selected = slices.Clone(out.Selected)
	out.Assets = cloneAssets(out.Assets)
	out.Manifest.Assets = cloneAssets(out.Manifest.Assets)
	return out
}
func cloneAssets(input []Asset) []Asset {
	out := slices.Clone(input)
	for i := range out {
		out[i].Files = slices.Clone(out[i].Files)
		out[i].RuntimeFiles = slices.Clone(out[i].RuntimeFiles)
		out[i].Dependencies = slices.Clone(out[i].Dependencies)
		out[i].LicenseFiles = slices.Clone(out[i].LicenseFiles)
		out[i].Features = slices.Clone(out[i].Features)
	}
	return out
}

type Result struct {
	State     string `json:"state"`
	Directory string `json:"directory"`
	Reused    bool   `json:"reused"`
	Plan      Plan   `json:"plan"`
}
