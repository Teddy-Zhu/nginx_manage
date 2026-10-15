// Package components manages authenticated native component preparation.
package components

import (
	"context"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/releases"
)

type Input struct {
	Action         string   `json:"action"`
	Tag            string   `json:"tag"`
	Prerelease     bool     `json:"prerelease"`
	Components     []string `json:"components,omitempty"`
	Assets         []string `json:"assets,omitempty"`
	PlanID         string   `json:"plan_id"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	TrustSHA256    string   `json:"trust_sha256"`
}

var operationID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return operationID.MatchString(id) }
func digest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == strings.ToLower(value)
}
func (in Input) Validate() error {
	if in.Action != "check" && in.Action != "prepare" {
		return fault.Invalid("未知组件操作")
	}
	if len(in.Components)+len(in.Assets) > 2 {
		return fault.Invalid("每次最多选择两个原生组件")
	}
	for _, id := range in.Components {
		if id != "nginx" && id != "fail2ban" {
			return fault.Invalid("组件入口只接受 Nginx 与 Fail2ban")
		}
	}
	if in.Action == "check" && (in.PlanID != "" || in.ManifestSHA256 != "" || in.TrustSHA256 != "") {
		return fault.Invalid("检查请求不能携带准备计划")
	}
	if in.Action == "prepare" && (in.Tag == "" || len(in.Components) != 0 || len(in.Assets) == 0 || !digest(in.PlanID) || !digest(in.ManifestSHA256) || !digest(in.TrustSHA256)) {
		return fault.Invalid("准备须绑定已检查的标签、资产、计划和信任散列")
	}
	if err := releases.ValidateOnlineSelection(in.online()); err != nil {
		return fault.Invalid(err.Error())
	}
	return nil
}
func (in Input) online() releases.OnlineInput {
	return releases.OnlineInput{Tag: in.Tag, Assets: slices.Clone(in.Assets), Components: slices.Clone(in.Components), AllowPrerelease: in.Prerelease, Prepare: in.Action == "prepare", AllowedComponents: []string{"nginx", "fail2ban"}, ExpectedPlanID: in.PlanID, ExpectedManifestSHA256: in.ManifestSHA256, ExpectedTrustSHA256: in.TrustSHA256}
}

type Request struct {
	Protocol    int    `json:"protocol"`
	OperationID string `json:"operation_id"`
	Input       Input  `json:"input"`
}
type Asset struct {
	ID                  string   `json:"id"`
	Component           string   `json:"component"`
	Version             string   `json:"version"`
	Architecture        string   `json:"architecture"`
	Distribution        string   `json:"distribution"`
	DistributionVersion string   `json:"distribution_version"`
	ABI                 string   `json:"abi"`
	SourceURL           string   `json:"source_url"`
	License             string   `json:"license"`
	Maintenance         string   `json:"maintenance"`
	Features            []string `json:"features"`
	Dependencies        []string `json:"dependencies"`
	RuntimeFiles        int      `json:"runtime_files"`
	ArchiveBytes        int64    `json:"archive_bytes"`
	UnpackedBytes       int64    `json:"unpacked_bytes"`
}
type Release struct {
	PlanID         string   `json:"plan_id"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	TrustSHA256    string   `json:"trust_sha256"`
	Repository     string   `json:"repository"`
	Version        string   `json:"version"`
	Tag            string   `json:"tag"`
	Channel        string   `json:"channel"`
	KeyID          string   `json:"key_id"`
	ExpiresAt      int64    `json:"expires_at"`
	Selected       []string `json:"selected"`
	Assets         []Asset  `json:"assets"`
	ArchiveBytes   int64    `json:"archive_bytes"`
	UnpackedBytes  int64    `json:"unpacked_bytes"`
}

func release(plan releases.Plan) Release {
	out := Release{PlanID: plan.ID, ManifestSHA256: plan.ManifestSHA256, TrustSHA256: plan.TrustSHA256, Repository: plan.Manifest.Repository, Version: plan.Manifest.Version, Tag: "v" + plan.Manifest.Version, Channel: plan.Manifest.Channel, KeyID: plan.KeyID, ExpiresAt: plan.Manifest.ExpiresAt, Selected: slices.Clone(plan.Selected), Assets: []Asset{}, ArchiveBytes: plan.ArchiveBytes, UnpackedBytes: plan.UnpackedBytes}
	for _, a := range plan.Assets {
		out.Assets = append(out.Assets, Asset{ID: a.ID, Component: a.Component, Version: a.Version, Architecture: a.Architecture, Distribution: a.Distribution, DistributionVersion: a.DistributionVersion, ABI: a.ABI, SourceURL: a.SourceURL, License: a.License, Maintenance: a.Maintenance, Features: append([]string{}, a.Features...), Dependencies: append([]string{}, a.Dependencies...), RuntimeFiles: len(a.RuntimeFiles), ArchiveBytes: a.Size, UnpackedBytes: a.UnpackedBytes})
	}
	return out
}

type Operation struct {
	Protocol      int      `json:"protocol"`
	ID            string   `json:"id"`
	RequestHash   string   `json:"request_hash"`
	Input         Input    `json:"input"`
	State         string   `json:"state"`
	Stage         string   `json:"stage"`
	ErrorCode     string   `json:"error_code"`
	Error         string   `json:"error"`
	CreatedAt     int64    `json:"created_at"`
	UpdatedAt     int64    `json:"updated_at"`
	Deadline      int64    `json:"deadline"`
	RuntimeReady  bool     `json:"runtime_ready"`
	RuntimeReason string   `json:"runtime_reason"`
	Release       *Release `json:"release,omitempty"`
}
type Overview struct {
	InstallAvailable bool                       `json:"install_available"`
	InstallReason    string                     `json:"install_reason"`
	Installation     *nginxruntime.Installation `json:"installation,omitempty"`
	Running          bool                       `json:"running"`
	RuntimeReason    string                     `json:"runtime_reason"`
	Available        bool                       `json:"available"`
	Scope            string                     `json:"scope"`
	Reason           string                     `json:"reason"`
	Repository       string                     `json:"repository"`
	TrustSHA256      string                     `json:"trust_sha256"`
	KeyIDs           []string                   `json:"key_ids"`
}
type Host interface {
	ReadComponents(context.Context) (Overview, error)
	SubmitComponent(context.Context, Request) (Operation, error)
	ComponentOperation(context.Context, string) (Operation, error)
}
