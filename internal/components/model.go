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
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
)

type Input struct {
	ImageID            string   `json:"image_id,omitempty"`
	FrontendBaseID     string   `json:"frontend_base_id,omitempty"`
	ExpectedFrontendID string   `json:"expected_frontend_id,omitempty"`
	OfflineID          string   `json:"offline_id,omitempty"`
	Action             string   `json:"action"`
	Tag                string   `json:"tag"`
	Prerelease         bool     `json:"prerelease"`
	Components         []string `json:"components,omitempty"`
	Assets             []string `json:"assets,omitempty"`
	PlanID             string   `json:"plan_id"`
	ManifestSHA256     string   `json:"manifest_sha256"`
	TrustSHA256        string   `json:"trust_sha256"`
}

var operationID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return operationID.MatchString(id) }
func digest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == strings.ToLower(value)
}
func (in Input) Validate() error {
	if in.OfflineID != "" && (!ValidID(in.OfflineID) || in.Tag == "" || len(in.Components) != 0 || len(in.Assets) == 0) {
		return fault.Invalid("离线组件须引用上传 UUID、固定标签及资产选择")
	}
	if in.Action != "check" && in.Action != "prepare" && in.Action != "activate" && in.Action != "pull" {
		return fault.Invalid("未知组件操作")
	}
	if len(in.Components)+len(in.Assets) > 2 {
		return fault.Invalid("每次最多选择两个组件")
	}
	if in.Action == "pull" {
		if (in.ImageID != "panel-launcher" && in.ImageID != "nginx") || len(in.Assets) != 1 {
			return fault.Invalid("镜像拉取须选择签名面板计划中的固定镜像")
		}
	} else if in.ImageID != "" {
		return fault.Invalid("此组件操作不能选择镜像")
	}
	for _, id := range in.Components {
		if id != "nginx" && id != "fail2ban" && id != "panel" && id != "web" {
			return fault.Invalid("组件入口只接受 Nginx、Fail2ban、面板与独立前端")
		}
	}
	if in.Action == "check" && (in.PlanID != "" || in.ManifestSHA256 != "" || in.TrustSHA256 != "") {
		return fault.Invalid("检查请求不能携带准备计划")
	}
	if in.Action != "check" && (in.Tag == "" || len(in.Components) != 0 || len(in.Assets) == 0 || !digest(in.PlanID) || !digest(in.ManifestSHA256) || !digest(in.TrustSHA256)) {
		return fault.Invalid("准备须绑定已检查的标签、资产、计划和信任散列")
	}
	if in.Action == "activate" {
		if len(in.Assets) != 1 || !digest(in.FrontendBaseID) || !digest(in.ExpectedFrontendID) {
			return fault.Invalid("前端激活须绑定当前后端和前端身份")
		}
	} else if in.FrontendBaseID != "" || in.ExpectedFrontendID != "" {
		return fault.Invalid("检查和准备不能携带前端激活身份")
	}
	if err := releases.ValidateOnlineSelection(in.online()); err != nil {
		return fault.Invalid(err.Error())
	}
	return nil
}
func (in Input) online() releases.OnlineInput {
	return releases.OnlineInput{Tag: in.Tag, Assets: slices.Clone(in.Assets), Components: slices.Clone(in.Components), AllowPrerelease: in.Prerelease, Prepare: in.Action == "prepare", AllowedComponents: []string{"nginx", "fail2ban", "panel", "web"}, ExpectedPlanID: in.PlanID, ExpectedManifestSHA256: in.ManifestSHA256, ExpectedTrustSHA256: in.TrustSHA256}
}

type PanelPreparation struct {
	ReleaseID         string `json:"release_id"`
	DatabaseSchema    int64  `json:"database_schema"`
	AutomaticRollback bool   `json:"automatic_rollback"`
}
type FrontendResult struct {
	ReleaseID  string `json:"release_id"`
	Version    string `json:"version"`
	Activated  bool   `json:"activated"`
	BaseID     string `json:"base_id"`
	PreviousID string `json:"previous_id"`
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
	Images         []Image               `json:"images"`
	Notes          string                `json:"notes"`
	Requirements   releases.Requirements `json:"requirements"`
	Receiver       releases.Receiver     `json:"receiver"`
	PlanID         string                `json:"plan_id"`
	ManifestSHA256 string                `json:"manifest_sha256"`
	TrustSHA256    string                `json:"trust_sha256"`
	Repository     string                `json:"repository"`
	Version        string                `json:"version"`
	Tag            string                `json:"tag"`
	Channel        string                `json:"channel"`
	KeyID          string                `json:"key_id"`
	ExpiresAt      int64                 `json:"expires_at"`
	Selected       []string              `json:"selected"`
	Assets         []Asset               `json:"assets"`
	ArchiveBytes   int64                 `json:"archive_bytes"`
	UnpackedBytes  int64                 `json:"unpacked_bytes"`
}

func release(plan releases.Plan) Release {
	out := Release{Notes: plan.Manifest.Notes, Requirements: releases.ManifestRequirements(plan.Manifest), Receiver: plan.Receiver, PlanID: plan.ID, ManifestSHA256: plan.ManifestSHA256, TrustSHA256: plan.TrustSHA256, Repository: plan.Manifest.Repository, Version: plan.Manifest.Version, Tag: "v" + plan.Manifest.Version, Channel: plan.Manifest.Channel, KeyID: plan.KeyID, ExpiresAt: plan.Manifest.ExpiresAt, Selected: slices.Clone(plan.Selected), Assets: []Asset{}, ArchiveBytes: plan.ArchiveBytes, UnpackedBytes: plan.UnpackedBytes}
	out.Images = images(plan)
	for _, a := range plan.Assets {
		out.Assets = append(out.Assets, Asset{ID: a.ID, Component: a.Component, Version: a.Version, Architecture: a.Architecture, Distribution: a.Distribution, DistributionVersion: a.DistributionVersion, ABI: a.ABI, SourceURL: a.SourceURL, License: a.License, Maintenance: a.Maintenance, Features: append([]string{}, a.Features...), Dependencies: append([]string{}, a.Dependencies...), RuntimeFiles: len(a.RuntimeFiles), ArchiveBytes: a.Size, UnpackedBytes: a.UnpackedBytes})
	}
	return out
}

type Operation struct {
	Image         *ImagePreparation      `json:"image,omitempty"`
	Announcement  *releases.Announcement `json:"announcement,omitempty"`
	Frontend      *FrontendResult        `json:"frontend,omitempty"`
	Protocol      int                    `json:"protocol"`
	ID            string                 `json:"id"`
	RequestHash   string                 `json:"request_hash"`
	Input         Input                  `json:"input"`
	State         string                 `json:"state"`
	Stage         string                 `json:"stage"`
	ErrorCode     string                 `json:"error_code"`
	Error         string                 `json:"error"`
	CreatedAt     int64                  `json:"created_at"`
	UpdatedAt     int64                  `json:"updated_at"`
	Deadline      int64                  `json:"deadline"`
	RuntimeReady  bool                   `json:"runtime_ready"`
	RuntimeReason string                 `json:"runtime_reason"`
	Release       *Release               `json:"release,omitempty"`
	Panel         *PanelPreparation      `json:"panel,omitempty"`
}
type Overview struct {
	Frontend         panelruntime.FrontendStatus `json:"frontend"`
	SwitchAvailable  bool                        `json:"switch_available"`
	SwitchReason     string                      `json:"switch_reason"`
	InstallAvailable bool                        `json:"install_available"`
	InstallReason    string                      `json:"install_reason"`
	Installation     *nginxruntime.Installation  `json:"installation,omitempty"`
	Running          bool                        `json:"running"`
	RuntimeReason    string                      `json:"runtime_reason"`
	Available        bool                        `json:"available"`
	Scope            string                      `json:"scope"`
	Reason           string                      `json:"reason"`
	Repository       string                      `json:"repository"`
	TrustSHA256      string                      `json:"trust_sha256"`
	KeyIDs           []string                    `json:"key_ids"`
}
type Host interface {
	ReadComponents(context.Context) (Overview, error)
	SubmitComponent(context.Context, Request) (Operation, error)
	ComponentOperation(context.Context, string) (Operation, error)
}
