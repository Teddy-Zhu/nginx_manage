package panelruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"nginxpanel/internal/platform"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

type StageInput struct {
	DataDir         string `json:"data_dir"`
	PlanID          string `json:"plan_id"`
	TrustPath       string `json:"trust_path"`
	AllowPrerelease bool   `json:"allow_prerelease"`
}

// StageApproval is written only after the immutable release is complete. Its
// admission time and original trust identity come from root, never an API input.
type StageApproval struct {
	Schema         int               `json:"schema"`
	PlanID         string            `json:"plan_id"`
	ReleaseID      string            `json:"release_id"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	TrustSHA256    string            `json:"trust_sha256"`
	TrustPath      string            `json:"trust_path"`
	Prerelease     bool              `json:"prerelease"`
	ApprovedAt     int64             `json:"approved_at"`
	Host           releases.Host     `json:"host"`
	Receiver       releases.Receiver `json:"receiver"`
}

type Compatibility struct {
	APIMajor             int   `json:"api_major"`
	DatabaseSchema       int64 `json:"database_schema"`
	MinimumAgentProtocol int   `json:"minimum_agent_protocol"`
	MinimumLauncher      int   `json:"minimum_launcher"`
	AutomaticRollback    bool  `json:"automatic_rollback"`
}

type StagedRelease struct {
	State         string        `json:"state"`
	Directory     string        `json:"directory"`
	Release       Release       `json:"release"`
	Approval      StageApproval `json:"approval"`
	Compatibility Compatibility `json:"compatibility"`
	Reused        bool          `json:"reused"`
}

// Agent and API protocols move together inside the core. The installed image
// launcher and update API remain the activation boundary.
func (s StagedRelease) RequireCurrent() error {
	if s.Compatibility.APIMajor != 1 || s.Release.AgentProtocol < s.Compatibility.MinimumAgentProtocol || s.Release.LauncherVersion != releases.LauncherVersion || s.Compatibility.MinimumLauncher > releases.LauncherVersion {
		return errors.New("此版本无法直接更新，请使用完整安装包重新安装")
	}
	return nil
}

func stageInput(in StageInput) error {
	if !digest.MatchString(in.PlanID) || len(in.TrustPath) > 512 || !filepath.IsAbs(in.TrustPath) || filepath.Clean(in.TrustPath) != in.TrustPath {
		return errors.New("面板暂存须指定准备计划及本机信任配置")
	}
	_, err := Root(in.DataDir)
	return err
}

func stageApprovalPath(root, id string) string {
	return filepath.Join(root, "approvals", id+".json")
}

func readStageApproval(root, id string) (StageApproval, error) {
	var a StageApproval
	name := stageApprovalPath(root, id)
	info, err := os.Lstat(name)
	if err != nil {
		return a, err
	}
	if info.Mode().Perm() != 0444 {
		return a, errors.New("面板暂存批准须为 root 只读记录")
	}
	raw, err := secure.ReadRootFile(name, 4096)
	if err != nil {
		return a, err
	}
	if err = decode(raw, &a); err != nil {
		return a, err
	}
	canonical, err := json.Marshal(a)
	if err != nil || !bytes.Equal(canonical, raw) || a.Schema != Schema || a.PlanID != id || !digest.MatchString(a.PlanID) || !digest.MatchString(a.ReleaseID) || !digest.MatchString(a.ManifestSHA256) || !digest.MatchString(a.TrustSHA256) || a.ApprovedAt <= 0 || a.ApprovedAt > time.Now().Unix()+300 || len(a.TrustPath) > 512 || !filepath.IsAbs(a.TrustPath) || filepath.Clean(a.TrustPath) != a.TrustPath || a.Host.OS != runtime.GOOS || a.Host.Architecture != runtime.GOARCH || a.Receiver.APIMajor != 1 || a.Receiver.AgentProtocol < 1 || a.Receiver.Launcher < 1 {
		return a, errors.New("面板暂存批准身份无效")
	}
	return a, nil
}

func stageSource(ctx context.Context, in StageInput, prior *StageApproval) (releases.Result, error) {
	host := platform.Detect()
	input := releases.Input{PanelStaging: true, TrustPath: in.TrustPath, Assets: []string{"panel-linux-" + runtime.GOARCH}, AllowedComponents: []string{"panel"}, AllowPrerelease: in.AllowPrerelease,
		Host:     releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: host.OS, Version: host.Version},
		Receiver: releases.Receiver{APIMajor: 1, AgentProtocol: protocol.Agent, Launcher: releases.LauncherVersion}}
	var source releases.Result
	var err error
	if prior == nil {
		source, err = releases.Prepared(ctx, input, in.PlanID)
	} else {
		if prior.TrustPath != in.TrustPath || prior.Prerelease != in.AllowPrerelease {
			return source, errors.New("暂存续用不能改变本机信任位置或预发布授权")
		}
		input.Host, input.Receiver = prior.Host, prior.Receiver
		source, err = releases.Installed(ctx, input, in.PlanID, prior.ApprovedAt, prior.TrustSHA256)
	}
	if err != nil {
		return source, err
	}
	p := source.Plan
	if len(p.Assets) != 1 || p.Assets[0].Component != "panel" || p.Assets[0].ABI != "static" {
		return source, errors.New("暂存须使用内置前端的独立静态核心程序")
	}
	if prior != nil && (p.ManifestSHA256 != prior.ManifestSHA256 || p.TrustSHA256 != prior.TrustSHA256) {
		return source, releases.ErrReleaseChanged
	}
	return source, nil
}

func stageMatches(r Release, source releases.Result) error {
	a := source.Plan.Assets[0]
	m := source.Plan.Manifest
	if r.Version != a.Version || r.DatabaseSchema != m.DatabaseSchema || m.APIMajor != 1 || r.AgentProtocol < m.MinimumAgentProtocol || r.LauncherVersion < m.MinimumLauncher {
		return errors.New("签名发行要求与目标程序的版本或协议不一致")
	}
	found := false
	for _, file := range a.Files {
		if file.Path == "nginxpanel" {
			found = file.SHA256 == r.BinarySHA256 && file.Size <= BinaryLimit && file.Mode == 0755
		}
	}
	if !found {
		return errors.New("面板程序不属于签名准备计划")
	}
	return nil
}

func stagedResult(root string, r Release, a StageApproval, p releases.Plan, reused bool) StagedRelease {
	m := p.Manifest
	return StagedRelease{State: "staged", Directory: filepath.Join(root, "releases", r.ID), Release: r, Approval: a, Reused: reused,
		Compatibility: Compatibility{APIMajor: m.APIMajor, DatabaseSchema: m.DatabaseSchema, MinimumAgentProtocol: m.MinimumAgentProtocol, MinimumLauncher: m.MinimumLauncher, AutomaticRollback: m.AutomaticRollback}}
}

// Staged reauthenticates an approval with current local keys. It never downloads,
// executes a program, creates directories or changes the running release.
func Staged(ctx context.Context, in StageInput) (StagedRelease, error) {
	var out StagedRelease
	if err := stageInput(in); err != nil {
		return out, err
	}
	root, _ := Root(in.DataDir)
	a, err := readStageApproval(root, in.PlanID)
	if err != nil {
		return out, err
	}
	source, err := stageSource(ctx, in, &a)
	if err != nil {
		return out, err
	}
	r, err := readRelease(filepath.Join(root, "releases", a.ReleaseID), a.ReleaseID)
	if err != nil {
		return out, err
	}
	if err = stageMatches(r, source); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	return stagedResult(root, r, a, source.Plan, true), nil
}

// Stage copies only a locally prepared signed panel into persistent storage. It
// deliberately cannot select current, restart a service or migrate the database;
// those operations require the independent maintenance/snapshot transaction.
func Stage(ctx context.Context, in StageInput) (StagedRelease, error) {
	var out StagedRelease
	if os.Geteuid() != 0 {
		return out, errors.New("面板版本暂存需要本机 root")
	}
	if err := stageInput(in); err != nil {
		return out, err
	}
	root, _ := Root(in.DataDir)
	unlock, err := publicationLock(root)
	if err != nil {
		return out, err
	}
	defer unlock()
	if _, err = readStageApproval(root, in.PlanID); err == nil {
		return Staged(ctx, in)
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if err = runtimeDir(filepath.Join(root, "approvals")); err != nil {
		return out, err
	}
	entries, err := os.ReadDir(filepath.Join(root, "approvals"))
	if err != nil {
		return out, err
	}
	if len(entries) >= 64 {
		return out, errors.New("面板暂存批准达到保留上限，须本机维护")
	}
	trust, err := releases.InspectTrust(in.TrustPath)
	if err != nil {
		return out, err
	}
	source, err := stageSource(ctx, in, nil)
	if err != nil {
		return out, err
	}
	at := time.Now().Unix()
	a := source.Plan.Assets[0]
	binary := filepath.Join(source.Directory, a.ID, "nginxpanel")
	// Authenticate bytes before the fixed version command may execute them.
	var expected string
	for _, file := range a.Files {
		if file.Path == "nginxpanel" {
			expected = file.SHA256
		}
	}
	actual, err := secure.HashRootFile(binary, BinaryLimit)
	if err != nil {
		return out, err
	}
	if actual != expected {
		return out, releases.ErrReleaseChanged
	}
	r, err := DescribeBinary(ctx, binary)
	if err != nil {
		return out, err
	}
	r.ID = releaseID(r)
	if err = stageMatches(r, source); err != nil {
		return out, err
	}
	if err = publishRelease(ctx, root, binary, r); err != nil {
		return out, err
	}
	current, err := releases.InspectTrust(in.TrustPath)
	if err != nil {
		return out, err
	}
	if current.SHA256 != trust.SHA256 || current.SHA256 != source.Plan.TrustSHA256 || time.Now().Unix() >= source.Plan.Manifest.ExpiresAt {
		return out, releases.ErrReleaseChanged
	}
	approval := StageApproval{Schema: Schema, PlanID: source.Plan.ID, ReleaseID: r.ID, ManifestSHA256: source.Plan.ManifestSHA256, TrustSHA256: source.Plan.TrustSHA256, TrustPath: in.TrustPath, Prerelease: in.AllowPrerelease, ApprovedAt: at, Host: source.Plan.Host, Receiver: source.Plan.Receiver}
	raw, err := json.Marshal(approval)
	if err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = publishFile(stageApprovalPath(root, in.PlanID), raw); err != nil {
		return out, err
	}
	return stagedResult(root, r, approval, source.Plan, false), nil
}
