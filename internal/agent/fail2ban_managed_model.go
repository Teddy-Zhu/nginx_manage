package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

const fail2banManagedUnit = "/etc/systemd/system/nginxpanel-fail2ban.service"
const fail2banManagedSocket = "/run/nginxpanel-fail2ban/fail2ban.sock"
const fail2banManagedService = "nginxpanel-fail2ban.service"

type Fail2banInstallOptions struct {
	DataDir, Scope, OperationID, PlanID, AssetID, TrustPath string
	Prerelease, Start, Enable, Resume                       bool
}

type fail2banManagedRecord struct {
	Schema         int               `json:"schema"`
	EventID        string            `json:"event_id"`
	At             int64             `json:"at"`
	PreviousEvent  string            `json:"previous_event"`
	OperationID    string            `json:"operation_id"`
	DataDir        string            `json:"data_dir"`
	State          string            `json:"state"`
	Reason         string            `json:"reason"`
	Action         string            `json:"action"`
	ActionState    string            `json:"action_state"`
	ApprovedAt     int64             `json:"approved_at"`
	PlanID         string            `json:"plan_id"`
	AssetID        string            `json:"asset_id"`
	TrustPath      string            `json:"trust_path"`
	TrustSHA256    string            `json:"trust_sha256"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	Prerelease     bool              `json:"prerelease"`
	Host           releases.Host     `json:"host"`
	Receiver       releases.Receiver `json:"receiver"`
	PackageRoot    string            `json:"package_root"`
	Version        string            `json:"version"`
	PythonPath     string            `json:"python_path"`
	PythonSHA256   string            `json:"python_sha256"`
	PythonVersion  string            `json:"python_version"`
	ManagerPath    string            `json:"manager_path"`
	ManagerSHA256  string            `json:"manager_sha256"`
	Start          bool              `json:"start"`
	Enable         bool              `json:"enable"`
}

func fail2banManagedDir(data string) string {
	return filepath.Join(fail2banBindingDir(data), "managed")
}
func (r fail2banManagedRecord) work() string {
	return filepath.Join(fail2banManagedDir(r.DataDir), r.OperationID)
}
func (r fail2banManagedRecord) view() fail2ban.Managed {
	return fail2ban.Managed{Available: true, State: r.State, OperationID: r.OperationID, Version: r.Version, PlanID: r.PlanID, AssetID: r.AssetID, Service: fail2banManagedService, Socket: fail2banManagedSocket, PythonPath: r.PythonPath, PythonVersion: r.PythonVersion, ApprovedAt: r.ApprovedAt, Reason: r.Reason}
}
func fail2banManagedData(data string) bool {
	return filepath.IsAbs(data) && filepath.Clean(data) == data && (strings.HasPrefix(data, "/srv/") || strings.HasPrefix(data, "/var/lib/")) && strings.Trim(data, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == ""
}
func fail2banManagedRoot(data, scope string) error {
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" || !fail2banManagedData(data) {
		return errors.New("受管 Fail2ban 须由宿主机 root 指定 host 范围，数据目录须位于 /var/lib 或 /srv")
	}
	return nil
}
func loadFail2banManaged(data string) (*fail2banManagedRecord, error) {
	if !fail2banManagedData(data) {
		return nil, errors.New("受管 Fail2ban 数据目录无效")
	}
	raw, err := listenerRead(filepath.Join(fail2banManagedDir(data), "current.json"), 16384)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r fail2banManagedRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	// The pointer is checked against the immutable event before it is used.
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Schema != 1 || !validID(r.EventID) || r.PreviousEvent != "" && !validID(r.PreviousEvent) || !validID(r.OperationID) || r.DataDir != data || r.ApprovedAt <= 0 || r.ApprovedAt > time.Now().Unix()+300 || !fail2banDigest.MatchString(r.PlanID) || !fail2banDigest.MatchString(r.TrustSHA256) || !fail2banDigest.MatchString(r.ManifestSHA256) || !fail2banDigest.MatchString(r.PythonSHA256) || !fail2banDigest.MatchString(r.ManagerSHA256) || r.Version != fail2ban.RegexVersion || !fail2banPythonPath.MatchString(r.PythonPath) || !fail2banVersion.MatchString(r.PythonVersion) || !filepath.IsAbs(r.ManagerPath) || filepath.Clean(r.ManagerPath) != r.ManagerPath || len(r.ManagerPath) > 512 || len(r.Reason) > 1024 {
		return nil, errors.New("受管 Fail2ban 安装记录无效")
	}
	if r.At <= 0 || r.At > time.Now().Unix()+300 {
		return nil, errors.New("受管引擎事件时间无效")
	}
	if r.Action != "install" && r.Action != "start" && r.Action != "stop" && r.Action != "enable" && r.Action != "disable" && r.Action != "rollback" {
		return nil, errors.New("受管引擎操作登记无效")
	}
	if r.ActionState != "pending" && r.ActionState != "completed" && r.ActionState != "unknown" {
		return nil, errors.New("受管引擎操作结果登记无效")
	}
	switch r.State {
	case "reserved", "ready", "installed", "interrupted", "rolling-back", "rolled-back":
	default:
		return nil, errors.New("受管 Fail2ban 安装状态无效")
	}
	if r.PackageRoot != filepath.Join(releases.Store, r.PlanID, r.AssetID) || r.AssetID == "" || len(r.AssetID) > 128 || strings.ContainsAny(r.AssetID, "/\\\x00") || !filepath.IsAbs(r.TrustPath) || filepath.Clean(r.TrustPath) != r.TrustPath || len(r.TrustPath) > 512 {
		return nil, errors.New("受管 Fail2ban 组件身份无效")
	}
	// A current pointer may only refer to an already durable immutable event.
	event, err := listenerRead(filepath.Join(fail2banManagedDir(data), "history", r.EventID+".json"), 16384)
	if err != nil || !bytes.Equal(event, raw) {
		return nil, errors.New("受管 Fail2ban 安装审计记录不一致")
	}
	return &r, nil
}
func saveFail2banManaged(r *fail2banManagedRecord, state, reason string) error {
	next := *r
	next.PreviousEvent, next.EventID, next.State, next.Reason = r.EventID, secure.ID(), state, reason
	next.At = time.Now().Unix()
	dir := fail2banManagedDir(r.DataDir)
	if err := secure.RootDirectory(filepath.Join(dir, "history"), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(&next)
	if err != nil {
		return err
	}
	if len(raw) > 16384 {
		return errors.New("受管引擎审计记录超限")
	}
	if err := writeFail2banManagedFile(filepath.Join(dir, "history", next.EventID+".json"), string(raw)); err != nil {
		return err
	}
	if err := rootJSONWrite(filepath.Join(dir, "current.json"), &next, 16384); err != nil {
		return err
	}
	*r = next
	return nil
}
func (r fail2banManagedRecord) releaseInput() releases.Input {
	return releases.Input{TrustPath: r.TrustPath, Assets: []string{r.AssetID}, AllowedComponents: []string{"fail2ban"}, AllowPrerelease: r.Prerelease, Host: r.Host, Receiver: r.Receiver}
}
func fail2banManagedRelease(p releases.Result, assetID string) (releases.Asset, error) {
	if len(p.Plan.Assets) != 1 || len(p.Plan.Selected) != 1 || p.Plan.Selected[0] != assetID || p.Plan.Assets[0].ID != assetID || p.Plan.Assets[0].Component != "fail2ban" || p.Plan.Assets[0].Version != fail2ban.RegexVersion {
		return releases.Asset{}, errors.New("须选择单个已准备且版本为 " + fail2ban.RegexVersion + " 的官方 Fail2ban 代码资产")
	}
	a := p.Plan.Assets[0]
	for _, name := range []string{"bin/fail2ban-server", "bin/fail2ban-client", "bin/fail2ban-regex", "fail2ban/__init__.py", "fail2ban/version.py", "fail2ban/client/fail2banserver.py", "fail2ban/client/fail2banclient.py", "fail2ban/client/fail2banregex.py", "fail2ban/server/server.py"} {
		found := false
		for _, f := range a.Files {
			if f.Path == name && f.Size > 0 {
				found = true
			}
		}
		if !found {
			return a, errors.New("Fail2ban 代码资产缺少固定入口或模块：" + name)
		}
	}
	return a, nil
}
func admitFail2banManaged(ctx context.Context, in Fail2banInstallOptions) (*fail2banManagedRecord, error) {
	p := platform.Detect()
	r := &fail2banManagedRecord{Schema: 1, Action: "install", ActionState: "pending", OperationID: in.OperationID, DataDir: in.DataDir, PlanID: in.PlanID, AssetID: in.AssetID, TrustPath: in.TrustPath, Prerelease: in.Prerelease, Start: in.Start, Enable: in.Enable, ApprovedAt: time.Now().Unix(), Host: releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: p.OS, Version: p.Version}, Receiver: releases.Receiver{APIMajor: 1, AgentProtocol: protocol.Agent, Launcher: releases.LauncherVersion}}
	prepared, err := releases.Prepared(ctx, r.releaseInput(), r.PlanID)
	if err != nil {
		return nil, err
	}
	a, err := fail2banManagedRelease(prepared, r.AssetID)
	if err != nil {
		return nil, err
	}
	python := readFail2banPython(ctx)
	if !python.Executable.Trusted || python.StandardLibrary == nil || !*python.StandardLibrary {
		return nil, errors.New("须先准备系统 Python 及所需标准库；安装器不执行 pip 或安装软件包")
	}
	r.PythonPath, r.PythonVersion = python.Executable.Resolved, python.Version
	found := false
	for _, f := range a.RuntimeFiles {
		if f.Path == r.PythonPath && f.Mode == 0755 {
			found = true
		}
	}
	if !found {
		return nil, errors.New("签名资产未约束实际系统 Python 解释器")
	}
	r.PythonSHA256, err = secure.HashRootFile(r.PythonPath, 64<<20)
	if err != nil {
		return nil, err
	}
	r.ManagerPath, err = os.Executable()
	if err != nil {
		return nil, err
	}
	r.ManagerPath, err = filepath.EvalSymlinks(r.ManagerPath)
	if err != nil {
		return nil, err
	}
	if len(r.ManagerPath) > 512 || strings.Trim(r.ManagerPath, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" || strings.HasPrefix(r.ManagerPath, "/home/") || strings.HasPrefix(r.ManagerPath, "/root/") || strings.HasPrefix(r.ManagerPath, "/run/") {
		return nil, errors.New("管理程序须位于服务可访问的固定 root 保护路径")
	}
	r.ManagerSHA256, err = secure.HashRootFile(r.ManagerPath, 256<<20)
	if err != nil {
		return nil, err
	}
	r.PackageRoot = filepath.Join(prepared.Directory, r.AssetID)
	r.Version = a.Version
	r.TrustSHA256, r.ManifestSHA256 = prepared.Plan.TrustSHA256, prepared.Plan.ManifestSHA256
	return r, nil
}
