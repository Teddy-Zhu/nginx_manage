package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
)

const (
	fail2banStateManifestLimit = 1 << 20
	fail2banStateArchiveLimit  = int64(390 << 20)
	fail2banStateStoreLimit    = int64(1 << 30)
	fail2banStateSnapshotLimit = 8
)

var fail2banStateResources = []struct {
	name  string
	limit int64
}{
	{"fail2ban.sqlite3", 128 << 20},
	{"fail2ban.sqlite3-wal", 128 << 20},
	{"fail2ban.sqlite3-shm", 4 << 20},
	{"fail2ban.sqlite3-journal", 128 << 20},
}

type Fail2banStateSnapshotOptions struct {
	DataDir, Scope, OperationID string
}

type fail2banStateFile struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Mode    uint32 `json:"mode"`
	SELinux string `json:"selinux"`
}

type fail2banStateBasis struct {
	Managed       fail2banManagedRecord `json:"managed"`
	Bundle        *fail2banJailBundle   `json:"bundle"`
	Configuration map[string]string     `json:"configuration"`
	Service       fail2ban.Service      `json:"service"`
	Invocation    string                `json:"invocation"`
	MachineID     string                `json:"machine_id"`
	BootID        string                `json:"boot_id"`
	StateLabel    string                `json:"state_label"`
}

type fail2banStateManifest struct {
	Schema      int                 `json:"schema"`
	OperationID string              `json:"operation_id"`
	DataDir     string              `json:"data_dir"`
	CreatedAt   int64               `json:"created_at"`
	Basis       fail2banStateBasis  `json:"basis"`
	Files       []fail2banStateFile `json:"files"`
}

type fail2banStateReceipt struct {
	Schema         int                      `json:"schema"`
	OperationID    string                   `json:"operation_id"`
	DataDir        string                   `json:"data_dir"`
	CreatedAt      int64                    `json:"created_at"`
	InstallationID string                   `json:"installation_id"`
	EventID        string                   `json:"event_id"`
	Component      Fail2banUpgradeComponent `json:"component"`
	MachineID      string                   `json:"machine_id"`
	ManifestSHA256 string                   `json:"manifest_sha256"`
	ArchiveSHA256  string                   `json:"archive_sha256"`
	ArchiveSize    int64                    `json:"archive_size"`
	KeyID          string                   `json:"key_id"`
}

// Snapshot results contain no database contents, configuration text or bans.
// Verified authenticates captured bytes; it does not assert DB compatibility
// or authorize installing the staged state into a running engine.
type Fail2banStateSnapshot struct {
	State          string                   `json:"state"`
	ID             string                   `json:"id"`
	CreatedAt      int64                    `json:"created_at"`
	InstallationID string                   `json:"installation_id"`
	EventID        string                   `json:"event_id"`
	Component      Fail2banUpgradeComponent `json:"component"`
	ManifestSHA256 string                   `json:"manifest_sha256"`
	ArchiveSHA256  string                   `json:"archive_sha256"`
	ArchiveSize    int64                    `json:"archive_size"`
	Files          []fail2banStateFile      `json:"files"`
}

func fail2banStateDir(data string) string {
	return filepath.Join(fail2banBindingDir(data), "state-snapshots")
}

func (r fail2banStateReceipt) result(state string, m fail2banStateManifest) Fail2banStateSnapshot {
	return Fail2banStateSnapshot{State: state, ID: r.OperationID, CreatedAt: r.CreatedAt, InstallationID: r.InstallationID, EventID: r.EventID, Component: r.Component, ManifestSHA256: r.ManifestSHA256, ArchiveSHA256: r.ArchiveSHA256, ArchiveSize: r.ArchiveSize, Files: m.Files}
}

func fail2banStateJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > fail2banStateManifestLimit {
		return nil, errors.Join(errors.New("Fail2ban 状态快照清单超出限制"), err)
	}
	return raw, nil
}

func readFail2banStateBasis(ctx context.Context, data string) (fail2banStateBasis, error) {
	var out fail2banStateBasis
	binding, err := selectFail2banBinding(data)
	if err != nil || binding == nil || binding.managed == nil || binding.managed.ActionState != "completed" {
		return out, errors.Join(errors.New("状态快照须选择操作已完成的独立受管实例"), err)
	}
	r := binding.managed
	if err = verifyFail2banManaged(ctx, r, true); err != nil {
		return out, err
	}
	if err = fail2banManagedNoOther(ctx, data, false); err != nil {
		return out, err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return out, err
	}
	out.Service, out.Invocation, err = lifecycleService(ctx)
	if err != nil {
		return out, err
	}
	if out.Service.Load != "loaded" {
		return out, errors.New("状态快照须核对原已加载服务")
	}
	if err = fail2banExistingStopped(r.binding(), out.Service); err != nil {
		return out, errors.Join(errors.New("状态快照仅处理已停止实例；须另行授权停止保护"), err)
	}
	out.MachineID, out.BootID, err = hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil {
		return out, err
	}
	out.Managed = *r
	_, out.Bundle, err = selectedFail2banJails(r)
	if err != nil {
		return out, err
	}
	out.Configuration, err = fail2banJailConfig(r, out.Bundle)
	if err != nil {
		return out, err
	}
	out.Configuration["service.unit"] = r.unit()
	out.StateLabel, err = fail2banStateDirectoryLabel(filepath.Join(r.work(), "state"), nil)
	if err != nil {
		return out, err
	}
	return out, ctx.Err()
}

func (m fail2banStateManifest) validate(data, id string) error {
	r := m.Basis.Managed
	if m.Schema != 1 || m.OperationID != id || !validID(id) || m.DataDir != data || m.CreatedAt <= 0 || m.CreatedAt > time.Now().Unix()+300 || r.State != "installed" || r.ActionState != "completed" || !fail2banDigest.MatchString(m.Basis.MachineID) || !validID(m.Basis.BootID) || len(m.Basis.StateLabel) > 4096 || len(m.Files) != len(fail2banStateResources) {
		return errors.New("Fail2ban 状态快照身份无效")
	}
	if err := validateFail2banManagedRecord(r, data); err != nil {
		return err
	}
	if m.Basis.Bundle == nil {
		if r.JailSelection != "" {
			return errors.New("Fail2ban 状态快照缺少原 jail 配置包")
		}
	} else if m.Basis.Bundle.ID != r.JailSelection {
		return errors.New("Fail2ban 状态快照 jail 身份不匹配")
	}
	config, err := fail2banJailConfig(&r, m.Basis.Bundle)
	if err != nil {
		return err
	}
	config["service.unit"] = r.unit()
	want, err := fail2banStateJSON(config)
	if err != nil {
		return err
	}
	actual, err := fail2banStateJSON(m.Basis.Configuration)
	if err != nil || !bytes.Equal(want, actual) {
		return errors.Join(errors.New("Fail2ban 状态快照原配置无法核对"), err)
	}
	service := m.Basis.Service
	if !service.Available || service.ID != fail2banManagedService || service.Load != "loaded" || service.MainPID == nil || *service.MainPID != 0 || service.Active != "inactive" && service.Active != "failed" || m.Basis.Invocation != "" && !fail2banInvocation.MatchString(m.Basis.Invocation) {
		return errors.New("Fail2ban 状态快照停止证明无效")
	}
	for i, file := range m.Files {
		if file.Name != fail2banStateResources[i].name || file.Size < 0 || file.Size > fail2banStateResources[i].limit {
			return errors.New("Fail2ban 状态快照文件清单无效")
		}
		if file.Present {
			if !fail2banDigest.MatchString(file.SHA256) || file.Mode > 0777 || file.Mode&0022 != 0 || file.Mode&0400 == 0 || len(file.SELinux) > 4096 || i == 0 && file.Size == 0 || i != 0 && !m.Files[0].Present {
				return errors.New("Fail2ban 状态快照文件身份无效")
			}
		} else if file.Size != 0 || file.SHA256 != "" || file.Mode != 0 || file.SELinux != "" {
			return errors.New("Fail2ban 状态快照缺失文件不能包含伪造内容")
		}
	}
	return nil
}

func (r fail2banStateReceipt) validate(data, id string) error {
	if r.Schema != 1 || r.OperationID != id || !validID(id) || r.DataDir != data || r.CreatedAt <= 0 || r.CreatedAt > time.Now().Unix()+300 || !validID(r.InstallationID) || !validID(r.EventID) || !fail2banDigest.MatchString(r.MachineID) || !fail2banDigest.MatchString(r.ManifestSHA256) || !fail2banDigest.MatchString(r.ArchiveSHA256) || !fail2banDigest.MatchString(r.KeyID) || r.ArchiveSize <= 0 || r.ArchiveSize > fail2banStateArchiveLimit || r.Component.Version != fail2ban.RegexVersion || !fail2banDigest.MatchString(r.Component.PlanID) || r.Component.AssetID == "" || !fail2banDigest.MatchString(r.Component.ManifestSHA256) || !fail2banDigest.MatchString(r.Component.TrustSHA256) || !fail2banDigest.MatchString(r.Component.EngineKey) {
		return errors.New("Fail2ban 状态快照回执无效")
	}
	return nil
}

func fail2banStateSnapshotAccess(in Fail2banStateSnapshotOptions) (func(), error) {
	if err := fail2banManagedRoot(in.DataDir, in.Scope); err != nil {
		return nil, err
	}
	if !validID(in.OperationID) {
		return nil, errors.New("须提供独立的 Fail2ban 状态快照 UUID")
	}
	return (&Journal{Dir: fail2banBindingDir(in.DataDir)}).rootLock("binding.lock")
}

func CaptureFail2banState(parent context.Context, in Fail2banStateSnapshotOptions) (Fail2banStateSnapshot, error) {
	var out Fail2banStateSnapshot
	unlock, err := fail2banStateSnapshotAccess(in)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	dir := filepath.Join(fail2banStateDir(in.DataDir), in.OperationID)
	if _, err = os.Lstat(dir); err == nil {
		r, m, e := readFail2banStateArchive(ctx, in.DataDir, in.OperationID, dir, nil)
		if e != nil {
			return out, e
		}
		return r.result("verified", m), nil
	} else if !os.IsNotExist(err) {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	access, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer access()
	if err = fail2banUpgradeIdle(j); err != nil {
		return out, err
	}
	return captureFail2banState(ctx, in, j)
}

// Inspect and Prepare remain usable after a code switch. They authenticate the
// original local encrypted state and never select its historical engine.
func InspectFail2banState(parent context.Context, in Fail2banStateSnapshotOptions) (Fail2banStateSnapshot, error) {
	var out Fail2banStateSnapshot
	unlock, err := fail2banStateSnapshotAccess(in)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	r, m, err := readFail2banStateArchive(ctx, in.DataDir, in.OperationID, filepath.Join(fail2banStateDir(in.DataDir), in.OperationID), nil)
	if err != nil {
		return out, err
	}
	return r.result("verified", m), nil
}

func PrepareFail2banState(parent context.Context, in Fail2banStateSnapshotOptions) (Fail2banStateSnapshot, error) {
	var out Fail2banStateSnapshot
	unlock, err := fail2banStateSnapshotAccess(in)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	return prepareFail2banState(ctx, in)
}
