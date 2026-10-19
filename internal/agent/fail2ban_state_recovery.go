package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

// This is a fresh observation, not a start grant or durable upgrade receipt.
// Raw ban addresses remain root-local and are represented only by digests.
type Fail2banStateRecovery struct {
	State          string                   `json:"state"`
	SnapshotID     string                   `json:"snapshot_id"`
	ManifestSHA256 string                   `json:"manifest_sha256"`
	InstallationID string                   `json:"installation_id"`
	EventID        string                   `json:"event_id"`
	JailSelection  string                   `json:"jail_selection"`
	Invocation     string                   `json:"invocation"`
	At             int64                    `json:"at"`
	DatabaseSchema int                      `json:"database_schema"`
	Source         Fail2banUpgradeComponent `json:"source"`
	Current        Fail2banUpgradeComponent `json:"current"`
	Expected       Fail2banUpgradeBans      `json:"expected"`
	Actual         Fail2banUpgradeBans      `json:"actual"`
}

type fail2banStateRecoveryJail struct {
	Name     string `json:"name"`
	Duration int64  `json:"duration"`
}

// Kept inside the caller's host/binding/maintenance locks. Addresses and the
// live Socket identity are never part of a public recovery result.
type fail2banStateRecoveryObservation struct {
	Receipt          fail2banStateReceipt
	Manifest         fail2banStateManifest
	Managed          *fail2banManagedRecord
	Bundle           *fail2banJailBundle
	Live             fail2banLiveService
	Expected, Actual fail2banBanProof
}

func fail2banRecoveryBundle(b *fail2banJailBundle) []byte {
	if b == nil {
		return []byte("null")
	}
	copy := *b
	// A code switch needs new engine/grant identities. Its logical policy,
	// protected addresses, log bindings and Nginx generation must stay exact.
	copy.ID, copy.EngineKey, copy.HostProtectionID = "", "", ""
	raw, _ := json.Marshal(copy)
	return raw
}

func fail2banStateRecoverySelection(ctx context.Context, data string, m fail2banStateManifest) (*fail2banManagedRecord, *fail2banJailBundle, string, error) {
	binding, err := selectFail2banBinding(data)
	if err != nil || binding == nil || binding.managed == nil || binding.managed.ActionState != "completed" {
		return nil, nil, "", errors.Join(errors.New("封禁恢复核对须选择操作已完成的受管实例"), err)
	}
	r, original := binding.managed, &m.Basis.Managed
	machine, _, err := hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil {
		return nil, nil, "", err
	}
	if machine != m.Basis.MachineID || r.OperationID != original.OperationID || r.Version != fail2ban.RegexVersion || original.Version != fail2ban.RegexVersion || r.PythonPath != original.PythonPath || r.PythonSHA256 != original.PythonSHA256 || r.PythonVersion != original.PythonVersion || r.ManagerPath != original.ManagerPath || r.ManagerSHA256 != original.ManagerSHA256 {
		return nil, nil, "", errors.New("封禁恢复核对须保持原本机、安装、官方版本、解释器及管理程序身份")
	}
	if err = verifyFail2banManaged(ctx, r, true); err != nil {
		return nil, nil, "", err
	}
	if err = verifyFail2banManaged(ctx, original, false); err != nil {
		return nil, nil, "", err
	}
	if err = fail2banManagedNoOther(ctx, data, false); err != nil {
		return nil, nil, "", err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return nil, nil, "", err
	}
	selection, bundle, err := selectedFail2banJails(r)
	if err != nil {
		return nil, nil, "", err
	}
	if !bytes.Equal(fail2banRecoveryBundle(bundle), fail2banRecoveryBundle(m.Basis.Bundle)) {
		return nil, nil, "", errors.New("封禁恢复核对期间不得变更原 jail 策略、日志、代理及受保护地址")
	}
	configuration, err := fail2banJailConfig(r, bundle)
	if err != nil {
		return nil, nil, "", err
	}
	// The signed code path in the systemd unit may change during an upgrade.
	// All generated Fail2ban configuration must remain byte-for-byte equal.
	if len(configuration)+1 != len(m.Basis.Configuration) {
		return nil, nil, "", errors.New("封禁恢复核对的配置清单已变化")
	}
	for name, content := range configuration {
		if originalContent, ok := m.Basis.Configuration[name]; !ok || originalContent != content {
			return nil, nil, "", errors.New("封禁恢复核对的原配置已变化")
		}
	}
	return r, bundle, selection, nil
}

func readFail2banStateRecovery(ctx context.Context, dir string, m fail2banStateManifest, at int64) (fail2banBanProof, error) {
	if !m.Files[0].Present {
		return nil, errors.New("原快照尚无官方状态库，不能推断已恢复零项封禁")
	}
	spec := struct {
		At    int64                       `json:"at"`
		Jails []fail2banStateRecoveryJail `json:"jails"`
	}{At: at, Jails: []fail2banStateRecoveryJail{}}
	if m.Basis.Bundle != nil {
		for _, jail := range m.Basis.Bundle.Policy.Jails {
			if jail.Enabled {
				spec.Jails = append(spec.Jails, fail2banStateRecoveryJail{Name: fail2banJailNameFor(jail.ID), Duration: jail.BanTime})
			}
		}
	}
	input, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	r := &m.Basis.Managed
	args := []string{"-I", "-S", "-B", "-c", fail2banStateRecoveryPython, r.PackageRoot, filepath.Join(dir, "fail2ban.sqlite3"), string(input)}
	raw, err := fail2banManagedExec(ctx, r.python(), args, 12*time.Second, fail2banBanProofLimit)
	if err != nil {
		return nil, errors.Join(errors.New("原快照官方数据库读取未完成，不认定封禁恢复成功"), err)
	}
	var proof fail2banBanProof
	if err = decodeFail2banNginxJSON(raw, &proof); err != nil || proof == nil || len(proof) != len(spec.Jails) {
		return nil, errors.Join(errors.New("官方数据库返回的完整 jail 记录不可核对"), err)
	}
	if m.Basis.Bundle != nil {
		for _, jail := range m.Basis.Bundle.Policy.Jails {
			if !jail.Enabled {
				continue
			}
			bans, ok := proof[fail2banJailNameFor(jail.ID)]
			if !ok || bans == nil || len(bans) > 1024 {
				return nil, errors.New("官方数据库遗漏原 jail 或封禁记录超限")
			}
			ignored, err := fail2banIgnoreSet(jail, m.Basis.Bundle)
			if err != nil {
				return nil, err
			}
			for address, ban := range bans {
				ip, err := netip.ParseAddr(address)
				if err != nil || ip.Zone() != "" || ip.Unmap().String() != address || ban.Duration < -1 || (ban.Duration == -1) != (ban.Expires == 0) || ban.Expires != 0 && ban.Expires <= at {
					return nil, errors.New("官方数据库返回的封禁地址或到期时间不可核对")
				}
				// Fixed generated jails use no DNS or ignorecommand. Match the
				// same canonical IP/network exclusions used on official startup.
				for _, value := range ignored {
					if value == address {
						delete(bans, address)
						break
					}
					if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(ip) {
						delete(bans, address)
						break
					}
				}
			}
		}
	}
	return proof, nil
}

func fail2banRecoveryBanSummary(proof fail2banBanProof, at int64) Fail2banUpgradeBans {
	raw, _ := json.Marshal(proof)
	out := Fail2banUpgradeBans{ObservedAt: at, SHA256: secure.Hash(raw)}
	for _, bans := range proof {
		out.Count += len(bans)
	}
	return out
}

// VerifyFail2banStateRecovery authenticates one encrypted snapshot, reads only
// its disposable copy, and observes the selected running engine. It neither
// starts a service nor changes its live database, configuration or grants.
func VerifyFail2banStateRecovery(parent context.Context, in Fail2banStateSnapshotOptions) (out Fail2banStateRecovery, resultErr error) {
	unlock, err := fail2banStateSnapshotAccess(in)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	access, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer access()
	return verifyFail2banStateRecovery(ctx, in, j, nil)
}

func verifyFail2banStateRecovery(ctx context.Context, in Fail2banStateSnapshotOptions, j *Journal, complete func(Fail2banStateRecovery, fail2banStateRecoveryObservation) error) (out Fail2banStateRecovery, resultErr error) {
	var err error
	if err = fail2banUpgradeIdle(j); err != nil {
		return out, err
	}
	dir := filepath.Join(fail2banStateDir(in.DataDir), in.OperationID)
	if err = fail2banStatePrivateDir(dir, false); err != nil {
		return out, err
	}
	var receipt fail2banStateReceipt
	if err = readFail2banNginxJSON(filepath.Join(dir, "receipt.json"), &receipt, 16<<10); err != nil {
		return out, err
	}
	if err = receipt.validate(in.DataDir, in.OperationID); err != nil {
		return out, err
	}
	declared := receipt
	// Reserve the complete clone and bounded SQLite journal recovery growth.
	if err = fail2banStateQuota(fail2banStateDir(in.DataDir), receipt.ArchiveSize+(128<<20), false); err != nil {
		return out, err
	}
	tmp, err := os.MkdirTemp(dir, ".verify-")
	if err != nil {
		return out, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(tmp)) }()
	var copiedSize int64
	visit := func(file fail2banStateFile, src io.Reader) (int64, error) {
		copiedSize += file.Size
		if copiedSize > declared.ArchiveSize {
			return 0, errors.New("Fail2ban 核对副本超过原配额预留")
		}
		f, err := os.OpenFile(filepath.Join(tmp, file.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return 0, err
		}
		n, copied := io.Copy(f, src)
		closed := f.Close()
		return n, errors.Join(copied, closed)
	}
	receipt, m, err := readFail2banStateArchive(ctx, in.DataDir, in.OperationID, dir, visit)
	if err != nil {
		return out, err
	}
	if receipt != declared {
		return out, errors.New("Fail2ban 核对期间快照回执发生变化")
	}
	r, bundle, selection, err := fail2banStateRecoverySelection(ctx, in.DataDir, m)
	if err != nil {
		return out, err
	}
	before, err := readFail2banLiveService(ctx, r.binding())
	if err != nil {
		return out, err
	}
	at := time.Now().Unix()
	expected, err := readFail2banStateRecovery(ctx, tmp, m, at)
	if err != nil {
		return out, err
	}
	actual, err := readFail2banJailRuntime(ctx, r, bundle)
	if err != nil {
		return out, err
	}
	actualAt := time.Now().Unix()
	if len(expected) != len(actual) {
		return out, errors.New("恢复后的完整 jail 名单与原快照不同")
	}
	for jail := range expected {
		if _, ok := actual[jail]; !ok {
			return out, errors.New("恢复后的实例遗漏原 jail")
		}
	}
	if err = checkFail2banBanPreservation(expected, actual); err != nil {
		return out, err
	}
	current, _, currentSelection, err := fail2banStateRecoverySelection(ctx, in.DataDir, m)
	if err != nil {
		return out, err
	}
	after, err := readFail2banLiveService(ctx, current.binding())
	if err != nil || !sameFail2banLive(before, after) || current.EventID != r.EventID || currentSelection != selection || fail2banUpgradeComponent(current) != fail2banUpgradeComponent(r) {
		return out, errors.Join(errors.New("封禁恢复核对期间安装、配置或运行代次发生变化"), err)
	}
	if err = fail2banUpgradeIdle(j); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	out = Fail2banStateRecovery{State: "verified", SnapshotID: in.OperationID, ManifestSHA256: receipt.ManifestSHA256, InstallationID: r.OperationID, EventID: r.EventID, JailSelection: selection, Invocation: before.invocation, At: time.Now().Unix(), DatabaseSchema: 4, Source: receipt.Component, Current: fail2banUpgradeComponent(r), Expected: fail2banRecoveryBanSummary(expected, at), Actual: fail2banRecoveryBanSummary(actual, actualAt)}
	if complete != nil {
		err = complete(out, fail2banStateRecoveryObservation{Receipt: receipt, Manifest: m, Managed: r, Bundle: bundle, Live: before, Expected: expected, Actual: actual})
		if err != nil {
			return Fail2banStateRecovery{}, err
		}
	}
	return out, ctx.Err()
}
