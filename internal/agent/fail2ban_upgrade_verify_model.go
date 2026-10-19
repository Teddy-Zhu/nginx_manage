package agent

import (
	"errors"
	"net/netip"
	"path/filepath"
	"time"

	"nginxpanel/internal/firewall"
)

const fail2banUpgradeVerificationKind = "fail2ban_upgrade_verification"
const fail2banUpgradeVerificationLimit = 12 << 20

type Fail2banUpgradeVerificationOptions struct {
	DataDir, Scope, OperationID, SwitchID, RestoreID string
	NginxBinary, NginxWorker                         string
	NginxContainer                                   bool
}

type Fail2banUpgradeActionVerification struct {
	State       string `json:"state"`
	Jails       int    `json:"jails"`
	Banned      int    `json:"banned"`
	Protected   int    `json:"protected"`
	SHA256      string `json:"sha256"`
	OperationID string `json:"operation_id"`
}

type Fail2banUpgradeVerification struct {
	ID          string                             `json:"id"`
	SwitchID    string                             `json:"switch_id,omitempty"`
	RestoreID   string                             `json:"restore_id,omitempty"`
	State       string                             `json:"state"`
	VerifiedAt  int64                              `json:"verified_at"`
	ProofSHA256 string                             `json:"proof_sha256"`
	Recovery    Fail2banStateRecovery              `json:"recovery"`
	Host        *Fail2banUpgradeActionVerification `json:"host"`
	Nginx       *Fail2banUpgradeActionVerification `json:"nginx"`
}

type fail2banUpgradeHostVerification struct {
	Runtime   fail2banHostRuntime
	Kernel    firewall.KernelView
	Protected []string
}

type fail2banUpgradeNginxVerification struct {
	Binary, BinarySHA256, RuntimeSHA256 string
	Container                           bool
	UID, GID                            int
	SocketInode                         string
	PID                                 int
	StartTicks                          uint64
	BootID                              string
	Directory                           string
	Manifest                            manifest
	Snapshot                            clientDenySnapshot
	Checkpoint                          Record
}

// Address-bearing evidence stays root-local. Public results contain only
// counts and hashes and describe this observation, never later live state.
type fail2banUpgradeVerification struct {
	Schema              int
	Request             Fail2banUpgradeVerificationOptions
	CreatedAt           int64
	SourceSHA256        string
	SourceReceiptSHA256 string
	Managed             fail2banManagedRecord
	Recovery            Fail2banStateRecovery
	Expected, Actual    fail2banBanProof
	Host                *fail2banUpgradeHostVerification
	Nginx               *fail2banUpgradeNginxVerification
}

func fail2banUpgradeVerifications(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-verifications")
}
func (v fail2banUpgradeVerification) path() string {
	return filepath.Join(fail2banUpgradeVerifications(v.Request.DataDir), v.Request.OperationID+".json")
}
func (v fail2banUpgradeVerification) hash() string {
	return fail2banUpgradeGrantHash("protection-verification", v)
}

func (v fail2banUpgradeVerification) record() Record {
	return Record{Kind: fail2banUpgradeVerificationKind, OperationID: v.Request.OperationID, RelatedOperationID: fail2banUpgradeSelectionSourceID(v.Request.SwitchID, v.Request.RestoreID), RequestHash: fail2banUpgradeGrantHash("verification-request", v.Request), CandidateHash: v.hash(), BeforeRevision: v.Recovery.Source.EngineKey, AfterRevision: v.Managed.EventID, ObservedRevision: fail2banUpgradeGrantHash("verification-actions", struct {
		Host  *fail2banUpgradeHostVerification
		Nginx *fail2banUpgradeNginxVerification
	}{v.Host, v.Nginx}), State: "succeeded", Stage: "protection_verified"}
}

func (v fail2banUpgradeVerification) result(i fail2banUpgradeSelection) (Fail2banUpgradeVerification, error) {
	out := Fail2banUpgradeVerification{ID: v.Request.OperationID, SwitchID: v.Request.SwitchID, RestoreID: v.Request.RestoreID, State: "verified_unacknowledged", VerifiedAt: v.CreatedAt, ProofSHA256: v.hash(), Recovery: v.Recovery}
	hostJails, nginxJails := 0, 0
	if b := i.Bundle; b != nil {
		for _, jail := range b.Policy.Jails {
			if !jail.Enabled {
				continue
			}
			if jail.Action == "host-input" {
				hostJails++
			} else {
				nginxJails++
			}
		}
	}
	if v.Host != nil {
		wanted, excluded, err := fail2banUpgradeHostAddresses(i.Bundle, v.Actual, v.Host.Protected)
		if err != nil {
			return out, err
		}
		out.Host = &Fail2banUpgradeActionVerification{State: "verified", Jails: hostJails, Banned: len(wanted), Protected: excluded, SHA256: v.Host.Kernel.Fingerprint, OperationID: v.Host.Runtime.Intent.OperationID}
	}
	if v.Nginx != nil {
		entries, excluded, err := fail2banUpgradeNginxEntries(i.Bundle, v.Actual, v.Nginx.Manifest.ClientDeny)
		if err != nil {
			return out, err
		}
		count := 0
		for _, addresses := range entries {
			count += len(addresses)
		}
		out.Nginx = &Fail2banUpgradeActionVerification{State: "verified", Jails: nginxJails, Banned: count, Protected: excluded, SHA256: fail2banUpgradeGrantHash("verified-nginx-entries", entries), OperationID: v.Nginx.Checkpoint.OperationID}
	}
	return out, nil
}

func (v fail2banUpgradeVerification) validate(data, id string, i fail2banUpgradeSelection) error {
	in := v.Request
	if v.Schema != 1 || in.DataDir != data || in.Scope != "host" || in.OperationID != id || !validID(id) || !i.matches(in.SwitchID, in.RestoreID) || v.CreatedAt < i.CompletedAt || v.CreatedAt > time.Now().Unix()+300 || v.SourceSHA256 != i.SHA256 || v.SourceReceiptSHA256 != i.ReceiptSHA256 {
		return errors.New("升级保护核对身份、切换或完成证明不匹配")
	}
	if err := i.independentID(id); err != nil {
		return err
	}
	r := v.Recovery
	if r.State != "verified" || r.SnapshotID != i.Snapshot.OperationID || r.ManifestSHA256 != i.Snapshot.ManifestSHA256 || r.InstallationID != i.Managed.OperationID || r.EventID != v.Managed.EventID || r.JailSelection != i.Managed.JailSelection || r.At != v.CreatedAt || r.DatabaseSchema != 4 || !fail2banInvocation.MatchString(r.Invocation) || r.Source != i.Snapshot.Component || r.Current != fail2banUpgradeComponent(&v.Managed) || !fail2banUpgradeCandidateCore(i.Managed, v.Managed) || v.Managed.ActionState != "completed" || v.Expected == nil || v.Actual == nil {
		return errors.New("升级保护证明的代码、官方封禁或配置身份无效")
	}
	if err := validateFail2banManagedRecord(v.Managed, data); err != nil {
		return err
	}
	if len(v.Expected) != len(v.Actual) || len(v.Actual) != len(fail2banJailNames(i.Bundle)) {
		return errors.New("升级保护证明未覆盖完整启用 jail")
	}
	for _, name := range fail2banJailNames(i.Bundle) {
		if v.Expected[name] == nil || v.Actual[name] == nil {
			return errors.New("升级保护证明缺少官方 jail")
		}
	}
	if err := validateFail2banUpgradeBanProof(v.Expected); err != nil {
		return err
	}
	if err := validateFail2banUpgradeBanProof(v.Actual); err != nil {
		return err
	}
	if fail2banRecoveryBanSummary(v.Expected, r.Expected.ObservedAt) != r.Expected || fail2banRecoveryBanSummary(v.Actual, r.Actual.ObservedAt) != r.Actual || r.Expected.ObservedAt <= 0 || r.Actual.ObservedAt < r.Expected.ObservedAt || r.At < r.Actual.ObservedAt {
		return errors.New("升级保护证明的封禁摘要或观测时间不匹配")
	}
	if err := checkFail2banBanPreservationAt(v.Expected, v.Actual, r.At); err != nil {
		return err
	}
	if fail2banJailNeedsHost(i.Bundle) != (v.Host != nil) || fail2banJailNeedsNginx(i.Bundle) != (v.Nginx != nil) {
		return errors.New("升级保护证明遗漏已启用动作")
	}
	if v.Host != nil {
		if v.Host.Kernel.ObservedAt <= 0 || v.Host.Kernel.ObservedAt > v.CreatedAt {
			return errors.New("宿主机规则证明的观测时间无效")
		}
		if err := validateFail2banUpgradeHostVerification(i, v.Actual, *v.Host); err != nil {
			return err
		}
	}
	if v.Nginx != nil {
		if v.Nginx.Snapshot.ObservedAt > v.CreatedAt || v.Nginx.Container != in.NginxContainer {
			return errors.New("Nginx 规则证明的观测时间或运行来源无效")
		}
		if err := validateFail2banUpgradeNginxVerification(i, v.Actual, r.Invocation, *v.Nginx); err != nil {
			return err
		}
	}
	return nil
}

func fail2banUpgradeVerificationID(id string, i fail2banUpgradeSwitch) error {
	ids := i.Prepared.Material.IDs
	for _, reserved := range []string{i.Request.OperationID, i.Request.PreparationID, i.Request.SnapshotID, i.After.OperationID, i.After.EventID, i.Prepared.Basis.Current.EventID, ids.Jails, ids.Nginx, ids.Sources, ids.Sync} {
		if id == reserved {
			return errors.New("保护核对 UUID 不得复用安装、切换、快照、选择或批准标识")
		}
	}
	return nil
}

func validateFail2banUpgradeBanProof(proof fail2banBanProof) error {
	for _, bans := range proof {
		if bans == nil || len(bans) > 1024 {
			return errors.New("升级完整封禁证明缺失或超过单 jail 1024 项上限")
		}
		for address, ban := range bans {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.Zone() != "" || ip.Unmap().String() != address || ban.Duration < -1 || (ban.Duration == -1) != (ban.Expires == 0) || ban.Expires < 0 {
				return errors.New("升级封禁证明的地址、时长或到期时间无效")
			}
		}
	}
	return nil
}

func fail2banUpgradeCandidateCore(expected, actual fail2banManagedRecord) bool {
	actual.EventID, actual.PreviousEvent, actual.At = expected.EventID, expected.PreviousEvent, expected.At
	actual.Action, actual.ActionState, actual.Reason = expected.Action, expected.ActionState, expected.Reason
	return fail2banUpgradeOneOf(actual, expected)
}
