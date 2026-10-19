package agent

import (
	"errors"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
)

const fail2banUpgradeQuiesceKind = "nginx.fail2ban-upgrade-quiesce"

// Quiesce authorizes stopping this exact running preparation. Its output is
// input to the stopped switch, not permission to start or select another code.
type Fail2banUpgradeQuiesceOptions struct{ DataDir, Scope, OperationID, PreparationID, Target string }

type Fail2banUpgradeQuiesce struct {
	ID                       string               `json:"id"`
	State                    string               `json:"state"`
	Stage                    string               `json:"stage"`
	PreparationID            string               `json:"preparation_id"`
	SnapshotID               string               `json:"snapshot_id"`
	StoppedPreparationID     string               `json:"stopped_preparation_id"`
	StoppedPreparationSHA256 string               `json:"stopped_preparation_sha256"`
	CompletedAt              int64                `json:"completed_at"`
	Bans                     *Fail2banUpgradeBans `json:"bans"`
	Reason                   string               `json:"reason"`
}

type fail2banUpgradeQuiesceIntent struct {
	Schema                           int
	CreatedAt                        int64
	Request                          Fail2banUpgradeQuiesceOptions
	PreparationReceiptSHA256         string
	SnapshotID, StoppedPreparationID string
	MachineID, BootID                string
	Directory                        fail2banStateDirectory
	Invocation, SocketInode          string
	PID                              int64
	Bans                             fail2banBanProof
	Recovery                         fail2banUpgradeHostRecovery
	Nginx                            *fail2banUpgradeQuiesceNginx
	Kernel                           firewall.KernelView
}

type fail2banUpgradeQuiesceStopped struct {
	fail2banUpgradeActivationMarker
	At          int64
	Service     fail2ban.Service
	Invocation  string
	FilesSHA256 string
}

type fail2banUpgradeQuiesceReceipt struct {
	fail2banUpgradeActivationMarker
	Outcome                                  string
	CompletedAt                              int64
	SnapshotReceiptSHA256, PreparationSHA256 string
	Bans                                     *Fail2banUpgradeBans
}

type fail2banUpgradeQuiesceFacts struct {
	Execution bool
	Stopped   *fail2banUpgradeQuiesceStopped
	Receipt   *fail2banUpgradeQuiesceReceipt
}

func fail2banUpgradeQuiescences(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-quiescences")
}
func (i fail2banUpgradeQuiesceIntent) dir() string {
	return filepath.Join(fail2banUpgradeQuiescences(i.Request.DataDir), i.Request.OperationID)
}
func (i fail2banUpgradeQuiesceIntent) hash() string { return fail2banUpgradeGrantHash("quiesce", i) }
func (i fail2banUpgradeQuiesceIntent) marker() fail2banUpgradeActivationMarker {
	return fail2banUpgradeActivationMarker{1, i.Request.OperationID, i.hash()}
}

func (i fail2banUpgradeQuiesceIntent) validate(data, id string, p fail2banUpgradePreparation, receipt fail2banUpgradePreparationReceipt) error {
	in, b := i.Request, p.Basis
	if i.Schema != 1 || in.DataDir != data || in.Scope != "host" || in.OperationID != id || !validID(id) || in.PreparationID != p.Request.OperationID || in.Target != p.hash() || i.PreparationReceiptSHA256 != fail2banUpgradeGrantHash("preparation-receipt", receipt) || i.CreatedAt < p.CreatedAt || i.CreatedAt > time.Now().Unix()+300 || b.Service.MainPID == nil || *b.Service.MainPID != i.PID || i.PID < 2 || b.Service.Active != "active" || b.Invocation != i.Invocation || !fail2banInvocation.MatchString(i.Invocation) || i.Directory.Inode == 0 || !fail2banDigest.MatchString(i.MachineID) || !validID(i.BootID) || i.Bans == nil || i.SocketInode == "" {
		return errors.New("升级停止意图与原运行准备或实例身份不匹配")
	}
	ids := []string{id, i.SnapshotID, i.StoppedPreparationID, in.PreparationID}
	for n, value := range ids {
		if !validID(value) {
			return errors.New("升级停止与子材料须使用独立 UUID")
		}
		for _, other := range ids[:n] {
			if value == other {
				return errors.New("升级停止标识重复")
			}
		}
		for _, old := range append(fail2banUpgradeOriginalIDs(b, i.Recovery), p.Material.IDs.Jails, p.Material.IDs.Nginx, p.Material.IDs.Sources, p.Material.IDs.Sync) {
			if value == old {
				return errors.New("升级停止不得复用原操作或批准标识")
			}
		}
	}
	if root := b.HostRegistration; root != nil && root.State == "registered" {
		copy := p
		copy.Recovery = i.Recovery
		program, expected := fail2banUpgradeOriginalHostProgram(copy)
		if !fail2banHostProgramShape(program, i.Kernel) || i.Kernel.NamespaceID != expected.NamespaceID || i.Kernel.Fingerprint != expected.Fingerprint {
			return errors.New("升级停止缺少完整原内核证明")
		}
	} else if i.Kernel != (firewall.KernelView{}) {
		return errors.New("升级停止包含范围外内核证明")
	}
	return i.validateNginx(p)
}

func (i fail2banUpgradeQuiesceIntent) record(receipt *fail2banUpgradeQuiesceReceipt) Record {
	r := Record{Kind: fail2banUpgradeQuiesceKind, OperationID: i.Request.OperationID, RelatedOperationID: i.Request.PreparationID, RequestHash: fail2banUpgradeGrantHash("quiesce-request", i.Request), CandidateHash: i.hash(), BeforeRevision: i.Request.Target, AfterRevision: i.StoppedPreparationID, State: "running", Stage: "quiescing"}
	if receipt != nil {
		r.ObservedRevision = fail2banUpgradeGrantHash("quiesce-receipt", receipt)
		r.State, r.Stage = "succeeded", "prepared_stopped"
		if receipt.Outcome == "cancelled" {
			r.State, r.Stage = "cancelled", "cancelled_before_stop"
		}
	}
	return r
}

func (i fail2banUpgradeQuiesceIntent) result(f fail2banUpgradeQuiesceFacts, acknowledged bool) Fail2banUpgradeQuiesce {
	out := Fail2banUpgradeQuiesce{ID: i.Request.OperationID, PreparationID: i.Request.PreparationID, SnapshotID: i.SnapshotID, StoppedPreparationID: i.StoppedPreparationID, State: "running", Stage: "intent_reserved"}
	if f.Execution {
		out.Stage = "stopping_original"
	}
	if f.Stopped != nil {
		out.Stage = "capturing_state"
	}
	if f.Receipt != nil {
		out.State, out.Stage, out.CompletedAt = "succeeded", "prepared_stopped", f.Receipt.CompletedAt
		out.StoppedPreparationSHA256, out.Bans = f.Receipt.PreparationSHA256, f.Receipt.Bans
		if f.Receipt.Outcome == "cancelled" {
			out.State, out.Stage = "cancelled", "cancelled_before_stop"
		}
		if !acknowledged {
			out.State, out.Stage = "recovery_required", "completion_unacknowledged"
		}
	}
	return out
}

func pendingFail2banUpgradeQuiesceRecord(actual, expected Record) bool {
	if len(actual.Error) > 1024 {
		return false
	}
	if actual.State == "recovery_required" {
		actual.State = "running"
	}
	actual.Error = ""
	return sameFail2banUpgradePreparationRecord(actual, expected)
}
