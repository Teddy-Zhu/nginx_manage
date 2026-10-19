package agent

import (
	"errors"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
)

const fail2banUpgradeActivationKind = "nginx.fail2ban-upgrade-activation"
const fail2banUpgradeActivationLimit = 64 << 10
const fail2banUpgradeActivationWindow = 5 * time.Minute

type Fail2banUpgradeActivationOptions struct {
	DataDir, Scope, OperationID, SwitchID string
	NginxBinary, NginxWorker              string
	NginxContainer                        bool
}

type Fail2banUpgradeActivation struct {
	ID             string `json:"id"`
	SwitchID       string `json:"switch_id"`
	VerificationID string `json:"verification_id"`
	State          string `json:"state"`
	Stage          string `json:"stage"`
	Deadline       int64  `json:"deadline"`
	VerifiedAt     int64  `json:"verified_at"`
	ProofSHA256    string `json:"proof_sha256"`
	Reason         string `json:"reason"`
}

type fail2banUpgradeActivationIntent struct {
	Schema                            int
	CreatedAt                         int64
	Request                           Fail2banUpgradeActivationOptions
	VerificationID, SelectedEvent     string
	SwitchSHA256, SwitchReceiptSHA256 string
	NginxRuntimeSHA256                string
}

type fail2banUpgradeActivationMarker struct {
	Schema           int
	ID, IntentSHA256 string
}

type fail2banUpgradeActivationStarted struct {
	fail2banUpgradeActivationMarker
	At                      int64
	Invocation, SocketInode string
	PID                     int64
}

type fail2banUpgradeActivationClaim struct {
	fail2banUpgradeActivationMarker
	At                int64
	Invocation, Nonce string
}

type fail2banUpgradeActivationStop struct {
	fail2banUpgradeActivationMarker
	At     int64
	Reason string
}

type fail2banUpgradeActivationReceipt struct {
	fail2banUpgradeActivationMarker
	CompletedAt        int64
	Outcome            string
	VerificationSHA256 string
	Stopped            *fail2banUpgradeActivationStopped
}

type fail2banUpgradeActivationStopped struct {
	Service     fail2ban.Service
	Invocation  string
	Directory   fail2banStateDirectory
	FilesSHA256 string
}

type fail2banUpgradeActivationFacts struct {
	Execution bool
	Claim     *fail2banUpgradeActivationClaim
	Started   *fail2banUpgradeActivationStarted
	Stop      *fail2banUpgradeActivationStop
	Receipt   *fail2banUpgradeActivationReceipt
}

func fail2banUpgradeActivations(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-activations")
}
func (i fail2banUpgradeActivationIntent) dir() string {
	return filepath.Join(fail2banUpgradeActivations(i.Request.DataDir), i.Request.OperationID)
}
func (i fail2banUpgradeActivationIntent) hash() string {
	return fail2banUpgradeGrantHash("activation", i)
}
func (i fail2banUpgradeActivationIntent) marker() fail2banUpgradeActivationMarker {
	return fail2banUpgradeActivationMarker{1, i.Request.OperationID, i.hash()}
}
func (i fail2banUpgradeActivationIntent) deadline() int64 {
	return i.CreatedAt + int64(fail2banUpgradeActivationWindow/time.Second)
}
func (i fail2banUpgradeActivationIntent) verification() Fail2banUpgradeVerificationOptions {
	in := i.Request
	return Fail2banUpgradeVerificationOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: i.VerificationID, SwitchID: in.SwitchID, NginxBinary: in.NginxBinary, NginxWorker: in.NginxWorker, NginxContainer: in.NginxContainer}
}

func (i fail2banUpgradeActivationIntent) validate(data, id string, s fail2banUpgradeSwitch, receipt fail2banUpgradeSwitchReceipt) error {
	in := i.Request
	if i.Schema != 1 || in.DataDir != data || in.Scope != "host" || in.OperationID != id || !validID(id) || !validID(i.VerificationID) || id == i.VerificationID || in.SwitchID != s.Request.OperationID || i.SelectedEvent != s.After.EventID || i.CreatedAt < receipt.CompletedAt || i.CreatedAt > time.Now().Unix()+300 || i.SwitchSHA256 != s.hash() || i.SwitchReceiptSHA256 != fail2banUpgradeGrantHash("switch-receipt", receipt) {
		return errors.New("升级启动意图与原选择或独立标识不匹配")
	}
	if err := fail2banUpgradeVerificationID(id, s); err != nil {
		return err
	}
	if err := fail2banUpgradeVerificationID(i.VerificationID, s); err != nil {
		return err
	}
	if fail2banJailNeedsNginx(s.Prepared.Material.Bundle) != (i.NginxRuntimeSHA256 != "") || i.NginxRuntimeSHA256 != "" && !fail2banDigest.MatchString(i.NginxRuntimeSHA256) {
		return errors.New("升级启动缺少固定 Nginx 运行来源")
	}
	return nil
}

func (i fail2banUpgradeActivationIntent) record(receipt *fail2banUpgradeActivationReceipt) Record {
	r := Record{Kind: fail2banUpgradeActivationKind, OperationID: i.Request.OperationID, RelatedOperationID: i.Request.SwitchID, RequestHash: fail2banUpgradeGrantHash("activation-request", i.Request), CandidateHash: i.hash(), BeforeRevision: i.SwitchSHA256, AfterRevision: i.VerificationID, State: "running", Stage: "activation"}
	if receipt != nil {
		r.ObservedRevision = fail2banUpgradeGrantHash("activation-receipt", receipt)
		if receipt.Outcome == "verified" {
			r.State, r.Stage = "succeeded", "protection_verified"
		} else {
			r.State, r.Stage = "failed", "candidate_stopped"
		}
	}
	return r
}

func (i fail2banUpgradeActivationIntent) result(f fail2banUpgradeActivationFacts, acknowledged bool) Fail2banUpgradeActivation {
	out := Fail2banUpgradeActivation{ID: i.Request.OperationID, SwitchID: i.Request.SwitchID, VerificationID: i.VerificationID, Deadline: i.deadline(), State: "running", Stage: "intent_reserved"}
	if f.Execution {
		out.Stage = "starting"
	}
	if f.Started != nil {
		out.Stage = "awaiting_protection"
	}
	if f.Stop != nil {
		out.State, out.Stage, out.Reason = "compensating", "stopping_candidate", f.Stop.Reason
	}
	if f.Receipt != nil {
		if f.Receipt.Outcome == "verified" {
			out.State, out.Stage, out.VerifiedAt, out.ProofSHA256 = "succeeded", "protection_verified", f.Receipt.CompletedAt, f.Receipt.VerificationSHA256
		} else {
			out.State, out.Stage = "failed", "candidate_stopped"
		}
		if !acknowledged {
			out.State, out.Stage = "recovery_required", "completion_unacknowledged"
		}
	}
	return out
}

func pendingFail2banUpgradeActivationRecord(actual, expected Record) bool {
	if len(actual.Error) > 1024 {
		return false
	}
	if actual.State == "recovery_required" {
		actual.State = "running"
	}
	actual.Error = ""
	return sameFail2banUpgradePreparationRecord(actual, expected)
}
