package agent

import (
	"errors"
	"path/filepath"
	"time"
)

const fail2banUpgradeRunKind = "nginx.fail2ban-upgrade-run"

// The parent authorizes a fixed running upgrade and its exact compensation.
// Child UUIDs are reserved before the first stop, never reconstructed on restart.
type Fail2banUpgradeRunOptions struct {
	DataDir, Scope, OperationID, PreparationID, Target string
	NginxBinary, NginxWorker                           string
	NginxContainer                                     bool
}

type Fail2banUpgradeRun struct {
	ID                   string `json:"id"`
	PreparationID        string `json:"preparation_id"`
	QuiesceID            string `json:"quiesce_id"`
	SwitchID             string `json:"switch_id"`
	ActivationID         string `json:"activation_id"`
	RestoreID            string `json:"restore_id"`
	RecoveryActivationID string `json:"recovery_activation_id"`
	State                string `json:"state"`
	Stage                string `json:"stage"`
	CompletedAt          int64  `json:"completed_at"`
	Reason               string `json:"reason"`
}

type fail2banUpgradeRunIntent struct {
	Schema                                                             int
	CreatedAt                                                          int64
	Request                                                            Fail2banUpgradeRunOptions
	PreparationReceiptSHA256, NginxRuntimeSHA256                       string
	QuiesceID, SwitchID, ActivationID, RestoreID, RecoveryActivationID string
}

type fail2banUpgradeRunStage struct {
	fail2banUpgradeActivationMarker
	Step         int
	At           int64
	SourceSHA256 string
}

type fail2banUpgradeRunReceipt struct {
	fail2banUpgradeActivationMarker
	Outcome      string
	CompletedAt  int64
	SourceSHA256 string
}

type fail2banUpgradeRunFacts struct {
	Execution bool
	Step      int
	Receipt   *fail2banUpgradeRunReceipt
}

func fail2banUpgradeRuns(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-runs")
}
func (i fail2banUpgradeRunIntent) dir() string {
	return filepath.Join(fail2banUpgradeRuns(i.Request.DataDir), i.Request.OperationID)
}
func (i fail2banUpgradeRunIntent) hash() string { return fail2banUpgradeGrantHash("upgrade-run", i) }
func (i fail2banUpgradeRunIntent) marker() fail2banUpgradeActivationMarker {
	return fail2banUpgradeActivationMarker{1, i.Request.OperationID, i.hash()}
}
func (i fail2banUpgradeRunIntent) child(step int) string {
	switch step {
	case 1:
		return i.QuiesceID
	case 2:
		return i.SwitchID
	case 3:
		return i.ActivationID
	case 4:
		return i.RestoreID
	case 5:
		return i.RecoveryActivationID
	}
	return ""
}

func (i fail2banUpgradeRunIntent) validate(data, id string, p fail2banUpgradePreparation, r fail2banUpgradePreparationReceipt) error {
	in := i.Request
	if i.Schema != 1 || in.DataDir != data || in.Scope != "host" || in.OperationID != id || in.PreparationID != p.Request.OperationID || in.Target != p.hash() || i.PreparationReceiptSHA256 != fail2banUpgradeGrantHash("preparation-receipt", r) || i.CreatedAt < p.CreatedAt || i.CreatedAt > time.Now().Unix()+300 || p.Basis.Service.Active != "active" {
		return errors.New("整体升级意图与原运行准备不匹配")
	}
	if fail2banJailNeedsNginx(p.Basis.Bundle) != (i.NginxRuntimeSHA256 != "") || i.NginxRuntimeSHA256 != "" && !fail2banDigest.MatchString(i.NginxRuntimeSHA256) {
		return errors.New("整体升级缺少固定 Nginx 运行来源")
	}
	ids := []string{id, i.QuiesceID, i.SwitchID, i.ActivationID, i.RestoreID, i.RecoveryActivationID}
	for n, value := range ids {
		if !validID(value) {
			return errors.New("整体升级须使用独立父子 UUID")
		}
		for _, old := range append(fail2banUpgradeOriginalIDs(p.Basis, p.Recovery), p.Request.OperationID, p.Material.IDs.Jails, p.Material.IDs.Nginx, p.Material.IDs.Sources, p.Material.IDs.Sync) {
			if value == old {
				return errors.New("整体升级不能复用原准备、安装或批准 UUID")
			}
		}
		for _, old := range ids[:n] {
			if value == old {
				return errors.New("整体升级父子 UUID 重复")
			}
		}
	}
	return nil
}

func (i fail2banUpgradeRunIntent) record(r *fail2banUpgradeRunReceipt) Record {
	out := Record{Kind: fail2banUpgradeRunKind, OperationID: i.Request.OperationID, RelatedOperationID: i.Request.PreparationID, RequestHash: fail2banUpgradeGrantHash("upgrade-run-request", i.Request), CandidateHash: i.hash(), BeforeRevision: i.Request.Target, AfterRevision: i.ActivationID, State: "running", Stage: "upgrading"}
	if r != nil {
		out.ObservedRevision = fail2banUpgradeGrantHash("upgrade-run-receipt", r)
		switch r.Outcome {
		case "upgraded":
			out.State, out.Stage = "succeeded", "protection_verified"
		case "restored":
			out.State, out.Stage = "failed", "original_protection_verified"
		case "cancelled":
			out.State, out.Stage = "cancelled", "cancelled_before_stop"
		}
	}
	return out
}

func pendingFail2banUpgradeRunRecord(a, b Record) bool {
	if a.State != "running" && a.State != "recovery_required" || a.Stage != "upgrading" || len([]rune(a.Error)) > 240 {
		return false
	}
	a.State, a.Error = "running", ""
	return sameFail2banUpgradePreparationRecord(a, b)
}

func (i fail2banUpgradeRunIntent) result(f fail2banUpgradeRunFacts, acknowledged bool) Fail2banUpgradeRun {
	out := Fail2banUpgradeRun{ID: i.Request.OperationID, PreparationID: i.Request.PreparationID, QuiesceID: i.QuiesceID, SwitchID: i.SwitchID, ActivationID: i.ActivationID, RestoreID: i.RestoreID, RecoveryActivationID: i.RecoveryActivationID, State: "running", Stage: "intent_reserved"}
	if f.Execution {
		out.Stage = []string{"", "quiescing_original", "switching_candidate", "activating_candidate", "restoring_original", "activating_original"}[f.Step]
	}
	if f.Receipt != nil {
		out.State, out.Stage, out.CompletedAt = "recovery_required", "completion_unacknowledged", f.Receipt.CompletedAt
		if acknowledged {
			r := i.record(f.Receipt)
			out.State, out.Stage = r.State, r.Stage
		}
	}
	return out
}
