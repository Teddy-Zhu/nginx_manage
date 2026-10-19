package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

const fail2banStateRestoreKind = "nginx.fail2ban-state-restore"

type Fail2banStateRestoreOptions struct {
	DataDir, Scope, OperationID, SnapshotID, Target string
}

type fail2banStateDirectory struct {
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	SELinux string `json:"selinux"`
}

type fail2banStateRestoreTarget struct {
	Snapshot  fail2banStateReceipt   `json:"snapshot"`
	Basis     fail2banStateBasis     `json:"basis"`
	Before    []fail2banStateFile    `json:"before"`
	Directory fail2banStateDirectory `json:"directory"`
}

func (t fail2banStateRestoreTarget) hash() string {
	raw, _ := json.Marshal(t)
	return secure.Hash(append([]byte("nginxpanel:fail2ban-state-restore-target:v1:\x00"), raw...))
}

type fail2banStateRestoreIntent struct {
	// A parent upgrade recovery owns the exchange without creating a second
	// public restore authorization, journal or independently writable fence.
	privateDir string
	Schema     int                        `json:"schema"`
	ID         string                     `json:"id"`
	CreatedAt  int64                      `json:"created_at"`
	DataDir    string                     `json:"data_dir"`
	Target     string                     `json:"target"`
	Input      fail2banStateRestoreTarget `json:"input"`
	After      []fail2banStateFile        `json:"after"`
}

func (i fail2banStateRestoreIntent) hash() string {
	raw, _ := json.Marshal(i)
	return secure.Hash(raw)
}

type fail2banStateRestoreMarker struct {
	Schema       int    `json:"schema"`
	ID           string `json:"id"`
	IntentSHA256 string `json:"intent_sha256"`
}

type fail2banStateRestoreReady struct {
	fail2banStateRestoreMarker
	Directory fail2banStateDirectory `json:"directory"`
}

type fail2banStateRestoreReceipt struct {
	fail2banStateRestoreMarker
	Outcome     string                 `json:"outcome"`
	CompletedAt int64                  `json:"completed_at"`
	Directory   fail2banStateDirectory `json:"directory"`
	FilesSHA256 string                 `json:"files_sha256"`
}

type Fail2banStateRestorePlan struct {
	At             int64                    `json:"at"`
	SnapshotID     string                   `json:"snapshot_id"`
	InstallationID string                   `json:"installation_id"`
	Target         string                   `json:"target"`
	Component      Fail2banUpgradeComponent `json:"component"`
	Before         []fail2banStateFile      `json:"before"`
	After          []fail2banStateFile      `json:"after"`
	Impacts        []string                 `json:"impacts"`
}

type Fail2banStateRestoreStatus struct {
	ID             string `json:"id"`
	SnapshotID     string `json:"snapshot_id"`
	InstallationID string `json:"installation_id"`
	Target         string `json:"target"`
	State          string `json:"state"`
	Stage          string `json:"stage"`
	Outcome        string `json:"outcome"`
	CompletedAt    int64  `json:"completed_at"`
	Error          string `json:"error"`
}

func fail2banStateRestores(data string) string {
	return filepath.Join(fail2banBindingDir(data), "state-restores")
}

func (i fail2banStateRestoreIntent) dir() string {
	if i.privateDir != "" {
		return i.privateDir
	}
	return filepath.Join(fail2banStateRestores(i.DataDir), i.ID)
}

func (i fail2banStateRestoreIntent) marker() fail2banStateRestoreMarker {
	return fail2banStateRestoreMarker{Schema: 1, ID: i.ID, IntentSHA256: i.hash()}
}

func fail2banStateFilesHash(files []fail2banStateFile) string {
	raw, _ := json.Marshal(files)
	return secure.Hash(raw)
}

func (i fail2banStateRestoreIntent) validate(data, id string) error {
	t := i.Input
	if i.Schema != 1 || i.ID != id || !validID(id) || i.DataDir != data || i.CreatedAt <= 0 || i.CreatedAt > time.Now().Unix()+300 || i.ID == t.Snapshot.OperationID || i.ID == t.Basis.Managed.OperationID || i.Target != t.hash() || t.Directory.Inode == 0 || t.Directory.SELinux != t.Basis.StateLabel || len(i.After) != len(fail2banStateResources) {
		return errors.New("Fail2ban 状态恢复意图无效")
	}
	if err := t.Snapshot.validate(data, t.Snapshot.OperationID); err != nil {
		return err
	}
	for _, files := range [][]fail2banStateFile{t.Before, i.After} {
		m := fail2banStateManifest{Schema: 1, OperationID: t.Snapshot.OperationID, DataDir: data, CreatedAt: i.CreatedAt, Basis: t.Basis, Files: files}
		if err := m.validate(data, m.OperationID); err != nil {
			return err
		}
	}
	if t.Snapshot.InstallationID != t.Basis.Managed.OperationID || t.Snapshot.MachineID != t.Basis.MachineID || t.Snapshot.Component != fail2banUpgradeComponent(&t.Basis.Managed) {
		return errors.New("Fail2ban 状态恢复须匹配原安装、代码及本机身份")
	}
	return nil
}

func readFail2banStateRestore(data, id string) (fail2banStateRestoreIntent, error) {
	var out fail2banStateRestoreIntent
	if !validID(id) {
		return out, errors.New("Fail2ban 状态恢复 UUID 无效")
	}
	if err := fail2banStatePrivateDir(fail2banStateRestores(data), false); err != nil {
		return out, err
	}
	if err := fail2banStatePrivateDir(filepath.Join(fail2banStateRestores(data), id), false); err != nil {
		return out, err
	}
	if err := readFail2banNginxJSON(filepath.Join(fail2banStateRestores(data), id, "intent.json"), &out, fail2banStateManifestLimit); err != nil {
		return out, err
	}
	return out, out.validate(data, id)
}

func (i fail2banStateRestoreIntent) ready() (*fail2banStateRestoreReady, error) {
	var out fail2banStateRestoreReady
	if err := readFail2banNginxJSON(filepath.Join(i.dir(), "ready.json"), &out, 4096); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if out.fail2banStateRestoreMarker != i.marker() || out.Directory.Device != i.Input.Directory.Device || out.Directory.Inode == 0 || out.Directory.SELinux != i.Input.Directory.SELinux || out.Directory == i.Input.Directory {
		return nil, errors.New("Fail2ban 状态恢复暂存目录身份无效")
	}
	return &out, nil
}

func (i fail2banStateRestoreIntent) reverting() (bool, error) {
	var marker fail2banStateRestoreMarker
	if err := readFail2banNginxJSON(filepath.Join(i.dir(), "revert.json"), &marker, 4096); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if marker != i.marker() {
		return false, errors.New("Fail2ban 状态恢复撤回授权不匹配")
	}
	return true, nil
}

func (i fail2banStateRestoreIntent) receipt() (*fail2banStateRestoreReceipt, error) {
	var out fail2banStateRestoreReceipt
	if err := readFail2banNginxJSON(filepath.Join(i.dir(), "receipt.json"), &out, 4096); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if out.fail2banStateRestoreMarker != i.marker() || out.CompletedAt <= 0 || out.CompletedAt > time.Now().Unix()+300 {
		return nil, errors.New("Fail2ban 状态恢复完成证明无效")
	}
	reverting, err := i.reverting()
	if err != nil {
		return nil, err
	}
	switch out.Outcome {
	case "restored":
		ready, e := i.ready()
		if e != nil || ready == nil || reverting || out.Directory != ready.Directory || out.FilesSHA256 != fail2banStateFilesHash(i.After) {
			return nil, errors.Join(errors.New("Fail2ban 状态恢复完成证明与暂存不匹配"), e)
		}
	case "reverted":
		if !reverting || out.Directory != i.Input.Directory || out.FilesSHA256 != fail2banStateFilesHash(i.Input.Before) {
			return nil, errors.New("Fail2ban 状态恢复撤回证明不匹配")
		}
	case "cancelled":
		ready, e := i.ready()
		if e != nil || ready != nil || !reverting || out.Directory != i.Input.Directory || !fail2banDigest.MatchString(out.FilesSHA256) {
			return nil, errors.Join(errors.New("Fail2ban 状态恢复交换前取消证明无效"), e)
		}
	default:
		return nil, errors.New("Fail2ban 状态恢复结果未知")
	}
	return &out, nil
}

func (i fail2banStateRestoreIntent) record(receipt *fail2banStateRestoreReceipt) Record {
	r := Record{OperationID: i.ID, Kind: fail2banStateRestoreKind, RequestHash: i.Target, RelatedOperationID: i.Input.Snapshot.OperationID, CandidateHash: i.hash(), State: "running", Stage: "restoring"}
	if receipt != nil {
		raw, _ := json.Marshal(receipt)
		r.ObservedRevision = secure.Hash(raw)
		r.State, r.Stage = "succeeded", receipt.Outcome
		if receipt.Outcome == "reverted" {
			r.State, r.Error = "failed", "管理员撤回状态恢复，原状态目录已保留"
		} else if receipt.Outcome == "cancelled" {
			r.State, r.Error = "failed", "管理员取消目录交换，保留当前状态"
		}
	}
	return r
}

func (i fail2banStateRestoreIntent) status(r Record, receipt *fail2banStateRestoreReceipt) Fail2banStateRestoreStatus {
	out := Fail2banStateRestoreStatus{ID: i.ID, SnapshotID: i.Input.Snapshot.OperationID, InstallationID: i.Input.Basis.Managed.OperationID, Target: i.Target, State: r.State, Stage: r.Stage, Error: r.Error}
	if receipt != nil {
		out.Outcome, out.CompletedAt = receipt.Outcome, receipt.CompletedAt
	}
	return out
}
