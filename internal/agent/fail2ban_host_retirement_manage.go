package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// Retirement is a local rescue authorization. It never creates a table or
// transfers protection/source approval into a different namespace.
func ManageFail2banHostRetirement(ctx context.Context, dataDir, scope, action, operationID, base string) (Fail2banHostRetirementStatus, error) {
	var out Fail2banHostRetirementStatus
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("宿主机动作退役须本机 root、宿主机范围及规范绝对数据目录")
	}
	if action != "retire" && action != "status" {
		return out, errors.New("未知宿主机退役操作")
	}
	if action == "status" {
		if base != "" || operationID != "" && !validID(operationID) {
			return out, errors.New("退役状态参数无效")
		}
		var r *fail2banHostRetirement
		var err error
		if operationID == "" {
			r, err = loadFail2banHostRetirement(dataDir)
		} else {
			r, err = loadFail2banHostRetirementEvent(dataDir, operationID)
		}
		if err != nil {
			return out, err
		}
		if r == nil {
			return Fail2banHostRetirementStatus{State: "uninitialized", Reason: "尚无本机宿主机动作退役"}, nil
		}
		return r.status(dataDir)
	}
	if !validID(operationID) || !validID(base) || operationID == base {
		return out, errors.New("退役须新操作 UUID 和当前独立登记 UUID")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	leave, err := fail2banHostSyncLocks(dataDir)
	if err != nil {
		return out, err
	}
	defer leave()
	if err = fail2banHostBootRecoveryIdle(dataDir); err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	admit, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer admit()
	r, err := loadFail2banHostRetirementEvent(dataDir, operationID)
	if err == nil {
		if r.RequestHash != fail2banHostRetirementRequest(operationID, base) {
			return out, errors.New("原退役请求的登记基础变化")
		}
		if record, e := r.record(dataDir); e == nil && record.State == "succeeded" {
			return r.status(dataDir)
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return out, e
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	} else {
		r, err = prepareFail2banHostRetirement(ctx, dataDir, operationID, base)
		if err != nil {
			return out, err
		}
	}
	selected, err := loadFail2banHostRetirement(dataDir)
	if err != nil {
		return out, err
	}
	if selected == nil && r.PreviousID != "" || selected != nil && selected.ID != r.ID && selected.ID != r.PreviousID {
		return out, errors.New("退役选择基础变化，不能重新选择历史请求")
	}
	if selected == nil || selected.ID != r.ID {
		if err = checkFail2banHostRetirementBase(dataDir, r); err != nil {
			return out, err
		}
		if err = rootJSONWrite(filepath.Join(fail2banHostRetirementDir(dataDir), "current.json"), struct {
			ID string `json:"id"`
		}{r.ID}, 1024); err != nil {
			return out, err
		}
	}
	if err = ensureFail2banHostRetirementRecord(dataDir, r); err != nil {
		return out, err
	}
	err = finishFail2banHostRetirement(ctx, dataDir, r)
	out, readErr := r.status(dataDir)
	return out, errors.Join(err, readErr)
}

func checkFail2banHostRetirementBase(dataDir string, r *fail2banHostRetirement) error {
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return err
	}
	if root == nil || root.OperationID != r.Root.OperationID {
		return errors.New("原退役尚未选择，登记基础已变化")
	}
	a, _ := json.Marshal(root)
	b, _ := json.Marshal(r.Root)
	if string(a) != string(b) {
		return errors.New("原退役的完整登记材料变化")
	}
	runtime, err := loadFail2banHostRuntimeRecord(dataDir)
	if err != nil {
		return err
	}
	a, _ = json.Marshal(runtime)
	b, _ = json.Marshal(r.Runtime)
	if string(a) != string(b) {
		return errors.New("原退役的运行检查点变化")
	}
	sync, err := loadFail2banHostSync(dataDir)
	if err != nil {
		return err
	}
	a, _ = json.Marshal(sync)
	b, _ = json.Marshal(r.Sync)
	if string(a) != string(b) {
		return errors.New("原退役的会话批准变化")
	}
	if r.SyncParent != nil {
		parent, e := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(r.Sync.ID)
		if e != nil || !sameFail2banRetirementRecord(parent, *r.SyncParent) {
			return errors.Join(errors.New("原退役的父会话回执变化"), e)
		}
		stopping, e := loadFail2banHostSyncStop(dataDir, r.Sync)
		if e != nil {
			return e
		}
		a, _ = json.Marshal(stopping)
		b, _ = json.Marshal(r.Stopping)
		if string(a) != string(b) {
			return errors.New("原退役的停止意图变化")
		}
	}
	return nil
}

func ensureFail2banHostRetirementRecord(dataDir string, r *fail2banHostRetirement) error {
	if _, err := r.record(dataDir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := checkFail2banHostRetirementBase(dataDir, r); err != nil {
		return err
	}
	return (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Put(r.journal("running"))
}

// Called only by the independent worker while holding host/binding locks and
// maintenance progress admission. It drains an already selected root intent.
func advanceFail2banHostRetirement(ctx context.Context, dataDir string) (bool, error) {
	r, err := loadFail2banHostRetirement(dataDir)
	if err != nil || r == nil {
		return false, err
	}
	if record, e := r.record(dataDir); e == nil && record.State == "succeeded" {
		return false, nil
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return true, e
	}
	admit, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).maintenanceLock()
	if err != nil {
		return true, err
	}
	defer admit()
	if err = ensureFail2banHostRetirementRecord(dataDir, r); err != nil {
		return true, err
	}
	return true, finishFail2banHostRetirement(ctx, dataDir, r)
}

// Caller holds host/binding and maintenance admission locks. Preparing does not
// select the intent or close any grant, so boot recovery can freeze it first.
func prepareFail2banHostRetirement(ctx context.Context, dataDir, operationID, base string) (*fail2banHostRetirement, error) {
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	if _, e := j.Get(operationID); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("退役操作标识已使用或无法核对")
	}
	previous, e := loadFail2banHostRetirement(dataDir)
	if e != nil {
		return nil, e
	}
	if e = fail2banHostRetirementIdle(dataDir); e != nil {
		return nil, e
	}
	records, e := j.List()
	if e != nil {
		return nil, e
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" || pendingNginxRecord(record) {
			return nil, ErrBusy
		}
	}
	root, e := loadFail2banHostRegistration(dataDir)
	if e != nil {
		return nil, e
	}
	if root == nil || root.OperationID != base {
		return nil, errors.New("当前登记基础变化，须重新核对")
	}
	if root.State != "registered" {
		return nil, errors.New("仅已确认登记的失联范围可退役；未确认的空表登记须先恢复原操作")
	}
	if !fail2banHostRegistrationReceipt(dataDir, root) {
		if e = saveFail2banHostRegistration(dataDir, root); e != nil {
			return nil, e
		}
	}
	r := &fail2banHostRetirement{Schema: 1, ID: operationID, RegistrationID: secure.ID(), Root: *root, RequestedAt: time.Now().Unix(), RequestHash: fail2banHostRetirementRequest(operationID, base)}
	if previous != nil {
		r.PreviousID = previous.ID
	}
	r.Runtime, e = loadFail2banHostRuntimeRecord(dataDir)
	if e != nil {
		return nil, e
	}
	selected, e := loadFail2banHostRuntime(dataDir)
	if e != nil {
		return nil, e
	}
	if selected != nil {
		r.RuntimeCurrent = fail2banHostRuntimeMatches(selected, root)
		if !r.RuntimeCurrent && (selected.State == "running" || selected.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, selected) || selected.effective().Set != nil) {
			return nil, errors.New("存在不属于待退役登记的未释放运行记录")
		}
		if r.RuntimeCurrent && selected.Intent.ControllerID == "" {
			old, e := j.Get(selected.Intent.OperationID)
			if e == nil {
				r.RuntimeJournal = &old
			} else if !errors.Is(e, os.ErrNotExist) {
				return nil, e
			}
		}
	}
	r.Sync, e = loadFail2banHostSync(dataDir)
	if e != nil {
		return nil, e
	}
	if r.Sync != nil && r.Sync.Action == "enable" {
		parent, e := j.Get(r.Sync.ID)
		if e != nil {
			return nil, e
		}
		r.SyncParent, r.StopID = &parent, secure.ID()
		r.Stopping, e = loadFail2banHostSyncStop(dataDir, r.Sync)
		if e != nil {
			return nil, e
		}
	}
	call, stop := context.WithTimeout(ctx, 3*time.Second)
	r.Absent, e = snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
	stop()
	if e != nil {
		return nil, e
	}
	if e = r.valid(dataDir); e != nil {
		return nil, e
	}
	dir := filepath.Join(fail2banHostRetirementDir(dataDir), "events")
	if e = secure.RootDirectory(dir, 0700); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if len(entries) >= 2048 {
		return nil, errors.New("退役记录容量已满，须本机维护")
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	if e = writeFail2banJailImmutable(filepath.Join(dir, r.ID+".json"), raw, fail2banHostRetirementBytes); e != nil {
		return nil, e
	}
	return r, nil
}
