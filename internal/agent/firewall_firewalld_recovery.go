package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func (f *hostFirewall) reconcileFirewalldConfirmed() error {
	v := f.firewalldState
	previous := *v
	if err := f.restoreFirewalldConfirmed(); err != nil {
		return err
	}
	if v.Operation != nil && (v.Call != nil || previous.RuntimeHash != v.RuntimeHash || previous.PermanentHash != v.PermanentHash || f.problem != "" || f.policyUncertain) {
		v.Call = nil
		written, err := f.persistFirewalld()
		if err != nil {
			if !written {
				*v = previous
			}
			return err
		}
	}
	f.problem, f.policyUncertain = "", false
	return nil
}

func (f *hostFirewall) rescueFirewalldLocked() error {
	raw, err := listenerRead(filepath.Join(filepath.Dir(firewalldStatePath(f.dataDir)), "rescue.json"), 1024)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var request struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &request) != nil || !validID(request.ID) {
		return errors.New("防火墙救援请求无效")
	}
	v := f.firewalldState
	if request.ID == v.LastRescue {
		return nil
	}
	if v.Candidate != nil {
		err = f.rollbackFirewalldLocked("本机 root 已请求恢复最后确认配置")
	} else {
		err = f.reconcileFirewalldConfirmed()
	}
	if err != nil {
		return err
	}
	v.LastRescue = request.ID
	if v.Operation != nil {
		return f.saveFirewalld()
	}
	return nil
}

// Agent-owned recovery remains active when the module or new-write grant is
// disabled. It never depends on the API process, browser or a cached observer.
func (f *hostFirewall) runFirewalldLocked(ctx context.Context, stopping bool, nextInspect, nextProtectionInspect *time.Time) {
	v := f.firewalldState
	if err := f.rescueFirewalldLocked(); err != nil {
		f.problem = "本机 firewalld 救援请求未处理完成"
	}
	if v.Candidate != nil {
		if stopping || f.expiredLocked() || v.Rollback || f.problem != "" || f.remote.web == nil || f.remote.problem != "" || f.remote.listener == nil {
			if stopping || !time.Now().Before(f.retryAt) {
				if err := f.rollbackFirewalldLocked("未确认、控制通道中断或 Agent 停止，恢复最后确认配置"); err != nil {
					f.retryAt = time.Now().Add(10 * time.Second)
				}
			}
		}
	} else if f.recovering && (!stopping && !time.Now().Before(*nextInspect) || stopping && v.Call != nil) {
		*nextInspect = time.Now().Add(30 * time.Second)
		if err := f.reconcileFirewalldConfirmed(); err != nil {
			f.problem = "firewalld 已确认配置无法核对或恢复；" + err.Error()
		}
	}
	if !stopping && v.Candidate == nil && v.Call == nil && f.problem == "" && !time.Now().Before(*nextProtectionInspect) {
		f.protectionObservation = f.observeProtectionsLocked(ctx, v.Confirmed)
		f.protectionObservedAt = time.Now()
		*nextProtectionInspect = time.Now().Add(30 * time.Second)
	}
}
