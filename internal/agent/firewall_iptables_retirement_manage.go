package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

// This console-only escape closes an already empty scope. It never executes a
// cleanup batch, changes a Docker target or presents disposal as rollback.
func ManageIPTablesRetirement(parent context.Context, dataDir, scope, action, id, base string) (IPTablesRetirementStatus, error) {
	var out IPTablesRetirementStatus
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || !validID(base) || action != "retire" && action != "status" || action == "retire" && (!validID(id) || id == base) || action == "status" && id != "" {
		return out, errors.New("iptables 退役须本机 root、--firewall-scope=host、原业务 --firewall-base；退役另须新的 --firewall-operation UUID")
	}
	r, err := loadIPTablesRetirement(dataDir, base)
	if err != nil {
		return out, err
	}
	if action == "status" {
		if r == nil {
			return IPTablesRetirementStatus{BusinessOperationID: base, State: "uninitialized", Reason: "原业务尚未由本机退役"}, nil
		}
		return r.status(dataDir)
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	leave, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return out, err
	}
	defer leave()
	r, err = loadIPTablesRetirement(dataDir, base)
	if err != nil || r != nil && r.ID != id {
		return out, errors.Join(errors.New("原业务已有其他退役意图或无法读取"), err)
	}
	if r != nil {
		if _, e := loadIPTablesReceipt(dataDir, r.ID); e == nil {
			record, _, readErr := r.record(dataDir)
			if readErr != nil {
				return out, readErr
			}
			if record.State == "succeeded" {
				return r.status(dataDir)
			}
		} else if !os.IsNotExist(e) {
			return out, e
		}
	} else if err = recoverIPTablesRestore(ctx, dataDir); err != nil {
		return out, err
	}
	registry, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return out, err
	}
	defer registry()
	process, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-process.lock")
	if err != nil {
		return out, err
	}
	defer process()
	guard, err := openIPTablesExecutionLock()
	if err != nil {
		return out, err
	}
	defer guard.Close()
	j := iptablesRegistrationJournal(dataDir)
	maintenance, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer maintenance()
	records, err := j.List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" {
			return out, errors.New("独立维护尚未结束，不能选择本机退役")
		}
	}
	if r == nil {
		if _, err = loadIPTablesReceipt(dataDir, id); !os.IsNotExist(err) {
			return out, errors.New("iptables 退役标识已使用或回执无法核对")
		}
		v, e := loadIPTablesChangeRaw(dataDir)
		if e != nil || v == nil || v.Operation.ID != base {
			return out, errors.Join(errors.New("须选择当前完整原业务，不能退役历史操作"), e)
		}
		if e = iptablesChangeAuthority(dataDir, v); e != nil {
			return out, e
		}
		if source := iptablesPolicySourceFor(v); source != nil {
			if e = verifyIPTablesSource(dataDir, source); e != nil {
				return out, e
			}
		}
		// Complete only an original checkpoint-first audit publication gap.
		if e = saveIPTablesChange(dataDir, v); e != nil {
			return out, e
		}
		r = &iptablesRetirement{Schema: 1, ID: id, RequestedAt: time.Now().Unix(), Business: *v}
		r.BusinessJournal, err = loadIPTablesReceipt(dataDir, base)
		if err != nil {
			return out, err
		}
		repair, e := loadIPTablesRepair(dataDir)
		if e != nil {
			return out, e
		}
		if repair != nil && !iptablesRepairTerminal(repair) {
			if !iptablesPolicySourceMatches(repair, v) {
				return out, errors.New("未完成的修复属于其他原确认来源")
			}
			if e = saveIPTablesRepair(dataDir, repair); e != nil {
				return out, e
			}
			r.Repair = repair
			record, e := loadIPTablesReceipt(dataDir, repair.Status.ID)
			if e != nil {
				return out, e
			}
			r.RepairJournal = &record
		}
		r.Child, err = loadIPTablesRestore(dataDir)
		if err != nil {
			return out, err
		}
		if r.Child != nil {
			record, e := loadIPTablesReceipt(dataDir, r.Child.ID)
			if e != nil {
				return out, e
			}
			r.ChildJournal = &record
		}
		before, e := inspectIPTablesRegistration(ctx, dataDir, v.Policy.Policy.Backend, false)
		if e != nil {
			return out, errors.Join(errors.New("须先在本机清理全部本应用 INPUT/Docker 链、规则、标记及引用；退役命令不删除规则"), e)
		}
		r.ConfigurationHash, r.ToolHash = before.Hash, before.ToolHash
		if e = r.valid(); e != nil {
			return out, e
		}
		for _, dir := range []string{iptablesRetirementDir(dataDir), filepath.Join(iptablesRetirementDir(dataDir), "receipts"), filepath.Join(iptablesRetirementDir(dataDir), "repairs")} {
			if e = secure.RootDirectory(dir, 0700); e != nil {
				return out, e
			}
		}
		if e = rootJSONWrite(r.path(dataDir), r, iptablesRetirementBytes); e != nil {
			return out, e
		}
	}
	if err = r.checkBase(dataDir); err != nil {
		return out, err
	}
	if r.Repair != nil {
		link, e := loadIPTablesRepairRetirement(dataDir, r.Repair.Status.ID)
		if e != nil || link != nil && link.ID != r.ID {
			return out, errors.Join(errors.New("iptables 退役修复引用冲突"), e)
		}
		if link == nil {
			if err = rootJSONWrite(filepath.Join(iptablesRetirementDir(dataDir), "repairs", r.Repair.Status.ID+".json"), struct {
				BusinessID string `json:"business_id"`
			}{base}, 1024); err != nil {
				return out, err
			}
		}
	}
	if _, err = loadIPTablesReceipt(dataDir, r.ID); os.IsNotExist(err) {
		err = j.Put(r.journal("running", nil))
	} else if err == nil {
		_, _, err = r.record(dataDir)
	}
	if err != nil {
		return out, err
	}
	after, err := inspectIPTablesRegistration(ctx, dataDir, r.Business.Policy.Policy.Backend, false)
	if err != nil || after.ToolHash != r.ToolHash {
		return out, errors.Join(errors.New("iptables 退役完成前空范围或固定诊断工具已变化"), err)
	}
	if err = r.checkBase(dataDir); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	receipt := &iptablesRetirementReceipt{Schema: 1, ID: r.ID, IntentHash: r.hash(), ConfigurationHash: after.Hash, ToolHash: after.ToolHash, CompletedAt: time.Now().Unix()}
	if receipt.CompletedAt < r.RequestedAt {
		return out, errors.New("系统时间早于原退役请求，保留原意图待核对")
	}
	if raw, e := listenerRead(r.receiptPath(dataDir), 4096); e == nil {
		previous := new(iptablesRetirementReceipt)
		if ufwToolJSON(raw, previous) != nil || previous.Schema != 1 || previous.ID != r.ID || previous.IntentHash != r.hash() || !firewalldDigest(previous.ConfigurationHash) || previous.ToolHash != r.ToolHash || previous.CompletedAt < r.RequestedAt {
			return out, errors.New("iptables 原退役完成证明冲突")
		}
		receipt = previous
	} else if !os.IsNotExist(e) {
		return out, e
	} else if err = rootJSONWrite(r.receiptPath(dataDir), receipt, 4096); err != nil {
		return out, err
	}
	if err = j.Put(r.journal("succeeded", receipt)); err != nil {
		return out, err
	}
	return r.status(dataDir)
}

func (r *iptablesRetirement) checkBase(dataDir string) error {
	v, err := loadIPTablesChangeRaw(dataDir)
	if err != nil || !sameIPTablesValue(v, &r.Business) {
		return errors.Join(errors.New("iptables 退役原业务已变化"), err)
	}
	if err = iptablesChangeAuthority(dataDir, v); err != nil {
		return err
	}
	repair, err := loadIPTablesRepairRaw(dataDir)
	if err == nil && r.Repair == nil && repair != nil {
		if retired, retireErr := retiredIPTablesRepair(dataDir, repair); retireErr != nil {
			return retireErr
		} else if retired {
			repair = nil
		}
	}
	if err != nil || r.Repair != nil && !sameIPTablesValue(repair, r.Repair) || r.Repair == nil && repair != nil && !iptablesRepairTerminal(repair) {
		return errors.Join(errors.New("iptables 退役原修复已变化"), err)
	}
	child, err := loadIPTablesRestore(dataDir)
	if err != nil || !sameIPTablesValue(child, r.Child) || child != nil && (child.Phase != "ended" || child.Process != nil && !networkdCallEnded(*child.Process)) {
		return errors.Join(errors.New("iptables 退役原执行进程尚未结束或已变化"), err)
	}
	return nil
}

func (r *iptablesRetirement) status(dataDir string) (IPTablesRetirementStatus, error) {
	out := IPTablesRetirementStatus{ID: r.ID, BusinessOperationID: r.Business.Operation.ID, State: "recovery_required", Reason: "须沿原本机退役操作续办"}
	record, receipt, err := r.record(dataDir)
	if err != nil {
		return out, err
	}
	out.State = record.State
	if receipt != nil {
		out.CompletedAt, out.Reason = receipt.CompletedAt, "空受管范围已由本机退役；原意图、调用结果及回执保留，不表示原操作已回滚"
	}
	return out, nil
}
