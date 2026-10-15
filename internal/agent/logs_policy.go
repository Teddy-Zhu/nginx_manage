package agent

import (
	"encoding/json"
	"os"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/secure"
)

type LogPolicyRequest struct {
	Protocol    int         `json:"protocol"`
	OperationID string      `json:"operation_id"`
	BaseVersion int64       `json:"base_version"`
	Policy      logs.Policy `json:"policy"`
}

func (m *managedLogs) recoverPolicy() error {
	records, err := m.nginx.Journal.List()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Kind != "logs.policy" || record.State != "running" && record.State != "recovery_required" {
			continue
		}
		if record.LogPolicy != nil && m.state.LastOperation == record.OperationID && m.state.Version == record.LogPolicyBase+1 && m.state.Policy == *record.LogPolicy {
			record.State, record.Stage, record.LogPolicyVersion = "succeeded", "policy_applied", m.state.Version
		} else if m.state.Version == record.LogPolicyBase {
			record.State, record.Stage, record.Error = "failed", "interrupted_before_policy", "策略保存前 Agent 中断，原策略保持生效"
		} else {
			record.State, record.Stage, record.Error = "recovery_required", "policy_state_uncertain", "日志策略与执行记录不一致，需本机恢复"
			m.policyUncertain = true
		}
		if err := m.nginx.Journal.Put(record); err != nil {
			return err
		}
	}
	return nil
}

func (n *Nginx) SetLogPolicy(in LogPolicyRequest) (Record, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.logs == nil {
		return Record{}, fault.Unavailable("日志 Agent 不可用")
	}
	if in.Protocol != Protocol || !validID(in.OperationID) || in.BaseVersion < 1 {
		return Record{}, fault.Invalid("日志策略操作合同无效")
	}
	if err := in.Policy.Validate(); err != nil {
		return Record{}, err
	}
	m := n.logs
	m.mu.Lock()
	defer m.mu.Unlock()
	if n.LogOwner != "agent" {
		return Record{}, fault.Conflict("日志仍由外部管理或所有者未确认，不能修改轮转策略")
	}
	if m.policyUncertain {
		return Record{}, fault.Unavailable("日志策略执行状态不确定，须本机恢复后重试")
	}
	encoded, _ := json.Marshal(in)
	digest := secure.Hash(encoded)
	if old, err := n.Journal.Get(in.OperationID); err == nil {
		if old.RequestHash != digest || old.Kind != "logs.policy" {
			return Record{}, fault.Conflict("幂等标识已用于其他请求")
		}
		return old, nil
	} else if !os.IsNotExist(err) {
		return Record{}, fault.Unavailable("日志策略执行记录不可用")
	}
	if m.state.Version != in.BaseVersion {
		return Record{}, fault.Conflict("日志策略已改变，请重新读取后保存")
	}
	record := Record{OperationID: in.OperationID, RequestHash: digest, Kind: "logs.policy", State: "running", Stage: "saving_policy", LogPolicy: &in.Policy, LogPolicyBase: in.BaseVersion}
	if err := n.Journal.Put(record); err != nil {
		return Record{}, fault.Unavailable("无法持久保存策略执行意图")
	}
	m.state.Version++
	m.state.Policy = in.Policy
	m.state.LastOperation = in.OperationID
	if err := m.saveLocked(); err != nil {
		m.policyUncertain = true
		return Record{}, fault.Unavailable("策略保存结果不确定，需 Agent 重启恢复")
	}
	record.State, record.Stage, record.LogPolicyVersion = "succeeded", "policy_applied", m.state.Version
	if err := n.Journal.Put(record); err != nil {
		m.policyUncertain = true
		return Record{}, fault.Unavailable("策略已保存，执行记录待 Agent 恢复")
	}
	return record, nil
}
