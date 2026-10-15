package hostdns

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
)

func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var reported bool
	for {
		if ctx.Err() != nil {
			return nil
		}
		if s.Agent != nil {
			call, cancel := context.WithTimeout(ctx, 12*time.Second)
			err := s.next(call)
			cancel()
			if err != nil && ctx.Err() == nil {
				if !reported {
					slog.Warn("host DNS task reconciliation failed", "error", err)
				}
				reported = true
			} else if err == nil {
				reported = false
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (s *Service) next(ctx context.Context) error {
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	var id string
	err := s.DB.QueryRowContext(ctx, "SELECT id FROM tasks WHERE kind='host.dns.apply' AND state IN ('queued','running','waiting_confirmation','compensating','recovery_required') ORDER BY created_at,id LIMIT 1").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	task, err := dbgen.New(s.DB).GetTask(ctx, id)
	if err != nil {
		return err
	}
	var sealed []byte
	var decision string
	if err = s.DB.QueryRowContext(ctx, "SELECT payload,decision FROM host_dns_operations WHERE task_id=?", id).Scan(&sealed, &decision); err != nil {
		return err
	}
	plain, err := s.Vault.Open(sealed, "host-dns:operation:"+id)
	if err != nil {
		return s.update(ctx, task, Status{State: "recovery_required", Stage: "plan_unreadable", Error: "DNS 任务计划无法解密，停止重新提交"}, nil, false)
	}
	var plan Plan
	if err = json.Unmarshal(plain, &plan); err != nil {
		return s.update(ctx, task, Status{State: "recovery_required", Stage: "plan_invalid", Error: "DNS 任务计划无法解析，停止重新提交"}, nil, false)
	}
	if plan.ID != plan.Hash() || plan.Input.Validate() != nil {
		return s.update(ctx, task, Status{State: "recovery_required", Stage: "plan_invalid", Error: "DNS 任务计划不匹配，停止重新提交"}, nil, false)
	}
	status, err := s.Agent.HostDNSOperation(ctx, task.OperationID)
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Code == "DNS_OPERATION_MISSING" {
		if task.AgentAccepted != 0 {
			return s.update(ctx, task, Status{State: "recovery_required", Stage: "operation_missing", Error: "已接受的 DNS 操作记录缺失，停止重新执行"}, nil, false)
		}
		if decision == "rollback" {
			return s.update(ctx, task, Status{State: "cancelled", Stage: "cancelled", Error: "DNS 应用前已取消"}, nil, true)
		}
		var enabled bool
		if err = s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='host-dns'").Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return s.update(ctx, task, Status{State: "failed", Stage: "module_disabled", Error: "主机 DNS 模块已停用"}, nil, false)
		}
		claimed, e := s.DB.ExecContext(ctx, "UPDATE tasks SET state='running',stage='agent_submit_pending',submit_started=1,attempts=attempts+1,updated_at=? WHERE id=? AND state IN ('queued','running','waiting_confirmation','compensating','recovery_required')", time.Now().Unix(), id)
		if e != nil {
			return e
		}
		n, e := claimed.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			return nil
		}
		status, err = s.Agent.ApplyHostDNS(ctx, task.OperationID, plan)
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			return s.update(ctx, task, Status{State: "failed", Stage: "preflight_rejected", Error: remote.Message}, nil, false)
		}
	}
	if err != nil {
		_, e := s.DB.ExecContext(ctx, "UPDATE tasks SET last_error='无法确认 Agent 状态；原操作继续受本机期限约束',updated_at=? WHERE id=? AND last_error!='无法确认 Agent 状态；原操作继续受本机期限约束' AND state IN ('queued','running','waiting_confirmation','compensating','recovery_required')", time.Now().Unix(), id)
		return e
	}
	if status.OperationID != task.OperationID || status.PlanID != plan.ID {
		return s.update(ctx, task, Status{State: "recovery_required", Stage: "operation_mismatch", Error: "DNS 操作身份或计划不一致"}, nil, false)
	}
	decisionApplied := false
	if decision != "" && (status.State == "running" || status.State == "waiting_confirmation" || status.State == "compensating" || status.State == "recovery_required") {
		status, err = s.Agent.DecideHostDNS(ctx, task.OperationID, decision)
		if err != nil {
			_, e := s.DB.ExecContext(ctx, "UPDATE tasks SET last_error='确认动作结果未知，继续查询 Agent',updated_at=? WHERE id=? AND last_error!='确认动作结果未知，继续查询 Agent' AND state IN ('queued','running','waiting_confirmation','compensating','recovery_required')", time.Now().Unix(), id)
			return e
		}
		decisionApplied = true
		if status.OperationID != task.OperationID || status.PlanID != plan.ID {
			return s.update(ctx, task, Status{State: "recovery_required", Stage: "operation_mismatch", Error: "DNS 确认响应身份不一致"}, nil, false)
		}
	}
	switch status.State {
	case "running", "waiting_confirmation", "compensating", "recovery_required", "rolled_back":
	case "succeeded":
		if len(status.SourceHash) != 64 {
			return s.update(ctx, task, Status{State: "recovery_required", Stage: "confirmation_invalid", Error: "DNS 确认响应缺少源版本"}, nil, false)
		}
	default:
		return s.update(ctx, task, Status{State: "recovery_required", Stage: "unknown_agent_state", Error: "Agent 返回未知 DNS 状态"}, nil, false)
	}
	return s.update(ctx, task, status, &plan, decisionApplied)
}
func (s *Service) update(ctx context.Context, task dbgen.Task, status Status, plan *Plan, clearDecision bool) error {
	if !clearDecision && task.State == status.State && task.Stage == status.Stage && task.LastError == status.Error && task.ObservedRevision == status.SourceHash && (plan == nil || task.AgentAccepted != 0) {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,agent_accepted=MAX(agent_accepted,?),updated_at=?,lease_until=NULL,observed_revision=? WHERE id=? AND state IN ('queued','running','waiting_confirmation','compensating','recovery_required')", status.State, status.Stage, status.Error, plan != nil, now, status.SourceHash, task.ID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if clearDecision {
		if _, err = tx.ExecContext(ctx, "UPDATE host_dns_operations SET decision='' WHERE task_id=?", task.ID); err != nil {
			return err
		}
	}
	if status.State == "succeeded" && plan != nil {
		raw, e := json.Marshal(plan.Input.Config)
		if e != nil {
			return e
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO host_dns_desired(target,version,payload,source_hash,updated_at) VALUES(?,1,?,?,?) ON CONFLICT(target) DO UPDATE SET version=version+1,payload=excluded.payload,source_hash=excluded.source_hash,updated_at=excluded.updated_at", plan.Input.Target, s.Vault.Seal(raw, "host-dns:desired:"+plan.Input.Target), status.SourceHash, now); err != nil {
			return err
		}
	}
	if status.State == "rolled_back" && plan != nil {
		if _, err = tx.ExecContext(ctx, "UPDATE host_dns_desired SET source_hash=? WHERE target=? AND source_hash=?", status.SourceHash, plan.Input.Target, plan.Input.SourceHash); err != nil {
			return err
		}
	}
	if status.State == "succeeded" || status.State == "failed" || status.State == "rolled_back" || status.State == "recovery_required" && task.State != "recovery_required" {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,'','system','host.dns.result',?,?,?)", secure.ID(), task.ID, status.State, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
