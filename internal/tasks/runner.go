package tasks

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/nginxconfig"
)

type Runner struct {
	DB     *sql.DB
	Config *nginxconfig.Service
	Agent  *agent.Client
}

func (r *Runner) Run(ctx context.Context) error {
	// Policy checks are pure and safe to repeat with the same operation ID.
	// Never use an expired lease alone to replay an operation with side effects.
	if _, err := r.DB.ExecContext(ctx, "UPDATE tasks SET state='queued',stage='recovering',lease_until=NULL WHERE state='running' AND kind='nginx.policy_check'"); err != nil {
		return err
	}
	if _, err := r.DB.ExecContext(ctx, "UPDATE tasks SET state='recovery_required',stage='reconcile_required' WHERE state='running' AND kind<>'nginx.policy_check'"); err != nil {
		return err
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := r.next(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (r *Runner) next(ctx context.Context) error {
	var id, kind, revision, operation string
	now := time.Now().Unix()
	err := r.DB.QueryRowContext(ctx, `UPDATE tasks SET state='running',stage='agent_policy_check',attempts=attempts+1,lease_until=?,updated_at=?
WHERE id=(SELECT id FROM tasks WHERE state='queued' ORDER BY created_at,id LIMIT 1)
RETURNING id,kind,revision_id,operation_id`, now+60, now).Scan(&id, &kind, &revision, &operation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	state, stage, message := "succeeded", "policy_checked", ""
	if kind != "nginx.policy_check" {
		state, stage, message = "recovery_required", "unknown_task", "未注册的任务类型"
	} else {
		var enabled bool
		err = r.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled)
		if err != nil {
			return err
		}
		if !enabled {
			state, stage, message = "failed", "module_disabled", "Nginx 配置模块已停用"
		} else {
			tree, err := r.Config.Get(ctx, revision)
			if err != nil {
				state, stage, message = "failed", "load_failed", "读取配置修订失败"
			} else if tree.State != "desired" {
				state, stage, message = "failed", "invalid_revision", "草稿不能执行"
			} else {
				out, err := r.Agent.Check(ctx, agent.CheckRequest{Protocol: agent.Protocol, OperationID: operation, RevisionID: revision, Files: tree.Files})
				if err != nil {
					state, stage, message = "failed", "agent_unavailable", err.Error()
				} else if len(out.Diagnostics) > 0 {
					state, stage, message = "failed", "policy_rejected", "Agent 安全策略拒绝配置，请重新检查原生配置"
				}
			}
		}
	}
	_, err = r.DB.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,lease_until=NULL,updated_at=? WHERE id=? AND state='running'", state, stage, message, time.Now().Unix(), id)
	return err
}
