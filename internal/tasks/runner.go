package tasks

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
)

type Runner struct {
	Maintenance *maintenance.Service
	DB          *sql.DB
	Config      *nginxconfig.Service
	Agent       *agent.Client
}

func (r *Runner) Run(ctx context.Context) error {
	// An expired Web lease is never evidence that the root operation stopped.
	if _, err := r.DB.ExecContext(ctx, "UPDATE tasks SET state='recovery_required',stage='unknown_task' WHERE state IN ('running','compensating') AND kind NOT IN ('nginx.apply','nginx.validate','nginx.restore','acme.account.register','acme.issue','host.dns.apply','component.check','component.prepare','component.install','panel.update','maintenance.enter','migration.push','migration.dependencies')"); err != nil {
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
	done, ok := r.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	var id string
	err := r.DB.QueryRowContext(ctx, "SELECT id FROM tasks WHERE kind IN ('nginx.apply','nginx.validate','nginx.restore') AND state IN ('running','compensating','recovery_required') ORDER BY created_at,id LIMIT 1").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		now := time.Now().Unix()
		err = r.DB.QueryRowContext(ctx, `UPDATE tasks SET state='running',stage='agent_submit_pending',attempts=attempts+1,lease_until=?,updated_at=?
WHERE id=(SELECT id FROM tasks WHERE state='queued' AND kind IN ('nginx.apply','nginx.validate','nginx.restore') ORDER BY created_at,id LIMIT 1) RETURNING id`, now+60, now).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	task, err := dbgen.New(r.DB).GetTask(ctx, id)
	if err != nil {
		return err
	}
	if task.Kind != "nginx.apply" && task.Kind != "nginx.validate" && task.Kind != "nginx.restore" {
		return r.finish(ctx, task, "recovery_required", "unknown_task", "未注册的任务类型", "")
	}
	record, err := r.Agent.Operation(ctx, task.OperationID)
	if errors.Is(err, agent.ErrOperationNotFound) {
		if task.AgentAccepted != 0 {
			if task.State == "recovery_required" && task.Stage == "operation_missing" {
				return nil
			}
			return r.finish(ctx, task, "recovery_required", "operation_missing", "已接受操作的 Agent 记录缺失，停止重复执行", "")
		}
		tree, loadErr := r.Config.Get(ctx, task.RevisionID.String)
		if loadErr != nil {
			if task.SubmitStarted != 0 {
				return r.finish(ctx, task, "recovery_required", "load_failed", "提交后的配置修订无法读取", "")
			}
			return r.finish(ctx, task, "failed", "load_failed", "读取配置修订失败", "")
		}
		materials, materialErr := r.Config.CertificateMaterials(ctx, tree)
		if materialErr != nil {
			if task.SubmitStarted != 0 {
				return r.finish(ctx, task, "recovery_required", "certificate_load_failed", "提交后的证书版本无法读取", "")
			}
			return r.finish(ctx, task, "failed", "certificate_load_failed", "读取修订引用的证书版本失败", "")
		}
		var previousFiles []nginxconfig.File
		if task.Kind == "nginx.restore" {
			previousFiles = nginxconfig.InitialFiles()
			if task.ExpectedRevision != "" {
				previous, previousErr := r.Config.Get(ctx, task.ExpectedRevision)
				if previousErr != nil {
					state := "failed"
					if task.SubmitStarted != 0 {
						state = "recovery_required"
					}
					return r.finish(ctx, task, state, "previous_load_failed", "无法读取外部快照对应的已生效修订", "")
				}
				previousFiles = previous.Files
			}
		}
		if task.SubmitStarted == 0 {
			var desired sql.NullString
			var enabled bool
			if err := r.DB.QueryRowContext(ctx, "SELECT desired_revision FROM config_head WHERE id=1").Scan(&desired); err != nil {
				return err
			}
			if err := r.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
				return err
			}
			if !enabled {
				return r.finish(ctx, task, "failed", "module_disabled", "Nginx 配置模块已停用", "")
			}
			if desired.String != task.RevisionID.String {
				return r.finish(ctx, task, "cancelled", "superseded", "期望修订已变化，未应用旧任务", "")
			}
			runtime, err := r.Agent.NginxState(ctx)
			if err != nil {
				return r.progress(ctx, task, "agent_unreachable", "无法查询 Agent 状态，保留操作标识等待核对")
			}
			if !runtime.Available || task.Kind != "nginx.restore" && !runtime.Integrity {
				return r.finish(ctx, task, "failed", "agent_not_ready", runtime.Reason, "")
			}
			if _, err := r.DB.ExecContext(ctx, "UPDATE tasks SET submit_started=1 WHERE id=?", task.ID); err != nil {
				return err
			}
		}
		record, err = r.Agent.Apply(ctx, agent.ApplyRequest{Protocol: agent.Protocol, OperationID: task.OperationID, RevisionID: tree.RevisionID, ExpectedRevision: task.ExpectedRevision, ValidateOnly: task.Kind == "nginx.validate", Files: tree.Files, Certificates: materials, RestoreSnapshot: task.RestoreSnapshot, PreviousFiles: previousFiles})
		if err != nil {
			// Reconcile the durable operation before deciding whether a failed IPC
			// request was rejected or is still executing independently of this process.
			submissionErr := err
			record, err = r.Agent.Operation(ctx, task.OperationID)
			if errors.Is(err, agent.ErrOperationNotFound) {
				if errors.Is(submissionErr, agent.ErrRequestTooLarge) {
					return r.finish(ctx, task, "failed", "request_too_large", submissionErr.Error(), "")
				}
				var rejected *agent.HTTPError
				if errors.As(submissionErr, &rejected) {
					return r.finish(ctx, task, "failed", "agent_rejected", "Agent 未接受操作；请检查运行修订及本机执行状态", "")
				}
				return r.progress(ctx, task, "submit_unconfirmed", "提交结果待确认，将使用原操作标识继续核对")
			}
		}
	}
	if err != nil {
		return r.progress(ctx, task, "reconciling", "无法确认 Agent 操作结果，保留原操作标识继续核对")
	}
	if _, err := r.DB.ExecContext(ctx, "UPDATE tasks SET agent_accepted=1 WHERE id=?", task.ID); err != nil {
		return err
	}
	if record.OperationID != task.OperationID || record.AfterDir != task.OperationID || record.AfterRevision != task.RevisionID.String || record.BeforeRevision != task.ExpectedRevision || record.Kind != task.Kind || record.RestoreSnapshot != task.RestoreSnapshot || task.Kind == "nginx.restore" && record.State == "rolled_back" {
		return r.finish(ctx, task, "recovery_required", "operation_mismatch", "Agent 执行合同与任务不一致", "")
	}
	switch record.State {
	case "succeeded", "rolled_back":
		if task.Kind == "nginx.apply" || task.Kind == "nginx.restore" {
			want := task.RevisionID.String
			deployment := record.AfterDir
			if record.State == "rolled_back" {
				want = task.ExpectedRevision
				deployment = record.BeforeDir
				if deployment == "bootstrap" {
					deployment = ""
				}
			}
			runtime, err := r.Agent.NginxState(ctx)
			if err != nil {
				return r.progress(ctx, task, "reconciling", "等待确认 Agent 当前运行修订")
			}
			if !runtime.Integrity || !runtime.Running || runtime.RevisionID != want || runtime.DeploymentID != deployment || record.ObservedRevision != want {
				return r.finish(ctx, task, "recovery_required", "runtime_mismatch", "执行记录与当前运行修订不一致", "")
			}
		}
		return r.finish(ctx, task, record.State, record.Stage, record.Error, record.ObservedRevision)
	case "failed", "recovery_required":
		if record.State == task.State && record.Stage == task.Stage && record.Error == task.LastError {
			return nil
		}
		return r.finish(ctx, task, record.State, record.Stage, record.Error, record.ObservedRevision)
	case "running", "compensating":
		task.State = record.State
		return r.progress(ctx, task, record.Stage, record.Error)
	default:
		return r.finish(ctx, task, "recovery_required", "unknown_agent_state", "Agent 返回未知执行状态", "")
	}
}
func (r *Runner) progress(ctx context.Context, t dbgen.Task, stage, message string) error {
	_, err := r.DB.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,updated_at=?,lease_until=? WHERE id=? AND state IN ('running','compensating','recovery_required')", t.State, stage, message, time.Now().Unix(), time.Now().Add(time.Minute).Unix(), t.ID)
	return err
}
func (r *Runner) finish(ctx context.Context, t dbgen.Task, state, stage, message, observed string) error {
	if t.State == state && t.Stage == stage && t.LastError == message && t.ObservedRevision == observed {
		return nil
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if (t.Kind == "nginx.apply" || t.Kind == "nginx.restore") && (state == "succeeded" || state == "rolled_back") {
		var revision any
		if observed != "" {
			revision = observed
		}
		if _, err := tx.ExecContext(ctx, "UPDATE config_head SET applied_revision=? WHERE id=1", revision); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,observed_revision=?,lease_until=NULL,updated_at=? WHERE id=? AND state IN ('running','compensating','recovery_required')", state, stage, message, observed, time.Now().Unix(), t.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", secure.ID(), t.OperationID, "system:tasks", t.Kind, t.RevisionID.String, state, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
