package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxconfig"
)

func (s *Service) nextDependencies(ctx context.Context) error {
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	if !s.mu.TryLock() {
		return nil
	}
	defer s.mu.Unlock()
	var id, owner, planOwner string
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT d.plan_id,d.principal,m.principal,d.payload FROM migration_dependencies d JOIN tasks t ON t.id=d.task_id JOIN migration_plans m ON m.id=d.plan_id
 WHERE t.state IN ('queued','running','recovery_required') ORDER BY t.created_at,t.id LIMIT 1`).Scan(&id, &owner, &planOwner, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	d, err := s.dependencyStatus(ctx, id)
	if err != nil {
		return err
	}
	finish := func(state, stage, message string) error { return s.saveDependency(ctx, id, d, state, stage, message) }
	if d.Deadline <= time.Now().Unix() {
		return s.expireDependencies(ctx, id, owner, d)
	}
	plain, err := s.Vault.Open(raw, "migration-dependencies:"+id)
	if err != nil {
		return err
	}
	var input DependencyInput
	if json.Unmarshal(plain, &input) != nil || input.validate() != nil {
		return finish("recovery_required", "input_invalid", "依赖准备授权无法确认，停止提交")
	}
	// The durable parent is the grant. Its children receive only the component
	// permission authorized at admission, never the caller's unrelated scopes.
	p := auth.Principal{ID: owner, Scopes: []string{"components.manage"}}
	st, err := s.load(ctx, auth.Principal{ID: planOwner}, id)
	if err != nil {
		return err
	}
	var version int64
	if err = s.DB.QueryRowContext(ctx, "SELECT version FROM config_head WHERE id=1").Scan(&version); err != nil {
		return err
	}
	if st.Plan.State != "planned" || version != st.Plan.BaseVersion {
		return finish("failed", "target_changed", "目标配置或迁移状态已变化，停止后续准备；已创建的组件任务保留原记录")
	}
	if s.Components == nil || s.Agent == nil {
		return finish("failed", "unavailable", "本机组件服务或 Agent 不可用")
	}
	if d.CheckTaskID == "" {
		features, e := s.Agent.NginxFeatures(ctx)
		if e != nil {
			return finish("failed", "unavailable", "无法核对目标 Nginx 状态，未提交组件准备")
		}
		if features.Available {
			return finish("succeeded", "not_required", "")
		}
		overview, e := s.Components.Overview(ctx)
		if e != nil {
			return finish("failed", "unavailable", "无法核对本机可信组件来源")
		}
		if !overview.Available || overview.Scope != "host" {
			return finish("failed", "unavailable", "当前部署不支持宿主机可信资产准备；Docker 须使用预置所需模块的镜像")
		}
		if overview.Installation != nil {
			return finish("failed", "runtime_recovery", "已有受管安装绑定，须恢复原实例，不能以准备新资产替代运行恢复")
		}
		child, e := s.Components.CreateLinked(ctx, p, id, "migration-deps:"+id+":check", components.CreateInput{Input: components.Input{Action: "check", Tag: input.Tag, Prerelease: input.Prerelease, Components: []string{"nginx"}}}, s.dependencyLink(ctx, id, "check", st.Plan.BaseVersion))
		if e != nil {
			return s.dependencyChildError(ctx, id, d, e)
		}
		d.CheckTaskID = child.ID
		return finish("running", "checking", "")
	}
	check, err := s.Components.Get(ctx, p, d.CheckTaskID)
	if err != nil {
		return s.dependencyChildError(ctx, id, d, err)
	}
	if state, message := dependencyChildState(check); state != "" {
		return finish(state, "checking", message)
	}
	if check.State != "succeeded" {
		return finish("running", "checking", "")
	}
	if check.Result == nil || check.Result.Release == nil {
		return finish("recovery_required", "check_unconfirmed", "组件检查结果缺失，停止准备")
	}
	r := check.Result.Release
	if !check.Result.RuntimeReady {
		return finish("failed", "system_dependencies", "目标系统运行依赖未就绪；请核对组件检查任务，未安装系统包")
	}
	parsed, err := nginxconfig.Parse(st.Payload.Files, s.Config.Policy)
	if err != nil {
		return err
	}
	matched := false
	for _, asset := range r.Assets {
		if asset.Component != "nginx" {
			continue
		}
		capabilities := map[string]bool{}
		for _, feature := range asset.Features {
			capabilities[feature] = true
		}
		matched = true
		for _, feature := range parsed.MigrationFeatures() {
			if !capabilities[feature] {
				matched = false
			}
		}
		if !matched {
			return finish("failed", "capability_missing", "已签名资产未声明迁移所需的全部 Nginx 能力，停止准备；不编译或增装模块")
		}
	}
	if !matched {
		return finish("failed", "capability_missing", "检查结果没有匹配的 Nginx 资产")
	}
	if d.PrepareTaskID == "" {
		if r.ExpiresAt <= time.Now().Unix() {
			return finish("failed", "release_expired", "已检查的发行清单过期，停止准备")
		}
		child, e := s.Components.CreateLinked(ctx, p, id, "migration-deps:"+id+":prepare", components.CreateInput{CheckTaskID: check.ID, Input: components.Input{Action: "prepare", Tag: r.Tag, Prerelease: input.Prerelease, Assets: r.Selected, PlanID: r.PlanID, ManifestSHA256: r.ManifestSHA256, TrustSHA256: r.TrustSHA256}}, s.dependencyLink(ctx, id, "prepare", st.Plan.BaseVersion))
		if e != nil {
			return s.dependencyChildError(ctx, id, d, e)
		}
		d.PrepareTaskID = child.ID
		return finish("running", "preparing", "")
	}
	prepared, err := s.Components.Get(ctx, p, d.PrepareTaskID)
	if err != nil {
		return s.dependencyChildError(ctx, id, d, err)
	}
	if state, message := dependencyChildState(prepared); state != "" {
		return finish(state, "preparing", message)
	}
	if prepared.State != "succeeded" {
		return finish("running", "preparing", "")
	}
	if prepared.Result == nil || prepared.Result.Stage != "prepared" || prepared.Result.Release == nil || prepared.Result.Release.PlanID != r.PlanID {
		return finish("recovery_required", "prepare_unconfirmed", "资产准备结果无法与原检查计划对应，须核对原组件任务")
	}
	return finish("succeeded", "prepared", "")
}

func dependencyChildState(t components.Task) (string, string) {
	switch t.State {
	case "recovery_required":
		return "recovery_required", "组件任务结果待恢复，停止后续准备；请核对原组件任务"
	case "failed", "cancelled", "rolled_back":
		return "failed", "组件任务未成功，停止后续准备；请核对原组件任务"
	}
	return "", ""
}
func (s *Service) dependencyChildError(ctx context.Context, id string, d *DependencyStatus, err error) error {
	var f *fault.Error
	if !errors.As(err, &f) {
		return err
	}
	if f.Status == 404 {
		return s.saveDependency(ctx, id, d, "recovery_required", "child_missing", "原组件任务缺失，停止重新创建")
	}
	if f.Status >= 400 && f.Status < 500 {
		return s.saveDependency(ctx, id, d, "failed", "preparation_blocked", "组件准备未获准，请核对并发任务、系统依赖及可信发行检查")
	}
	return err
}
func (s *Service) saveDependency(ctx context.Context, id string, d *DependencyStatus, state, stage, message string) error {
	if d.State == state && d.Stage == stage && d.Error == message {
		// Child IDs may have changed while the visible stage stayed the same.
		var check, prepare string
		if err := s.DB.QueryRowContext(ctx, "SELECT check_task_id,prepare_task_id FROM migration_dependencies WHERE plan_id=?", id).Scan(&check, &prepare); err != nil {
			return err
		}
		if check == d.CheckTaskID && prepare == d.PrepareTaskID {
			return nil
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE migration_dependencies SET check_task_id=?,prepare_task_id=? WHERE plan_id=?", d.CheckTaskID, d.PrepareTaskID, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,updated_at=? WHERE id=? AND state IN ('queued','running','recovery_required')", state, stage, message, time.Now().Unix(), d.TaskID); err != nil {
		return err
	}
	if d.State != state || d.Stage != stage {
		if err = pushAudit(ctx, tx, "system:migration", d.TaskID, id, "migration.dependencies."+stage, state); err != nil {
			return err
		}
	}
	return tx.Commit()
}
