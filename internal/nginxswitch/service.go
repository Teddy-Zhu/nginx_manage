package nginxswitch

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/secure"
)

type Service struct {
	DB          *sql.DB
	Vault       *secure.Vault
	Maintenance *maintenance.Service
	Components  *components.Service
	Agent       Host
}

type rowReader interface{ Scan(...any) error }

const taskColumns = "t.id,t.operation_id,i.prepare_task_id,i.sequence,i.command,t.state,t.stage,t.last_error,t.created_at,t.updated_at,i.authorization_until,i.payload,i.result,i.principal"

func (s *Service) read(row rowReader) (Task, string, error) {
	var t Task
	var payload, result []byte
	var owner string
	if err := row.Scan(&t.ID, &t.OperationID, &t.PrepareTaskID, &t.Sequence, &t.Command, &t.State, &t.Stage, &t.Error, &t.CreatedAt, &t.UpdatedAt, &t.AuthorizationUntil, &payload, &result, &owner); err != nil {
		return t, owner, err
	}
	raw, err := s.Vault.Open(payload, "nginx-switch:input:"+t.ID)
	if err != nil {
		return t, owner, err
	}
	if json.Unmarshal(raw, &t.Input) != nil || t.Input.Validate() != nil {
		return t, owner, errors.New("切换任务输入损坏")
	}
	if len(result) > 0 {
		raw, err = s.Vault.Open(result, "nginx-switch:result:"+t.ID)
		if err != nil {
			return t, owner, err
		}
		var op Operation
		if json.Unmarshal(raw, &op) != nil || op.Validate(t.OperationID, t.Input) != nil {
			return t, owner, errors.New("切换任务结果不一致")
		}
		t.Result = &op
	}
	return t, owner, nil
}

func (s *Service) Get(ctx context.Context, p auth.Principal, id string) (Task, error) {
	if err := p.Require("components.manage"); err != nil {
		return Task{}, err
	}
	if !components.ValidID(id) {
		return Task{}, fault.Invalid("切换任务标识无效")
	}
	t, owner, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM nginx_switches i JOIN tasks t ON t.id=i.task_id WHERE t.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, fault.NotFound("切换任务不存在")
	}
	if err != nil {
		return Task{}, err
	}
	if owner != p.ID && !p.Has("auth.manage") {
		return Task{}, auth.ErrForbidden
	}
	return t, nil
}
func (s *Service) List(ctx context.Context, p auth.Principal) ([]Task, error) {
	if err := p.Require("read", "components.manage"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+taskColumns+" FROM nginx_switches i JOIN tasks t ON t.id=i.task_id WHERE i.principal=? OR ? ORDER BY t.created_at DESC,t.id DESC LIMIT 64", p.ID, p.Has("auth.manage"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		t, _, e := s.read(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func requestHash(action string, in any) string {
	raw, _ := json.Marshal(struct {
		Action string
		Input  any
	}{action, in})
	return secure.Hash(raw)
}
func validKey(key string) bool {
	return key != "" && len(key) <= 128 && !strings.ContainsAny(key, "\x00\r\n")
}
func (s *Service) replay(ctx context.Context, p auth.Principal, key, hash string) (Task, bool, error) {
	var old string
	var sealed []byte
	var out Task
	err := s.DB.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&old, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if old != hash {
		return out, false, fault.Conflict("同一幂等键不能改换切换请求")
	}
	raw, err := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, true, err
}
func (s *Service) receipt(ctx context.Context, tx *sql.Tx, p auth.Principal, requestID, key, hash, action string, t Task) error {
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, hash, s.Vault.Seal(raw, "idempotency:"+p.ID+":"+key), now); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'queued',?)", secure.ID(), requestID, p.ID, action, t.ID, now)
	return err
}

func (s *Service) Create(ctx context.Context, p auth.Principal, requestID, key string, in CreateInput) (Task, error) {
	var out Task
	if err := p.Require("components.manage", "system.write"); err != nil {
		return out, err
	}
	if !validKey(key) || in.MaintenanceID != "" && !components.ValidID(in.MaintenanceID) || !components.ValidID(in.PrepareTaskID) || !assetValue.MatchString(in.AssetID) || !in.AllowDowntime || !sha256Value.MatchString(in.ExpectedSHA256) || in.ExpectedRevision != "" && !components.ValidID(in.ExpectedRevision) || in.ExpectedDeployment != "" && !components.ValidID(in.ExpectedDeployment) {
		return out, fault.Invalid("切换任务参数或幂等键无效")
	}
	hash := requestHash("nginx.switch", in)
	replay := func() (Task, bool, error) { return s.replay(ctx, p, key, hash) }
	if t, found, err := replay(); err != nil || found {
		return t, err
	}
	if in.MaintenanceID == "" {
		var task Task
		err := s.Maintenance.Submit(ctx, p, requestID, func(id string) (string, error) {
			in.MaintenanceID = id
			var err error
			task, err = s.Create(ctx, p, requestID, key, in)
			return task.ID, err
		})
		return task, err
	}
	if s.Agent == nil || s.Components == nil {
		return out, fault.Unavailable("切换执行器未配置")
	}
	availability, err := s.Components.Overview(ctx)
	if err != nil {
		return out, err
	}
	if !availability.SwitchAvailable || availability.Installation == nil || availability.Installation.SHA256 != in.ExpectedSHA256 {
		return out, fault.Conflict("目标未开放原生 Nginx 组件切换")
	}
	prepared, err := s.Components.Get(ctx, p, in.PrepareTaskID)
	if err != nil {
		return out, err
	}
	r := prepared.Result
	if prepared.Action != "prepare" || prepared.State != "succeeded" || r == nil || r.Release == nil || !r.RuntimeReady || r.Release.ExpiresAt <= time.Now().Unix() {
		return out, fault.Conflict("须选择已完成且仍可准入的组件准备任务")
	}
	if err = r.Validate(components.Request{Protocol: r.Protocol, OperationID: r.ID, Input: r.Input}); err != nil {
		return out, err
	}
	matched := false
	for _, a := range r.Release.Assets {
		if a.ID == in.AssetID && a.Component == "nginx" {
			for _, id := range r.Release.Selected {
				if id == a.ID {
					matched = true
				}
			}
		}
	}
	if !matched {
		return out, fault.Invalid("所选资产不是该准备任务中的 Nginx")
	}
	_, done, err := s.Maintenance.Held(in.MaintenanceID)
	if err != nil {
		return out, err
	}
	defer done()
	// Recheck the receipt while holding admission, before opening a transaction.
	if t, found, e := replay(); e != nil || found {
		return t, e
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var owner string
	if err = tx.QueryRowContext(ctx, "SELECT principal FROM maintenance_sessions WHERE task_id=?", in.MaintenanceID).Scan(&owner); err != nil {
		return out, err
	}
	if owner != p.ID && !p.Has("auth.manage") {
		return out, auth.ErrForbidden
	}
	var active, count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks t WHERE kind='component.switch' AND state NOT IN ('succeeded','failed','rolled_back') AND NOT EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=t.id)").Scan(&active); err != nil {
		return out, err
	}
	if active != 0 {
		return out, fault.Conflict("已有组件切换任务执行中或待恢复")
	}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nginx_switches").Scan(&count); err != nil {
		return out, err
	}
	if count >= 64 {
		return out, fault.Conflict("组件切换记录达到 64 项上限，须本机维护")
	}
	now := time.Now().Unix()
	until := now + 300
	out = Task{ID: secure.ID(), OperationID: secure.ID(), PrepareTaskID: in.PrepareTaskID, Input: Input{MaintenanceID: in.MaintenanceID, PlanID: r.Release.PlanID, AssetID: in.AssetID, ManifestSHA256: r.Release.ManifestSHA256, TrustSHA256: r.Release.TrustSHA256, Prerelease: r.Input.Prerelease, AllowDowntime: in.AllowDowntime, ExpectedSHA256: in.ExpectedSHA256, ExpectedRevision: in.ExpectedRevision, ExpectedDeployment: in.ExpectedDeployment}, Sequence: 1, Command: "switch", State: "queued", Stage: "queued", CreatedAt: now, UpdatedAt: now, AuthorizationUntil: until}
	if err = out.Input.Validate(); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'component.switch','native-nginx','queued','queued',?,?,?)", out.ID, out.OperationID, now, now); err != nil {
		return out, err
	}
	raw, err := json.Marshal(out.Input)
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO nginx_switches(task_id,principal,maintenance_id,prepare_task_id,sequence,command,authorization_until,payload) VALUES(?,?,?,?,1,'switch',?,?)", out.ID, p.ID, in.MaintenanceID, in.PrepareTaskID, out.AuthorizationUntil, s.Vault.Seal(raw, "nginx-switch:input:"+out.ID)); err != nil {
		return out, err
	}
	if err = s.receipt(ctx, tx, p, requestID, key, hash, "component.switch", out); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Service) Control(ctx context.Context, p auth.Principal, requestID, key, id, command string) (Task, error) {
	var out Task
	if err := p.Require("components.manage", "system.write"); err != nil {
		return out, err
	}
	if !validKey(key) || !components.ValidID(id) || (command != "resume" && command != "rollback") {
		return out, fault.Invalid("切换控制参数无效")
	}
	hash := requestHash("nginx.switch."+command, id)
	if t, found, err := s.replay(ctx, p, key, hash); err != nil || found {
		return t, err
	}
	t, err := s.Get(ctx, p, id)
	if err != nil {
		return out, err
	}
	_, done, err := s.Maintenance.Held(t.Input.MaintenanceID)
	if err != nil {
		return out, err
	}
	defer done()
	if replay, found, e := s.replay(ctx, p, key, hash); e != nil || found {
		return replay, e
	}
	t, err = s.Get(ctx, p, id)
	if err != nil {
		return out, err
	}
	if t.Stage == "restore_isolated" {
		return out, fault.Conflict("来自备份的源切换任务已隔离，不能续办或补偿")
	}
	if t.State != "recovery_required" || t.Result == nil || t.Result.Active || t.Result.Sequence > t.Sequence || (t.Result.Sequence < t.Sequence && t.Stage != "control_rejected" && t.Stage != "authorization_expired") {
		return out, fault.Conflict("须先核对原切换回执及服务停止状态，不能改换尚未确认的控制操作")
	}
	if t.Sequence >= 32 {
		return out, fault.Conflict("切换恢复授权达到 32 次上限，须本机恢复")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	t.Sequence++
	t.Command = command
	t.State = "running"
	t.Stage = "control_pending"
	t.Error = ""
	t.UpdatedAt = time.Now().Unix()
	t.AuthorizationUntil = t.UpdatedAt + 300
	if _, err = tx.ExecContext(ctx, "UPDATE nginx_switches SET sequence=?,command=?,authorization_until=? WHERE task_id=?", t.Sequence, command, t.AuthorizationUntil, id); err != nil {
		return out, err
	}
	changed, err := tx.ExecContext(ctx, "UPDATE tasks SET state='running',stage='control_pending',last_error='',updated_at=? WHERE id=? AND state='recovery_required' AND NOT EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=tasks.id)", t.UpdatedAt, id)
	if err != nil {
		return out, err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return out, err
	}
	if n != 1 {
		return out, fault.Conflict("原切换状态已变化，请重新核对")
	}
	if err = s.receipt(ctx, tx, p, requestID, key, hash, "component.switch."+command, t); err != nil {
		return out, err
	}
	return t, tx.Commit()
}
