package panelupdates

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
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

type Service struct {
	DB          *sql.DB
	Vault       *secure.Vault
	Maintenance *maintenance.Service
	Components  *components.Service
	Agent       Agent
}

type rowReader interface{ Scan(...any) error }

const taskColumns = "t.id,t.operation_id,i.prepare_task_id,t.state,t.stage,t.last_error,t.created_at,t.updated_at,i.input,i.result,i.principal,q.id,q.payload,q.dispatched"
const taskJoin = " FROM panel_updates i JOIN tasks t ON t.id=i.task_id JOIN panel_update_requests q ON q.id=i.request_id AND q.task_id=i.task_id "

func (s *Service) read(row rowReader) (Task, string, error) {
	var t Task
	var input, result, request []byte
	var owner string
	if err := row.Scan(&t.ID, &t.OperationID, &t.PrepareTaskID, &t.State, &t.Stage, &t.Error, &t.CreatedAt, &t.UpdatedAt, &input, &result, &owner, &t.requestID, &request, &t.dispatched); err != nil {
		return t, owner, err
	}
	raw, err := s.Vault.Open(input, "panel-update:input:"+t.ID)
	if err != nil {
		return t, owner, err
	}
	if json.Unmarshal(raw, &t.Input) != nil || t.Input.Validate() != nil {
		return t, owner, errors.New("更新任务输入损坏")
	}
	raw, err = s.Vault.Open(request, "panel-update:request:"+t.requestID)
	if err != nil {
		return t, owner, err
	}
	if json.Unmarshal(raw, &t.Request) != nil || t.Request.Validate() != nil || t.Request.OperationID != t.OperationID || t.Request.Input != t.Input {
		return t, owner, errors.New("更新任务授权与原输入不一致")
	}
	t.Sequence, t.Command, t.AuthorizationUntil = t.Request.Sequence, t.Request.Command, t.Request.AuthorizationUntil
	if len(result) > 0 {
		raw, err = s.Vault.Open(result, "panel-update:result:"+t.ID)
		if err != nil {
			return t, owner, err
		}
		var op Operation
		if json.Unmarshal(raw, &op) != nil || op.Validate(t.OperationID, t.Input) != nil {
			return t, owner, errors.New("更新任务回执与原输入不一致")
		}
		t.Result = &op
	}
	return t, owner, nil
}

func (s *Service) Get(ctx context.Context, p auth.Principal, id string) (Task, error) {
	if err := p.Require("read", "components.manage"); err != nil {
		return Task{}, err
	}
	if !components.ValidID(id) {
		return Task{}, fault.Invalid("更新任务标识无效")
	}
	t, owner, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+taskJoin+"WHERE t.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, fault.NotFound("更新任务不存在")
	}
	if err == nil && owner != p.ID && !p.Has("auth.manage") {
		return Task{}, auth.ErrForbidden
	}
	return t, err
}

func (s *Service) List(ctx context.Context, p auth.Principal) ([]Task, error) {
	if err := p.Require("read", "components.manage"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+taskColumns+taskJoin+"WHERE i.principal=? OR ? ORDER BY t.created_at DESC,t.id DESC LIMIT 64", p.ID, p.Has("auth.manage"))
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

func validKey(key string) bool {
	return key != "" && len(key) <= 128 && !strings.ContainsAny(key, "\x00\r\n")
}
func requestHash(action string, in any) string {
	raw, _ := json.Marshal(struct {
		Action string
		Input  any
	}{action, in})
	return secure.Hash(raw)
}

func (s *Service) replay(ctx context.Context, p auth.Principal, key, hash string) (Task, bool, error) {
	var previous string
	var sealed []byte
	var t Task
	err := s.DB.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&previous, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, nil
	}
	if err != nil {
		return t, false, err
	}
	if previous != hash {
		return t, false, fault.Conflict("同一幂等键不能改换更新请求")
	}
	raw, err := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
	if err == nil {
		err = json.Unmarshal(raw, &t)
	}
	return t, true, err
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

func (s *Service) saveAuthorization(ctx context.Context, tx *sql.Tx, p auth.Principal, t Task) error {
	raw, err := json.Marshal(t.Request)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO panel_update_requests(id,task_id,principal,payload,created_at) VALUES(?,?,?,?,?)", t.requestID, t.ID, p.ID, s.Vault.Seal(raw, "panel-update:request:"+t.requestID), time.Now().Unix())
	return err
}

func (s *Service) Create(ctx context.Context, p auth.Principal, requestID, key string, in CreateInput) (Task, error) {
	var zero Task
	if err := p.Require("components.manage", "system.write"); err != nil {
		return zero, err
	}
	if !validKey(key) || !components.ValidID(in.MaintenanceID) || !components.ValidID(in.PrepareTaskID) {
		return zero, fault.Invalid("更新参数或幂等键无效")
	}
	hash := requestHash("panel.update", in)
	if t, found, err := s.replay(ctx, p, key, hash); err != nil || found {
		return t, err
	}
	if s.Agent == nil || s.Components == nil {
		return zero, fault.Unavailable("独立更新执行器未配置")
	}
	prepared, err := s.Components.Get(ctx, p, in.PrepareTaskID)
	if err != nil {
		return zero, err
	}
	r := prepared.Result
	if prepared.Action != "prepare" || prepared.State != "succeeded" || r == nil || r.Release == nil || !r.RuntimeReady || r.Panel == nil || !r.Panel.AutomaticRollback {
		return zero, fault.Conflict("须选择已完成暂存且允许自动回滚的面板准备任务")
	}
	if err = r.Validate(components.Request{Protocol: r.Protocol, OperationID: r.ID, Input: r.Input}); err != nil {
		return zero, err
	}
	root, done, err := s.Maintenance.Held(in.MaintenanceID)
	if err != nil {
		return zero, err
	}
	defer done()
	if t, found, e := s.replay(ctx, p, key, hash); e != nil || found {
		return t, e
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	var count, active int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('panel.update','agent.upgrade') AND state NOT IN ('succeeded','failed','rolled_back','cancelled')").Scan(&active); err != nil {
		return zero, err
	}
	if active != 0 {
		return zero, fault.Conflict("已有更新任务执行中或待恢复")
	}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM panel_updates").Scan(&count); err != nil {
		return zero, err
	}
	if count >= 64 {
		return zero, fault.Conflict("更新任务达到 64 项保留上限，须本机维护")
	}
	now := time.Now().Unix()
	t := Task{ID: secure.ID(), OperationID: secure.ID(), PrepareTaskID: in.PrepareTaskID, Input: Input{MaintenanceID: in.MaintenanceID, PlanID: r.Release.PlanID, Prerelease: r.Input.Prerelease}, State: "queued", Stage: "queued", Sequence: 1, Command: "update", AuthorizationUntil: now + 300, CreatedAt: now, UpdatedAt: now, requestID: secure.ID()}
	t.Request = Request{Actor: p.ID, RequestID: requestID, Protocol: protocol.Agent, OperationID: t.OperationID, Input: t.Input, Sequence: 1, Command: "update", Epoch: root.Epoch, AuthorizationUntil: t.AuthorizationUntil}
	if err = t.Request.Validate(); err != nil {
		return zero, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'panel.update','panel','queued','queued',?,?,?)", t.ID, t.OperationID, now, now); err != nil {
		return zero, err
	}
	raw, err := json.Marshal(t.Input)
	if err != nil {
		return zero, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO panel_updates(task_id,principal,maintenance_id,prepare_task_id,input,request_id) VALUES(?,?,?,?,?,?)", t.ID, p.ID, in.MaintenanceID, in.PrepareTaskID, s.Vault.Seal(raw, "panel-update:input:"+t.ID), t.requestID); err != nil {
		return zero, err
	}
	if err = s.saveAuthorization(ctx, tx, p, t); err != nil {
		return zero, err
	}
	if err = s.receipt(ctx, tx, p, requestID, key, hash, "panel.update", t); err != nil {
		return zero, err
	}
	return t, tx.Commit()
}

func (s *Service) Resume(ctx context.Context, p auth.Principal, requestID, key, id string) (Task, error) {
	var zero Task
	if err := p.Require("components.manage", "system.write"); err != nil {
		return zero, err
	}
	if !validKey(key) || !components.ValidID(id) {
		return zero, fault.Invalid("更新续办参数无效")
	}
	hash := requestHash("panel.update.resume", id)
	if t, found, err := s.replay(ctx, p, key, hash); err != nil || found {
		return t, err
	}
	t, err := s.Get(ctx, p, id)
	if err != nil {
		return zero, err
	}
	root, done, err := s.Maintenance.Held(t.Input.MaintenanceID)
	if err != nil {
		return zero, err
	}
	defer done()
	if prior, found, e := s.replay(ctx, p, key, hash); e != nil || found {
		return prior, e
	}
	t, err = s.Get(ctx, p, id)
	if err != nil {
		return zero, err
	}
	if s.Agent == nil {
		return zero, fault.Unavailable("独立更新执行器未配置")
	}
	if t.State != "recovery_required" {
		return zero, fault.Conflict("须先核对原更新的待恢复状态")
	}
	op, err := s.Agent.PanelUpdate(ctx, t.OperationID)
	sequence, command := 1, "update"
	var observed *Operation
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Status == 404 && remote.Code == "NOT_FOUND" {
		var attempts int
		if err = s.DB.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM panel_update_requests WHERE task_id=? AND dispatched=1)+submit_started+agent_accepted FROM tasks WHERE id=?", id, id).Scan(&attempts); err != nil {
			return zero, err
		}
		if attempts != 0 || t.Result != nil {
			return zero, fault.Conflict("曾提交的独立更新记录缺失，须本机恢复，不能重建")
		}
	} else if err != nil {
		return zero, err
	} else {
		if err = op.Validate(t.OperationID, t.Input); err != nil {
			return zero, err
		}
		if op.Active || op.Finalized || op.Sequence >= 32 {
			return zero, fault.Conflict("须先确认原事务停止且尚未结束，才能追加续办授权")
		}
		if t.Result != nil && t.Result.IntentSHA256 != op.IntentSHA256 {
			return zero, fault.Conflict("独立更新原意图已偏离，须本机恢复")
		}
		sequence, command = op.Sequence+1, "resume"
		observed = &op
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM panel_update_requests WHERE task_id=?", id).Scan(&count); err != nil {
		return zero, err
	}
	if count >= 64 {
		return zero, fault.Conflict("更新续办请求达到保留上限，须本机维护")
	}
	previous := t.requestID
	t.requestID = secure.ID()
	t.dispatched = false
	t.Sequence = sequence
	t.Command = command
	t.AuthorizationUntil = time.Now().Unix() + 300
	t.State = "running"
	t.Stage = "control_pending"
	t.Error = ""
	t.UpdatedAt = time.Now().Unix()
	t.Result = observed
	t.Request = Request{Actor: p.ID, RequestID: requestID, Protocol: protocol.Agent, OperationID: t.OperationID, Input: t.Input, Sequence: t.Sequence, Command: t.Command, Epoch: root.Epoch, AuthorizationUntil: t.AuthorizationUntil}
	if err = t.Request.Validate(); err != nil {
		return zero, err
	}
	if err = s.saveAuthorization(ctx, tx, p, t); err != nil {
		return zero, err
	}
	if observed != nil {
		raw, e := json.Marshal(observed)
		if e != nil {
			return zero, e
		}
		if _, err = tx.ExecContext(ctx, "UPDATE panel_updates SET result=? WHERE task_id=?", s.Vault.Seal(raw, "panel-update:result:"+id), id); err != nil {
			return zero, err
		}
	}
	changed, err := tx.ExecContext(ctx, "UPDATE panel_updates SET request_id=? WHERE task_id=? AND request_id=?", t.requestID, id, previous)
	if err != nil {
		return zero, err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return zero, err
	}
	if n != 1 {
		return zero, fault.Conflict("原更新授权已变化，请重新核对")
	}
	changed, err = tx.ExecContext(ctx, "UPDATE tasks SET state='running',stage='control_pending',last_error='',updated_at=? WHERE id=? AND state='recovery_required'", t.UpdatedAt, id)
	if err != nil {
		return zero, err
	}
	n, err = changed.RowsAffected()
	if err != nil {
		return zero, err
	}
	if n != 1 {
		return zero, fault.Conflict("原更新状态已变化，请重新核对")
	}
	if err = s.receipt(ctx, tx, p, requestID, key, hash, "panel.update.resume", t); err != nil {
		return zero, err
	}
	return t, tx.Commit()
}
