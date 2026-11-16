package imageupdates

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

const taskColumns = "t.id,t.operation_id,t.kind,i.prepare_task_id,t.state,t.stage,t.last_error,t.created_at,t.updated_at,i.input,i.result,i.principal,q.id,q.payload,q.dispatched"
const taskJoin = " FROM panel_image_upgrades i JOIN tasks t ON t.id=i.task_id JOIN panel_image_upgrade_requests q ON q.id=i.request_id AND q.task_id=i.task_id "

func (s *Service) read(row rowReader) (Task, string, error) {
	var t Task
	var input, result, request []byte
	var owner, kind string
	if err := row.Scan(&t.ID, &t.OperationID, &kind, &t.PrepareTaskID, &t.State, &t.Stage, &t.Error, &t.CreatedAt, &t.UpdatedAt, &input, &result, &owner, &t.requestID, &request, &t.dispatched); err != nil {
		return t, owner, err
	}
	raw, err := s.Vault.Open(input, "panel-image-upgrade:input:"+t.ID)
	if err != nil {
		return t, owner, err
	}
	if json.Unmarshal(raw, &t.Input) != nil || t.Input.Validate() != nil || Kind(t.Input.Component) != kind {
		return t, owner, errors.New("镜像替换任务输入损坏")
	}
	raw, err = s.Vault.Open(request, "panel-image-upgrade:request:"+t.requestID)
	if err != nil {
		return t, owner, err
	}
	if json.Unmarshal(raw, &t.Request) != nil || t.Request.ValidateStored() != nil || t.Request.OperationID != t.OperationID || t.Request.Input != t.Input {
		return t, owner, errors.New("镜像替换任务授权与原输入不一致")
	}
	t.Sequence, t.Command, t.AuthorizationUntil = t.Request.Sequence, t.Request.Command, t.Request.AuthorizationUntil
	if len(result) > 0 {
		raw, err = s.Vault.Open(result, "panel-image-upgrade:result:"+t.ID)
		if err != nil {
			return t, owner, err
		}
		var op Operation
		if json.Unmarshal(raw, &op) != nil || op.Validate(t.OperationID, t.Input) != nil {
			return t, owner, errors.New("镜像替换任务回执与原输入不一致")
		}
		t.Result = &op
	}
	return t, owner, nil
}

func (s *Service) Get(ctx context.Context, p auth.Principal, component, id string) (Task, error) {
	if err := p.Require("read", "components.manage"); err != nil {
		return Task{}, err
	}
	return s.ownedTask(ctx, p, component, id)
}

// Write-authorized continuation must not depend on an additional read scope.
// Both entry points retain the same component and principal ownership checks.
func (s *Service) ownedTask(ctx context.Context, p auth.Principal, component, id string) (Task, error) {
	if err := p.Require("components.manage"); err != nil {
		return Task{}, err
	}
	if Kind(component) == "" || !components.ValidID(id) {
		return Task{}, fault.Invalid("镜像替换任务标识无效")
	}
	t, owner, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+taskJoin+"WHERE t.id=? AND t.kind=?", id, Kind(component)))
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, fault.NotFound("镜像替换任务不存在")
	}
	if err == nil && owner != p.ID && !p.Has("auth.manage") {
		return Task{}, auth.ErrForbidden
	}
	return t, err
}

func (s *Service) List(ctx context.Context, p auth.Principal, component string) ([]Task, error) {
	if err := p.Require("read", "components.manage"); err != nil {
		return nil, err
	}
	if Kind(component) == "" {
		return nil, fault.Invalid("镜像组件无效")
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+taskColumns+taskJoin+"WHERE t.kind=? AND (i.principal=? OR ?) ORDER BY t.created_at DESC,t.id DESC LIMIT 64", Kind(component), p.ID, p.Has("auth.manage"))
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
		return t, false, fault.Conflict("同一幂等键不能改换镜像替换请求")
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
	_, err = tx.ExecContext(ctx, "INSERT INTO panel_image_upgrade_requests(id,task_id,principal,payload,created_at) VALUES(?,?,?,?,?)", t.requestID, t.ID, p.ID, s.Vault.Seal(raw, "panel-image-upgrade:request:"+t.requestID), time.Now().Unix())
	return err
}

func (s *Service) Create(ctx context.Context, p auth.Principal, requestID, key, component string, in CreateInput) (Task, error) {
	var zero Task
	if err := p.Require("components.manage", "system.write"); err != nil {
		return zero, err
	}
	if Kind(component) == "" || component == Nginx && !in.AllowDowntime || !validKey(key) || in.MaintenanceID != "" && !components.ValidID(in.MaintenanceID) || !components.ValidID(in.PrepareTaskID) {
		return zero, fault.Invalid("镜像替换参数或幂等键无效")
	}
	hash := requestHash(Kind(component), in)
	if t, found, err := s.replay(ctx, p, key, hash); err != nil || found {
		return t, err
	}
	if in.MaintenanceID == "" {
		var task Task
		err := s.Maintenance.Submit(ctx, p, requestID, func(id string) (string, error) {
			in.MaintenanceID = id
			var err error
			task, err = s.Create(ctx, p, requestID, key, component, in)
			return task.ID, err
		})
		return task, err
	}
	if s.Agent == nil || s.Components == nil || s.Maintenance == nil {
		return zero, fault.Unavailable("镜像替换执行器未配置")
	}
	prepared, err := s.Components.Get(ctx, p, in.PrepareTaskID)
	if err != nil {
		return zero, err
	}
	r := prepared.Result
	if prepared.Action != "prepare" || prepared.State != "succeeded" || r == nil || r.Release == nil || !r.RuntimeReady || component == Panel && r.Panel == nil {
		return zero, fault.Conflict("须选择已完成签名准备的任务")
	}
	if component == Panel && r.Panel.RequiresCoordination && !in.AllowDowntime {
		return zero, fault.Conflict("此准备版本仅允许明确授权停机后替换面板运行镜像")
	}
	if err = r.Validate(components.Request{Protocol: r.Protocol, OperationID: r.ID, Input: r.Input}); err != nil {
		return zero, err
	}
	available := false
	if component == Nginx {
		available = len(r.Release.Assets) == 0 && len(r.Release.Selected) == 1 && r.Release.Selected[0] == "image-nginx" && len(r.Release.Images) == 1 && r.Release.Images[0].ID == Nginx
	} else {
		for _, image := range r.Release.Images {
			if image.ID == component {
				available = true
			}
		}
	}
	if !available {
		return zero, fault.Conflict("签名准备任务未提供所选组件镜像")
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
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('panel.update','agent.upgrade','panel.image','nginx.image') AND state NOT IN ('succeeded','failed','rolled_back','cancelled') AND stage<>'restore_isolated'").Scan(&active); err != nil {
		return zero, err
	}
	if active != 0 {
		return zero, fault.Conflict("已有独立更新任务执行中或待恢复")
	}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM panel_image_upgrades").Scan(&count); err != nil {
		return zero, err
	}
	if count >= 64 {
		return zero, fault.Conflict("镜像替换任务达到 64 项保留上限，须本机维护")
	}
	now := time.Now().Unix()
	t := Task{ID: secure.ID(), OperationID: secure.ID(), PrepareTaskID: in.PrepareTaskID, Input: Input{Component: component, AllowDowntime: in.AllowDowntime, MaintenanceID: in.MaintenanceID, PlanID: r.Release.PlanID, Prerelease: r.Input.Prerelease}, State: "queued", Stage: "queued", Sequence: 1, Command: "upgrade", AuthorizationUntil: now + 300, CreatedAt: now, UpdatedAt: now, requestID: secure.ID()}
	t.Request = Request{Actor: p.ID, RequestID: requestID, Protocol: protocol.Agent, OperationID: t.OperationID, Input: t.Input, Sequence: 1, Command: "upgrade", Epoch: root.Epoch, AuthorizationUntil: t.AuthorizationUntil}
	if err = t.Request.Validate(); err != nil {
		return zero, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,?,?,'queued','queued',?,?,?)", t.ID, Kind(component), component, t.OperationID, now, now); err != nil {
		return zero, err
	}
	raw, err := json.Marshal(t.Input)
	if err != nil {
		return zero, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO panel_image_upgrades(task_id,principal,maintenance_id,prepare_task_id,input,request_id) VALUES(?,?,?,?,?,?)", t.ID, p.ID, in.MaintenanceID, in.PrepareTaskID, s.Vault.Seal(raw, "panel-image-upgrade:input:"+t.ID), t.requestID); err != nil {
		return zero, err
	}
	if err = s.saveAuthorization(ctx, tx, p, t); err != nil {
		return zero, err
	}
	if err = s.receipt(ctx, tx, p, requestID, key, hash, Kind(component), t); err != nil {
		return zero, err
	}
	return t, tx.Commit()
}

func (s *Service) Resume(ctx context.Context, p auth.Principal, requestID, key, component, id string) (Task, error) {
	var zero Task
	if err := p.Require("components.manage", "system.write"); err != nil {
		return zero, err
	}
	if Kind(component) == "" || !validKey(key) || !components.ValidID(id) {
		return zero, fault.Invalid("镜像替换续办参数无效")
	}
	hash := requestHash(Kind(component)+".resume", id)
	if t, found, err := s.replay(ctx, p, key, hash); err != nil || found {
		return t, err
	}
	t, err := s.ownedTask(ctx, p, component, id)
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
	t, err = s.ownedTask(ctx, p, component, id)
	if err != nil {
		return zero, err
	}
	if s.Agent == nil {
		return zero, fault.Unavailable("镜像替换执行器未配置")
	}
	if t.State != "recovery_required" {
		return zero, fault.Conflict("须先核对原镜像替换的待恢复状态")
	}
	var isolated int
	if err = s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM restore_quarantined_tasks WHERE task_id=?", id).Scan(&isolated); err != nil {
		return zero, err
	}
	if isolated != 0 || t.Stage == "restore_isolated" {
		return zero, fault.Conflict("从备份隔离的源镜像替换不能在恢复目标续办")
	}
	op, err := s.Agent.ImageUpgrade(ctx, t.Input.Component, t.OperationID)
	sequence, command := 1, "upgrade"
	var observed *Operation
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Status == 404 && remote.Code == "NOT_FOUND" {
		var attempts int
		if err = s.DB.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM panel_image_upgrade_requests WHERE task_id=? AND dispatched=1)+submit_started+agent_accepted FROM tasks WHERE id=?", id, id).Scan(&attempts); err != nil {
			return zero, err
		}
		if attempts != 0 || t.Result != nil {
			return zero, fault.Conflict("曾提交的镜像替换记录缺失，须本机恢复，不能重建")
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
			return zero, fault.Conflict("镜像替换原意图已偏离，须本机恢复")
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
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM panel_image_upgrade_requests WHERE task_id=?", id).Scan(&count); err != nil {
		return zero, err
	}
	if count >= 64 {
		return zero, fault.Conflict("镜像替换续办请求达到保留上限，须本机维护")
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
		if _, err = tx.ExecContext(ctx, "UPDATE panel_image_upgrades SET result=? WHERE task_id=?", s.Vault.Seal(raw, "panel-image-upgrade:result:"+id), id); err != nil {
			return zero, err
		}
	}
	changed, err := tx.ExecContext(ctx, "UPDATE panel_image_upgrades SET request_id=? WHERE task_id=? AND request_id=?", t.requestID, id, previous)
	if err != nil {
		return zero, err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return zero, err
	}
	if n != 1 {
		return zero, fault.Conflict("原镜像替换授权已变化，请重新核对")
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
		return zero, fault.Conflict("原镜像替换状态已变化，请重新核对")
	}
	if err = s.receipt(ctx, tx, p, requestID, key, hash, Kind(component)+".resume", t); err != nil {
		return zero, err
	}
	return t, tx.Commit()
}
