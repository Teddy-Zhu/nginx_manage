package fail2ban

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (s *PolicyService) ExistingResources(ctx context.Context) ([]ExistingResource, error) {
	e, ok := s.Agent.(ExistingPolicyExecutor)
	if !ok {
		return nil, fault.Unavailable("未连接已有 jail 执行器")
	}
	return e.ReadFail2banExistingResources(ctx)
}

func (s *PolicyService) ExistingResource(ctx context.Context, name string) (ExistingResourcePolicy, error) {
	e, ok := s.Agent.(ExistingPolicyExecutor)
	if !ok {
		return ExistingResourcePolicy{}, fault.Unavailable("未连接已有 jail 执行器")
	}
	return e.ReadFail2banExistingResource(ctx, name)
}

func (s *PolicyService) existingPayload(id, operation string, sealed []byte) (existingTaskPayload, error) {
	var p existingTaskPayload
	plain, err := s.Vault.Open(sealed, "fail2ban:operation:"+id)
	if err != nil {
		return p, err
	}
	if json.Unmarshal(plain, &p) != nil || !p.valid(operation) {
		return p, errors.New("已有 jail 任务材料无法核对")
	}
	return p, nil
}

func (s *PolicyService) existingTask(ctx context.Context, q PolicyReader, id string) (ExistingPolicyTaskStatus, existingTaskPayload, error) {
	var item ExistingPolicyTaskStatus
	var sealed []byte
	if !policyID.MatchString(id) {
		return item, existingTaskPayload{}, fault.Invalid("已有 jail 任务标识无效")
	}
	err := q.QueryRowContext(ctx, "SELECT t.id,t.operation_id,t.state,t.stage,t.last_error,t.created_at,o.payload FROM tasks t JOIN fail2ban_operations o ON o.task_id=t.id WHERE t.id=? AND t.kind='fail2ban.existing'", id).Scan(&item.ID, &item.OperationID, &item.State, &item.Stage, &item.Error, &item.CreatedAt, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		err = fault.New(404, "NOT_FOUND", "已有 jail 任务不存在")
	}
	if err != nil {
		return item, existingTaskPayload{}, err
	}
	p, err := s.existingPayload(item.ID, item.OperationID, sealed)
	return p.status(item), p, err
}

func (s *PolicyService) ExistingTask(ctx context.Context, id string) (ExistingPolicyTaskStatus, error) {
	item, _, err := s.existingTask(ctx, s.DB, id)
	return item, err
}

func (s *PolicyService) ExistingTasks(ctx context.Context) ([]ExistingPolicyTaskStatus, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT t.id,t.operation_id,t.state,t.stage,t.last_error,t.created_at,o.payload FROM tasks t JOIN fail2ban_operations o ON o.task_id=t.id WHERE t.kind='fail2ban.existing' ORDER BY t.created_at DESC,t.id DESC LIMIT 16")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExistingPolicyTaskStatus{}
	for rows.Next() {
		var item ExistingPolicyTaskStatus
		var sealed []byte
		if err = rows.Scan(&item.ID, &item.OperationID, &item.State, &item.Stage, &item.Error, &item.CreatedAt, &sealed); err != nil {
			return nil, err
		}
		p, err := s.existingPayload(item.ID, item.OperationID, sealed)
		if err != nil {
			return nil, err
		}
		out = append(out, p.status(item))
	}
	return out, rows.Err()
}

func existingKey(key string) bool {
	return key != "" && len(key) <= 128 && !strings.ContainsAny(key, "\x00\r\n")
}

func (s *PolicyService) existingReplay(ctx context.Context, tx *sql.Tx, principal, key, digest string) (ExistingPolicyTask, bool, error) {
	var out ExistingPolicyTask
	var hash string
	var sealed []byte
	err := tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", principal, key).Scan(&hash, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if hash != digest {
		return out, true, fault.Conflict("同一幂等键不能用于不同请求")
	}
	raw, err := s.Vault.Open(sealed, "idempotency:"+principal+":"+key)
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, true, err
}

func (s *PolicyService) existingReceipt(ctx context.Context, tx *sql.Tx, p auth.Principal, requestID, key, digest, action string, out ExistingPolicyTask) error {
	raw, _ := json.Marshal(out)
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(raw, "idempotency:"+p.ID+":"+key), now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'queued',?)", secure.ID(), requestID, p.ID, action, out.TaskID, now)
	return err
}

func (s *PolicyService) ChangeExistingPolicy(ctx context.Context, p auth.Principal, requestID, key string, in ExistingPolicyInput) (ExistingPolicyTask, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out ExistingPolicyTask
	if err := p.Require("security.write"); err != nil {
		return out, err
	}
	if !existingKey(key) {
		return out, fault.Invalid("幂等键无效")
	}
	request, err := in.request(secure.ID()).Normalize()
	if err != nil {
		return out, err
	}
	in.Policy = request.Policy
	raw, _ := json.Marshal(struct {
		Action string
		Input  ExistingPolicyInput
	}{"fail2ban.existing", in})
	digest := secure.Hash(raw)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if prior, found, err := s.existingReplay(ctx, tx, p.ID, key, digest); found || err != nil {
		return prior, err
	}
	if _, ok := s.Agent.(ExistingPolicyExecutor); !ok {
		return out, fault.Unavailable("未连接已有 jail 执行器")
	}
	if err = s.moduleEnabled(ctx, tx); err != nil {
		return out, err
	}
	if err = s.migrationIdle(ctx, tx); err != nil {
		return out, err
	}
	if err = s.applyIdle(ctx, tx); err != nil {
		return out, err
	}
	if in.Action == "apply" {
		var id string
		if err = tx.QueryRowContext(ctx, "SELECT id FROM tasks WHERE kind='fail2ban.existing' AND operation_id=? AND state='succeeded'", in.PreviewID).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return out, fault.Conflict("成功的原参数预览任务不存在")
			}
			return out, err
		}
		_, preview, err := s.existingTask(ctx, tx, id)
		if err != nil {
			return out, err
		}
		plan := preview.Result
		if preview.Input.Action != "preview" || plan == nil || plan.State != "succeeded" || plan.Plan == nil || plan.AdoptionID != in.AdoptionID || plan.Target != in.Target || !sameExistingPolicy(plan.Plan.After, in.Policy) || plan.Plan.StopConfirmation != in.ConfirmStop || time.Now().Unix() < plan.Plan.At || time.Now().Unix()-plan.Plan.At > 300 {
			return out, fault.Conflict("预览已过期、参数变化或停用确认不符，须重新预览")
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM fail2ban_operations").Scan(&count); err != nil {
		return out, err
	}
	if count >= 256 {
		return out, fault.Conflict("Fail2ban 操作记录达到容量上限，须本机维护")
	}
	out = ExistingPolicyTask{TaskID: secure.ID(), OperationID: request.OperationID}
	payload, _ := json.Marshal(existingTaskPayload{Input: in, Request: request})
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'fail2ban.existing',?,'queued','queued',?,?,?)", out.TaskID, in.AdoptionID, out.OperationID, now, now); err != nil {
		return ExistingPolicyTask{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO fail2ban_operations(task_id,payload) VALUES(?,?)", out.TaskID, s.Vault.Seal(payload, "fail2ban:operation:"+out.TaskID)); err != nil {
		return ExistingPolicyTask{}, err
	}
	if err = s.existingReceipt(ctx, tx, p, requestID, key, digest, "fail2ban.existing", out); err != nil {
		return ExistingPolicyTask{}, err
	}
	return out, tx.Commit()
}

func (s *PolicyService) CancelExistingPolicy(ctx context.Context, p auth.Principal, requestID, key, id string) (ExistingPolicyTask, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out ExistingPolicyTask
	if err := p.Require("security.write"); err != nil {
		return out, err
	}
	if !existingKey(key) {
		return out, fault.Invalid("幂等键无效")
	}
	digest := secure.Hash([]byte("fail2ban.existing.cancel:" + id))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if prior, found, err := s.existingReplay(ctx, tx, p.ID, key, digest); found || err != nil {
		return prior, err
	}
	item, payload, err := s.existingTask(ctx, tx, id)
	if err != nil {
		return out, err
	}
	if item.Stage == "restore_isolated" || item.State == "succeeded" || item.State == "failed" || item.State == "cancelled" {
		return out, fault.Conflict("任务已结束或已恢复隔离，不能申请取消")
	}
	if payload.CancelGeneration == 0 || payload.CancelObserved == payload.CancelGeneration && payload.CancelError != "" {
		if payload.CancelGeneration >= 32 {
			return out, fault.Conflict("取消申请已达上限，须本机核对原操作")
		}
		payload.CancelGeneration++
		payload.CancelError = ""
	}
	raw, _ := json.Marshal(payload)
	if _, err = tx.ExecContext(ctx, "UPDATE fail2ban_operations SET payload=? WHERE task_id=?", s.Vault.Seal(raw, "fail2ban:operation:"+id), id); err != nil {
		return out, err
	}
	out = ExistingPolicyTask{TaskID: item.ID, OperationID: item.OperationID}
	if err = s.existingReceipt(ctx, tx, p, requestID, key, digest, "fail2ban.existing.cancel", out); err != nil {
		return ExistingPolicyTask{}, err
	}
	return out, tx.Commit()
}
