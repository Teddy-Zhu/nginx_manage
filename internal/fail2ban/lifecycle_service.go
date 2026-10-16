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
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

type lifecycleTaskPayload struct {
	Input   LifecycleInput      `json:"input"`
	Request LifecycleRequest    `json:"request"`
	Result  *LifecycleOperation `json:"result"`
}

func (s *PolicyService) PreviewLifecycle(ctx context.Context, p auth.Principal, in LifecyclePreviewInput) (LifecyclePlan, error) {
	if err := in.Validate(); err != nil {
		return LifecyclePlan{}, err
	}
	if err := p.Require(in.Scopes()...); err != nil {
		return LifecyclePlan{}, err
	}
	executor, ok := s.Agent.(LifecycleExecutor)
	if !ok {
		return LifecyclePlan{}, fault.Unavailable("未连接受管引擎执行器")
	}
	return executor.PreviewFail2banLifecycle(ctx, in)
}

func (s *PolicyService) LifecycleTasks(ctx context.Context) ([]LifecycleTaskStatus, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT t.id,t.operation_id,t.state,t.stage,t.last_error,t.created_at,o.payload FROM tasks t JOIN fail2ban_operations o ON o.task_id=t.id WHERE t.kind='fail2ban.lifecycle' ORDER BY t.created_at DESC,t.id DESC LIMIT 16")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LifecycleTaskStatus{}
	for rows.Next() {
		var item LifecycleTaskStatus
		var sealed []byte
		if err = rows.Scan(&item.ID, &item.OperationID, &item.State, &item.Stage, &item.Error, &item.CreatedAt, &sealed); err != nil {
			return nil, err
		}
		plain, err := s.Vault.Open(sealed, "fail2ban:operation:"+item.ID)
		if err != nil {
			return nil, err
		}
		var payload lifecycleTaskPayload
		if json.Unmarshal(plain, &payload) != nil || !payload.valid(item.OperationID) {
			return nil, errors.New("受管引擎操作历史材料无法核对")
		}
		item.Input, item.Result = payload.Input, payload.Result
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p lifecycleTaskPayload) valid(id string) bool {
	return p.Request.Valid() && p.Input.Validate() == nil && p.Request.OperationID == id && p.Input == p.Request.Input && (p.Result == nil || p.Result.ID == id && p.Result.RequestHash == p.Request.Hash() && p.Result.Input == p.Input)
}

func (s *PolicyService) ChangeLifecycle(ctx context.Context, p auth.Principal, requestID, key string, in LifecycleInput) (LifecycleTask, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out LifecycleTask
	if err := p.Require(in.Scopes()...); err != nil {
		return out, err
	}
	if err := in.Validate(); err != nil {
		return out, err
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("幂等键无效")
	}
	raw, _ := json.Marshal(struct {
		Action string
		Input  LifecycleInput
	}{"fail2ban.lifecycle", in})
	digest := secure.Hash(raw)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if err == nil {
		if prior != digest {
			return out, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, err := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
		if err != nil {
			return out, err
		}
		err = json.Unmarshal(plain, &out)
		return out, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if _, ok := s.Agent.(LifecycleExecutor); !ok {
		return out, fault.Unavailable("未连接受管引擎执行器")
	}
	if err = s.migrationIdle(ctx, tx); err != nil {
		return out, err
	}
	if err = s.applyIdle(ctx, tx); err != nil {
		return out, err
	}
	if in.NeedsEnabled() {
		if err = s.moduleEnabled(ctx, tx); err != nil {
			return out, err
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM fail2ban_operations").Scan(&count); err != nil {
		return out, err
	}
	if count >= 256 {
		return out, fault.Conflict("Fail2ban 操作记录达到容量上限，须本机维护")
	}
	out = LifecycleTask{TaskID: secure.ID(), OperationID: secure.ID()}
	request := LifecycleRequest{Protocol: protocol.Agent, OperationID: out.OperationID, Input: in}
	payload, _ := json.Marshal(lifecycleTaskPayload{Input: in, Request: request})
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'fail2ban.lifecycle','host','queued','queued',?,?,?)", out.TaskID, out.OperationID, now, now); err != nil {
		return LifecycleTask{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO fail2ban_operations(task_id,payload) VALUES(?,?)", out.TaskID, s.Vault.Seal(payload, "fail2ban:operation:"+out.TaskID)); err != nil {
		return LifecycleTask{}, err
	}
	response, _ := json.Marshal(out)
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return LifecycleTask{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,'fail2ban.lifecycle',?,'queued',?)", secure.ID(), requestID, p.ID, out.TaskID, now); err != nil {
		return LifecycleTask{}, err
	}
	return out, tx.Commit()
}
