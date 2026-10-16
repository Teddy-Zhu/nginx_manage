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

type jailTaskPayload struct {
	Input   ApplyInput   `json:"input"`
	Request JailsRequest `json:"request"`
}

func (s *PolicyService) applyIdle(ctx context.Context, q PolicyReader) error {
	var pending int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('fail2ban.apply','fail2ban.address','fail2ban.lifecycle','fail2ban.python') AND state IN ('queued','running','compensating','recovery_required')").Scan(&pending); err != nil {
		return err
	}
	if pending > 0 {
		return fault.Conflict("Fail2ban 操作正在执行或等待恢复，暂不能修改配置或创建新操作")
	}
	return nil
}

func (s *PolicyService) moduleEnabled(ctx context.Context, q PolicyReader) error {
	var enabled bool
	if err := q.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='fail2ban'").Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return fault.Conflict("请先启用 Fail2ban 管理模块")
	}
	return nil
}

func (s *PolicyService) Runtime(ctx context.Context) (JailsRuntime, error) {
	executor, ok := s.Agent.(JailsExecutor)
	if !ok {
		return JailsRuntime{}, fault.Unavailable("未连接受管 jail 执行器")
	}
	return executor.ReadFail2banJailsRuntime(ctx)
}

func (s *PolicyService) ApplyTasks(ctx context.Context) ([]ApplyTaskStatus, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT t.id,t.operation_id,t.state,t.stage,t.last_error,t.created_at FROM tasks t JOIN fail2ban_operations o ON o.task_id=t.id WHERE t.kind='fail2ban.apply' ORDER BY t.created_at DESC,t.id DESC LIMIT 16")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ApplyTaskStatus{}
	for rows.Next() {
		var item ApplyTaskStatus
		if err = rows.Scan(&item.ID, &item.OperationID, &item.State, &item.Stage, &item.Error, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PolicyService) Apply(ctx context.Context, p auth.Principal, requestID, key string, in ApplyInput) (ApplyTask, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out ApplyTask
	if err := p.Require("security.write"); err != nil {
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
		Input  ApplyInput
	}{"fail2ban.apply", in})
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
	if _, ok := s.Agent.(JailsExecutor); !ok {
		return out, fault.Unavailable("未连接受管 jail 执行器")
	}
	if err = s.migrationIdle(ctx, tx); err != nil {
		return out, err
	}
	if err = s.applyIdle(ctx, tx); err != nil {
		return out, err
	}
	if err = s.moduleEnabled(ctx, tx); err != nil {
		return out, err
	}
	view, err := s.ReadPolicy(ctx, tx)
	if err != nil {
		return out, err
	}
	if view.Version != in.Version || view.Policy.Hash() != in.PolicyHash {
		return out, fault.Conflict("jail 期望版本已变化，请重新预览")
	}
	for _, j := range view.Policy.Jails {
		if j.Enabled && !(j.Action == "nginx-client" && j.Template != PanelLoginTemplate || j.Action == "host-input" && j.Template == PanelLoginTemplate) {
			return out, fault.Conflict("当前支持 Nginx 客户端动作及面板登录宿主机入口")
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM fail2ban_operations").Scan(&count); err != nil {
		return out, err
	}
	if count >= 256 {
		return out, fault.Conflict("jail 应用记录达到容量上限，须本机维护")
	}
	out = ApplyTask{TaskID: secure.ID(), OperationID: secure.ID(), Version: in.Version}
	request := JailsRequest{Protocol: protocol.Agent, OperationID: out.OperationID, BaseID: in.BaseID, Target: in.Target, Policy: view.Policy}
	payload, _ := json.Marshal(jailTaskPayload{Input: in, Request: request})
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'fail2ban.apply','host','queued','queued',?,?,?)", out.TaskID, out.OperationID, now, now); err != nil {
		return ApplyTask{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO fail2ban_operations(task_id,payload) VALUES(?,?)", out.TaskID, s.Vault.Seal(payload, "fail2ban:operation:"+out.TaskID)); err != nil {
		return ApplyTask{}, err
	}
	response, _ := json.Marshal(out)
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return ApplyTask{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,'fail2ban.apply',?,'queued',?)", secure.ID(), requestID, p.ID, out.TaskID, now); err != nil {
		return ApplyTask{}, err
	}
	return out, tx.Commit()
}
