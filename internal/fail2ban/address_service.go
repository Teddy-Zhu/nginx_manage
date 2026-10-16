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

type addressTaskPayload struct {
	Input   AddressInput      `json:"input"`
	Request AddressRequest    `json:"request"`
	Result  *AddressOperation `json:"result"`
}

func (s *PolicyService) AddressRuntime(ctx context.Context, jail, ip string) (AddressStatus, error) {
	executor, ok := s.Agent.(AddressExecutor)
	if !ok {
		return AddressStatus{}, fault.Unavailable("未连接手动封禁执行器")
	}
	return executor.ReadFail2banAddress(ctx, jail, ip)
}

func (s *PolicyService) AddressTasks(ctx context.Context) ([]AddressTaskStatus, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT t.id,t.operation_id,t.state,t.stage,t.last_error,t.created_at,o.payload FROM tasks t JOIN fail2ban_operations o ON o.task_id=t.id WHERE t.kind='fail2ban.address' ORDER BY t.created_at DESC,t.id DESC LIMIT 16")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AddressTaskStatus{}
	for rows.Next() {
		var item AddressTaskStatus
		var sealed []byte
		if err = rows.Scan(&item.ID, &item.OperationID, &item.State, &item.Stage, &item.Error, &item.CreatedAt, &sealed); err != nil {
			return nil, err
		}
		plain, err := s.Vault.Open(sealed, "fail2ban:operation:"+item.ID)
		if err != nil {
			return nil, err
		}
		var payload addressTaskPayload
		if json.Unmarshal(plain, &payload) != nil || !payload.valid(item.OperationID) {
			return nil, errors.New("手动封禁历史材料无法核对")
		}
		item.Input, item.Result = payload.Input, payload.Result
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p addressTaskPayload) valid(id string) bool {
	return p.Request.Valid() && p.Input.Validate() == nil && p.Request.OperationID == id && p.Input == p.Request.Input && (p.Result == nil || p.Result.ID == id && p.Result.RequestHash == p.Request.Hash() && p.Result.Input == p.Input)
}

func (s *PolicyService) ChangeAddress(ctx context.Context, p auth.Principal, requestID, key string, in AddressInput) (AddressTask, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out AddressTask
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
		Input  AddressInput
	}{"fail2ban.address", in})
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
	if _, ok := s.Agent.(AddressExecutor); !ok {
		return out, fault.Unavailable("未连接手动封禁执行器")
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
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM fail2ban_operations").Scan(&count); err != nil {
		return out, err
	}
	if count >= 256 {
		return out, fault.Conflict("Fail2ban 操作记录达到容量上限，须本机维护")
	}
	out = AddressTask{TaskID: secure.ID(), OperationID: secure.ID()}
	request := AddressRequest{Protocol: protocol.Agent, OperationID: out.OperationID, Input: in}
	payload, _ := json.Marshal(addressTaskPayload{Input: in, Request: request})
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'fail2ban.address',?,'queued','queued',?,?,?)", out.TaskID, in.Jail, out.OperationID, now, now); err != nil {
		return AddressTask{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO fail2ban_operations(task_id,payload) VALUES(?,?)", out.TaskID, s.Vault.Seal(payload, "fail2ban:operation:"+out.TaskID)); err != nil {
		return AddressTask{}, err
	}
	response, _ := json.Marshal(out)
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return AddressTask{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,'fail2ban.address',?,'queued',?)", secure.ID(), requestID, p.ID, out.TaskID, now); err != nil {
		return AddressTask{}, err
	}
	return out, tx.Commit()
}
