package components

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/secure"
)

type Service struct {
	Maintenance *maintenance.Service
	DB          *sql.DB
	Vault       *secure.Vault
	Agent       Host
}
type CreateInput struct {
	PrepareTaskID string `json:"prepare_task_id,omitempty"`
	Input         Input  `json:"input"`
	CheckTaskID   string `json:"check_task_id"`
}
type Task struct {
	ID          string     `json:"id"`
	OperationID string     `json:"operation_id"`
	Action      string     `json:"action"`
	State       string     `json:"state"`
	Stage       string     `json:"stage"`
	Error       string     `json:"error"`
	CreatedAt   int64      `json:"created_at"`
	UpdatedAt   int64      `json:"updated_at"`
	Result      *Operation `json:"result,omitempty"`
}

func (s *Service) Overview(ctx context.Context) (Overview, error) {
	if s.Agent == nil {
		return Overview{Reason: "未连接本机 Agent", KeyIDs: []string{}}, nil
	}
	return s.Agent.ReadComponents(ctx)
}
func (s *Service) Create(ctx context.Context, p auth.Principal, requestID, key string, in CreateInput) (Task, error) {
	return s.CreateLinked(ctx, p, requestID, key, in, nil)
}

// CreateLinked atomically links a child to an already-authorized durable parent.
func (s *Service) CreateLinked(ctx context.Context, p auth.Principal, requestID, key string, in CreateInput, link func(*sql.Tx, Task) error) (Task, error) {
	var out Task
	if err := p.Require("components.manage"); err != nil {
		return out, err
	}
	if err := in.Input.Validate(); err != nil {
		return out, err
	}
	if in.Input.Action == "software" {
		if err := p.Require("system.write"); err != nil {
			return out, err
		}
		if in.Input.Software.Action == "fail2ban" {
			if err := p.Require("security.write"); err != nil {
				return out, err
			}
		}
		if in.CheckTaskID != "" || in.PrepareTaskID != "" {
			return out, fault.Invalid("软件操作不能引用组件任务")
		}
	}
	if in.Input.Action == "activate" || in.Input.Action == "pull" {
		if err := p.Require("system.write"); err != nil {
			return out, err
		}
		if !ValidID(in.PrepareTaskID) || in.CheckTaskID != "" {
			return out, fault.Invalid("此操作须引用本人准备任务")
		}
	} else if in.PrepareTaskID != "" {
		return out, fault.Invalid("此操作不能引用准备任务")
	}
	if in.Input.Action == "check" && in.CheckTaskID != "" || in.Input.Action == "prepare" && !ValidID(in.CheckTaskID) {
		return out, fault.Invalid("组件准备须引用有效的检查任务")
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("幂等键无效")
	}
	plain, err := json.Marshal(struct {
		Action string
		Input  CreateInput
	}{"components.create", in})
	if err != nil {
		return out, err
	}
	hash := secure.Hash(plain)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if err == nil {
		if prior != hash {
			return out, fault.Conflict("同一幂等键不能用于不同请求")
		}
		raw, e := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
		if e != nil {
			return out, e
		}
		if e = json.Unmarshal(raw, &out); e != nil {
			return out, e
		}
		if link != nil {
			if e = link(tx, out); e != nil {
				return out, e
			}
			return out, tx.Commit()
		}
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('component.check','component.prepare','component.activate','component.pull','component.software') AND state IN ('queued','running','recovery_required') AND stage<>'restore_isolated'").Scan(&active); err != nil {
		return out, err
	}
	if active != 0 {
		return out, fault.Conflict("已有组件任务执行中或待恢复")
	}
	now := time.Now().Unix()
	if in.Input.Action == "pull" {
		if err = s.validateImageParent(ctx, tx, p.ID, in, now); err != nil {
			return out, err
		}
	}
	if in.Input.Action == "activate" {
		if err = s.validateFrontendParent(ctx, tx, p.ID, in, now); err != nil {
			return out, err
		}
	}
	if in.Input.Action == "prepare" {
		var checked Operation
		var state string
		err = tx.QueryRowContext(ctx, "SELECT t.state,o.result FROM component_operations o JOIN tasks t ON t.id=o.task_id WHERE o.task_id=? AND o.principal=? AND t.kind='component.check'", in.CheckTaskID, p.ID).Scan(&state, &sealed)
		if errors.Is(err, sql.ErrNoRows) {
			return out, fault.NotFound("组件检查任务不存在")
		}
		if err != nil {
			return out, err
		}
		if state != "succeeded" || len(sealed) == 0 {
			return out, fault.Conflict("须先完成组件检查")
		}
		raw, e := s.Vault.Open(sealed, "components:result:"+in.CheckTaskID)
		if e != nil {
			return out, e
		}
		if e = json.Unmarshal(raw, &checked); e != nil {
			return out, e
		}
		if e = checked.Validate(Request{Protocol: checked.Protocol, OperationID: checked.ID, Input: checked.Input}); e != nil {
			return out, e
		}
		r := checked.Release
		if checked.Input.Action != "check" || r == nil || checked.State != "succeeded" || !checked.RuntimeReady || r.ExpiresAt <= now || in.Input.OfflineID != checked.Input.OfflineID || in.Input.Tag != r.Tag || in.Input.Prerelease != checked.Input.Prerelease || in.Input.PlanID != r.PlanID || in.Input.ManifestSHA256 != r.ManifestSHA256 || in.Input.TrustSHA256 != r.TrustSHA256 || !sameAssets(in.Input.Assets, r.Selected) {
			return out, fault.Conflict("准备请求与检查结果不一致，或系统依赖尚未就绪；请重新检查")
		}
	}
	out = Task{ID: secure.ID(), OperationID: secure.ID(), Action: in.Input.Action, State: "queued", Stage: "queued", CreatedAt: now, UpdatedAt: now}
	raw, err := json.Marshal(in.Input)
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,?,?,'queued','queued',?,?,?)", out.ID, "component."+in.Input.Action, "native-components", out.OperationID, now, now); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO component_operations(task_id,principal,payload) VALUES(?,?,?)", out.ID, p.ID, s.Vault.Seal(raw, "components:input:"+out.ID)); err != nil {
		return out, err
	}
	response, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, hash, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'queued',?)", secure.ID(), requestID, p.ID, "component."+in.Input.Action, out.ID, now); err != nil {
		return out, err
	}
	if link != nil {
		if err = link(tx, out); err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}
func (s *Service) List(ctx context.Context, p auth.Principal) ([]Task, error) {
	if err := p.Require("read", "components.manage"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT t.id,t.operation_id,t.kind,t.state,t.stage,t.last_error,t.created_at,t.updated_at,o.result FROM component_operations o JOIN tasks t ON t.id=o.task_id WHERE o.principal=? ORDER BY t.created_at DESC,t.id DESC LIMIT 64", p.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var t Task
		var kind string
		var sealed []byte
		if err = rows.Scan(&t.ID, &t.OperationID, &kind, &t.State, &t.Stage, &t.Error, &t.CreatedAt, &t.UpdatedAt, &sealed); err != nil {
			return nil, err
		}
		t.Action = strings.TrimPrefix(kind, "component.")
		if len(sealed) > 0 {
			raw, e := s.Vault.Open(sealed, "components:result:"+t.ID)
			if e != nil {
				return nil, e
			}
			var op Operation
			if e = json.Unmarshal(raw, &op); e != nil {
				return nil, e
			}
			redactOperation(&op)
			t.Result = &op
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
