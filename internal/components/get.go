package components

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
)

// Get is also used by an already-authorized migration to follow its own child.
func (s *Service) Get(ctx context.Context, p auth.Principal, id string) (Task, error) {
	var out Task
	if err := p.Require("components.manage"); err != nil {
		return out, err
	}
	if !ValidID(id) {
		return out, fault.Invalid("组件任务标识无效")
	}
	var owner, kind string
	var sealed []byte
	err := s.DB.QueryRowContext(ctx, "SELECT o.principal,t.id,t.operation_id,t.kind,t.state,t.stage,t.last_error,t.created_at,t.updated_at,o.result FROM component_operations o JOIN tasks t ON t.id=o.task_id WHERE t.id=?", id).Scan(&owner, &out.ID, &out.OperationID, &kind, &out.State, &out.Stage, &out.Error, &out.CreatedAt, &out.UpdatedAt, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound("组件任务不存在")
	}
	if err != nil {
		return out, err
	}
	if owner != p.ID && !p.Has("auth.manage") {
		return Task{}, auth.ErrForbidden
	}
	out.Action = strings.TrimPrefix(kind, "component.")
	if len(sealed) > 0 {
		raw, e := s.Vault.Open(sealed, "components:result:"+id)
		if e != nil {
			return Task{}, e
		}
		var op Operation
		if e = json.Unmarshal(raw, &op); e != nil {
			return Task{}, e
		}
		if op.Protocol != protocol.Agent || op.ID != out.OperationID || op.Input.Action != out.Action {
			return Task{}, errors.New("组件任务结果与原任务不一致")
		}
		redactOperation(&op)
		out.Result = &op
	}
	return s.withCoreUpdate(out), nil
}

// Public task results expose settings without returning stored client credentials.
func redactOperation(op *Operation) {
	if request := op.Input.Software; request != nil && request.Frps != nil && request.Frps.Config != nil {
		request.Frps.Config.Token = ""
	}
}
