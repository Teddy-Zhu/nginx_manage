package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// The plan fixes the imported bytes. A small same-transaction receipt can
// therefore recognize its original execution after the payload is retired.
func executionDigest(id string, in ExecuteInput) string {
	raw, _ := json.Marshal(struct {
		ID    string       `json:"id"`
		Input ExecuteInput `json:"input"`
	}{id, in})
	return secure.Hash(append([]byte("migration.execute\x00"), raw...))
}

func (s *Service) executionPrior(ctx context.Context, p auth.Principal, key, id string, in ExecuteInput) (bool, error) {
	var planOwner, owner, originalKey, digest, state, revision, task string
	err := s.DB.QueryRowContext(ctx, "SELECT principal,execution_principal,execution_key,execution_hash,state,revision_id,task_id FROM migration_plans WHERE id=?", id).Scan(&planOwner, &owner, &originalKey, &digest, &state, &revision, &task)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if planOwner != p.ID && !p.Has("auth.manage") {
		return false, auth.ErrForbidden
	}
	if digest == "" {
		if owner != "" || originalKey != "" {
			return false, fault.Unavailable("迁移执行回执不完整，须核对原计划")
		}
		return false, nil
	}
	if owner == "" || !validPushKey(originalKey) {
		return false, fault.Unavailable("迁移执行回执无效，须核对原计划")
	}
	if owner != p.ID || originalKey != key || digest != executionDigest(id, in) {
		return false, fault.Conflict("迁移计划已由原操作执行，须使用原身份、幂等键和执行选项核对结果")
	}
	valid := validTransferID(revision)
	switch in.Mode {
	case "draft":
		valid = valid && state == "draft" && task == ""
	case "save":
		valid = valid && state == "saved" && task == ""
	case "apply":
		valid = valid && validTransferID(task) && (state == "applying" || state == "succeeded" || state == "rolled_back" || state == "recovery_required")
	default:
		valid = false
	}
	if !valid {
		return false, fault.Unavailable("原迁移执行回执与结果不一致，须核对原计划")
	}
	return true, nil
}
