package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (s *Service) StartPush(ctx context.Context, p auth.Principal, requestID, key string, in PushInput) (PushTask, error) {
	if err := pushPermission(p); err != nil {
		return PushTask{}, err
	}
	if !validPushKey(key) || in.BaseVersion != nil && *in.BaseVersion < 0 || in.Mode != "preview" && in.Mode != "draft" && in.Mode != "save" && in.Mode != "apply" || in.Remote.NodeID != "" && (!validTransferID(in.Remote.NodeID) || in.Remote.NodeID == s.NodeID) {
		return PushTask{}, fault.Invalid("迁出模式、基础版本、节点或幂等键无效")
	}
	if err := in.Fail2ban.validate(); err != nil {
		return PushTask{}, err
	}
	if in.Fail2ban.Mode != "" && in.Fail2ban.Mode != "preserve" && !in.Remote.Selection.Fail2ban {
		return PushTask{}, fault.Invalid("合并或替换 jail 须选择导出其期望配置")
	}
	if err := in.Firewall.validate(); err != nil {
		return PushTask{}, err
	}
	if in.Firewall.Mode != "" && in.Firewall.Mode != "preserve" && !in.Remote.Selection.Firewall {
		return PushTask{}, fault.Invalid("合并或替换防火墙须选择导出其期望规则")
	}
	if in.Dependencies != nil {
		if in.Mode == "preview" {
			return PushTask{}, fault.Invalid("仅预检不执行依赖准备")
		}
		if err := in.Dependencies.validate(); err != nil {
			return PushTask{}, err
		}
	}
	if len(in.Mappings) > 128 {
		return PushTask{}, fault.Invalid("迁移映射最多 128 项")
	}
	for from, to := range in.Mappings {
		if len(from) > 4096 || len(to) > 4096 || strings.ContainsAny(from+to, "\x00\r\n") {
			return PushTask{}, fault.Invalid("迁移映射无效")
		}
	}
	client, base, err := remoteClient(in.Remote)
	if err != nil {
		return PushTask{}, err
	}
	client.CloseIdleConnections()
	raw, err := json.Marshal(struct {
		Action string
		Input  PushInput
	}{"migration.push", in})
	if err != nil {
		return PushTask{}, err
	}
	hash := secure.Hash(raw)
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	if prior, found, e := s.pushPrior(ctx, p, key, hash); found || e != nil {
		return prior, e
	}
	passphrase := secure.Token()
	packet, err := s.Export(ctx, p, requestID, ExportInput{Passphrase: passphrase, Selection: in.Remote.Selection})
	// Keep the randomly generated passphrase in the same protected job as its
	// frozen package; neither is returned by the task API.
	if err != nil {
		return PushTask{}, err
	}
	return s.createPush(ctx, p, requestID, key, hash, in, base, packet, passphrase)
}
func (s *Service) createPush(ctx context.Context, p auth.Principal, requestID, key, hash string, in PushInput, base string, packet Package, passphrase string) (PushTask, error) {
	now := time.Now().Unix()
	out := PushTask{ID: secure.ID(), State: "queued", Stage: "connecting", Mode: in.Mode, TargetURL: base, TargetNode: in.Remote.NodeID, PackageSHA256: packet.SHA256, CreatedAt: now, UpdatedAt: now, ExpiresAt: now + pushGrantSeconds}
	payload := pushPayload{Input: in, Transfer: ImportInput{Content: packet.Content, Passphrase: passphrase}, ResumeStage: "connecting"}
	raw, err := json.Marshal(payload)
	if err != nil {
		return out, err
	}
	if len(raw) > MaxRequestBytes-256 {
		return out, fault.Invalid("迁出暂存材料超过限制")
	}
	sealed := s.Vault.Seal(raw, "migration-push:"+out.ID)
	summary, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var count int
	var retained int64
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_pushes").Scan(&count); err != nil {
		return out, err
	}
	if count >= maxPushes {
		return out, fault.Conflict("迁出记录达到 64 项保留上限，须本机维护")
	}
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT COALESCE(SUM(length(payload)),0) FROM migration_plans)+(SELECT COALESCE(SUM(length(payload)),0) FROM migration_pushes)").Scan(&retained); err != nil {
		return out, err
	}
	if retained+int64(len(sealed))+256 > 128<<20 {
		return out, fault.Conflict("迁移暂存材料已达 128 MiB 保留配额")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'migration.push',?,'queued','connecting',?,?,?)", out.ID, base, out.ID, now, now); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO migration_pushes(task_id,principal,payload,summary,expires_at) VALUES(?,?,?,?,?)", out.ID, p.ID, sealed, s.Vault.Seal(summary, "migration-push-summary:"+out.ID), out.ExpiresAt); err != nil {
		return out, err
	}
	if err = s.pushReceipt(ctx, tx, p, key, hash, out); err != nil {
		return out, err
	}
	if err = pushAudit(ctx, tx, p.ID, requestID, out.ID, "migration.push", "queued"); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Service) resumePush(ctx context.Context, p auth.Principal, requestID, key, hash string, j *pushJob) (PushTask, error) {
	err := s.savePushWith(ctx, j, func(tx *sql.Tx) error {
		if err := s.pushReceipt(ctx, tx, p, key, hash, j.Task); err != nil {
			return err
		}
		return pushAudit(ctx, tx, p.ID, requestID, j.Task.ID, "migration.push.resume", "queued")
	})
	if err == errPushChanged {
		err = fault.Conflict("迁出任务状态已变化，请刷新后继续")
	}
	return j.Task, err
}
func (s *Service) ResumePush(ctx context.Context, p auth.Principal, requestID, key, id string, in PushResumeInput) (PushTask, error) {
	if err := pushPermission(p); err != nil {
		return PushTask{}, err
	}
	if !validPushKey(key) || !validTransferID(id) {
		return PushTask{}, fault.Invalid("迁移标识或幂等键无效")
	}
	raw, err := json.Marshal(struct {
		Action, ID string
		Input      PushResumeInput
	}{"migration.push.resume", id, in})
	if err != nil {
		return PushTask{}, err
	}
	hash := secure.Hash(raw)
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	if prior, found, e := s.pushPrior(ctx, p, key, hash); found || e != nil {
		return prior, e
	}
	j, err := s.readPush(ctx, id, true)
	if err != nil {
		return PushTask{}, err
	}
	if j.Owner != p.ID && !p.Has("auth.manage") {
		return PushTask{}, auth.ErrForbidden
	}
	if j.Task.State != "waiting_confirmation" && j.Task.State != "recovery_required" {
		return PushTask{}, fault.Conflict("任务当前不需要恢复")
	}
	updated := j.Payload.Input.Remote
	updated.APIKey = in.APIKey
	client, _, err := remoteClient(updated)
	if err != nil {
		return PushTask{}, err
	}
	client.CloseIdleConnections()
	if j.Payload.ResumeStage == "" {
		return PushTask{}, fault.Conflict("迁出恢复阶段缺失，须核对原任务")
	}
	j.Payload.Input.Remote = updated
	j.Task.State, j.Task.Stage, j.Task.Error = "queued", j.Payload.ResumeStage, ""
	j.Task.ExpiresAt = time.Now().Unix() + pushGrantSeconds
	j.NextAttempt, j.Attempts = 0, 0
	// savePush and the idempotency receipt are committed together below.
	return s.resumePush(ctx, p, requestID, key, hash, &j)
}
