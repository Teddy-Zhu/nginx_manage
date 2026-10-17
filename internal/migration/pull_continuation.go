package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// A pull continuation retains only the local, bounded grant. The source API key
// and archive passphrase are never needed again after the snapshot is captured.
type pullGrant struct {
	Execute      ExecuteInput    `json:"execute"`
	Dependencies DependencyInput `json:"dependencies"`
	Scopes       []string        `json:"scopes"`
}

type PullStatus struct {
	State    string `json:"state"`
	Stage    string `json:"stage"`
	Mode     string `json:"mode"`
	Error    string `json:"error"`
	Deadline int64  `json:"deadline"`
}

func (s *Service) authorizePull(in PullInput, p auth.Principal) (*pullGrant, error) {
	if in.Dependencies == nil {
		return nil, nil
	}
	if in.Mode == "preview" {
		return nil, fault.Invalid("预检模式不能授权组件准备或首次安装")
	}
	if err := in.Dependencies.validate(); err != nil {
		return nil, err
	}
	scopes := []string{"backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write", "components.manage"}
	if in.EnableNginx || in.Dependencies.Install != nil {
		scopes = append(scopes, "system.write")
	}
	if in.HostDNS.Mode == "map" {
		scopes = append(scopes, "host.dns.write")
	}
	if in.Monitoring.Mode == "replace" {
		scopes = append(scopes, "monitoring.write")
	}
	if in.Remote.Selection.Notifications {
		scopes = append(scopes, "notifications.write")
	}
	if err := p.Require(scopes...); err != nil {
		return nil, err
	}
	if s.Components == nil || in.Dependencies.Install != nil && (s.Installations == nil || s.Maintenance == nil) {
		return nil, fault.Unavailable("迁移依赖协调服务未配置")
	}
	return &pullGrant{Execute: ExecuteInput{Mode: in.Mode, EnableNginx: in.EnableNginx}, Dependencies: *in.Dependencies, Scopes: scopes}, nil
}

func (s *Service) createPullContinuation(ctx context.Context, tx *sql.Tx, plan *Plan, grant *pullGrant, owner, requestID string) error {
	raw, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	sealed := s.Vault.Seal(raw, "migration-pull:"+plan.ID)
	if len(sealed) > 16384 {
		return fault.Invalid("迁入授权超过保存上限")
	}
	var retained int64
	if err = tx.QueryRowContext(ctx, migrationRetainedSQL).Scan(&retained); err != nil {
		return err
	}
	if retained+int64(len(sealed)) > 128<<20 {
		return fault.Conflict("迁移暂存材料已达 128 MiB 保留配额")
	}
	_, err = tx.ExecContext(ctx, "UPDATE migration_pulls SET continuation=?,state='queued',stage='preparing_dependencies',mode=?,deadline=? WHERE plan_id=?", sealed, grant.Execute.Mode, plan.ExpiresAt, plan.ID)
	if err != nil {
		return err
	}
	plan.Pull = &PullStatus{State: "queued", Stage: "preparing_dependencies", Mode: grant.Execute.Mode, Deadline: plan.ExpiresAt}
	return pushAudit(ctx, tx, owner, requestID, plan.ID, "migration.pull.queued", "queued")
}

const migrationRetainedSQL = "SELECT (SELECT COALESCE(SUM(length(payload)),0) FROM migration_plans)+(SELECT COALESCE(SUM(length(payload)),0) FROM migration_pushes)+(SELECT COALESCE(SUM(length(continuation)),0) FROM migration_pulls)"

func (s *Service) pullStatus(ctx context.Context, id string) (*PullStatus, error) {
	var status PullStatus
	err := s.DB.QueryRowContext(ctx, "SELECT state,stage,mode,last_error,deadline FROM migration_pulls WHERE plan_id=? AND mode!=''", id).Scan(&status.State, &status.Stage, &status.Mode, &status.Error, &status.Deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (s *Service) openPullGrant(id, mode string, raw []byte) (pullGrant, error) {
	var grant pullGrant
	plain, err := s.Vault.Open(raw, "migration-pull:"+id)
	if err != nil {
		return grant, err
	}
	if decodeStrict(plain, &grant) != nil || grant.Execute.Mode != mode || mode != "draft" && mode != "save" && mode != "apply" || grant.Dependencies.validate() != nil {
		return grant, fault.Conflict("原迁入授权无法确认")
	}
	return grant, nil
}

func pullExecuteKey(owner, key string) string {
	return "migration-pull-" + secure.Hash([]byte(owner+":"+key))
}

// Ordinary execution cannot change a queued continuation's frozen intent.
func (s *Service) admitPullExecution(ctx context.Context, p auth.Principal, key, id string, in ExecuteInput) error {
	var owner, originalKey, mode, stage string
	var raw []byte
	err := s.DB.QueryRowContext(ctx, "SELECT principal,key,mode,continuation,stage FROM migration_pulls WHERE plan_id=? AND continuation IS NOT NULL", id).Scan(&owner, &originalKey, &mode, &raw, &stage)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	grant, err := s.openPullGrant(id, mode, raw)
	if err != nil {
		return err
	}
	if p.ID != owner || key != pullExecuteKey(owner, originalKey) || grant.Execute != in || stage != "executing" {
		return fault.Conflict("迁入任务已固定执行选项，请先核对原任务结果")
	}
	var deadline int64
	if err := s.DB.QueryRowContext(ctx, "SELECT deadline FROM migration_pulls WHERE plan_id=?", id).Scan(&deadline); err != nil {
		return err
	}
	if deadline <= time.Now().Unix() {
		return fault.Conflict("迁入授权已过期，停止新的配置提交")
	}
	return nil
}

func (s *Service) admitPullDependencies(ctx context.Context, p auth.Principal, id string, in DependencyInput) error {
	var owner, mode string
	var raw []byte
	err := s.DB.QueryRowContext(ctx, "SELECT principal,mode,continuation FROM migration_pulls WHERE plan_id=? AND continuation IS NOT NULL", id).Scan(&owner, &mode, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	grant, err := s.openPullGrant(id, mode, raw)
	if err != nil {
		return err
	}
	expected, err := dependencyDigest(id, grant.Dependencies)
	if err != nil {
		return err
	}
	actual, err := dependencyDigest(id, in)
	if err != nil {
		return err
	}
	if owner != p.ID || actual != expected {
		return fault.Conflict("原迁入任务已固定依赖准备和首次安装选项")
	}
	return nil
}
