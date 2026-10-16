package modules

import (
	"context"
	"database/sql"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
)

type Definition struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Available    bool     `json:"available"`
	Enabled      bool     `json:"enabled"`
	Dependencies []string `json:"dependencies"`
	Reason       string   `json:"reason,omitempty"`
}

var definitions = []Definition{
	{ID: "nginx-config", Name: "Nginx 配置", Available: true, Enabled: true, Dependencies: []string{}},
	{ID: "firewall", Name: "防火墙", Available: true, Dependencies: []string{}},
	{ID: "host-dns", Name: "主机 DNS", Available: true, Dependencies: []string{}},
	{ID: "monitoring", Name: "基础监控", Available: true, Dependencies: []string{}},
	{ID: "fail2ban", Name: "Fail2ban", Dependencies: []string{"firewall"}, Reason: "当前版本暂不提供 Fail2ban 管理"},
	{ID: "notifications", Name: "外部通知", Available: true, Dependencies: []string{}},
	{ID: "automatic-backups", Name: "定期备份", Available: true, Dependencies: []string{}},
}

func Init(ctx context.Context, db *sql.DB) error {
	for _, m := range definitions {
		if _, err := db.ExecContext(ctx, "INSERT INTO module_settings(id,enabled) VALUES(?,?) ON CONFLICT(id) DO NOTHING", m.ID, m.Enabled); err != nil {
			return err
		}
	}
	return nil
}
func List(ctx context.Context, db *sql.DB) ([]Definition, error) {
	result := append([]Definition(nil), definitions...)
	for i := range result {
		if err := db.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id=?", result[i].ID).Scan(&result[i].Enabled); err != nil {
			return nil, err
		}
	}
	return result, nil
}
func Set(ctx context.Context, db *sql.DB, p auth.Principal, id string, enabled bool) error {
	if err := p.Require("system.write"); err != nil {
		return err
	}
	var target *Definition
	for i := range definitions {
		if definitions[i].ID == id {
			target = &definitions[i]
			break
		}
	}
	if target == nil {
		return fault.Invalid("未知模块")
	}
	if enabled && !target.Available {
		return fault.Unavailable(target.Reason)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if id == "automatic-backups" && enabled {
		if err = p.Require("backup.export", "backup.secrets"); err != nil {
			return err
		}
		var approved bool
		if err = tx.QueryRowContext(ctx, "SELECT recipient<>'' AND key_saved_at>0 AND authorization_until>? AND principal<>'' FROM backup_policy WHERE id=1", time.Now().Unix()).Scan(&approved); err != nil {
			return err
		}
		if !approved {
			return fault.Conflict("请在备份设置中确认恢复公钥及定期备份授权")
		}
	}
	if id == "nginx-config" {
		var pending int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_plans WHERE state IN ('applying','recovery_required')").Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return fault.Conflict("迁移正在应用或等待恢复，暂不能修改 Nginx 模块状态")
		}
	}
	// Passive sampling and notification delivery own no protection rules.
	if !enabled && id != "monitoring" && id != "notifications" && id != "automatic-backups" {
		var pending int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running','waiting_confirmation','compensating','recovery_required')").Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return fault.Conflict("有在途任务，不能停用模块")
		}
	}
	for _, dep := range target.Dependencies {
		var active bool
		if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id=?", dep).Scan(&active); err != nil {
			return err
		}
		if enabled && !active {
			return fault.Conflict("须先启用依赖模块：" + dep)
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE module_settings SET enabled=?,version=version+1 WHERE id=?", enabled, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}
