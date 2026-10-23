package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"nginxpanel/internal/panelruntime"
)

// CheckInstallationRemoval only inspects state. Host protections must be
// released through their owners before removing the executors and recovery data.
func CheckInstallationRemoval(ctx context.Context, data string) error {
	if os.Geteuid() != 0 {
		return errors.New("卸载检查需要本机 root")
	}
	if _, err := panelruntime.ReadDeployment(data); err != nil {
		return err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	var records []Record
	if _, err := os.Lstat(j.Dir); err == nil {
		var err error
		records, err = (&maintenanceGate{journal: j}).rawRecords()
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, r := range records {
		switch r.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		default:
			return fmt.Errorf("操作 %s（%s / %s）尚未结束，请沿原任务完成或恢复后卸载", r.OperationID, r.Kind, r.State)
		}
	}
	// Open the existing database without migration, initialization or task writes.
	name := filepath.Join(data, "app", "panel.db")
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("业务数据库不是普通文件，停止卸载")
	}
	dsn := (&url.URL{Scheme: "file", Path: name}).String() + "?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	var pending int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running','waiting_confirmation','compensating','recovery_required')").Scan(&pending); err != nil {
		return err
	}
	if pending != 0 {
		return fmt.Errorf("仍有 %d 个未结束或待恢复的业务任务，请先处理后卸载", pending)
	}
	checks := []struct {
		name string
		read func() (bool, error)
	}{
		{"nftables 登记（firewall-remove）", func() (bool, error) {
			r, e := loadNFTRegistration(data)
			return r != nil && r.State != "released", e
		}},
		{"firewalld 登记（firewalld-remove）", func() (bool, error) {
			r, e := loadFirewalldRegistration(data)
			return r != nil && r.State != "released", e
		}},
		{"UFW 登记（ufw-remove）", func() (bool, error) {
			r, e := loadUFWRegistration(data)
			return r != nil && r.State != "released", e
		}},
		{"iptables 登记（iptables-remove）", func() (bool, error) {
			r, e := loadIPTablesRegistration(data)
			return r != nil && r.State != "released", e
		}},
		{"Docker 防火墙登记（docker-firewall-remove）", func() (bool, error) {
			r, e := loadDockerRegistration(data)
			return r != nil && r.State != "released", e
		}},
		{"Fail2ban 宿主机持续同步（fail2ban-host-sync-disable）", func() (bool, error) {
			r, e := loadFail2banHostSync(data)
			return r != nil && r.Action == "enable", e
		}},
	}
	for _, check := range checks {
		active, err := check.read()
		if err != nil {
			return fmt.Errorf("无法核对 %s：%w", check.name, err)
		}
		if active {
			return fmt.Errorf("请先通过原模块解除 %s，避免删除仍需维护的主机规则", check.name)
		}
	}
	// Existing jails use files outside the data directory and belong to another
	// service. Refuse to remove their receipts while an overlay is still present.
	overlays, err := filepath.Glob("/etc/fail2ban/jail.d/zzzz-nginxpanel-existing-*.local")
	if err != nil {
		return err
	}
	if len(overlays) != 0 {
		return errors.New("仍有本应用接管的外部 Fail2ban jail，请先通过 fail2ban-existing-jail-release 解除接管")
	}
	return nil
}
