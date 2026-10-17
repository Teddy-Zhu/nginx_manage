package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"nginxpanel/internal/acme"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/notifications"
	"nginxpanel/internal/secure"
)

func (s *Service) Export(ctx context.Context, p auth.Principal, requestID string, in ExportInput) (Package, error) {
	if err := p.Require("backup.export"); err != nil {
		return Package{}, err
	}
	if err := validateExport(in); err != nil {
		return Package{}, err
	}
	if in.Mode == "encrypted" {
		if err := p.Require("backup.secrets", "config.secrets"); err != nil {
			return Package{}, err
		}
	}
	if !s.mu.TryLock() {
		return Package{}, fault.Conflict("已有迁移包正在处理")
	}
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Package{}, err
	}
	defer tx.Rollback()
	tree, err := s.Config.Snapshot(ctx, tx)
	if err != nil {
		return Package{}, err
	}
	payload := Payload{Files: tree.Files, Certificates: []Certificate{}, Credentials: []Credential{}, Channels: []notifications.TransferChannel{}, Automation: acme.TransferAutomation{Accounts: []acme.TransferAccount{}, Profiles: []acme.TransferProfile{}}}
	m := Manifest{Mode: in.Mode, Schema: Schema, SourceNode: s.NodeID, SourceVersion: s.Version, CreatedAt: time.Now().Unix(), Selection: in.Selection, Omissions: []string{"目标节点身份、管理员、机器授权、管理监听与 TLS 信任保留", "目标主机 DNS 运行配置、模块开关及日志轮转所有者保留；DNS 迁入材料须单独生成计划并确认", "目标防火墙内核运行规则、所有权与恢复状态保留，迁入规则须单独确认应用", "Fail2ban 实例、Socket、所有权与封禁状态保留，迁入 jail 须单独核对运行接入", "会话、任务、日志、指标历史、执行器信任及救援记录不迁移", "导入的通知渠道、自动续期与自动部署均停用，HTTP-01 公网确认须在目标重新完成"}}
	parsed, err := nginxconfig.Parse(tree.Files, s.Config.Policy)
	if err != nil {
		return Package{}, err
	}
	if in.Mode == "portable" {
		if len(parsed.Tree.Diagnostics) != 0 {
			return Package{}, fault.Invalid("源配置存在解析或安全冲突，请先检查原生配置")
		}
		var omitted []string
		payload.Files, omitted = parsed.PortableFiles()
		m.Omissions = append(m.Omissions, omitted...)
	}
	if in.Selection.Certificates {
		uses, err := parsed.CertificateUses()
		if err != nil {
			return Package{}, err
		}
		paths := []string{}
		for _, use := range uses {
			paths = append(paths, use.Path)
		}
		payload.Certificates, err = s.Config.Certificates.Export(ctx, tx, paths)
		if err != nil {
			return Package{}, err
		}
	} else {
		m.Omissions = append(m.Omissions, "证书材料未选择；目标须映射或补齐证书引用")
	}
	if in.Selection.DNSCredentials {
		payload.Credentials, err = s.ACME.ExportCredentials(ctx, tx)
		if err != nil {
			return Package{}, err
		}
	}
	if in.Selection.Automation {
		payload.Automation, err = s.ACME.ExportAutomation(ctx, tx)
		if err != nil {
			return Package{}, err
		}
	}
	if in.Selection.HostDNS {
		if s.HostDNS == nil {
			return Package{}, fault.Unavailable("主机 DNS 服务未配置")
		}
		payload.HostDNS, err = s.HostDNS.Export(ctx, tx)
		if err != nil {
			return Package{}, err
		}
	}
	if in.Selection.Monitoring {
		if s.Monitoring == nil {
			return Package{}, fault.Unavailable("监控配置服务未配置")
		}
		view, err := s.Monitoring.ReadSettings(ctx, tx)
		if err != nil {
			return Package{}, err
		}
		payload.Monitoring = &view.Settings
	} else {
		m.Omissions = append(m.Omissions, "未选择监控配置，目标设置保留")
	}
	if in.Selection.Fail2ban {
		if s.Fail2ban == nil {
			return Package{}, fault.Unavailable("jail 配置服务未配置")
		}
		payload.Fail2ban, err = s.Fail2ban.Export(ctx, tx)
		if err != nil {
			return Package{}, err
		}
	}
	if in.Selection.Firewall {
		if s.Firewall == nil {
			return Package{}, fault.Unavailable("防火墙策略服务未配置")
		}
		payload.Firewall, err = s.Firewall.Export(ctx, tx)
		if err != nil {
			return Package{}, err
		}
	} else {
		m.Omissions = append(m.Omissions, "未选择防火墙期望规则，目标策略保留")
	}
	if in.Selection.Notifications {
		payload.Channels, err = s.Notifications.ExportChannels(ctx, tx)
		if err != nil {
			return Package{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Package{}, err
	}
	content, err := encodeArchive(&m, payload, in.Passphrase)
	if err != nil {
		return Package{}, err
	}
	if _, err := s.DB.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'succeeded',?)", secure.ID(), requestID, p.ID, "migration.export."+in.Mode, s.NodeID, time.Now().Unix()); err != nil {
		return Package{}, err
	}
	extension := ".tar.age"
	if in.Mode == "portable" {
		extension = ".tar"
	}
	return Package{Filename: "nginxpanel-config-" + time.Now().UTC().Format("20060102T150405Z") + extension, Content: content, SHA256: secure.Hash(content), Manifest: m}, nil
}

func (s *Service) Prepare(ctx context.Context, p auth.Principal, requestID string, in ImportInput) (Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write"); err != nil {
		return Plan{}, err
	}
	if !s.mu.TryLock() {
		return Plan{}, fault.Conflict("已有迁移包正在处理")
	}
	defer s.mu.Unlock()
	m, payload, err := decodeArchive(in.Content, in.Passphrase)
	if err != nil {
		return Plan{}, err
	}
	return s.prepare(ctx, p, requestID, m, payload, in.BaseVersion, in.Mappings, in.Firewall, in.Fail2ban, in.Monitoring, in.HostDNS, nil, nil)
}

func (s *Service) prepare(ctx context.Context, p auth.Principal, requestID string, m Manifest, payload Payload, base int64, mappings map[string]string, firewallInput FirewallInput, fail2banInput Fail2banInput, monitoringInput MonitoringInput, hostDNSInput HostDNSInput, pull *pullReservation, receive *receiveReservation) (Plan, error) {
	if base < 0 || m.SourceNode == s.NodeID {
		return Plan{}, fault.Invalid("基础版本无效或来源为当前节点")
	}
	if err := certificates.ValidateTransfer(payload.Certificates); err != nil {
		return Plan{}, err
	}
	if err := acme.ValidateTransferCredentials(payload.Credentials); err != nil {
		return Plan{}, err
	}
	if m.Omissions == nil {
		m.Omissions = []string{}
	}
	st := storedPlan{Plan: Plan{Mode: m.Mode, ID: secure.ID(), SourceNode: m.SourceNode, SourceVersion: m.SourceVersion, BaseVersion: base, ExpiresAt: time.Now().Add(30 * time.Minute).Unix(), State: "planned", Steps: []Step{}, Omissions: m.Omissions}, Payload: payload, Manifest: m, Mappings: mappings, CertificateIDs: map[string]string{}, VersionIDs: map[string]string{}, CredentialIDs: map[string]string{}}
	if receive != nil {
		st.Plan.ID = receive.ID
		st.Plan.PackageSHA256 = receive.PackageSHA256
	}
	if hostDNSInput.Mode == "map" {
		if err := p.Require("host.dns.write"); err != nil {
			return Plan{}, err
		}
	}
	if err := prepareHostDNS(&st, hostDNSInput); err != nil {
		return Plan{}, err
	}
	if monitoringInput.Mode == "replace" {
		if err := p.Require("monitoring.write"); err != nil {
			return Plan{}, err
		}
	}
	if err := s.prepareMonitoring(ctx, &st, monitoringInput); err != nil {
		return Plan{}, err
	}
	if err := s.prepareFail2ban(ctx, &st, fail2banInput); err != nil {
		return Plan{}, err
	}
	if err := s.prepareFirewall(ctx, &st, firewallInput); err != nil {
		return Plan{}, err
	}
	for _, c := range payload.Certificates {
		if st.CertificateIDs[c.Material.CertificateID] == "" {
			st.CertificateIDs[c.Material.CertificateID] = secure.ID()
		}
		st.VersionIDs[c.Material.VersionID] = secure.ID()
	}
	for _, c := range payload.Credentials {
		st.CredentialIDs[c.ID] = secure.ID()
	}
	if err := acme.ValidateTransferAutomation(payload.Automation, payload.Credentials, st.CertificateIDs); err != nil {
		return Plan{}, err
	}
	if err := notifications.ValidateTransferChannels(payload.Channels); err != nil {
		return Plan{}, err
	}
	files, err := nginxconfig.MigrationFiles(payload.Files, s.Config.Policy, mappings, st.CertificateIDs, st.VersionIDs)
	if err != nil {
		return Plan{}, fault.Invalid(err.Error())
	}
	st.Payload.Files = files
	if err := s.inspect(ctx, &st); err != nil {
		return Plan{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Plan{}, err
	}
	defer tx.Rollback()
	var version int64
	var basis, applied sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT version,desired_revision,applied_revision FROM config_head WHERE id=1").Scan(&version, &basis, &applied); err != nil {
		return Plan{}, err
	}
	if err := s.checkMonitoringBase(ctx, tx, &st); err != nil {
		return Plan{}, err
	}
	if err := s.checkFail2banBase(ctx, tx, &st); err != nil {
		return Plan{}, err
	}
	if err := s.checkFirewallBase(ctx, tx, &st); err != nil {
		return Plan{}, err
	}
	if version != base {
		return Plan{}, nginxconfig.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "UPDATE migration_plans SET state='failed',last_error='计划已过期，未执行迁入',updated_at=? WHERE state='planned' AND expires_at<?", time.Now().Unix(), time.Now().Unix()); err != nil {
		return Plan{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_plans WHERE state='planned'").Scan(&count); err != nil {
		return Plan{}, err
	}
	if count >= 8 {
		return Plan{}, fault.Conflict("待执行迁移计划已达 8 个")
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_plans").Scan(&count); err != nil {
		return Plan{}, err
	}
	if count >= 128 {
		return Plan{}, fault.Conflict("迁移记录已达保留上限，须先进行历史维护")
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return Plan{}, err
	}
	summary, err := encodeSummary(st.Plan)
	if err != nil {
		return Plan{}, err
	}
	if len(raw) > MaxRequestBytes-256 {
		return Plan{}, fault.Invalid("迁移计划内容超过暂存上限")
	}
	var retained int64
	if err := tx.QueryRowContext(ctx, migrationRetainedSQL).Scan(&retained); err != nil {
		return Plan{}, err
	}
	if retained+int64(len(raw))+256 > 128<<20 {
		return Plan{}, fault.Conflict("迁移暂存材料已达 128 MiB 保留配额，须先进行历史维护")
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "INSERT INTO migration_plans(id,principal,payload,summary,state,basis_revision,basis_version,basis_applied,expires_at,created_at,updated_at) VALUES(?,?,?,?,'planned',?,?,?,?,?,?)", st.Plan.ID, p.ID, s.Vault.Seal(raw, "migration:"+st.Plan.ID), s.Vault.Seal(summary, "migration-summary:"+st.Plan.ID), basis.String, base, applied.String, st.Plan.ExpiresAt, now, now); err != nil {
		return Plan{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'planned',?)", secure.ID(), requestID, p.ID, "migration.prepare", st.Plan.ID, now); err != nil {
		return Plan{}, err
	}
	if pull != nil {
		if _, err := tx.ExecContext(ctx, "INSERT INTO migration_pulls(principal,key,request_hash,plan_id,created_at) VALUES(?,?,?,?,?)", pull.Principal, pull.Key, pull.Digest, st.Plan.ID, now); err != nil {
			return Plan{}, err
		}
		if pull.Grant != nil {
			if err := s.createPullContinuation(ctx, tx, &st.Plan, pull.Grant, pull.Principal, requestID); err != nil {
				return Plan{}, err
			}
		}
	}
	if receive != nil {
		if _, err := tx.ExecContext(ctx, "INSERT INTO migration_receives(plan_id,request_hash) VALUES(?,?)", receive.ID, receive.Digest); err != nil {
			return Plan{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Plan{}, err
	}
	return st.Plan, nil
}

func (s *Service) inspect(ctx context.Context, st *storedPlan) error {
	plan := &st.Plan
	plan.Steps = []Step{}
	plan.CanSave = true
	plan.CanApply = true
	stepCount := 0
	blocking := func(state string) bool { return state == "blocked" || state == "unavailable" }
	add := func(kind, resource, state, message string) {
		stepCount++
		if len(message) > 1024 {
			runes := []rune(message)
			message = string(runes[:min(256, len(runes))]) + "…"
		}
		step := Step{kind, resource, state, message}
		if blocking(state) {
			plan.CanSave = false
			plan.CanApply = false
			// Missing prerequisites must not disappear behind the resource inventory.
			at := 0
			for at < len(plan.Steps) && blocking(plan.Steps[at].State) {
				at++
			}
			if at < 128 {
				if len(plan.Steps) < 128 {
					plan.Steps = append(plan.Steps, Step{})
				}
				copy(plan.Steps[at+1:], plan.Steps[at:len(plan.Steps)-1])
				plan.Steps[at] = step
			}
		} else if len(plan.Steps) < 128 {
			plan.Steps = append(plan.Steps, step)
		}
	}
	if err := s.inspectHostDNS(ctx, st, add); err != nil {
		return err
	}
	if err := s.inspectMonitoring(ctx, st, add); err != nil {
		return err
	}
	if err := s.inspectFail2ban(ctx, st, add); err != nil {
		return err
	}
	if err := s.inspectFirewall(ctx, st, add); err != nil {
		return err
	}
	parsed, err := nginxconfig.Parse(st.Payload.Files, s.Config.Policy)
	if err != nil {
		return err
	}
	for _, d := range parsed.Tree.Diagnostics {
		add("configuration", d.FileID, "blocked", fmt.Sprintf("第 %d 行：%s", d.Line, d.Message))
	}
	uses, err := parsed.CertificateUses()
	if err != nil {
		add("certificate", "references", "blocked", "无法解析证书引用")
	}
	materials := []certificates.Material{}
	provided := map[string]bool{}
	for _, c := range st.Payload.Certificates {
		m := c.Material
		m.CertificateID = st.CertificateIDs[m.CertificateID]
		m.VersionID = st.VersionIDs[m.VersionID]
		materials = append(materials, m)
		provided[m.VersionID] = true
	}
	paths := []string{}
	for _, use := range uses {
		_, version, _, ok := certificates.Reference(use.Path)
		if ok && !provided[version] {
			paths = append(paths, use.Path)
		}
	}
	for _, name := range parsed.MigrationLocalDependencies() {
		add("mapping", name, "blocked", "本机信任证书须映射为目标受管证书，或在草稿中改为目标系统信任")
	}
	if len(paths) > 0 {
		existing, e := s.Config.Certificates.Materials(ctx, s.DB, paths)
		if e != nil {
			add("certificate", "materials", "blocked", "目标缺少已引用的证书材料，请包含证书导出或映射目标证书")
		} else {
			materials = append(materials, existing...)
		}
	}
	if len(parsed.Tree.Diagnostics) == 0 {
		if err := parsed.ValidateTLS(materials); err != nil {
			add("certificate", "tls", "blocked", err.Error())
		}
	}
	for _, r := range parsed.Tree.Resources {
		for name, field := range r.Fields {
			if name == "listeners" || name == "upstream" || name == "upstream_servers" || name == "domains" {
				for _, value := range field.Values {
					add("review", r.ID+":"+name, "review", value)
				}
			}
		}
	}
	if err := s.DB.QueryRowContext(ctx, "SELECT enabled,version FROM module_settings WHERE id='nginx-config'").Scan(&plan.NginxEnabled, &st.ModuleVersion); err != nil {
		return err
	}
	if !plan.NginxEnabled {
		add("enable", "nginx-config", "authorization", "需要本次授权启用 Nginx 配置模块")
	}
	if s.Agent == nil {
		add("component", "nginx", "unavailable", "目标执行器未连接，需安装并接入受管 Nginx 实例及本机 Agent")
	} else {
		features, e := s.Agent.NginxFeatures(ctx)
		if e != nil {
			features.Available = false
		}
		runtime, e := s.Agent.NginxState(ctx)
		if e != nil {
			runtime.Available = false
		}
		for _, step := range InspectNginxTarget(parsed, features, runtime) {
			add(step.Kind, step.Resource, step.State, step.Message)
		}
	}
	var version int64
	var desired, applied sql.NullString
	if err := s.DB.QueryRowContext(ctx, "SELECT version,desired_revision,applied_revision FROM config_head WHERE id=1").Scan(&version, &desired, &applied); err != nil {
		return err
	}
	if version != plan.BaseVersion {
		return nginxconfig.ErrConflict
	}
	if desired.String != applied.String {
		add("configuration", "target", "unavailable", "目标有待应用修订，须先处理后再执行迁移应用")
	}
	var certificateCount, credentialCount, channelCount, profileCount int
	if err := s.DB.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM certificates),(SELECT COUNT(*) FROM dns_credentials),(SELECT COUNT(*) FROM notification_channels),(SELECT COUNT(*) FROM acme_profiles WHERE state!='archived')").Scan(&certificateCount, &credentialCount, &channelCount, &profileCount); err != nil {
		return err
	}
	for _, capacity := range []struct {
		name                string
		current, added, max int
	}{{"certificates", certificateCount, len(st.CertificateIDs), limits.Certificates}, {"dns-credentials", credentialCount, len(st.CredentialIDs), limits.DNSCredentials}, {"notifications", channelCount, len(st.Payload.Channels), notifications.MaxChannels}, {"acme-profiles", profileCount, len(st.Payload.Automation.Profiles), limits.Certificates}} {
		if capacity.current+capacity.added > capacity.max {
			add("capacity", capacity.name, "blocked", "目标资源保留容量不足")
		}
	}
	add("restore", "nginx-tree", "ready", "替换目标 Nginx 业务配置；保留原修订用于补偿")
	add("restore", "certificates", "ready", fmt.Sprintf("新增 %d 个证书资源、%d 个不可变版本", len(st.CertificateIDs), len(st.VersionIDs)))
	add("restore", "dns-credentials", "ready", fmt.Sprintf("新增 %d 个 DNS 凭据，使用目标主密钥重新加密", len(st.CredentialIDs)))
	add("restore", "acme", "ready", fmt.Sprintf("恢复 %d 个 ACME 账户和 %d 个签发配置；自动续期及部署停用，HTTP-01 须重新确认", len(st.Payload.Automation.Accounts), len(st.Payload.Automation.Profiles)))
	add("restore", "notifications", "ready", fmt.Sprintf("恢复 %d 个通知渠道，全部保持停用", len(st.Payload.Channels)))
	if stepCount > 128 {
		plan.Steps = append(plan.Steps, Step{"preview", "remaining", "review", fmt.Sprintf("预检共 %d 项，优先展示阻塞项，最多展示 128 项；全部项目均参与准入判断", stepCount)})
	}
	return nil
}

func (s *Service) load(ctx context.Context, p auth.Principal, id string) (storedPlan, error) {
	var raw []byte
	var owner string
	var st storedPlan
	var state, revision, task, lastError string
	err := s.DB.QueryRowContext(ctx, "SELECT principal,payload,state,revision_id,task_id,last_error FROM migration_plans WHERE id=?", id).Scan(&owner, &raw, &state, &revision, &task, &lastError)
	if errors.Is(err, sql.ErrNoRows) {
		return st, fault.NotFound("迁移计划不存在")
	}
	if err != nil {
		return st, err
	}
	if owner != p.ID && !p.Has("auth.manage") {
		return st, auth.ErrForbidden
	}
	plain, err := s.Vault.Open(raw, "migration:"+id)
	if err != nil {
		return st, err
	}
	if err := decodeStrict(plain, &st); err != nil {
		return st, err
	}
	if err := prepareHostDNS(&st, st.HostDNS); err != nil {
		return st, fault.Unavailable("主机 DNS 迁移材料无效，须重新准备")
	}
	if st.Manifest.Selection.HostDNS != (st.Payload.HostDNS != nil) {
		return st, fault.Unavailable("主机 DNS 迁移范围与材料不一致")
	}
	if st.Payload.HostDNS != nil && st.Plan.HostDNS == nil {
		return st, fault.Unavailable("主机 DNS 迁移摘要缺失")
	}
	if st.Manifest.Schema != Schema || st.Manifest.Mode != st.Plan.Mode || (st.Manifest.Mode != "portable" && st.Manifest.Mode != "encrypted") || st.Monitoring != nil && (st.Plan.Monitoring == nil || st.Payload.Monitoring == nil) || st.Fail2ban != nil && (st.Plan.Fail2ban == nil || st.Payload.Fail2ban == nil) || st.Firewall != nil && (st.Plan.Firewall == nil || st.Payload.Firewall == nil) {
		return st, fault.Unavailable("迁移计划格式或配置恢复材料无效，须重新准备或由本机检查")
	}
	st.Plan.State = state
	st.Plan.RevisionID = revision
	st.Plan.TaskID = task
	st.Plan.LastError = lastError
	reflectHostDNSState(&st.Plan)
	return st, nil
}
func (s *Service) Get(ctx context.Context, p auth.Principal, id string) (Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets"); err != nil {
		return Plan{}, err
	}
	var owner string
	var raw []byte
	var plan Plan
	var state, revision, task, lastError string
	err := s.DB.QueryRowContext(ctx, "SELECT principal,summary,state,revision_id,task_id,last_error FROM migration_plans WHERE id=?", id).Scan(&owner, &raw, &state, &revision, &task, &lastError)
	if errors.Is(err, sql.ErrNoRows) {
		return plan, fault.NotFound("迁移计划不存在")
	}
	if err != nil {
		return plan, err
	}
	if owner != p.ID && !p.Has("auth.manage") {
		return plan, auth.ErrForbidden
	}
	plain, err := s.Vault.Open(raw, "migration-summary:"+id)
	if err != nil {
		return plan, err
	}
	if err := decodeStrict(plain, &plan); err != nil {
		return plan, err
	}
	plan.State = state
	plan.RevisionID = revision
	plan.TaskID = task
	plan.LastError = lastError
	if plan.Monitoring != nil && plan.Monitoring.Mode != "preserve" {
		if state == "rolled_back" {
			plan.Monitoring.State = "restored"
		}
		if state == "recovery_required" {
			plan.Monitoring.State = "recovery_required"
		}
	}
	if plan.Fail2ban != nil && plan.Fail2ban.Mode != "preserve" {
		if state == "rolled_back" {
			plan.Fail2ban.State = "restored"
		}
		if state == "recovery_required" {
			plan.Fail2ban.State = "recovery_required"
		}
	}
	if plan.Firewall != nil && plan.Firewall.Mode != "preserve" {
		if state == "rolled_back" {
			plan.Firewall.State = "restored"
		}
		if state == "recovery_required" {
			plan.Firewall.State = "recovery_required"
		}
	}
	reflectHostDNSState(&plan)
	plan.Dependencies, err = s.dependencyStatus(ctx, id)
	if err == nil {
		plan.Pull, err = s.pullStatus(ctx, id)
	}
	return plan, err
}
func (s *Service) List(ctx context.Context, p auth.Principal) ([]Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT id FROM migration_plans WHERE principal=? OR ? ORDER BY created_at DESC,id LIMIT 30", p.ID, p.Has("auth.manage"))
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []Plan{}
	for _, id := range ids {
		plan, err := s.Get(ctx, p, id)
		if err != nil {
			return nil, err
		}
		plan.Steps = []Step{}
		plan.Omissions = []string{}
		plan.Firewall = nil
		plan.Fail2ban = nil
		plan.Monitoring = nil
		plan.HostDNS = nil
		out = append(out, plan)
	}
	return out, nil
}

func (s *Service) Execute(ctx context.Context, p auth.Principal, requestID, key, id string, in ExecuteInput) (Plan, error) {
	if !s.mu.TryLock() {
		return Plan{}, fault.Conflict("已有迁移正在处理")
	}
	defer s.mu.Unlock()
	return s.execute(ctx, p, requestID, key, id, in)
}

// The caller holds the migration coordinator lock.
func (s *Service) execute(ctx context.Context, p auth.Principal, requestID, key, id string, in ExecuteInput) (Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write"); err != nil {
		return Plan{}, err
	}
	if in.Mode != "draft" && in.Mode != "save" && in.Mode != "apply" {
		return Plan{}, fault.Invalid("迁移模式须为 draft、save 或 apply")
	}
	if in.EnableNginx {
		if err := p.Require("system.write"); err != nil {
			return Plan{}, err
		}
	}
	if err := s.admitPullExecution(ctx, p, key, id, in); err != nil {
		return Plan{}, err
	}
	st, err := s.load(ctx, p, id)
	if err != nil {
		return Plan{}, err
	}
	d, err := s.dependencyStatus(ctx, id)
	if err != nil {
		return Plan{}, err
	}
	if d != nil && (d.State == "queued" || d.State == "running" || d.State == "recovery_required") {
		return Plan{}, s.migrationBlocked(ctx, "依赖准备尚未结束或结果需要恢复，请先核对原任务", st.Plan)
	}
	if st.Plan.State == "failed" {
		return Plan{}, fault.Conflict("迁移计划已过期或结束，请重新预检")
	}
	if st.HostDNS.Mode == "map" {
		if err := p.Require("host.dns.write"); err != nil {
			return Plan{}, err
		}
	}
	if st.Monitoring != nil {
		if err := p.Require("monitoring.write"); err != nil {
			return Plan{}, err
		}
	}
	if len(st.Payload.Channels) > 0 {
		if err := p.Require("notifications.write"); err != nil {
			return Plan{}, err
		}
	}
	if st.Plan.State == "planned" {
		if time.Now().Unix() >= st.Plan.ExpiresAt {
			return Plan{}, fault.Conflict("迁移计划已过期，请重新预检")
		}
		if err := s.inspect(ctx, &st); err != nil {
			return Plan{}, err
		}
		if in.Mode != "draft" && (!st.Plan.CanSave || !st.Plan.NginxEnabled && !in.EnableNginx) {
			return Plan{}, s.migrationBlocked(ctx, "配置冲突未解决或未授权启用所需模块", st.Plan)
		}
		if in.Mode == "apply" && !st.Plan.CanApply {
			return Plan{}, s.migrationBlocked(ctx, "目标依赖、镜像能力或运行条件不满足，不能应用", st.Plan)
		}
	}
	if st.Firewall != nil && !st.Firewall.Resolved {
		return Plan{}, s.migrationBlocked(ctx, "防火墙网卡映射未完成，请重新准备迁移计划", st.Plan)
	}
	request := nginxconfig.SaveRequest{BaseVersion: st.Plan.BaseVersion, Files: st.Payload.Files, Draft: in.Mode == "draft", Apply: in.Mode == "apply"}
	_, err = s.Config.SaveImported(ctx, p, requestID, key, id+":"+in.Mode+":"+fmt.Sprint(in.EnableNginx), request, func(tx *sql.Tx) error {
		var state string
		if err := tx.QueryRowContext(ctx, "SELECT state FROM migration_plans WHERE id=?", id).Scan(&state); err != nil {
			return err
		}
		if state != "planned" {
			return fault.Conflict("迁移计划已执行")
		}
		var pending int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_plans WHERE state IN ('applying','recovery_required')").Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return fault.Conflict("已有迁移等待完成或恢复")
		}
		var version int64
		var basis, applied sql.NullString
		if err := tx.QueryRowContext(ctx, "SELECT version,desired_revision,applied_revision FROM config_head WHERE id=1").Scan(&version, &basis, &applied); err != nil {
			return err
		}
		if version != st.Plan.BaseVersion {
			return nginxconfig.ErrConflict
		}
		if in.Mode == "apply" && basis.String != applied.String {
			return fault.Conflict("目标仍有待应用配置，须先处理")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE migration_plans SET basis_revision=?,basis_applied=? WHERE id=? AND state='planned'", basis.String, applied.String, id); err != nil {
			return err
		}
		if in.EnableNginx && !st.Plan.NginxEnabled {
			result, err := tx.ExecContext(ctx, "UPDATE module_settings SET enabled=1,version=version+1 WHERE id='nginx-config' AND version=? AND enabled=0", st.ModuleVersion)
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return fault.Conflict("模块状态已变化，请重新预检")
			}
			st.EnabledByMigration = true
		}
		if in.Mode == "draft" {
			var enabled bool
			if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
				return err
			}
			if !enabled {
				return fault.Conflict("须启用 Nginx 配置模块才能保存草稿")
			}
		}
		if err := s.Config.Certificates.Import(ctx, tx, st.Payload.Certificates, st.CertificateIDs, st.VersionIDs); err != nil {
			return err
		}
		if err := s.ACME.ImportCredentials(ctx, tx, st.Payload.Credentials, st.CredentialIDs); err != nil {
			return err
		}
		if err := s.ACME.ImportAutomation(ctx, tx, st.Payload.Automation, st.Payload.Credentials, st.CertificateIDs, st.CredentialIDs); err != nil {
			return err
		}
		if err := s.Notifications.ImportChannels(ctx, tx, st.Payload.Channels); err != nil {
			return err
		}
		if err := s.importMonitoring(ctx, tx, &st, p.ID, requestID, in.Mode == "draft"); err != nil {
			return err
		}
		if err := s.importFail2ban(ctx, tx, &st, p.ID, requestID); err != nil {
			return err
		}
		return s.importFirewall(ctx, tx, &st, p.ID, requestID)
	}, func(tx *sql.Tx, result nginxconfig.SaveResult) error {
		state := "saved"
		if in.Mode == "draft" {
			state = "draft"
		}
		if in.Mode == "apply" {
			state = "applying"
		}
		st.Plan.State = state
		reflectHostDNSState(&st.Plan)
		st.Plan.RevisionID = result.Tree.RevisionID
		st.Plan.TaskID = result.TaskID
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		var retained int64
		if err := tx.QueryRowContext(ctx, "SELECT (SELECT COALESCE(SUM(length(payload)),0) FROM migration_plans WHERE id!=?)+(SELECT COALESCE(SUM(length(payload)),0) FROM migration_pushes)+(SELECT COALESCE(SUM(length(continuation)),0) FROM migration_pulls)", id).Scan(&retained); err != nil {
			return err
		}
		if len(raw) > MaxRequestBytes-256 || retained+int64(len(raw))+256 > 128<<20 {
			return fault.Conflict("迁移暂存材料超过保留配额，须先进行历史维护")
		}
		summary, err := encodeSummary(st.Plan)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE migration_plans SET state=?,revision_id=?,task_id=?,payload=?,summary=?,updated_at=? WHERE id=? AND state='planned'", state, result.Tree.RevisionID, result.TaskID, s.Vault.Seal(raw, "migration:"+id), s.Vault.Seal(summary, "migration-summary:"+id), time.Now().Unix(), id)
		return err
	})
	if err != nil {
		return Plan{}, err
	}
	if st.Monitoring != nil && in.Mode != "draft" {
		s.Monitoring.Wake()
	}
	return s.Get(ctx, p, id)
}

func encodeSummary(plan Plan) ([]byte, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	if len(raw) > 262144-8192 {
		return nil, fault.Invalid("迁移预览超过大小限制，请减少导出范围")
	}
	return raw, nil
}

func blockedPlan(message string, plan Plan) error {
	err := fault.New(409, "MIGRATION_BLOCKED", message)
	err.Data = plan
	return err
}

func redactedRemoteError() error {
	return fault.Unavailable("无法连接源节点或源节点拒绝导出，请检查 API 地址、TLS 信任和 Key 授权")
}
