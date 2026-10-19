package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (f *fail2banJailsExecutor) submitJails(ctx context.Context, in Fail2banJailsRequest) (Fail2banJailsOperation, error) {
	var out Fail2banJailsOperation
	normalized, err := in.Policy.Normalize()
	if err != nil {
		return out, err
	}
	in.Policy = normalized
	if !in.Valid() || !fail2banDigest.MatchString(in.Target) || in.OperationID == in.BaseID {
		return out, fault.Invalid("受管 jail 应用合同无效")
	}
	for _, j := range in.Policy.Jails {
		if j.Enabled && !(j.Action == "nginx-client" && j.Template != fail2ban.PanelLoginTemplate || j.Action == "host-input" && j.Template == fail2ban.PanelLoginTemplate) {
			return out, fault.Invalid("当前支持 Nginx 客户端动作及面板登录宿主机入口")
		}
	}
	hash := in.Hash()
	leave, err := f.lock(false)
	if err != nil {
		return out, err
	}
	defer leave()
	if old, e := f.journal().Get(in.OperationID); e == nil {
		if old.Kind != fail2banJailsKind || old.RequestHash != hash || old.Fail2banJails == nil {
			return out, fault.Conflict("受管 jail 操作 ID 冲突")
		}
		return fail2banJailsView(old), nil
	} else if !os.IsNotExist(e) {
		return out, e
	}
	records, err := f.journal().List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if pendingNginxRecord(record) {
			return out, ErrBusy
		}
	}
	// Persisting a new operation also shares admission with an offline root CLI.
	admit, err := f.journal().maintenanceLock()
	if err != nil {
		return out, err
	}
	defer admit()
	records, err = f.journal().List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" {
			return out, ErrBusy
		}
	}
	binding, err := selectFail2banBinding(f.server.DataDir)
	if err != nil || binding == nil || binding.managed == nil {
		return out, errors.New("jail 应用仅允许独立受管实例；已有实例保持只读")
	}
	r := binding.managed
	if r.ActionState != "completed" {
		return out, fault.Conflict("原受管实例操作尚未确认完成，不能应用 jail 配置")
	}
	if err = verifyFail2banManaged(ctx, r, true); err != nil {
		return out, err
	}
	beforeID, before, err := selectedFail2banJails(r)
	if err != nil {
		return out, err
	}
	if beforeID != in.BaseID {
		return out, fault.Conflict("受管 jail 配置基准已变化")
	}
	if err = verifyFail2banManagedLive(ctx, r); err != nil {
		return out, err
	}
	live, err := readFail2banLiveService(ctx, binding)
	if err != nil {
		return out, err
	}
	basis, m, host, nginxReason := f.basis(ctx, r)
	if in.Target != fail2ban.JailTarget(fail2banNginxEngineKey(binding), beforeID, basis.NginxDir, basis.NginxHash, basis.RegistryID, live.invocation, basis.HostHash) {
		return out, fault.Conflict("jail 目标实例、日志或动作批准已变化，请重新预览")
	}
	bundle := fail2banJailBundle{Schema: 1, ID: in.OperationID, InstallationID: r.OperationID, EngineKey: fail2banNginxEngineKey(binding), Policy: in.Policy, Sources: map[string]string{}, Proxies: map[string][]string{}, HostProtected: []string{}}
	needsNginx := fail2banJailNeedsNginx(before)
	old := map[string]fail2ban.DesiredJail{}
	if before != nil {
		for _, j := range before.Policy.Jails {
			if j.Enabled {
				old[j.ID] = j
			}
		}
	}
	for _, j := range in.Policy.Jails {
		if !j.Enabled {
			continue
		}
		if previous, ok := old[j.ID]; ok && (previous.ResourceID != j.ResourceID || previous.Template != j.Template || previous.Action != j.Action) {
			return out, fault.Invalid("同一 jail 标识不能转移站点、模板或动作")
		}
		if j.Template == fail2ban.PanelLoginTemplate {
			if !host.ready {
				return out, errors.New(host.reason)
			}
			if err = (panelLoginLog{server: f.server}).prepare(); err != nil {
				return out, err
			}
			bundle.Sources[j.ID] = fail2banPanelLoginPath
			bundle.HostProtectionID, bundle.HostProtected = host.protectionID, append([]string{}, host.protected...)
			continue
		}
		needsNginx = true
		if basis.NginxDir == "" || len(m.ClientDeny[j.ResourceID]) == 0 {
			return out, fault.Invalid("Nginx jail 须有已发布的客户端拒绝入口及可信代理配置")
		}
		matches := 0
		for _, source := range m.Logs {
			if source.Source.Active && source.Source.ResourceID == j.ResourceID && source.Source.Category == "http_access" && source.Source.Format == "nginxpanel_http" && source.Source.AuthPresence {
				matches++
				bundle.Sources[j.ID] = source.Path
			}
		}
		if matches != 1 {
			return out, fault.Invalid("jail 须引用唯一的当前受管 HTTP 日志")
		}
		bundle.Proxies[j.ResourceID] = append([]string{}, m.ClientDeny[j.ResourceID]...)
	}
	if needsNginx {
		if basis.NginxDir == "" {
			return out, errors.New(nginxReason)
		}
		bundle.NginxDir, bundle.NginxHash = basis.NginxDir, basis.NginxHash
	}
	intent := &fail2banJailIntent{Basis: basis, Nginx: needsNginx, InstallationID: r.OperationID, EngineKey: bundle.EngineKey, Target: in.Target, BeforeID: beforeID, AfterID: bundle.ID, Invocation: live.invocation, SocketInode: live.inode}
	if needsNginx {
		registry, e := loadFail2banNginxRegistry(f.server.DataDir)
		if e != nil {
			return out, e
		}
		if registry.ID != basis.RegistryID {
			return out, ErrExternalChange
		}
		grants, e := fail2banJailGrants(registry, before, &bundle)
		if e != nil {
			return out, e
		}
		now := time.Now().Unix()
		intent.BeforeRegistry = registry
		intent.AfterRegistry = fail2banNginxRegistry{Schema: 1, ID: in.OperationID, PreviousID: registry.ID, RequestHash: hash, ApprovedAt: now, Grants: grants}
		intent.RollbackRegistry = fail2banNginxRegistry{Schema: 1, ID: secure.ID(), PreviousID: in.OperationID, RequestHash: secure.Hash([]byte("fail2ban.jails.rollback:" + hash)), ApprovedAt: now, Grants: registry.Grants}
		if err = validFail2banNginxRegistry(intent.AfterRegistry, false); err != nil {
			return out, err
		}
		if _, err = os.Lstat(filepath.Join(fail2banNginxDir(f.server.DataDir), "grants", in.OperationID+".json")); err == nil {
			return out, fault.Conflict("操作 UUID 已用于动作批准")
		} else if !os.IsNotExist(err) {
			return out, err
		}
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = rememberFail2banJailIdentities(r, bundle.Policy); err != nil {
		return out, err
	}
	if err = saveFail2banJailBundle(r, bundle); err != nil {
		return out, err
	}
	record := Record{OperationID: in.OperationID, RequestHash: hash, Kind: fail2banJailsKind, State: "running", Stage: "queued", BeforeDir: bundle.NginxDir, AfterDir: bundle.NginxDir, Fail2banJails: intent}
	if needsNginx {
		record.BeforeRevision, record.AfterRevision = m.RevisionID, m.RevisionID
	}
	if err = f.persist(record); err != nil {
		return out, err
	}
	f.enqueue()
	return fail2banJailsView(record), nil
}

func fail2banJailGrants(registry fail2banNginxRegistry, before, after *fail2banJailBundle) ([]fail2banNginxGrant, error) {
	owned := map[string]fail2banNginxGrant{}
	if before != nil {
		for _, j := range before.Policy.Jails {
			if j.Enabled && j.Action == "nginx-client" {
				owned[fail2banJailNameFor(j.ID)] = fail2banNginxGrant{Jail: fail2banJailNameFor(j.ID), ResourceID: j.ResourceID, EngineKey: before.EngineKey}
			}
		}
	}
	grants := []fail2banNginxGrant{}
	for _, grant := range registry.Grants {
		if expected, ok := owned[grant.Jail]; ok {
			if expected != grant {
				return nil, ErrExternalChange
			}
			delete(owned, grant.Jail)
			continue
		}
		grants = append(grants, grant)
	}
	if len(owned) > 0 {
		return nil, errors.New("原受管 jail 的动作授权已被撤销，须先本机核对")
	}
	for _, j := range after.Policy.Jails {
		if !j.Enabled || j.Action != "nginx-client" {
			continue
		}
		name := fail2banJailNameFor(j.ID)
		for _, grant := range grants {
			if grant.Jail == name {
				return nil, errors.New("受管 jail 名称与独立 root 动作授权冲突")
			}
		}
		grants = append(grants, fail2banNginxGrant{Jail: name, ResourceID: j.ResourceID, EngineKey: after.EngineKey})
	}
	if len(grants) > 32 {
		return nil, fault.Invalid("合并后的 Nginx 动作授权超过 32 项")
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Jail < grants[j].Jail })
	return grants, nil
}

func fail2banJailBansPath(r *fail2banManagedRecord, id string) string {
	return filepath.Join(r.work(), "jail-bundles", id+".bans.json")
}

func rememberFail2banJailIdentities(r *fail2banManagedRecord, policy fail2ban.Policy) error {
	dir := filepath.Join(r.work(), "jail-identities")
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	for _, j := range policy.Jails {
		identity := struct{ ID, ResourceID, Template, Action string }{j.ID, j.ResourceID, j.Template, j.Action}
		raw, _ := json.Marshal(identity)
		if err := writeFail2banJailImmutable(filepath.Join(dir, j.ID+".json"), raw, 2048); err != nil {
			return errors.New("jail 标识已属于其他站点、模板或动作，或身份记录无法核对")
		}
	}
	return nil
}
