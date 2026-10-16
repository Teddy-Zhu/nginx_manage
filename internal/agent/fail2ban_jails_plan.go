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

func (f *fail2banNginxExecutor) submitJails(ctx context.Context, in Fail2banJailsRequest) (Fail2banJailsOperation, error) {
	var out Fail2banJailsOperation
	normalized, err := in.Policy.Normalize()
	if err != nil {
		return out, err
	}
	in.Policy = normalized
	if in.Protocol != Protocol || !validID(in.OperationID) || in.OperationID == in.BaseID || in.BaseID != "" && !validID(in.BaseID) {
		return out, fault.Invalid("受管 jail 应用合同无效")
	}
	raw, _ := json.Marshal(in)
	hash := secure.Hash(raw)
	n := f.nginx
	leave, ok := n.maintenance.enter(false)
	if !ok {
		return out, ErrBusy
	}
	defer leave()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.unlock == nil {
		return out, ErrRuntimeUnavailable
	}
	if old, e := n.Journal.Get(in.OperationID); e == nil {
		if old.Kind != fail2banJailsKind || old.RequestHash != hash || old.Fail2banJails == nil {
			return out, fault.Conflict("受管 jail 操作 ID 冲突")
		}
		return fail2banJailsView(old), nil
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if n.disasterBusy != "" || n.http01 != nil && n.http01.busy() {
		return out, ErrBusy
	}
	records, err := n.Journal.List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if pendingNginxRecord(record) {
			return out, ErrBusy
		}
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(n.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	binding, err := selectFail2banBinding(n.DataDir)
	if err != nil || binding == nil || binding.managed == nil {
		return out, errors.New("jail 安装仅允许已批准的独立受管实例；已有实例保持只读")
	}
	r := binding.managed
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
	dir, m, err := n.active()
	if err != nil {
		return out, err
	}
	if err = n.observe(ctx, m); err != nil {
		return out, errors.New("受管 jail 安装前无法确认当前 Nginx 运行修订")
	}
	bundle := fail2banJailBundle{Schema: 1, ID: in.OperationID, InstallationID: r.OperationID, EngineKey: fail2banNginxEngineKey(binding), NginxDir: dir, NginxHash: manifestHash(m), Policy: in.Policy, Sources: map[string]string{}, Proxies: map[string][]string{}}
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
			return out, fault.Invalid("同一 jail 标识不能转移站点、模板或动作；请创建新 jail 标识")
		}
		if j.Action != "nginx-client" || len(m.ClientDeny[j.ResourceID]) == 0 {
			return out, fault.Invalid("当前执行器仅允许已发布客户端拒绝入口的 Nginx 动作")
		}
		matches := 0
		for _, source := range m.Logs {
			if source.Source.Active && source.Source.ResourceID == j.ResourceID && source.Source.Category == "http_access" && source.Source.Format == "nginxpanel_http" && source.Source.AuthPresence {
				matches++
				bundle.Sources[j.ID] = source.Path
			}
		}
		if matches != 1 {
			return out, fault.Invalid("jail 须引用唯一且包含认证标记的当前受管 HTTP 日志")
		}
		bundle.Proxies[j.ResourceID] = append([]string{}, m.ClientDeny[j.ResourceID]...)
	}
	registry, err := loadFail2banNginxRegistry(n.DataDir)
	if err != nil {
		return out, err
	}
	afterGrants, err := fail2banJailGrants(registry, before, &bundle)
	if err != nil {
		return out, err
	}
	now := time.Now().Unix()
	afterRegistry := fail2banNginxRegistry{Schema: 1, ID: in.OperationID, PreviousID: registry.ID, RequestHash: hash, ApprovedAt: now, Grants: afterGrants}
	rollbackRegistry := fail2banNginxRegistry{Schema: 1, ID: secure.ID(), PreviousID: in.OperationID, RequestHash: secure.Hash([]byte("fail2ban.jails.rollback:" + hash)), ApprovedAt: now, Grants: registry.Grants}
	if err = validFail2banNginxRegistry(afterRegistry, false); err != nil {
		return out, err
	}
	if _, err = os.Lstat(filepath.Join(fail2banNginxDir(n.DataDir), "grants", in.OperationID+".json")); err == nil {
		return out, fault.Conflict("该操作 UUID 已用于 Nginx 动作授权")
	} else if !os.IsNotExist(err) {
		return out, err
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
	intent := &fail2banJailIntent{InstallationID: r.OperationID, EngineKey: bundle.EngineKey, BeforeID: beforeID, AfterID: bundle.ID, Invocation: live.invocation, SocketInode: live.inode, BeforeRegistry: registry, AfterRegistry: afterRegistry, RollbackRegistry: rollbackRegistry}
	record := Record{OperationID: in.OperationID, RequestHash: hash, Kind: fail2banJailsKind, State: "running", Stage: "queued", BeforeDir: dir, AfterDir: dir, BeforeRevision: m.RevisionID, AfterRevision: m.RevisionID, Fail2banJails: intent}
	if err = n.persist(record); err != nil {
		return out, err
	}
	f.enqueue()
	return fail2banJailsView(record), nil
}

func fail2banJailGrants(registry fail2banNginxRegistry, before, after *fail2banJailBundle) ([]fail2banNginxGrant, error) {
	owned := map[string]fail2banNginxGrant{}
	if before != nil {
		for _, j := range before.Policy.Jails {
			if j.Enabled {
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
		if !j.Enabled {
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
