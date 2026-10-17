package agent

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

type netplanNMProposal struct {
	Plan          hostdns.Plan
	Netplan       netplanCheckpoint
	Target        *nmTarget
	Before, After dnsFile
}

func (d *HostDNS) netplanNMPrepare(input hostdns.PlanInput) (netplanNMProposal, error) {
	var out netplanNMProposal
	if d.Owner != "netplan" || d.hostScopeReason() != "" {
		return out, fault.Unavailable("须由本机确认 netplan 所有者及宿主机范围")
	}
	if d.problem != "" || d.checkpoint != nil && dnsActive(d.checkpoint.Status.State) {
		return out, fault.Conflict("存在待处理的 DNS 恢复记录")
	}
	s := readNetplanSources()
	if s.problem != "" {
		return out, fault.Unavailable(s.problem)
	}
	operation, stop := context.WithTimeout(context.Background(), 12*time.Second)
	defer stop()
	b, err := openDNSBus(operation)
	if err != nil {
		return out, fault.Unavailable("无法连接 NetworkManager")
	}
	defer b.close()
	if err = nmSupported(b); err != nil {
		return out, fault.Unavailable("需要 NetworkManager 1.44 及以上的版本检查接口")
	}
	t, err := nmFindSource(b, input.Target, true)
	if err != nil {
		return out, fault.Unavailable("无法完整读取 netplan 目标连接")
	}
	if reason := netplanNMReason(s, t); reason != "" {
		return out, fault.Unavailable(reason)
	}
	if input.SourceHash != netplanViewHash(s, t.View.SourceHash) {
		return out, fault.Conflict("netplan 源或运行状态已变化，请刷新")
	}
	flat, err := netplanNMFlat(input.Config)
	if err != nil {
		return out, fault.Invalid(err.Error())
	}
	if (input.Config.IPv4 == nil) != (t.View.Applied.IPv4 == nil) || (input.Config.IPv6 == nil) != (t.View.Applied.IPv6 == nil) {
		return out, fault.Invalid("须提供该连接所有受支持地址族的 DNS 设置")
	}
	routes, err := netplanNMRoutes(t.Persistent)
	if err != nil {
		return out, err
	}
	for _, name := range flat.Search {
		for _, route := range routes {
			if strings.EqualFold(name, strings.TrimSuffix(strings.TrimPrefix(route, "~"), ".")) {
				return out, fault.Invalid("搜索域与保留路由域冲突")
			}
		}
	}
	if reflect.DeepEqual(input.Config, *t.View.Applied) {
		return out, fault.Invalid("DNS 设置与当前状态相同，无需应用")
	}
	source, after, err := netplanEditedSource(s, t.View.Interface, flat, routes)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	before, err := readDNSFile(t.Filename)
	if err != nil || secure.Hash(before.Data) != t.FileHash {
		return out, fault.Conflict("netplan 生成连接文件变化")
	}
	tool, err := s.generator()
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	b.close()
	call, cancel := context.WithTimeout(operation, 7*time.Second)
	defer cancel()
	generated, err := d.netplanNativeCandidate(call, s, tool, source, after, networkSource{Path: t.Filename, File: before}, input.Config, routes)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	b2, err := openDNSBus(operation)
	if err != nil {
		return out, fault.Unavailable("原生生成后无法复核运行状态")
	}
	defer b2.close()
	fresh, err := nmFindSource(b2, input.Target, true)
	if err != nil || input.SourceHash != netplanViewHash(s, fresh.View.SourceHash) || !s.stable() {
		return out, fault.Conflict("netplan 生成期间源或连接状态变化")
	}
	proofs := make([]netplanSourceProof, 0, len(s.files))
	for _, file := range s.files {
		proofs = append(proofs, netplanSourceProof{file.Path, file.File.hash()})
	}
	now := time.Now().Unix()
	plan := hostdns.Plan{Owner: "netplan", Input: input, Before: *t.View.Applied, CreatedAt: now, ExpiresAt: now + 300, Impact: "仅临时调整所选静态连接的 DNS，保留 IP、网关、路由域及其他连接。确认后保存原 netplan 源和对应运行目录连接，不重启网络；未确认将独立恢复。"}
	plan.ID = plan.Hash()
	out = netplanNMProposal{Plan: plan, Target: fresh, Before: before, After: generated, Netplan: netplanCheckpoint{File: source.Path, Before: source.File, After: after, Sources: proofs, Tool: tool, ProfileHash: nmNonDNSHash(t.Persistent), AppliedHash: nmNonDNSHash(t.Applied), WrittenHash: before.hash()}}
	return out, nil
}

func (d *HostDNS) netplanNMPlan(input hostdns.PlanInput) (hostdns.Plan, error) {
	p, err := d.netplanNMPrepare(input)
	return p.Plan, err
}

func (d *HostDNS) netplanNMApply(id string, plan hostdns.Plan) (hostdns.Status, error) {
	p, err := d.netplanNMPrepare(plan.Input)
	if err != nil {
		return hostdns.Status{}, err
	}
	if plan.Owner != "netplan" || !reflect.DeepEqual(p.Plan.Before, plan.Before) {
		return hostdns.Status{}, fault.Conflict("netplan 计划与连接状态不一致")
	}
	b, err := openDNSBus(context.Background())
	if err != nil {
		return hostdns.Status{}, err
	}
	defer b.close()
	t, err := nmFindSource(b, plan.Input.Target, true)
	if err != nil || t.View.SourceHash != p.Target.View.SourceHash {
		return hostdns.Status{}, fault.Conflict("netplan 执行前连接状态变化")
	}
	n := &nmCheckpoint{BusID: b.busID, Owner: b.owner, Filename: t.Filename, Method4: t.View.Method4, Method6: t.View.Method6}
	n.BeforeApplied, err = nmCapture(t.Applied)
	if err != nil {
		return hostdns.Status{}, err
	}
	n.BeforePersistent, err = nmCapture(t.Persistent)
	if err != nil {
		return hostdns.Status{}, err
	}
	if err = netplanNMModify(t.Applied, plan.Input.Config); err != nil {
		return hostdns.Status{}, err
	}
	if err = netplanNMModify(t.Persistent, plan.Input.Config); err != nil {
		return hostdns.Status{}, err
	}
	n.AfterApplied, err = nmCapture(t.Applied)
	if err != nil {
		return hostdns.Status{}, err
	}
	n.AfterPersistent, err = nmCapture(t.Persistent)
	if err != nil {
		return hostdns.Status{}, err
	}
	n.SnapshotHash = n.hash()
	now := time.Now().Unix()
	if now >= plan.ExpiresAt {
		return hostdns.Status{}, fault.Conflict("DNS 计划已过期")
	}
	d.checkpoint = &dnsCheckpoint{Kind: "host.dns.apply", Plan: plan, NM: n, Netplan: &p.Netplan, Before: p.Before, After: p.After, VerifyAfter: now + 6, Status: hostdns.Status{OperationID: id, PlanID: plan.ID, State: "running", Stage: "applying", Deadline: now + plan.Input.TimeoutSeconds}}
	d.expiry = time.Now().Add(time.Duration(plan.Input.TimeoutSeconds) * time.Second)
	if err = d.persist(); err != nil {
		return d.checkpoint.Status, err
	}
	if _, err = d.netplanSourcesCheck(false); err == nil {
		err = d.nmWrite(b, t, false, n.AfterApplied)
	}
	if err != nil {
		err = d.rollback("netplan 连接 DNS 临时应用未确认，恢复原设置")
		return d.checkpoint.Status, err
	}
	d.checkpoint.Status.State, d.checkpoint.Status.Stage = "waiting_confirmation", "verification_pending"
	return d.checkpoint.Status, d.persist()
}

func netplanNMGeneratedMatches(file dnsFile, config hostdns.Config, routes []string) error {
	actual, domains, err := netplanNMFile(file.Data)
	if err != nil || !reflect.DeepEqual(actual, config) || !slices.Equal(domains, routes) {
		return errors.New("netplan generated connection differs from approved DNS")
	}
	return nil
}
