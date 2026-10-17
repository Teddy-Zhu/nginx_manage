package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type dockerTargetHost struct {
	Addresses  []firewall.DockerLocalAddress
	Interfaces map[string]net.Interface
	Hash       string
}

func readDockerTargetHost(ctx context.Context) (dockerTargetHost, error) {
	out := dockerTargetHost{Addresses: []firewall.DockerLocalAddress{}, Interfaces: map[string]net.Interface{}}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) > 512 {
		return out, errors.New("Docker 目标接口清单无法完整读取")
	}
	type identity struct {
		Index, MTU int
		Name       string
		Flags      net.Flags
		Addresses  []string
	}
	identities := []identity{}
	addressCount := 0
	for _, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		addresses, err := iface.Addrs()
		addressCount += len(addresses)
		if err != nil || len(addresses) > 512 || addressCount > 2048 {
			return out, errors.New("Docker 目标接口地址无法完整读取或超过预算")
		}
		entry := identity{Index: iface.Index, MTU: iface.MTU, Name: iface.Name, Flags: iface.Flags, Addresses: []string{}}
		out.Interfaces[iface.Name] = iface
		for _, address := range addresses {
			entry.Addresses = append(entry.Addresses, address.String())
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return out, errors.New("Docker 目标接口地址格式无法核对")
			}
			ip := prefix.Addr()
			family := "ipv6"
			if ip.Is4() {
				family = "ipv4"
			}
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || !firewall.DockerTargetInterface(iface.Name) || !firewall.DockerTargetAddress(ip.String(), family) {
				continue
			}
			out.Addresses = append(out.Addresses, firewall.DockerLocalAddress{Interface: iface.Name, Family: family, Address: ip.String()})
			if len(out.Addresses) > 512 {
				return out, errors.New("Docker 可绑定主机地址超过预算")
			}
		}
		slices.Sort(entry.Addresses)
		identities = append(identities, entry)
	}
	slices.SortFunc(identities, func(a, b identity) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(out.Addresses, func(a, b firewall.DockerLocalAddress) int {
		return strings.Compare(a.Interface+":"+a.Address, b.Interface+":"+b.Address)
	})
	raw, err := json.Marshal(identities)
	if err != nil || len(raw) > 256<<10 {
		return out, errors.New("Docker 目标接口报告超过预算")
	}
	out.Hash = secure.Hash(append([]byte("docker:host-interfaces:v1:\x00"), raw...))
	return out, nil
}

func resolveDockerTarget(snapshot *dockerFirewallSnapshot, host dockerTargetHost, binding firewall.DockerRuleBinding) (firewall.DockerResolvedBinding, error) {
	out := firewall.DockerResolvedBinding{Binding: binding}
	invalid := errors.New("Docker 绑定的映射、原始目的地址、入口或同族 bridge 端点无法完整核对")
	if snapshot == nil || !slices.Contains(host.Addresses, firewall.DockerLocalAddress{Interface: binding.InputInterface, Family: binding.Family, Address: binding.Destination}) {
		return out, invalid
	}
	for _, container := range snapshot.Containers {
		if container.ID != binding.ContainerID {
			continue
		}
		mapping := slices.ContainsFunc(container.Ports, func(port dockerFirewallPort) bool {
			return port.IP == binding.HostIP && port.PublicPort == binding.HostPort && port.PrivatePort == binding.ContainerPort && port.Type == binding.Protocol
		})
		port := firewall.DockerPublishedPort{Family: binding.Family, Protocol: binding.Protocol, HostIP: binding.HostIP, HostPort: binding.HostPort, NetworkIDs: []string{binding.NetworkID}}
		for _, endpoint := range container.NetworkSettings.Networks {
			if endpoint.NetworkID != binding.NetworkID {
				return out, invalid
			}
			out.ContainerAddress = endpoint.IPAddress
			if binding.Family == "ipv6" {
				out.ContainerAddress = endpoint.GlobalIPv6Address
			}
		}
		path, _ := dockerFirewallPortPath(snapshot, container, port)
		if !mapping || len(container.NetworkSettings.Networks) != 1 || path != "bridge_nat_candidate" || !firewall.DockerTargetAddress(out.ContainerAddress, binding.Family) || out.ContainerAddress == binding.Destination {
			return out, invalid
		}
		for _, network := range snapshot.Networks {
			if network.ID != binding.NetworkID {
				continue
			}
			out.OutputInterface = network.Options["com.docker.network.bridge.name"]
			if out.OutputInterface == "" && network.Options["com.docker.network.bridge.default_bridge"] != "true" {
				// Moby bridge_linux.go's generated name; existence and actual
				// sysfs bridge type are checked below, never inferred from name.
				out.OutputInterface = "br-" + network.ID[:12]
			}
		}
		iface, exists := host.Interfaces[out.OutputInterface]
		if !exists || !firewall.DockerTargetInterface(out.OutputInterface) || out.OutputInterface == binding.InputInterface || iface.Flags&net.FlagUp == 0 {
			return out, invalid
		}
		path = "/sys/class/net/" + out.OutputInterface + "/bridge"
		info, err := os.Stat(path)
		var stat unix.Statfs_t
		if err != nil || !info.IsDir() || unix.Statfs(path, &stat) != nil || uint64(stat.Type) != uint64(unix.SYSFS_MAGIC) {
			return out, invalid
		}
		return out, nil
	}
	return out, invalid
}

// Docker and INPUT share typed transaction material, while independently
// retaining their grants and grammars. Live execution remains unavailable.
func (f *hostFirewall) planDockerLocked(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var out firewall.Plan
	policy, err := in.Policy.Normalize()
	if err != nil {
		return out, err
	}
	if in.Version < 1 || in.Action != "apply" || !validIPTablesBackend(policy.Backend) {
		return out, fault.Invalid("Docker 目标计划仅支持显式 iptables 后端的应用预览")
	}
	if !f.iptablesPlannerLocked() || !f.iptablesPlanning || !f.recovering || f.policyUncertain || f.problem != "" || f.owner != policy.Backend || iptablesRegistrationPending(f.dataDir) {
		return out, fault.Unavailable("Docker 目标计划要求已登记的本机 iptables 宿主机范围，且原恢复已完成")
	}
	if os.Geteuid() != 0 || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return out, fault.Unavailable("Docker 目标计划仅允许真实宿主机 root")
	}
	if f.activeLocked() || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) || f.remote.pendingLocked() {
		return out, fault.Conflict("存在未完成的可达性变更")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	registrationUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return out, fault.Conflict("其他防火墙登记或执行器正在占用宿主机")
	}
	defer registrationUnlock()
	registration, err := iptablesRegistrationAuthority(f.dataDir)
	if err != nil || registration.NextClaim.Backend != f.owner {
		return out, fault.Unavailable("本机 iptables 授权无法核对")
	}
	if err = f.refreshIPTablesStateLocked(); err != nil {
		return out, err
	}
	protections, listeners, source, err := firewallProtections(ctx, firewall.HostPolicy(policy), f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	hostProgram, err := firewall.CompileIPTablesProtected(firewall.HostPolicy(policy), protections)
	if err != nil {
		return out, err
	}
	id := secure.ID()
	hostRuntime, err := firewall.CompileIPTablesRuntime(firewall.HostPolicy(policy), protections, registration.NextClaim.Owner, id, "apply")
	if err != nil {
		return out, err
	}
	var before iptablesRegistrationSnapshot
	var inspectErr error
	var runtime firewall.DockerRuntime
	var snapshot *dockerFirewallSnapshot
	previous := iptablesPlanPrevious(f.iptablesState, registration.NextClaim.Owner, registration.NextClaim.OperationID)
	inspect := func() (iptablesRegistrationSnapshot, error) {
		if previous != nil {
			return inspectIPTablesSource(ctx, f.dataDir, previous, false)
		}
		return inspectIPTablesRegistration(ctx, f.dataDir, f.owner, false)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); runtime, snapshot = readDockerFirewallState(ctx) }()
	go func() {
		defer wg.Done()
		before, inspectErr = inspect()
	}()
	wg.Wait()
	if inspectErr != nil {
		return out, fault.Unavailable("Docker 目标计划的完整内核视图不可核对：" + boundedIPTablesError(inspectErr))
	}
	if !runtime.Available || snapshot == nil {
		return out, fault.Unavailable(runtime.Reason)
	}
	if runtime.Rootless || runtime.Swarm != "inactive" {
		return out, fault.Unavailable("rootless 或 Swarm 不在本机 bridge/NAT 绑定范围内")
	}
	if before.Observed.Docker.BackendHint != "iptables" {
		return out, fault.Unavailable("Docker 转发后端未知或混合，不能核对单一 iptables 挂接")
	}
	problems, _ := firewall.IPTablesEnvironment(before.Observed, &firewall.IPTablesProgram{Backend: f.owner})
	if len(problems) != 0 {
		return out, fault.Unavailable(strings.Join(problems, "；"))
	}
	if err = checkIPTablesInterfaces(firewall.HostPolicy(policy), before.Observed); err != nil {
		return out, fault.Unavailable(err.Error())
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !slices.ContainsFunc(policy.Rules, func(rule firewall.Rule) bool {
			return rule.Enabled && rule.Scope == "docker_published" && (rule.Family == family || rule.Family == "both")
		}) {
			continue
		}
		found := false
		for _, image := range before.Images {
			if image.Family != family {
				continue
			}
			hook := observeDockerFirewallHook(image)
			if !hook.Observed {
				return out, fault.Unavailable(family + "：" + hook.Reason)
			}
			found = true
		}
		if !found {
			return out, fault.Unavailable("Docker 对应地址族的原生挂接未完整读取")
		}
	}
	host, err := readDockerTargetHost(ctx)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	nativeHashes := func(value iptablesRegistrationSnapshot) []string {
		out := []string{}
		for _, image := range value.Images {
			out = append(out, image.Family+":"+image.hash())
		}
		slices.Sort(out)
		return out
	}
	native := nativeHashes(before)
	routingHash := ""
	var transition *iptablesTransition
	var hostSummary *firewall.IPTablesPlan
	var record *firewallPolicyRecord
	detail := &firewall.DockerPlan{EngineHash: runtime.EngineHash, SnapshotHash: runtime.SnapshotHash, ObservedAt: runtime.ObservedAt, Ports: runtime.Ports, Truncated: runtime.Truncated, Addresses: host.Addresses, Bindings: []firewall.DockerResolvedBinding{}, Entries: []firewall.PreviewEntry{}, HostProgramHash: hostProgram.Hash, HostGeneratedRules: hostProgram.BaseRules + len(hostProgram.Entries), Warnings: []string{"绑定只覆盖明确选择的主机映射、原始目的地址和入口接口；不代表所有容器或通配地址均受保护", "完整绑定计划使用固定工具预演候选与同表正反向批次；不安装规则或探测数据包", "允许采用 RETURN 交还 DOCKER-USER 和 Docker 后续判断；路径证据不保证其他过滤规则、转发设置或云安全组放行", "当前仅支持规则预览，无法应用规则"}, Reason: "请选择目标映射、实际原始目的地址及入口接口；当前计划仅供核对，不能应用"}
	if in.DockerTargets != nil {
		targets, err := in.DockerTargets.Normalize(policy)
		if err != nil {
			return out, err
		}
		if targets.EngineHash != runtime.EngineHash || targets.SnapshotHash != runtime.SnapshotHash {
			return out, fault.Conflict("Docker 实例、网络或端口映射已变化，请重新读取目标并绑定")
		}
		grant, err := dockerRegistrationAuthority(f.dataDir, registration, runtime.EngineHash)
		if err != nil {
			return out, fault.Unavailable(err.Error())
		}
		reader, err := openDockerRouteRead()
		if err != nil {
			return out, fault.Unavailable("无法建立只读路由查询：" + boundedIPTablesError(err))
		}
		defer reader.close()
		families := dockerTargetFamilies(targets)
		var tools *iptablesToolBinding
		if previous != nil {
			tools = &previous.Tools
		} else {
			tools, err = bindIPTablesTools(ctx, f.owner)
			if err != nil {
				return out, fault.Unavailable("Docker 固定工具绑定失败：" + boundedIPTablesError(err))
			}
		}
		if err = before.verifyBoundDocker(ctx, tools, families); err != nil {
			return out, fault.Unavailable("Docker 固定规则读取失败：" + boundedIPTablesError(err))
		}
		routing, err := reader.snapshot(ctx, families)
		if err != nil {
			return out, fault.Unavailable(boundedIPTablesError(err))
		}
		routingHash = routing.Hash
		detail.Bindings, err = resolveDockerPolicyBindings(ctx, reader, routing, snapshot, host, before.Images, policy, targets)
		if err != nil {
			return out, err
		}
		program, err := firewall.CompileDockerIPTables(policy, targets, detail.Bindings)
		if err != nil {
			return out, err
		}
		detail.Compiled, detail.BindingsHash, detail.ProgramHash, detail.ProgramBytes = true, program.BindingsHash, program.Hash, program.Bytes
		detail.GeneratedRules = len(program.Entries)
		runtimeProgram, err := firewall.CompileDockerIPTablesRuntime(policy, targets, detail.Bindings, grant.Owner, id)
		if err != nil {
			return out, err
		}
		detail.Entries = append(detail.Entries, runtimeProgram.Entries[:min(128, len(runtimeProgram.Entries))]...)
		detail.EntriesTruncated = len(runtimeProgram.Entries) > len(detail.Entries)
		if runtimeProgram.GeneratedRules+detail.HostGeneratedRules+2*len(hostProgram.Families) > firewall.MaxEntries {
			return out, fault.Invalid("包含主机保护、Docker 入口及代际指针的规则超过 8192 条")
		}
		transition = &iptablesTransition{Previous: previous, Owner: registration.NextClaim.Owner, MachineHash: registration.NextClaim.MachineHash, RegistrationOperationID: registration.NextClaim.OperationID, RegistrationRequestHash: registration.RequestHash, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, Program: hostRuntime, Docker: &dockerIPTablesPolicyRecord{Registration: *grant, Targets: targets, Bindings: slices.Clone(detail.Bindings), Program: runtimeProgram}, Tools: tools, Materials: []iptablesChangeMaterial{}}
		record = &firewallPolicyRecord{Action: "apply", PlanID: id, Version: in.Version, Policy: policy, PolicyHash: policy.Hash(), ProgramHash: iptablesTransitionProgramHash(transition), Protections: protections, Marker: hostRuntime.Marker, ProtectionBasis: firewallProtectionBasis{SSHProfile: f.sshMode, SSHListeners: listeners, Listener: f.remote.state.Confirmed.Listen, AllowedSources: slices.Clone(f.remote.state.Confirmed.AllowedSources), ControlSource: source}}
		if err = validateDockerIPTablesPolicy(transition.Docker, *record, transition.Owner, transition.MachineHash, transition.RegistrationOperationID, transition.RegistrationRequestHash); err != nil {
			return out, err
		}
		detail.Transition, hostSummary, err = prepareIPTablesTransition(ctx, before, transition)
		if err != nil {
			return out, fault.Unavailable(boundedIPTablesError(err))
		}
		detail.Reason = "目标路径及主机入站/Docker 转发的联合规则预演已核对；当前仅可预览"
		// Bracket the proof with fresh native, routing and Docker observations.
		// Keep the existing plan deadline: timeout rejects rather than returning
		// a partial proof. These reads do not make the snapshots atomic.
		var after iptablesRegistrationSnapshot
		var afterRuntime firewall.DockerRuntime
		var afterRouting dockerRoutingSnapshot
		var afterRoutingErr error
		wg.Add(3)
		go func() { defer wg.Done(); after, inspectErr = inspect() }()
		go func() { defer wg.Done(); afterRuntime, _ = readDockerFirewallState(ctx) }()
		go func() { defer wg.Done(); afterRouting, afterRoutingErr = reader.snapshot(ctx, families) }()
		wg.Wait()
		if inspectErr != nil {
			return out, fault.Unavailable("DNAT 后读失败：" + boundedIPTablesError(inspectErr))
		}
		if afterRoutingErr != nil {
			return out, fault.Unavailable("路由后读失败：" + boundedIPTablesError(afterRoutingErr))
		}
		if !afterRuntime.Available {
			return out, fault.Unavailable(afterRuntime.Reason)
		}
		if after.Hash != before.Hash || after.ToolHash != before.ToolHash || !slices.Equal(native, nativeHashes(after)) || afterRouting.Hash != routing.Hash || afterRuntime.EngineHash != runtime.EngineHash || afterRuntime.SnapshotHash != runtime.SnapshotHash {
			return out, fault.Conflict("Docker 实例、原生规则或路由在路径核对期间变化，请重新生成计划")
		}
		if err = after.verifyBoundDocker(ctx, tools, families); err != nil {
			return out, fault.Unavailable("Docker 官方预演后的固定读取失败：" + boundedIPTablesError(err))
		}
		if err = after.admitTransitionReadback(transition); err != nil {
			return out, fault.Unavailable(boundedIPTablesError(err))
		}
	}
	afterHost, err := readDockerTargetHost(ctx)
	if err != nil {
		return out, fault.Unavailable("主机接口后读失败：" + boundedIPTablesError(err))
	}
	if host.Hash != afterHost.Hash {
		return out, fault.Conflict("主机接口或地址在目标计划期间变化，请重新读取")
	}
	if transition != nil {
		parent, err := iptablesRegistrationAuthority(f.dataDir)
		if err != nil {
			return out, fault.Unavailable("Docker 计划结束时无法核对父授权")
		}
		grant, err := dockerRegistrationAuthority(f.dataDir, parent, runtime.EngineHash)
		if err != nil || parent.NextClaim.Owner != transition.Owner || parent.NextClaim.OperationID != transition.RegistrationOperationID || parent.RequestHash != transition.RegistrationRequestHash || dockerRegistrationReceiptHash(grant) != dockerRegistrationReceiptHash(&transition.Docker.Registration) {
			return out, fault.Conflict("Docker 独立授权在计划期间变化，请重新生成")
		}
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	configuration, err := json.Marshal(struct {
		Rules, Tools, Interfaces, Routing string
		Native                            []string
	}{before.Hash, before.ToolHash, host.Hash, routingHash, native})
	if err != nil {
		return out, err
	}
	detail.ConfigurationHash = secure.Hash(append([]byte("docker:planning-environment:v2:\x00"), configuration...))
	if detail.GeneratedRules+detail.HostGeneratedRules > firewall.MaxEntries {
		return out, fault.Invalid("包含主机入口保护及 Docker 目标的规则展开后超过 8192 条")
	}
	out = firewall.Plan{Docker: detail, IPTables: hostSummary, Backend: f.owner, CanApply: false, Action: "apply", ID: id, Version: in.Version, PolicyHash: policy.Hash(), Baseline: firewall.KernelView{Reason: "Docker 目标与路径核对摘要见 Docker 子计划"}, Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source, ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, GeneratedRules: detail.GeneratedRules + detail.HostGeneratedRules}
	if transition != nil {
		if err = validateIPTablesTransition(transition, *record); err != nil {
			return firewall.Plan{}, err
		}
		raw, err := json.Marshal(transition)
		if err != nil || len(raw) > 16<<20 {
			return firewall.Plan{}, errors.New("iptables 联合私有计划超过 16 MiB 或无法编码")
		}
		out.ProgramHash = record.ProgramHash
		out.TransactionHash = secure.Hash(append([]byte("iptables:plan:v2:\x00"), raw...))
		out.TransactionBytes = detail.Transition.TransactionBytes
		detail.Transition.TransactionHash = out.TransactionHash
		out.GeneratedRules += 2*len(hostRuntime.Families) + 2*len(transition.Docker.Program.Families)
	}
	if !validDockerPlan(out, in) {
		return firewall.Plan{}, errors.New("Docker 完整目标计划无法编码或超过预算")
	}
	if err = f.storePlanLocked(out, record); err != nil {
		return firewall.Plan{}, err
	}
	private := f.plans[id]
	private.iptables = transition
	f.plans[id] = private
	return out, nil
}
