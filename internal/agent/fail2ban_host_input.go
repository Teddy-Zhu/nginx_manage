package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
)

type fail2banHostInputReader struct {
	ctx      context.Context
	server   *Server
	firewall *firewallObserver
	cache    fail2banReadCache[fail2ban.HostInputPreview]
	budget   fail2banReadBudget
}

// Protection includes every sampled local address, plus fixed non-routable
// ranges. A write executor must additionally freeze approved proxy/admin
// sources and refresh this inventory before mutating its own target.
func fail2banHostLocalSources(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil || len(addresses) > 512 {
		return nil, errors.New("宿主机本地地址无法在预算内完整读取")
	}
	sources := []string{"0.0.0.0/32", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::/128", "::1/128", "fe80::/10", "ff00::/8"}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || prefix.Addr().Zone() != "" {
			return nil, errors.New("宿主机本地地址来源格式无法核对")
		}
		ip := prefix.Addr().Unmap()
		sources = append(sources, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	set, err := (firewall.NFTBanSet{Addresses: []string{}, Protected: sources}).Normalize()
	if err != nil {
		return nil, err
	}
	return set.Protected, ctx.Err()
}

func (f *fail2banHostInputReader) collect(ctx context.Context) fail2ban.HostInputPreview {
	out := fail2ban.EmptyHostInput(f.server.MetricsScope, "")
	if f.server.Dev {
		out.Scope = "development"
	}
	if f.server.Dev || os.Geteuid() != 0 || f.server.MetricsScope != "host" || f.server.MaintenanceScope != "host" {
		out.Reason = "宿主机入口动作须由 root Agent 确认宿主机范围"
		return out
	}
	observed, err := f.firewall.read(ctx)
	if err != nil {
		out.Reason = "防火墙管理器诊断暂不可读取"
		return out
	}
	out.Manager = observed.Manager
	out.ManagerObservedAt = observed.At
	if !observed.Available {
		out.Reason = "宿主机防火墙观测范围尚未确认"
		return out
	}
	out.Available = true
	if err = checkFirewallManagers(observed); err != nil {
		out.Reason = "当前管理器、混合后端或读取不完整不支持直接 nftables 宿主机动作"
		return out
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out.Kernel, err = snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
	if err != nil {
		out.Kernel = firewall.KernelView{Reason: "独立宿主机动作目标表无法完整核对"}
		out.Reason = out.Kernel.Reason
		return out
	}
	out.Registration = fail2banHostRegistrationView(f.server.DataDir, out.Kernel)
	if out.Registration.State != "unregistered" && out.Registration.State != "released" && !out.Registration.Verified || out.Kernel.TableExists && !out.Registration.Verified {
		out.Reason = out.Registration.Reason
		if out.Reason == "" {
			out.Reason = "独立宿主机动作所有权尚未确认"
		}
		return out
	}
	out.ProtectedSources, err = fail2banHostLocalSources(ctx)
	if err != nil {
		out.ProtectedSources = []string{}
		out.Reason = "本地地址保护来源无法完整核对"
		return out
	}
	set := firewall.NFTBanSet{Addresses: []string{}, Protected: out.ProtectedSources}
	program, err := firewall.CompileNFTBans(set)
	if err != nil {
		out.Reason = "宿主机动作基础配置无法编译"
		return out
	}
	// A preview marker is not an owner or an execution grant. No encoded bytes
	// or caller-selected target can cross this read-only API.
	batch, err := firewall.PrepareNFTBans(set, out.Kernel, "nginxpanel:fail2ban:preview:v1:"+program.Hash)
	if err != nil {
		out.Reason = "宿主机动作事务无法在当前基线编码"
		return out
	}
	out.CanPrepare = true
	out.ProgramHash, out.TransactionHash = program.Hash, batch.Hash
	out.TransactionBytes, out.GeneratedRules = len(batch.Wire), len(program.Rules)
	return out
}

func (s *Server) fail2banHostInputHandlers(mux *http.ServeMux, ctx context.Context, observer *firewallObserver) {
	f := &fail2banHostInputReader{ctx: ctx, server: s, firewall: observer}
	mux.HandleFunc("GET /v1/fail2ban/host-input", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.cache.read(r.Context(), f.ctx, &f.budget, "direct-nftables/v1", f.collect)
		fail2banNginxReply(w, out, err)
	})
}
func (c *Client) ReadFail2banHostInput(ctx context.Context) (fail2ban.HostInputPreview, error) {
	var out fail2ban.HostInputPreview
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/host-input", nil, &out)
	if err == nil && !out.Valid() {
		err = errors.New("宿主机入口动作预检合同无法核对")
	}
	return out, err
}
