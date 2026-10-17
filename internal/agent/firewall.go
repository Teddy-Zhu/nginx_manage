package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

// A single in-flight observation and a minimum cache interval prevent a read
// endpoint from repeatedly forking privileged tools. Cancellation of one HTTP
// request never starts a second copy while the original job is still alive.
type firewallObserver struct {
	mu      sync.Mutex
	ctx     context.Context
	scope   string
	dataDir string
	dev     bool
	done    chan struct{}
	last    time.Time
	value   firewall.Observation
}

func (f *firewallObserver) read(ctx context.Context) (firewall.Observation, error) {
	f.mu.Lock()
	if f.done == nil && (f.last.IsZero() || time.Since(f.last) >= 30*time.Second) {
		f.last = time.Now()
		f.done = make(chan struct{})
		done := f.done
		go func() {
			call, cancel := context.WithTimeout(f.ctx, 6*time.Second)
			defer cancel()
			value := f.collect(call)
			f.mu.Lock()
			f.value = value
			f.done = nil
			close(done)
			f.mu.Unlock()
		}()
	}
	done := f.done
	if done == nil {
		value := f.value
		f.mu.Unlock()
		return value, nil
	}
	f.mu.Unlock()
	select {
	case <-ctx.Done():
		return firewall.Observation{}, fault.Unavailable("防火墙诊断仍在读取，请稍后刷新")
	case <-done:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.value, nil
}
func (f *firewallObserver) collect(ctx context.Context) firewall.Observation {
	out := firewall.Empty(f.scope, "")
	out.At = time.Now().Unix()
	if f.dev {
		out.Scope = "development"
		out.Source = "development-agent"
	}
	// Reuse the existing local host-observation grant, never a module switch or
	// an API boolean. A container/unknown namespace must not masquerade as host.
	host := HostDNS{Dev: f.dev, Scope: f.scope}
	if reason := host.hostScopeReason(); reason != "" || os.Geteuid() != 0 {
		out.Reason = "宿主机防火墙诊断须由 root Agent 在本机以 --metrics-scope=host 确认范围"
		return out
	}
	if ctx.Err() != nil {
		out.Reason = "宿主机诊断已停止"
		return out
	}
	out.Available = true
	if interfaces, e := net.Interfaces(); e == nil && len(interfaces) <= 512 {
		for _, item := range interfaces {
			out.Interfaces = append(out.Interfaces, item.Name)
		}
		sort.Strings(out.Interfaces)
	} else {
		out.Warnings = append(out.Warnings, "目标接口清单无法在预算内读取")
	}
	out.Rulesets = make([]firewall.Ruleset, 5)
	out.Iptables = make([]firewall.Iptables, 2)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out.Kernel = readNFTKernel(ctx)
		out.Registration = nftRegistrationView(f.dataDir, out.Kernel)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		out.Firewalld = readFirewalld(ctx)
		out.Firewalld.Registration = firewalldRegistrationView(f.dataDir, out.Firewalld.PolicyInventory)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		out.UFW = readUFW(ctx)
		out.UFW.Registration = ufwRegistrationView(ctx, f.dataDir, out.UFW)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := firewall.Ruleset{ID: "nftables", Backend: "nftables", Family: "all", Tables: []firewall.Table{}, Reason: "nft 程序不可用或无法完整读取内核规则"}
		if raw, e := firewallRead(ctx, "nft", "rules", 4<<20); e == nil {
			if tables, e := nftInventory(raw); e == nil {
				r.Tables = tables
				r.Available = true
				r.Reason = ""
			} else {
				r.Reason = "nftables JSON 结构无效或超出读取预算"
			}
		}
		out.Rulesets[0] = r
	}()
	for index, variant := range []string{"nft", "legacy"} {
		for fi, family := range []string{"ipv4", "ipv6"} {
			wg.Add(1)
			go func() { defer wg.Done(); out.Rulesets[1+2*index+fi] = readXtables(ctx, variant, family) }()
		}
	}
	for i, name := range []string{"iptables", "ip6tables"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state := firewall.Iptables{Family: []string{"ipv4", "ipv6"}[i], Backend: "unknown", Reason: "默认 iptables 工具不可用"}
			if raw, e := firewallRead(ctx, name, "version", 1024); e == nil {
				backend, version, e := firewallVersion(raw)
				state.Version = version
				if e == nil {
					state.Backend = backend
					state.Reason = ""
				} else {
					state.Reason = "默认 iptables 命令的后端无法确认"
				}
			}
			out.Iptables[i] = state
		}()
	}
	wg.Wait()
	classifyFirewall(&out)
	if out.Iptables[0].Backend != "unknown" && out.Iptables[1].Backend != "unknown" && out.Iptables[0].Backend != out.Iptables[1].Backend {
		out.Warnings = append(out.Warnings, "默认 IPv4 与 IPv6 iptables 命令指向不同后端")
	}
	return out
}
func (s *Server) firewallHandlers(mux *http.ServeMux, ctx context.Context) *firewallObserver {
	f := &firewallObserver{ctx: ctx, scope: s.MetricsScope, dev: s.Dev, dataDir: s.DataDir}
	mux.HandleFunc("GET /v1/firewall", func(w http.ResponseWriter, r *http.Request) { out, e := f.read(r.Context()); dnsReply(w, out, e) })
	return f
}
func (c *Client) ReadFirewall(ctx context.Context) (firewall.Observation, error) {
	var out firewall.Observation
	e := c.envelopeRequest(ctx, http.MethodGet, "/v1/firewall", nil, &out)
	if e == nil && (out.Source != "host-agent" && out.Source != "development-agent" || out.At <= 0 || out.Writable || out.Docker.Writable || len(out.Rulesets) > 5 || len(out.Iptables) > 2 || out.Kernel.Available && (out.Kernel.Generation == 0 || len(out.Kernel.NamespaceID) != 64 || len(out.Kernel.Fingerprint) != 64 || out.Kernel.Chains < 0 || out.Kernel.Chains > 128 || out.Kernel.Rules < 0 || out.Kernel.Rules > firewall.MaxEntries || out.Kernel.Bytes < 0 || out.Kernel.Bytes > nftReadBytes || out.Kernel.ObservedAt <= 0)) {
		e = errors.New("invalid firewall observation")
	}
	if e == nil {
		if !validUFWRules(out.UFW.RuleInventory) || !validUFWRegistrationView(out.UFW.Registration) || out.UFW.RuleInventory.Available && !out.UFW.Installed || out.UFW.Registration.Verified && (!out.UFW.Installed || out.UFW.IPv6 == nil || !out.UFW.RuleInventory.Available) {
			e = errors.New("invalid UFW rule inventory")
		}
	}
	if e == nil {
		if !validFirewalldPolicies(out.Firewalld.PolicyInventory) || !validFirewalldRegistrationView(out.Firewalld.Registration, out.Firewalld.PolicyInventory) || out.Firewalld.PolicyInventory.Available && (out.Firewalld.Running == nil || !*out.Firewalld.Running) {
			e = errors.New("invalid firewalld policy inventory")
		}
	}
	if e == nil {
		switch out.Registration.State {
		case "unavailable", "unregistered", "registered", "managed", "released", "missing", "drifted", "recovery_required":
		default:
			e = errors.New("invalid firewall registration state")
		}
		if out.Registration.Verified && (out.Registration.State != "registered" && out.Registration.State != "managed" || !out.Kernel.Available || !out.Kernel.TableExists || out.Registration.State == "registered" && (out.Kernel.Chains != 0 || out.Kernel.Rules != 0) || out.Registration.State == "managed" && (out.Kernel.Chains != 1 || out.Kernel.Rules < 2) || !validID(out.Registration.OperationID)) {
			e = errors.New("invalid firewall registration proof")
		}
	}
	return out, e
}
