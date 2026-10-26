package agent

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/panelruntime"
)

// Discovery is independent of a confirmed filtering policy, so shortcuts also
// work on a fresh installation. It never grants or changes firewall access.
func (f *hostFirewall) shortcutPorts(ctx context.Context) firewall.ShortcutPorts {
	out := firewall.ShortcutPorts{Management: []int{}, SSH: []int{}}
	if f.remote != nil && f.remote.mu.TryLock() {
		listen := f.remote.state.Confirmed.Listen
		ready := f.remote.available && f.remote.problem == "" && f.remote.state.Confirmed.Enabled && !f.remote.pendingLocked()
		f.remote.mu.Unlock()
		if ready {
			_, raw, err := net.SplitHostPort(listen)
			if err == nil {
				if port, err := strconv.Atoi(raw); err == nil && port > 0 && port <= 65535 {
					out.Management = append(out.Management, port)
				}
			}
		}
	}
	// The main HTTP/HTTPS listener also exists when the optional controlled
	// ingress is disabled. Read its root-owned deployment, never the browser URL.
	if deployment, err := panelruntime.ReadDeployment(f.dataDir); err == nil {
		if address, err := netip.ParseAddrPort(deployment.Listen); err == nil && !address.Addr().IsLoopback() {
			out.Management = append(out.Management, int(address.Port()))
		}
	}
	slices.Sort(out.Management)
	out.Management = slices.Compact(out.Management)
	if f.sshMode == "none" {
		out.SSHDetected = true
		return out
	}
	if f.sshMode != "openssh" {
		out.Reason = "无法识别 SSH 服务，请手动添加实际使用的端口"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	sockets, err := firewallTCPSockets(ctx)
	if err != nil {
		out.Reason = "SSH 监听读取失败，请稍后重试或手动添加端口"
		return out
	}
	listeners, err := firewallSSHListeners(ctx, sockets)
	if err != nil {
		out.Reason = "SSH 监听读取失败，请稍后重试或手动添加端口"
		return out
	}
	for raw := range listeners {
		address, err := netip.ParseAddrPort(raw)
		if err != nil {
			out.SSH = []int{}
			out.Reason = "SSH 监听地址无法识别，请手动添加端口"
			return out
		}
		out.SSH = append(out.SSH, int(address.Port()))
	}
	slices.Sort(out.SSH)
	out.SSH = slices.Compact(out.SSH)
	out.SSHDetected = true
	return out
}
