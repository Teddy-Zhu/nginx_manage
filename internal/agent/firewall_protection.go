package agent

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"nginxpanel/internal/firewall"
)

type firewallTCPSocket struct {
	local, remote netip.AddrPort
	state, inode  string
	uid           uint64
}

func firewallProcRead(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("防火墙保护项源超限")
	}
	return raw, nil
}
func firewallProcAddress(raw string, ipv6 bool) (netip.AddrPort, error) {
	host, port, ok := strings.Cut(raw, ":")
	if !ok || len(port) != 4 || len(host) != 8 && !ipv6 || ipv6 && len(host) != 32 {
		return netip.AddrPort{}, errors.New("TCP 地址格式未知")
	}
	decoded, err := hex.DecodeString(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for i := 0; i < len(decoded); i += 4 {
		value := binary.BigEndian.Uint32(decoded[i : i+4])
		binary.NativeEndian.PutUint32(decoded[i:i+4], value)
	}
	address, ok := netip.AddrFromSlice(decoded)
	if !ok {
		return netip.AddrPort{}, errors.New("TCP 地址无效")
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, uint16(p)), nil
}
func firewallTCPSockets(ctx context.Context) ([]firewallTCPSocket, error) {
	out := []firewallTCPSocket{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := firewallProcRead(path, 2<<20)
		if os.IsNotExist(err) && strings.HasSuffix(path, "6") {
			continue
		}
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(raw), "\n")
		if len(lines) < 2 || lines[len(lines)-1] != "" || !strings.Contains(lines[0], "local_address") || (!strings.Contains(lines[0], "rem_address") && !strings.Contains(lines[0], "remote_address")) {
			return nil, errors.New("TCP 监听源不完整")
		}
		for _, line := range lines[1 : len(lines)-1] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				return nil, errors.New("TCP 状态格式未知")
			}
			if len(out) >= 16384 {
				return nil, errors.New("TCP 监听源超过保护项预算")
			}
			local, err := firewallProcAddress(fields[1], strings.HasSuffix(path, "6"))
			if err != nil {
				return nil, err
			}
			remote, err := firewallProcAddress(fields[2], strings.HasSuffix(path, "6"))
			if err != nil {
				return nil, err
			}
			uid, err := strconv.ParseUint(fields[7], 10, 32)
			if err != nil {
				return nil, err
			}
			out = append(out, firewallTCPSocket{local: local, remote: remote, state: fields[3], uid: uid, inode: fields[9]})
		}
	}
	return out, nil
}

// Read root sshd listener descriptors as well as effective configuration. This
// includes -p command-line overrides; configured root listeners also cover
// socket-activated SSH. Neither a fixed port 22 nor a process name alone proves
// an active port. Raced process exits may disappear; other incomplete reads fail.
func firewallSSHListeners(ctx context.Context, sockets []firewallTCPSocket) (map[string]bool, error) {
	raw, err := firewallRead(ctx, "sshd", "effective", 64<<10)
	if err != nil {
		return nil, err
	}
	configured := map[uint16]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "port" {
			continue
		}
		if len(fields) != 2 {
			return nil, errors.New("OpenSSH 端口配置未知")
		}
		p, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil || p == 0 {
			return nil, errors.New("OpenSSH 端口配置无效")
		}
		configured[uint16(p)] = true
	}
	if len(configured) == 0 || len(configured) > 16 {
		return nil, errors.New("OpenSSH 端口配置数量无效")
	}
	listeners := map[string]bool{}
	inodes := map[string]firewallTCPSocket{}
	for _, s := range sockets {
		if s.state == "0A" && s.uid == 0 {
			inodes[s.inode] = s
			if configured[s.local.Port()] {
				listeners[s.local.String()] = true
			}
		}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	if len(entries) > 65536 {
		return nil, errors.New("进程清单超出 SSH 保护项预算")
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		comm, err := firewallProcRead(filepath.Join(dir, "comm"), 128)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(string(comm)) != "sshd" && strings.TrimSpace(string(comm)) != "sshd-session" {
			continue
		}
		exe, err := os.Open(filepath.Join(dir, "exe"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := exe.Stat()
		exe.Close()
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, "fd"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(files) > 4096 {
			return nil, errors.New("OpenSSH 描述符超过保护项预算")
		}
		for _, file := range files {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			target, err := os.Readlink(filepath.Join(dir, "fd", file.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				if s, ok := inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")]; ok {
					listeners[s.local.String()] = true
				}
			}
		}
	}
	return listeners, nil
}

// Caller holds the root listener mutex; addresses are actual accepted TCP
// endpoints and locally confirmed ACLs, never proxy headers or API assertions.
func firewallProtections(ctx context.Context, policy firewall.Policy, sshMode string, m *remoteListener, connection string) ([]firewall.Protection, []string, string, error) {
	control, ok := m.connections[connection]
	if !ok || m.web == nil || m.listener == nil || m.pendingLocked() || m.problem != "" || !m.state.Confirmed.Enabled || control.version != m.state.Version {
		return nil, nil, "", errors.New("须通过已确认的受控管理监听生成和应用防火墙计划")
	}
	source, err := netip.ParseAddr(control.source)
	if err != nil {
		return nil, nil, "", err
	}
	source = source.Unmap()
	if source.IsLoopback() || source.IsUnspecified() || source.Zone() != "" {
		return nil, nil, "", errors.New("须从非回环的目标管理连接核对可达性")
	}
	_, port, err := net.SplitHostPort(m.state.Confirmed.Listen)
	if err != nil {
		return nil, nil, "", err
	}
	managementPort, err := strconv.Atoi(port)
	if err != nil {
		return nil, nil, "", err
	}
	families := map[string]map[string]bool{"ipv4": {}, "ipv6": {}}
	add := func(raw string) error {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p != p.Masked() || p.Addr().Is4In6() {
			return errors.New("保护来源无效")
		}
		family := "ipv6"
		if p.Addr().Is4() {
			family = "ipv4"
		}
		families[family][p.String()] = true
		return nil
	}
	if err = add(netip.PrefixFrom(source, source.BitLen()).String()); err != nil {
		return nil, nil, "", err
	}
	for _, cidr := range m.state.Confirmed.AllowedSources {
		if err = add(cidr); err != nil {
			return nil, nil, "", err
		}
	}
	sockets, err := firewallTCPSockets(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	ssh := map[string]bool{}
	if sshMode == "openssh" {
		ssh, err = firewallSSHListeners(ctx, sockets)
		if err != nil {
			return nil, nil, "", err
		}
	} else if sshMode != "none" {
		return nil, nil, "", errors.New("须由本机确认 OpenSSH 保护或无 SSH 的范围")
	}
	ports := map[string]map[int]bool{"ipv4": {}, "ipv6": {}}
	observed := []string{}
	for address := range ssh {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, nil, "", err
		}
		family := "ipv6"
		if ap.Addr().Unmap().Is4() {
			family = "ipv4"
		}
		ports[family][int(ap.Port())] = true
		if ap.Addr().Is6() && ap.Addr().IsUnspecified() {
			ports["ipv4"][int(ap.Port())] = true
		}
		observed = append(observed, address)
	}
	sort.Strings(observed)
	for _, s := range sockets {
		if s.state != "01" || s.remote.Addr().IsUnspecified() {
			continue
		}
		family := "ipv6"
		if s.local.Addr().Unmap().Is4() {
			family = "ipv4"
		}
		if !ports[family][int(s.local.Port())] {
			continue
		}
		peer := s.remote.Addr().Unmap()
		if err = add(netip.PrefixFrom(peer, peer.BitLen()).String()); err != nil {
			return nil, nil, "", err
		}
	}
	protections := []firewall.Protection{}
	for _, family := range []string{"ipv4", "ipv6"} {
		sources := []string{}
		for cidr := range families[family] {
			sources = append(sources, cidr)
		}
		sort.Strings(sources)
		protectedPorts := []int{}
		for p := range ports[family] {
			protectedPorts = append(protectedPorts, p)
		}
		sort.Ints(protectedPorts)
		if len(sources) == 0 {
			for _, rule := range policy.Rules {
				if !rule.Enabled || rule.Scope != "host_input" || rule.Protocol != "tcp" || rule.Action == "allow" || rule.Family != family && rule.Family != "both" {
					continue
				}
				for _, r := range rule.Ports {
					for _, p := range protectedPorts {
						if r.From <= p && p <= r.To {
							return nil, nil, "", errors.New("所选地址族的 SSH 阻止规则缺少可核对的保护来源")
						}
					}
				}
			}
			continue
		}
		appendGuard := func(service string, p int) {
			for start := 0; start < len(sources); start += 32 {
				end := min(start+32, len(sources))
				protections = append(protections, firewall.Protection{Service: service, Family: family, Port: p, Sources: append([]string{}, sources[start:end]...)})
			}
		}
		appendGuard("management", managementPort)
		for _, p := range protectedPorts {
			appendGuard("ssh", p)
		}
	}
	if len(protections) > 128 {
		return nil, nil, "", errors.New("防火墙保护项超过 128 项")
	}
	return protections, observed, source.String(), nil
}
