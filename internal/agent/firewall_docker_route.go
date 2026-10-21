package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// Linux rtnetlink/fib_rules UAPI attribute numbers. This reader sends only
// GETRULE/GETROUTE, without multicast membership or a route mutation method.
const (
	dockerRouteBytes            = 2 << 20
	dockerRouteObjects          = 8192
	dockerRouteDST              = 1
	dockerRouteSRC              = 2
	dockerRouteOIF              = 4
	dockerRoutePriority         = 6
	dockerRoutePreferredSource  = 7
	dockerRouteCache            = 12
	dockerRouteTable            = 15
	dockerRoutePreference       = 20
	dockerRouteExpires          = 23
	dockerRoutePadding          = 24
	dockerRulePriority          = 6
	dockerRuleSuppressPrefixLen = 14
	dockerRuleTable             = 15
	dockerRulePadding           = 18
	dockerRuleProtocol          = 21
)

type dockerRouteAttribute struct {
	Type  uint16
	Value []byte
}
type dockerRouteRecord struct {
	Header     [12]byte
	Attributes []dockerRouteAttribute
}
type dockerRoutingSnapshot struct {
	Routes map[string]bool
	Hash   string
}
type dockerRouteReader struct{ socket *nftReadSocket }

func openDockerRouteRead() (*dockerRouteReader, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	address, err := unix.Getsockname(fd)
	local, ok := address.(*unix.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		unix.Close(fd)
		return nil, errors.New("Docker 路由读取端口无效")
	}
	// Only the bounded receive/poll transport is shared with the nft reader;
	// its NFtables query/send allowlist is deliberately not widened.
	return &dockerRouteReader{socket: &nftReadSocket{fd: fd, pid: local.Pid, buffer: make([]byte, nftDatagramBytes)}}, nil
}

func (r *dockerRouteReader) close() { r.socket.close() }

func dockerRouteFamily(family string) byte {
	if family == "ipv4" {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func (r *dockerRouteReader) query(ctx context.Context, family byte, rules bool, destination netip.Addr, fn func(dockerRouteRecord) error) error {
	kind, reply := uint16(unix.RTM_GETROUTE), uint16(unix.RTM_NEWROUTE)
	if rules {
		kind, reply = unix.RTM_GETRULE, unix.RTM_NEWRULE
	}
	data := make([]byte, 12)
	data[0] = family
	flags := netlink.Request | netlink.Dump
	if destination.IsValid() {
		if rules || destination.Is4() != (family == unix.AF_INET) {
			return errors.New("Docker 路由读取请求无效")
		}
		flags = netlink.Request
		data[1] = byte(destination.BitLen())
		routeFlags := uint32(unix.RTM_F_FIB_MATCH)
		if family == unix.AF_INET {
			// Ask for the selected table when exposed. Merged local/main FIBs
			// still require the inventory proof below for local destinations.
			routeFlags |= unix.RTM_F_LOOKUP_TABLE
		}
		binary.NativeEndian.PutUint32(data[8:12], routeFlags)
		value := destination.AsSlice()
		attribute := make([]byte, 4+len(value))
		binary.NativeEndian.PutUint16(attribute[:2], uint16(len(attribute)))
		binary.NativeEndian.PutUint16(attribute[2:4], dockerRouteDST)
		copy(attribute[4:], value)
		data = append(data, attribute...)
	}
	r.socket.sequence++
	message := netlink.Message{Header: netlink.Header{Length: uint32(unix.NLMSG_HDRLEN + len(data)), Type: netlink.HeaderType(kind), Flags: flags, Sequence: r.socket.sequence, PID: r.socket.pid}, Data: data}
	raw, err := message.MarshalBinary()
	if err != nil {
		return err
	}
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		err = unix.Sendto(r.socket.fd, raw, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EAGAIN) {
			break
		}
		if err = r.socket.wait(ctx, unix.POLLOUT); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	count := 0
	for {
		done, err := r.socket.receive(ctx, r.socket.sequence, func(message netlink.Message) error {
			if r.socket.bytes > dockerRouteBytes || r.socket.objects > dockerRouteObjects {
				return errors.New("Docker 完整路由读取超过 2 MiB 或 8192 项预算")
			}
			if uint16(message.Header.Type) != reply {
				return errors.New("Docker 路由响应类型无效")
			}
			record, err := parseDockerRouteRecord(message.Data, family, rules)
			if err != nil {
				return err
			}
			count++
			if destination.IsValid() && count > 1 {
				return errors.New("Docker FIB 查询返回多个结果")
			}
			return fn(record)
		})
		if err != nil {
			return err
		}
		if r.socket.bytes > dockerRouteBytes || r.socket.objects > dockerRouteObjects {
			return errors.New("Docker 完整路由读取超过预算")
		}
		if done {
			if destination.IsValid() && count != 1 {
				return errors.New("Docker FIB 查询没有完整结果")
			}
			return nil
		}
	}
}

func parseDockerRouteRecord(data []byte, family byte, rules bool) (dockerRouteRecord, error) {
	var out dockerRouteRecord
	invalid := errors.New("Docker 路由或策略规则编码不完整")
	if len(data) < 12 || data[0] != family {
		return out, invalid
	}
	copy(out.Header[:], data[:12])
	data = data[12:]
	out.Attributes = []dockerRouteAttribute{}
	seen := map[uint16]bool{}
	for len(data) > 0 {
		if len(data) < 4 {
			return out, invalid
		}
		length := int(binary.NativeEndian.Uint16(data[:2]))
		kind := binary.NativeEndian.Uint16(data[2:4])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(data) || seen[kind] {
			return out, invalid
		}
		for _, b := range data[length:aligned] {
			if b != 0 {
				return out, invalid
			}
		}
		seen[kind] = true
		value := slices.Clone(data[4:length])
		if !rules && kind == dockerRouteCache {
			if len(value) != 32 {
				return out, invalid
			}
			// Cache use/reference counters and timestamps are not route identity.
			// Keep expiry and error: a selected route must have neither.
			for i := range value {
				if i < 8 || i >= 16 {
					value[i] = 0
				}
			}
		}
		out.Attributes = append(out.Attributes, dockerRouteAttribute{kind, value})
		data = data[aligned:]
	}
	slices.SortFunc(out.Attributes, func(a, b dockerRouteAttribute) int { return int(a.Type) - int(b.Type) })
	return out, nil
}

func (record dockerRouteRecord) attribute(kind uint16) ([]byte, bool) {
	for _, attribute := range record.Attributes {
		if attribute.Type == kind {
			return attribute.Value, true
		}
	}
	return nil, false
}

func (record dockerRouteRecord) table(kind uint16) (uint32, error) {
	table := uint32(record.Header[4])
	if value, ok := record.attribute(kind); ok {
		if len(value) != 4 {
			return 0, errors.New("Docker 路由表编号无效")
		}
		explicit := binary.NativeEndian.Uint32(value)
		if table != 0 && explicit != table && !(table == 252 && explicit >= 256) {
			return 0, errors.New("Docker 路由表编号冲突")
		}
		table = explicit
	}
	if table == 0 {
		return 0, errors.New("Docker 路由表编号缺失")
	}
	return table, nil
}

func dockerDefaultRoutingRule(record dockerRouteRecord) (uint32, error) {
	invalid := errors.New("Docker 路径核对不支持条件策略路由或非默认规则")
	h := record.Header
	flags := binary.NativeEndian.Uint32(h[8:12])
	if h[1] != 0 || h[2] != 0 || h[3] != 0 || h[5] != 0 || h[6] != 0 || h[7] != 1 || flags&^uint32(1) != 0 {
		return 0, invalid
	}
	table, err := record.table(dockerRuleTable)
	if err != nil {
		return 0, err
	}
	priority := uint32(0) // Kernel omits FRA_PRIORITY for the priority-zero local rule.
	for _, attribute := range record.Attributes {
		switch attribute.Type {
		case dockerRuleTable:
		case dockerRulePriority:
			if len(attribute.Value) != 4 {
				return 0, invalid
			}
			priority = binary.NativeEndian.Uint32(attribute.Value)
		case dockerRuleProtocol:
			// FRA_PROTOCOL identifies the rule's installer, not packet protocol.
			if len(attribute.Value) != 1 {
				return 0, invalid
			}
		case dockerRuleSuppressPrefixLen:
			// Kernel dumps include UINT32_MAX for disabled prefix suppression.
			// Finite suppressors change lookup behavior and remain unsupported.
			if len(attribute.Value) != 4 || binary.NativeEndian.Uint32(attribute.Value) != ^uint32(0) {
				return 0, invalid
			}
		case dockerRulePadding:
			for _, b := range attribute.Value {
				if b != 0 {
					return 0, invalid
				}
			}
		default:
			return 0, invalid
		}
	}
	if table != 255 && table != 254 && table != 253 || table == 255 && priority != 0 || table == 254 && priority != 32766 || table == 253 && priority != 32767 {
		return 0, invalid
	}
	return table, nil
}

func (r *dockerRouteReader) snapshot(ctx context.Context, families []string) (dockerRoutingSnapshot, error) {
	out := dockerRoutingSnapshot{Routes: map[string]bool{}}
	// Route/rule records are framed separately even if their raw UAPI bytes match.
	type item struct {
		Rules  bool
		Record dockerRouteRecord
	}
	items := []string{}
	add := func(rules bool, record dockerRouteRecord) error {
		digestRecord := record
		if !rules {
			var err error
			digestRecord, err = dockerRoutingEnvironmentRecord(record)
			if err != nil {
				return err
			}
		}
		raw, err := json.Marshal(item{rules, digestRecord})
		if err != nil {
			return err
		}
		items = append(items, string(raw))
		if !rules {
			out.Routes[dockerRouteIdentity(record)] = true
		}
		return nil
	}
	for _, family := range families {
		seen := map[uint32]bool{}
		err := r.query(ctx, dockerRouteFamily(family), true, netip.Addr{}, func(record dockerRouteRecord) error {
			table, err := dockerDefaultRoutingRule(record)
			if err != nil {
				return err
			}
			if seen[table] {
				return errors.New("Docker 路径包含重复默认策略规则")
			}
			seen[table] = true
			return add(true, record)
		})
		if err != nil {
			return out, err
		}
		if !seen[255] || !seen[254] {
			return out, errors.New("Docker 路径缺少默认 local/main 策略规则")
		}
		err = r.query(ctx, dockerRouteFamily(family), false, netip.Addr{}, func(record dockerRouteRecord) error {
			table, err := record.table(dockerRouteTable)
			if err != nil {
				return err
			}
			if table == 255 || table == 254 || table == 253 {
				_, source := record.attribute(dockerRouteSRC)
				if record.Header[2] != 0 || record.Header[3] != 0 || source {
					return errors.New("Docker 路径核对不支持来源专用或 TOS 路由")
				}
				for _, attribute := range record.Attributes {
					switch attribute.Type {
					case dockerRouteDST, dockerRouteOIF, dockerRoutePriority, dockerRoutePreferredSource, dockerRouteCache, dockerRouteTable, dockerRoutePreference, dockerRoutePadding:
					case 5, 8, 9, 11, 21, 22, dockerRouteExpires, 26, 30:
						// Gateway, metrics, multipath, realm, encapsulation, expiry,
						// TTL propagation and nexthop ID are retained in inventory.
						// They remain unsupported on the selected direct route.
					default:
						return errors.New("Docker 默认查表包含未支持的路由属性或条件")
					}
				}
			}
			return add(false, record)
		})
		if err != nil {
			return out, err
		}
	}
	slices.Sort(items)
	raw, err := json.Marshal(items)
	if err != nil || len(raw) > 4<<20 {
		return out, errors.New("Docker 完整路由摘要超过预算")
	}
	out.Hash = secure.Hash(append([]byte("docker:routing-environment:v1:\x00"), raw...))
	return out, nil
}

func dockerRoutingEnvironmentRecord(record dockerRouteRecord) (dockerRouteRecord, error) {
	record.Attributes = slices.Clone(record.Attributes)
	for i, attribute := range record.Attributes {
		var offset int
		switch attribute.Type {
		case dockerRouteCache:
			if len(attribute.Value) != 32 {
				return record, errors.New("Docker 路由缓存编码无效")
			}
			offset = 8
		case dockerRouteExpires:
			if len(attribute.Value) != 4 {
				return record, errors.New("Docker 路由有效期编码无效")
			}
		default:
			continue
		}
		// Unrelated RA routes count down between plan and apply. Keep lifetime
		// state and errors in the digest; the selected route still must be permanent.
		value := slices.Clone(attribute.Value)
		expires := binary.NativeEndian.Uint32(value[offset : offset+4])
		if expires != 0 {
			normalized := uint32(1)
			if attribute.Type == dockerRouteCache && int32(expires) < 0 {
				normalized = ^uint32(0)
			}
			binary.NativeEndian.PutUint32(value[offset:offset+4], normalized)
		}
		record.Attributes[i].Value = value
	}
	return record, nil
}

func dockerRouteIdentity(value dockerRouteRecord) string {
	value.Attributes = slices.DeleteFunc(slices.Clone(value.Attributes), func(a dockerRouteAttribute) bool { return a.Type == dockerRouteCache || a.Type == dockerRoutePadding })
	raw, _ := json.Marshal(value)
	return string(raw)
}

func dockerRouteInventoryIdentity(record dockerRouteRecord, snapshot dockerRoutingSnapshot, local bool) string {
	table, err := record.table(dockerRouteTable)
	if err != nil {
		return ""
	}
	want := uint32(unix.RT_TABLE_MAIN)
	if local {
		want = unix.RT_TABLE_LOCAL
	}
	identity := dockerRouteIdentity(record)
	if table == want {
		if snapshot.Routes[identity] {
			return identity
		}
		return ""
	}
	// Linux can merge the IPv4 local trie into main and report main for a
	// FIB_MATCH local result. Under the already verified default lookup rules,
	// require the otherwise identical local inventory entry and no matching
	// main entry. Preserve the observed reply; bind both identities into proof.
	if !local || record.Header[0] != unix.AF_INET || record.Header[1] != 32 || record.Header[7] != unix.RTN_LOCAL || table != unix.RT_TABLE_MAIN || snapshot.Routes[identity] {
		return ""
	}
	canonical := record
	canonical.Header[4] = unix.RT_TABLE_LOCAL
	canonical.Attributes = slices.Clone(record.Attributes)
	for i, attribute := range canonical.Attributes {
		if attribute.Type == dockerRouteTable {
			canonical.Attributes[i].Value = slices.Clone(attribute.Value)
			binary.NativeEndian.PutUint32(canonical.Attributes[i].Value, unix.RT_TABLE_LOCAL)
		}
	}
	identity = dockerRouteIdentity(canonical)
	if snapshot.Routes[identity] {
		return identity
	}
	return ""
}

func (r *dockerRouteReader) prove(ctx context.Context, snapshot dockerRoutingSnapshot, resolved firewall.DockerResolvedBinding, inputIndex, outputIndex int) (firewall.DockerPathProof, error) {
	out := firewall.DockerPathProof{RoutingHash: snapshot.Hash, OutputIndex: outputIndex, RouteTable: 254}
	_, original, err := r.selectedRoute(ctx, snapshot, resolved, netip.MustParseAddr(resolved.Binding.Destination), inputIndex, true)
	if err != nil {
		return out, err
	}
	out.OriginalRouteHash = original
	prefix, route, err := r.selectedRoute(ctx, snapshot, resolved, netip.MustParseAddr(resolved.ContainerAddress), outputIndex, false)
	out.RoutePrefix, out.RouteHash = prefix, route
	return out, err
}

func (r *dockerRouteReader) selectedRoute(ctx context.Context, snapshot dockerRoutingSnapshot, resolved firewall.DockerResolvedBinding, destination netip.Addr, outputIndex int, local bool) (string, string, error) {
	invalid := errors.New("内核 FIB 未选择所选 bridge 的永久直连容器路由")
	routeType := byte(unix.RTN_UNICAST)
	if local {
		routeType = unix.RTN_LOCAL
		invalid = errors.New("原始目的地址缺少所选入口的内核本地路由")
	}
	if !destination.IsValid() || outputIndex < 1 {
		return "", "", invalid
	}
	var selectedPrefix, selectedHash string
	err := r.query(ctx, dockerRouteFamily(resolved.Binding.Family), false, destination, func(record dockerRouteRecord) error {
		h := record.Header
		validScope := h[6] == 0 || h[6] == 253
		if local {
			validScope = h[6] == 0 || h[6] == 254
		}
		if h[2] != 0 || h[3] != 0 || h[5] != unix.RTPROT_KERNEL || !validScope || h[7] != routeType || binary.NativeEndian.Uint32(h[8:12]) != 0 || int(h[1]) > destination.BitLen() || local && int(h[1]) != destination.BitLen() {
			return invalid
		}
		var prefix netip.Prefix
		foundOutput := false
		for _, attribute := range record.Attributes {
			value := attribute.Value
			switch attribute.Type {
			case dockerRouteDST:
				ip, ok := netip.AddrFromSlice(value)
				if !ok || ip.Is4() != destination.Is4() {
					return invalid
				}
				prefix = netip.PrefixFrom(ip, int(h[1]))
				if prefix != prefix.Masked() {
					return invalid
				}
			case dockerRouteOIF:
				if len(value) != 4 || binary.NativeEndian.Uint32(value) != uint32(outputIndex) {
					return invalid
				}
				foundOutput = true
			case dockerRouteTable, dockerRoutePriority:
				if len(value) != 4 {
					return invalid
				}
			case dockerRoutePreferredSource:
				ip, ok := netip.AddrFromSlice(value)
				if !ok || ip.Is4() != destination.Is4() || !ip.IsGlobalUnicast() {
					return invalid
				}
			case dockerRoutePreference:
				if len(value) != 1 || !slices.Contains([]byte{0, 1, 3}, value[0]) {
					return invalid
				}
			case dockerRouteCache:
				if binary.NativeEndian.Uint32(value[8:12]) != 0 || binary.NativeEndian.Uint32(value[12:16]) != 0 {
					return invalid
				}
			case dockerRoutePadding:
				for _, b := range value {
					if b != 0 {
						return invalid
					}
				}
			default:
				return invalid
			}
		}
		if !foundOutput || !prefix.IsValid() || prefix.Bits() == 0 || !prefix.Contains(destination) {
			return invalid
		}
		// FIB_MATCH must be an actual inventory entry, not a cached route with
		// an artificial host prefix. Padding/cache metadata may differ.
		inventory := dockerRouteInventoryIdentity(record, snapshot, local)
		if inventory == "" {
			return invalid
		}
		selectedPrefix = prefix.String()
		raw, err := json.Marshal(struct {
			Binding          firewall.DockerRuleBinding
			Endpoint, Bridge string
			Route            dockerRouteRecord
			Inventory        string
			Index            int
		}{resolved.Binding, resolved.ContainerAddress, resolved.OutputInterface, record, inventory, outputIndex})
		if err != nil {
			return err
		}
		selectedHash = secure.Hash(append([]byte("docker:fib-route:v2:\x00"), raw...))
		return nil
	})
	return selectedPrefix, selectedHash, err
}
