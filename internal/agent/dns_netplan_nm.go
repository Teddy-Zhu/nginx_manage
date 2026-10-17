package agent

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"

	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

func nmNonDNSHash(settings nmSettings) string {
	other := nmSettings{}
	for group, props := range settings {
		other[group] = map[string]dbus.Variant{}
		for key, value := range props {
			// NetworkManager updates this read-only activation timestamp while
			// a connection is active; it is not part of its network policy.
			if group == "connection" && key == "timestamp" {
				continue
			}
			if (group == "ipv4" || group == "ipv6") && slices.Contains(nmDNSKeys, key) {
				continue
			}
			other[group][key] = value
		}
	}
	return secure.Hash([]byte(dbus.MakeVariant(other).String()))
}

// Static netplan nameservers do not change an IP method or its automatic
// policy. Keep the exact ignore-auto-dns property, including absence.
func netplanNMModify(settings nmSettings, config hostdns.Config) error {
	before, err := nmCapture(settings)
	if err != nil {
		return err
	}
	if err = nmModify(settings, config); err != nil {
		return err
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if settings[family] == nil {
			continue
		}
		delete(settings[family], "ignore-auto-dns")
		if value, exists := before[family]["ignore-auto-dns"]; exists {
			v, err := value.variant()
			if err != nil {
				return err
			}
			settings[family]["ignore-auto-dns"] = v
		}
	}
	return nil
}

func netplanNMFlat(config hostdns.Config) (hostdns.Config, error) {
	out := hostdns.Config{Servers: []string{}, Search: []string{}}
	first := true
	for _, family := range []*hostdns.Family{config.IPv4, config.IPv6} {
		if family == nil {
			continue
		}
		if family.Automatic {
			return out, errors.New("静态 netplan 连接不能启用自动 DNS")
		}
		if !first && !slices.Equal(out.Search, family.Search) {
			return out, errors.New("netplan 的两个地址族须使用相同搜索域")
		}
		if first {
			out.Search = append([]string{}, family.Search...)
			first = false
		}
		out.Servers = append(out.Servers, family.Servers...)
	}
	if first {
		return out, errors.New("netplan 连接没有可管理的地址族")
	}
	return out, nil
}

func netplanNMRoutes(settings nmSettings) ([]string, error) {
	var routes []string
	for _, name := range []string{"ipv4", "ipv6"} {
		family, current, err := nmFamily(settings, name)
		if err != nil {
			return nil, err
		}
		if family == nil {
			continue
		}
		if routes != nil && !slices.Equal(routes, current) {
			return nil, errors.New("netplan 地址族的路由域不同，不能合并写入源")
		}
		routes = append([]string{}, current...)
	}
	if routes == nil {
		return nil, errors.New("netplan 路由域未确认")
	}
	return routes, nil
}

// Read only native DNS fields. Other keyfile bytes participate in the native
// before/after comparison; secrets and parser diagnostics are never returned.
func netplanNMFile(raw []byte) (hostdns.Config, []string, error) {
	settings, err := netplanNMFileSettings(raw)
	if err != nil {
		return hostdns.Config{}, nil, err
	}
	config, _, err := nmConfig(settings)
	if err != nil {
		return config, nil, err
	}
	routes, err := netplanNMRoutes(settings)
	return config, routes, err
}

func netplanNMFileSettings(raw []byte) (nmSettings, error) {
	file, err := netplanNMKeyfile(raw)
	if err != nil {
		return nil, err
	}
	settings := nmSettings{}
	for _, section := range []string{"ipv4", "ipv6"} {
		if file[section] == nil {
			continue
		}
		settings[section] = map[string]dbus.Variant{}
		for key, value := range file[section] {
			switch key {
			case "method":
				settings[section][key] = dbus.MakeVariant(value)
			case "dns", "dns-search":
				if strings.ContainsAny(value, "\\\r\x00") {
					return nil, errors.New("netplan keyfile DNS 转义不受支持")
				}
				values := []string{}
				if value != "" {
					values = strings.Split(strings.TrimSuffix(value, ";"), ";")
				}
				if key == "dns" {
					for _, text := range values {
						ip, err := netip.ParseAddr(text)
						if err != nil || ip.Zone() != "" || ip.Is4In6() || section == "ipv4" && !ip.Is4() || section == "ipv6" && !ip.Is6() {
							return nil, errors.New("netplan keyfile DNS 地址不受支持")
						}
					}
					key = "dns-data"
				}
				settings[section][key] = dbus.MakeVariant(values)
			case "ignore-auto-dns":
				if value != "true" && value != "false" {
					return nil, errors.New("netplan keyfile DNS 策略未确认")
				}
				settings[section][key] = dbus.MakeVariant(value == "true")
			}
		}
	}
	return settings, nil
}

func netplanNMKeyfile(raw []byte) (map[string]map[string]string, error) {
	file := map[string]map[string]string{}
	section := ""
	for _, physical := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(physical)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if section == "" || file[section] != nil {
				return nil, errors.New("netplan keyfile 含重复分组")
			}
			file[section] = map[string]string{}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		_, duplicate := file[section][key]
		if !ok || section == "" || key == "" || duplicate {
			return nil, errors.New("netplan keyfile 语法未确认")
		}
		file[section][key] = value
	}
	return file, nil
}

func stripNetplanNMDNS(raw []byte) []byte {
	var out strings.Builder
	section := ""
	for _, physical := range strings.SplitAfter(string(raw), "\n") {
		line := strings.TrimSpace(physical)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
		}
		key, _, ok := strings.Cut(line, "=")
		if ok && (section == "ipv4" || section == "ipv6") && (strings.TrimSpace(key) == "dns" || strings.TrimSpace(key) == "dns-search") {
			continue
		}
		out.WriteString(physical)
	}
	return []byte(out.String())
}

func netplanNMReason(s *netplanSnapshot, t *nmTarget) string {
	if s.problem != "" {
		return s.problem
	}
	info := s.source("NetworkManager", t.Filename)
	if info == nil || info.State != "associated" || info.DeviceType != "ethernets" || info.Definition != t.View.Interface || info.Settings == nil {
		return "当前仅支持与网卡同名、源字段完整的 netplan Ethernet 连接"
	}
	for _, flag := range []*bool{info.Settings.DHCP4, info.Settings.DHCP6, info.Settings.AcceptRA} {
		if flag == nil || *flag {
			return "netplan 目标须明确关闭 DHCPv4、DHCPv6 和 IPv6 RA，自动来源保持只读"
		}
	}
	for _, settings := range []nmSettings{t.Persistent, t.Applied} {
		if nmString(settings, "connection", "type") != "802-3-ethernet" || settings["802-1x"] != nil {
			return "当前仅支持无独立认证秘密的直接 Ethernet 连接"
		}
		if nmString(settings, "connection", "interface-name") != t.View.Interface {
			return "netplan 连接须按接口名称独占所选网卡"
		}
		if value, exists := settings["connection"]["multi-connect"]; exists {
			mode, ok := value.Value().(int32)
			if !ok || mode < 0 || mode > 1 {
				return "允许多个设备共享的连接保持只读"
			}
		}
	}
	if t.View.Persistent == nil || t.View.Applied == nil || !reflect.DeepEqual(*t.View.Persistent, *t.View.Applied) {
		return "netplan 持久与已应用 DNS 不一致"
	}
	if t.View.Persistent.Validate(t.View.Target) != nil {
		return "netplan 当前 DNS 超出可写范围"
	}
	for _, method := range []string{t.View.Method4, t.View.Method6} {
		if method != "manual" && method != "disabled" && method != "ignore" && method != "link-local" {
			return "netplan 当前连接存在自动或未知 IP 方法"
		}
	}
	flat, err := netplanNMFlat(*t.View.Persistent)
	if err != nil {
		return err.Error()
	}
	routes, err := netplanNMRoutes(t.Persistent)
	if err != nil {
		return err.Error()
	}
	appliedRoutes, err := netplanNMRoutes(t.Applied)
	if err != nil || !slices.Equal(routes, appliedRoutes) {
		return "netplan 持久与已应用路由域不一致"
	}
	file, err := readDNSFile(t.Filename)
	if err != nil || secure.Hash(file.Data) != t.FileHash {
		return "无法核对 netplan 生成连接文件"
	}
	if file.Mode != 0600 || file.GID != 0 {
		return "netplan 生成连接须为 root 独占的标准 0600 文件"
	}
	config, fileRoutes, err := netplanNMFile(file.Data)
	if err != nil || !reflect.DeepEqual(config, *t.View.Persistent) || !slices.Equal(routes, fileRoutes) {
		return "netplan 生成文件与已加载 DNS 不一致"
	}
	generated, err := netplanNMFileSettings(file.Data)
	if err != nil || nmString(generated, "ipv4", "method") != t.View.Method4 || nmString(generated, "ipv6", "method") != t.View.Method6 {
		return "netplan 生成文件与已加载 IP 方法不一致"
	}
	if _, err = netplanNMNonDNSFile(file.Data, nmString(t.Persistent, "connection", "uuid")); err != nil {
		return "netplan 生成连接的非 DNS 字段未完整识别"
	}
	if _, _, err = netplanEditedSource(s, t.View.Interface, flat, routes); err != nil {
		return err.Error()
	}
	if _, err = s.generator(); err != nil {
		return err.Error()
	}
	return ""
}
