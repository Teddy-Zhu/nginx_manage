package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/dockerapi"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type dockerFirewallInfo struct {
	ID, ServerVersion, OSType string
	SecurityOptions           []string
	Swarm                     struct{ LocalNodeState string }
}

type dockerFirewallNetwork struct {
	ID                            string `json:"Id"`
	Name, Driver, Scope           string
	Internal, Ingress, EnableIPv6 bool
	Options                       map[string]string
}

type dockerFirewallPort struct {
	IP                      string
	PrivatePort, PublicPort int
	Type                    string
}

type dockerFirewallEndpoint struct {
	NetworkID, IPAddress, GlobalIPv6Address string
}

type dockerFirewallContainer struct {
	ID              string `json:"Id"`
	State           string
	Ports           []dockerFirewallPort
	HostConfig      struct{ NetworkMode string }
	NetworkSettings *struct {
		Networks map[string]dockerFirewallEndpoint
	}
}

type dockerFirewallSnapshot struct {
	Info       dockerFirewallInfo
	Networks   []dockerFirewallNetwork
	Containers []dockerFirewallContainer
}

func dockerFirewallText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func dockerFirewallPortKey(port dockerFirewallPort) string {
	return port.IP + ":" + strconv.Itoa(port.PublicPort) + ":" + strconv.Itoa(port.PrivatePort) + ":" + port.Type
}

func (snapshot *dockerFirewallSnapshot) normalize() error {
	invalid := errors.New("Docker 实例、网络或容器清单不完整、无效或超过预算")
	info := &snapshot.Info
	if !dockerFirewallText(info.ID, 128) || !dockerFirewallText(info.ServerVersion, 64) || info.OSType != "linux" || info.SecurityOptions == nil || len(info.SecurityOptions) > 32 || !slices.Contains([]string{"inactive", "pending", "active", "error", "locked"}, info.Swarm.LocalNodeState) || snapshot.Networks == nil || len(snapshot.Networks) > 128 || snapshot.Containers == nil || len(snapshot.Containers) > 128 {
		return invalid
	}
	slices.Sort(info.SecurityOptions)
	for index, option := range info.SecurityOptions {
		if !dockerFirewallText(option, 512) || index > 0 && option == info.SecurityOptions[index-1] {
			return invalid
		}
	}
	networks := map[string]bool{}
	for index := range snapshot.Networks {
		network := &snapshot.Networks[index]
		if !firewalldDigest(network.ID) || networks[network.ID] || !dockerFirewallText(network.Name, 255) || !dockerFirewallText(network.Driver, 128) || !dockerFirewallText(network.Scope, 32) || len(network.Options) > 64 {
			return invalid
		}
		networks[network.ID] = true
		if network.Options == nil {
			network.Options = map[string]string{}
		}
		for name, value := range network.Options {
			if !dockerFirewallText(name, 128) || value != "" && !dockerFirewallText(value, 1024) {
				return invalid
			}
		}
	}
	containers, ports := map[string]bool{}, 0
	for index := range snapshot.Containers {
		container := &snapshot.Containers[index]
		if !firewalldDigest(container.ID) || containers[container.ID] || !slices.Contains([]string{"running", "paused", "restarting"}, container.State) || !dockerFirewallText(container.HostConfig.NetworkMode, 255) || container.NetworkSettings == nil || container.NetworkSettings.Networks == nil || len(container.NetworkSettings.Networks) > 16 {
			return invalid
		}
		containers[container.ID] = true
		endpointNetworks := map[string]bool{}
		for name, endpoint := range container.NetworkSettings.Networks {
			if !dockerFirewallText(name, 255) || !networks[endpoint.NetworkID] || endpointNetworks[endpoint.NetworkID] {
				return invalid
			}
			endpointNetworks[endpoint.NetworkID] = true
			for family, value := range []string{endpoint.IPAddress, endpoint.GlobalIPv6Address} {
				if value == "" {
					continue
				}
				ip, err := netip.ParseAddr(value)
				if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.Is4() != (family == 0) || ip.IsUnspecified() || ip.IsMulticast() {
					return invalid
				}
			}
		}
		ports += len(container.Ports)
		if ports > 1024 {
			return invalid
		}
		if container.Ports == nil {
			container.Ports = []dockerFirewallPort{}
		}
		seen := map[string]bool{}
		for _, port := range container.Ports {
			key := dockerFirewallPortKey(port)
			if seen[key] || port.PrivatePort < 1 || port.PrivatePort > 65535 || port.PublicPort < 0 || port.PublicPort > 65535 || !slices.Contains([]string{"tcp", "udp", "sctp"}, port.Type) {
				return invalid
			}
			seen[key] = true
			if port.IP != "" {
				ip, err := netip.ParseAddr(port.IP)
				if err != nil || ip.Zone() != "" || ip.Is4In6() {
					return invalid
				}
			}
		}
		slices.SortFunc(container.Ports, func(a, b dockerFirewallPort) int {
			return strings.Compare(dockerFirewallPortKey(a), dockerFirewallPortKey(b))
		})
	}
	slices.SortFunc(snapshot.Networks, func(a, b dockerFirewallNetwork) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Containers, func(a, b dockerFirewallContainer) int { return strings.Compare(a.ID, b.ID) })
	return nil
}

func (snapshot *dockerFirewallSnapshot) rootless() bool {
	for _, option := range snapshot.Info.SecurityOptions {
		if slices.Contains(strings.Split(option, ","), "name=rootless") {
			return true
		}
	}
	return false
}

// Docker recreates its default bridge at daemon startup. Its transient ID
// must not invalidate an otherwise unchanged report of a selected custom
// network. Only this report projection uses the alias: endpoint resolution and
// frozen execution bindings continue to require the actual network IDs.
func (snapshot *dockerFirewallSnapshot) reportHash() (string, error) {
	report := *snapshot
	report.Networks = slices.Clone(snapshot.Networks)
	aliases := map[string]string{}
	for index, network := range report.Networks {
		if network.Name != "bridge" || network.Driver != "bridge" || network.Scope != "local" || network.Internal || network.Ingress || network.Options["com.docker.network.bridge.default_bridge"] != "true" {
			continue
		}
		if len(aliases) != 0 {
			return "", errors.New("Docker 默认桥网络身份不唯一")
		}
		aliases[network.ID] = "builtin:bridge"
		report.Networks[index].ID = "builtin:bridge"
	}
	if len(aliases) != 0 {
		// Sort again after projection, since the raw IDs determine input order.
		slices.SortFunc(report.Networks, func(a, b dockerFirewallNetwork) int { return strings.Compare(a.ID, b.ID) })
		report.Containers = slices.Clone(snapshot.Containers)
		for index := range report.Containers {
			container := &report.Containers[index]
			if alias, ok := aliases[container.HostConfig.NetworkMode]; ok {
				container.HostConfig.NetworkMode = alias
			}
			settings := *container.NetworkSettings
			settings.Networks = maps.Clone(settings.Networks)
			for name, endpoint := range settings.Networks {
				if alias, ok := aliases[endpoint.NetworkID]; ok {
					endpoint.NetworkID = alias
					settings.Networks[name] = endpoint
				}
			}
			container.NetworkSettings = &settings
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return secure.Hash(append([]byte("docker:firewall-report:v2:\x00"), raw...)), nil
}

func dockerFirewallPortPath(snapshot *dockerFirewallSnapshot, container dockerFirewallContainer, port firewall.DockerPublishedPort) (string, string) {
	if snapshot.rootless() || snapshot.Info.Swarm.LocalNodeState != "inactive" {
		return "unconfirmed", "rootless 或 Swarm 流量不按本机 bridge 入站路径处理"
	}
	if container.State != "running" || port.Protocol == "sctp" {
		return "unconfirmed", "容器状态或端口协议不在当前转发适配范围内"
	}
	if port.HostIP == "" || port.HostPort == 0 {
		return "unconfirmed", "未报告完整主机地址及发布端口，不能推断 NAT 映射"
	}
	ip, _ := netip.ParseAddr(port.HostIP)
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return "unconfirmed", "该发布地址不按普通外部 bridge 入站路径处理"
	}
	if len(port.NetworkIDs) != 1 || container.HostConfig.NetworkMode == "host" || strings.HasPrefix(container.HostConfig.NetworkMode, "container:") {
		return "unconfirmed", "容器网络未唯一绑定本机 bridge，不能从端口清单推断转发出口"
	}
	for _, network := range snapshot.Networks {
		if network.ID != port.NetworkIDs[0] {
			continue
		}
		if network.Driver != "bridge" || network.Scope != "local" || network.Internal || network.Ingress {
			return "unconfirmed", "网络驱动、范围或隔离模式不在本机 bridge/NAT 范围内"
		}
		mode := network.Options["com.docker.network.bridge.gateway_mode_"+port.Family]
		if mode != "" && mode != "nat" {
			return "unconfirmed", "网络不是 nat 网关模式，不能作为普通发布端口 DNAT 路径"
		}
		for _, endpoint := range container.NetworkSettings.Networks {
			address := endpoint.IPAddress
			if port.Family == "ipv6" {
				address = endpoint.GlobalIPv6Address
				if !network.EnableIPv6 {
					address = ""
				}
			}
			if address == "" {
				return "unconfirmed", "缺少同地址族 bridge 端点，不能将代理转发视为同族 DNAT"
			}
		}
		return "bridge_nat_candidate", "bridge/NAT 映射候选；仍须绑定目标地址并核对实际 DNAT 和转发路径"
	}
	return "unconfirmed", "端口对应的网络未完整核对"
}

// Only these fixed GETs are used. Only instance, network and port fields are
// retained; labels and mount metadata in list responses are discarded. No
// container inspect, image configuration, credential or exec API is requested.
func readDockerFirewallSnapshot(ctx context.Context, client *dockerapi.Client) (dockerFirewallSnapshot, error) {
	var out dockerFirewallSnapshot
	for _, read := range []struct {
		path  string
		value any
	}{{"/info", &out.Info}, {"/networks", &out.Networks}, {"/containers/json?all=false&size=false", &out.Containers}} {
		if err := client.JSON(ctx, http.MethodGet, read.path, nil, read.value); err != nil {
			return out, err
		}
	}
	return out, out.normalize()
}

func readDockerFirewallRuntime(ctx context.Context) firewall.DockerRuntime {
	out, _ := readDockerFirewallState(ctx)
	return out
}

// The selected private topology is retained only for this fresh plan. Public
// observations and migration archives never carry it as an execution binding.
func readDockerFirewallState(ctx context.Context) (firewall.DockerRuntime, *dockerFirewallSnapshot) {
	fail := func(reason string) (firewall.DockerRuntime, *dockerFirewallSnapshot) {
		return firewall.EmptyDockerRuntime(reason), nil
	}
	client, err := dockerapi.New()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fail("本机 Docker Socket 不存在，未读取容器端口映射")
		}
		return fail("本机 Docker Socket 或 root 对端无法核对")
	}
	defer client.Close()
	call, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	before, err := readDockerFirewallSnapshot(call, client)
	if err != nil {
		return fail("Docker 实例及完整端口映射读取失败：" + boundedIPTablesError(err))
	}
	after, err := readDockerFirewallSnapshot(call, client)
	if err != nil || call.Err() != nil {
		return fail("Docker 实例及完整端口映射后读失败或超时")
	}
	first, err := json.Marshal(before)
	if err != nil {
		return fail("Docker 实例及端口映射摘要无法编码")
	}
	last, err := json.Marshal(after)
	if err != nil || !bytes.Equal(first, last) {
		return fail("Docker 实例、网络或端口映射在读取期间变化，请重新读取")
	}
	reportHash, err := before.reportHash()
	if err != nil {
		return fail("Docker 实例及端口映射摘要无法核对：" + err.Error())
	}
	out := firewall.DockerRuntime{Available: true, EngineHash: secure.Hash([]byte("docker:engine:v1:\x00" + before.Info.ID)), Version: before.Info.ServerVersion, APIVersion: dockerapi.Version, SnapshotHash: reportHash, ObservedAt: time.Now().Unix(), Rootless: before.rootless(), Swarm: before.Info.Swarm.LocalNodeState, Networks: len(before.Networks), Containers: len(before.Containers), Ports: []firewall.DockerPublishedPort{}, Reason: "前后 Docker 报告一致；不是原子内核快照、规则授权或外部可达性证明"}
	for _, container := range before.Containers {
		networks := []string{}
		for _, endpoint := range container.NetworkSettings.Networks {
			networks = append(networks, endpoint.NetworkID)
		}
		slices.Sort(networks)
		for _, port := range container.Ports {
			if port.PublicPort == 0 && port.IP == "" {
				continue // An exposed-only container port is not a host mapping.
			}
			out.PublishedPorts++
			if len(out.Ports) >= 128 {
				continue
			}
			entry := firewall.DockerPublishedPort{ContainerID: container.ID, Family: "unknown", Protocol: port.Type, HostIP: port.IP, HostPort: port.PublicPort, ContainerPort: port.PrivatePort, NetworkIDs: slices.Clone(networks)}
			if ip, err := netip.ParseAddr(port.IP); err == nil {
				entry.Family = "ipv6"
				if ip.Is4() {
					entry.Family = "ipv4"
				}
			}
			entry.Path, entry.Reason = dockerFirewallPortPath(&before, container, entry)
			out.Ports = append(out.Ports, entry)
		}
	}
	out.Truncated = out.PublishedPorts > len(out.Ports)
	return out, &before
}
