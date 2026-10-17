package agent

import "nginxpanel/internal/hostdns"

func (d *HostDNS) observeNetplan() hostdns.Observation {
	var source *netplanSnapshot
	if d.hostScopeReason() == "" {
		source = readNetplanSources()
	}
	out := d.observeNetworkd(source)
	nm := d.observeNM(source)
	out.Owner, out.Connections = "netplan", nm.Connections
	out.Writable = out.Writable || nm.Writable
	if source != nil && source.problem == "" && !source.stable() {
		for i := range out.Links {
			link := &out.Links[i]
			invalidateNetplanSource(link.Netplan)
			link.Writable, link.SourceHash, link.Reason = false, "", "netplan 源在观测期间变化，请刷新"
		}
		for i := range out.Connections {
			connection := &out.Connections[i]
			invalidateNetplanSource(connection.Netplan)
			connection.Writable, connection.SourceHash, connection.Reason = false, "", "netplan 源在观测期间变化，请刷新"
		}
		out.Writable = false
	}
	if len(out.Current.Servers) == 0 && len(nm.Current.Servers) > 0 {
		out.Current = nm.Current
	}
	if out.Writable {
		out.Reason = ""
	} else {
		out.Reason = d.hostScopeReason()
		if out.Reason == "" {
			out.Reason = "没有可安全接管的 netplan 链路或连接，请查看各目标的只读原因"
		}
	}
	return d.withPending(out)
}
