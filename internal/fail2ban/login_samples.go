package fail2ban

import "strings"

func panelLoginSamples() []FilterSample {
	line := func(ip, event string) string {
		return (PanelLoginEvent{Time: "2026-01-02T03:04:05+00:00", Event: event, PeerAddr: ip, Source: "tcp_peer", RequestID: "10000000-0000-4000-8000-000000000001"}).Line()
	}
	return []FilterSample{
		{Name: "IPv4 密码拒绝", Line: line("192.0.2.10", "login_failed"), ExpectedIP: "192.0.2.10"},
		{Name: "IPv6 密码拒绝", Line: line("2001:db8::11", "login_failed"), ExpectedIP: "2001:db8::11"},
		{Name: "IPv4 映射地址", Line: line("::ffff:192.0.2.12", "login_failed"), ExpectedIP: "192.0.2.12"},
		{Name: "登录成功不匹配", Line: line("192.0.2.13", "login_succeeded")},
		{Name: "限流不匹配", Line: line("192.0.2.14", "login_throttled")},
		{Name: "主机名拒绝", Line: line("client.example", "login_failed")},
		{Name: "非法 IPv4 拒绝", Line: line("999.999.999.999", "login_failed")},
		{Name: "非法 IPv6 拒绝", Line: line("2001:db8::1::2", "login_failed")},
		{Name: "事件字段伪造", Line: line("192.0.2.15", `login_failed","peer_addr":"198.51.100.99`)},
		{Name: "转发来源不匹配", Line: strings.Replace(line("192.0.2.16", "login_failed"), `"tcp_peer"`, `"forwarded_header"`, 1)},
		{Name: "额外字段拒绝", Line: strings.TrimSuffix(line("192.0.2.17", "login_failed"), "}") + `,"peer_addr":"198.51.100.99"}`},
		{Name: "不完整记录拒绝", Line: strings.TrimSuffix(line("192.0.2.18", "login_failed"), "}")},
	}
}
