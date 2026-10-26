package firewall

import (
	"fmt"
	"strings"
	"testing"
)

func conflictRule(index int, action string) Rule {
	return Rule{ID: fmt.Sprintf("10000000-0000-4000-8000-%012d", index), Name: fmt.Sprintf("规则%d", index),
		Enabled: true, Scope: "host_input", Family: "both", Protocol: "tcp", Ports: []PortRange{{80, 80}},
		Sources: []string{}, Action: action, Priority: index * 10}
}

func TestPolicyOrderChecks(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(*Rule, *Rule)
		blocked bool
	}{
		{"相反动作被完全遮挡", func(a, b *Rule) { b.Action = "deny" }, true},
		{"重复放行", func(a, b *Rule) {}, true},
		{"停用规则不遮挡", func(a, b *Rule) { a.Enabled = false }, false},
		{"不同协议", func(a, b *Rule) { b.Protocol = "udp" }, false},
		{"不同流量范围", func(a, b *Rule) { b.Scope = "docker_published" }, false},
		{"不同地址族", func(a, b *Rule) { a.Family, b.Family = "ipv4", "ipv6" }, false},
		{"指定网卡不能遮挡其他网卡", func(a, b *Rule) { a.Interface = "eth0" }, false},
		{"全网卡包含指定网卡", func(a, b *Rule) { b.Interface = "eth0" }, true},
		{"全部协议覆盖UDP", func(a, b *Rule) { a.Protocol = "any"; a.Ports = []PortRange{{1, 65535}}; b.Protocol = "udp" }, true},
		{"相邻网段合并后包含来源", func(a, b *Rule) {
			a.Sources = []string{"192.0.2.0/25", "192.0.2.128/25"}
			b.Sources = []string{"192.0.2.0/24"}
		}, true},
		{"网段缺口不能误判包含", func(a, b *Rule) {
			a.Sources = []string{"192.0.2.0/26", "192.0.2.128/25"}
			b.Sources = []string{"192.0.2.0/24"}
		}, false},
		{"端口缺口不能误判包含", func(a, b *Rule) {
			a.Ports = []PortRange{{79, 79}, {81, 81}}
			b.Ports = []PortRange{{79, 81}}
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, b := conflictRule(1, "allow"), conflictRule(2, "allow")
			test.edit(&a, &b)
			policy, err := (Policy{Backend: "direct-nftables", Rules: []Rule{a, b}}).Normalize()
			if err != nil {
				t.Fatal(err)
			}
			err = checkPolicyOrder(policy)
			if (err != nil) != test.blocked {
				t.Fatalf("blocked=%v, err=%v", test.blocked, err)
			}
			if err != nil && (!strings.Contains(err.Error(), a.Name) || !strings.Contains(err.Error(), b.Name)) {
				t.Fatalf("错误未指出相关规则：%v", err)
			}
		})
	}
}

func TestDefaultsAndConflictConfirmation(t *testing.T) {
	allow := conflictRule(1, "allow")
	allow.Sources = []string{"192.0.2.0/24"}
	tcp, udp := conflictRule(2, "deny"), conflictRule(3, "deny")
	tcp.Ports, udp.Ports = []PortRange{{1, 65535}}, []PortRange{{1, 65535}}
	udp.Protocol = "udp"
	policy := Policy{Backend: "direct-nftables", Rules: []Rule{allow, tcp, udp}}
	if err := checkPolicyOrder(policy); err != nil {
		t.Fatal(err)
	}
	if found := policyConflicts(policy, DefaultPolicy()); len(found) != 0 {
		t.Fatalf("白名单与末尾默认屏蔽不应要求重复确认：%v", found)
	}
	deny := conflictRule(4, "deny")
	deny.Sources = []string{"192.0.2.128/25"}
	policy.Rules = []Rule{deny, allow}
	if err := checkPolicyOrder(policy); err != nil {
		t.Fatal(err)
	}
	if len(policyConflicts(policy, DefaultPolicy())) != 1 {
		t.Fatal("不同动作的部分重叠须确认")
	}
	if len(policyConflicts(policy, policy)) != 0 {
		t.Fatal("已经确认且未变化的顺序不应重复确认")
	}
	policy.Rules = []Rule{allow, deny}
	if checkPolicyOrder(policy) == nil {
		t.Fatal("先放行整个网段后屏蔽其子网段无法生效")
	}
	policy.Rules = []Rule{tcp, conflictRule(5, "deny")}
	policy.Rules[1].Ports = []PortRange{{1, 65535}}
	if checkPolicyOrder(policy) == nil {
		t.Fatal("末尾默认规则也不能重复")
	}
}
