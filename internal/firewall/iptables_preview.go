package firewall

import "slices"

// This checks read-only metadata, not extensions, ownership, hook position or
// readiness to mutate chains. Those require a fresh independent root plan.
func IPTablesEnvironment(observed Observation, program *IPTablesProgram) (errors, warnings []string) {
	errors, warnings = []string{}, []string{}
	if program == nil || !slices.Contains([]string{"iptables-nft", "iptables-legacy"}, program.Backend) {
		return []string{"iptables 目标程序或后端无效"}, warnings
	}
	if !observed.Available || observed.Scope != "host" {
		errors = append(errors, "宿主机 iptables 观测范围未确认")
	}
	if observed.Manager != "direct-candidate" {
		errors = append(errors, "未排除现有防火墙管理器，不能直接接管 iptables")
	}
	backend := "nftables"
	if program.Backend == "iptables-legacy" {
		backend = "legacy"
	}
	if observed.Backend != "unknown" && observed.Backend != backend {
		errors = append(errors, "目标内核后端与所选 iptables 后端不同或混合，不能切换 alternatives 或覆盖其他规则体系")
	}
	sets := map[string]Ruleset{}
	complete := len(observed.Rulesets) == 5
	for _, set := range observed.Rulesets {
		if _, exists := sets[set.ID]; exists || !slices.Contains([]string{"nftables", "iptables-nft-ipv4", "iptables-nft-ipv6", "iptables-legacy-ipv4", "iptables-legacy-ipv6"}, set.ID) {
			complete = false
		}
		sets[set.ID] = set
		complete = complete && set.Available
	}
	if !complete {
		errors = append(errors, "完整内核后端视图不可用，不能排除其他规则体系")
	}
	for _, family := range program.Families {
		set, exists := sets[program.Backend+"-"+family.Family]
		if !exists || !set.Available || set.Backend != backend || set.Family != family.Family {
			errors = append(errors, family.Family+" 的显式 iptables 命令、导出工具或规则视图无法核对")
			continue
		}
		input := false
		for _, table := range set.Tables {
			if table.Name != "filter" {
				continue
			}
			for _, chain := range table.Chains {
				if chain.Name == "INPUT" && (chain.Policy == "accept" || chain.Policy == "drop") {
					input = true
				}
				if chain.Name == IPTablesHostChain {
					errors = append(errors, family.Family+" 的同名目标链已存在，独立所有权未核对，禁止接管")
				}
				if chain.Name == "INPUT" && chain.Rules > 0 {
					warnings = append(warnings, family.Family+" INPUT 已有规则；实际跳转位置须单独核对，本应用 ACCEPT 可能提前结束后续 INPUT 规则判断")
				}
				if chain.Name == "INPUT" && chain.Policy == "drop" {
					warnings = append(warnings, family.Family+" INPUT 默认 DROP；本应用未匹配流量返回调用链，仍可能被默认策略阻止")
				}
			}
		}
		if !input {
			errors = append(errors, family.Family+" filter/INPUT 及其默认策略尚未观察到，预览不自动加载或创建系统表链")
		}
	}
	return errors, warnings
}
