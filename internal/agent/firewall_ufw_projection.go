package agent

import (
	"bytes"
	"errors"
	"slices"
	"strings"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// Numeric input rules do not require a new logging or limit capability. Keep
// those original auxiliaries instead of executing UFW's capability probes or
// applying dry-run's synthetic IPv4/IPv6 limit defaults to the live firewall.
func projectUFWAuxiliaries(before, candidate []byte, family string) ([]byte, error) {
	original, err := parseUFWNative(before, family, true)
	if err != nil {
		return nil, err
	}
	generated, err := parseUFWNative(candidate, family, true)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(before, candidate) {
		return bytes.Clone(before), nil
	}
	if generated.Bootstrap {
		return nil, errors.New("UFW 非空候选不能退回空初始模板")
	}
	if original.Bootstrap {
		prefix, _, _ := ufwNativeIdentity(family)
		original.Limiting = family == "ipv4"
		if original.Limiting {
			original.Rate = []string{"-A " + prefix + "-user-limit -m limit --limit 3/minute -j LOG --log-prefix \"[UFW LIMIT BLOCK] \"", "-A " + prefix + "-user-limit -j REJECT", "-A " + prefix + "-user-limit-accept -j ACCEPT"}
		}
	}
	chains := ufwNativeChainNames(family)
	var text strings.Builder
	text.WriteString("*filter\n")
	for index, name := range chains {
		if index < len(chains)-2 || original.Limiting {
			text.WriteString(":" + name + " - [0:0]\n")
		}
	}
	text.WriteString("### RULES ###\n")
	for _, rule := range generated.Rules {
		text.WriteString("\n" + rule.Tuple + "\n")
		for _, packet := range rule.Packets {
			text.WriteString(packet + "\n")
		}
	}
	text.WriteString("\n### END RULES ###\n\n### LOGGING ###\n")
	for _, line := range original.Logging {
		text.WriteString(line + "\n")
	}
	text.WriteString("### END LOGGING ###\n")
	if original.Limiting {
		text.WriteString("\n### RATE LIMITING ###\n")
		for _, line := range original.Rate {
			text.WriteString(line + "\n")
		}
		text.WriteString("### END RATE LIMITING ###\n")
	}
	text.WriteString("COMMIT\n")
	out := []byte(text.String())
	if len(out) > firewall.UFWReadBytes {
		return nil, errors.New("UFW 保留原辅助规则后的候选超过 2 MiB")
	}
	parsed, err := parseUFWNative(out, family, false)
	if err != nil || len(parsed.Rules) != len(generated.Rules) {
		return nil, errors.New("UFW 原辅助规则投影无法完整核对")
	}
	for index, rule := range generated.Rules {
		if !ufwNativeRuleEqual(rule, parsed.Rules[index]) {
			return nil, errors.New("UFW 辅助规则投影改变了用户规则")
		}
	}
	if _, err = ufwReloadConfigured(out, family); err != nil {
		return nil, err
	}
	return out, nil
}

func ufwDeclaredChains(raw []byte, family string) map[string]bool {
	out := map[string]bool{}
	for _, name := range ufwNativeChainNames(family) {
		out[name] = bytes.Contains(raw, []byte("\n:"+name+" - [0:0]\n"))
	}
	return out
}

func ufwReloadImages(before, after []byte, family string, observed []ufwReloadChain) ([]ufwReloadChain, []ufwReloadChain, error) {
	original, err := ufwReloadConfigured(before, family)
	if err != nil {
		return nil, nil, err
	}
	candidate, err := ufwReloadConfigured(after, family)
	if err != nil {
		return nil, nil, err
	}
	names := ufwNativeChainNames(family)
	if len(observed) != len(names) {
		return nil, nil, errors.New("UFW 原重载范围的链清单不完整")
	}
	declared := ufwDeclaredChains(after, family)
	previous, next := make([]ufwReloadChain, len(names)), make([]ufwReloadChain, len(names))
	for index, name := range names {
		chain := observed[index]
		if chain.Name != name || !chain.Present && len(chain.Rules) != 0 || !slices.Equal(chain.Rules, original[name]) {
			return nil, nil, errors.New("UFW 原重载链与固定配置不一致")
		}
		previous[index] = ufwReloadChain{Name: name, Present: chain.Present, Rules: slices.Clone(chain.Rules)}
		next[index] = ufwReloadChain{Name: name, Present: chain.Present || declared[name], Rules: slices.Clone(candidate[name])}
		if !declared[name] && !slices.Equal(chain.Rules, candidate[name]) {
			return nil, nil, errors.New("UFW 候选未声明包含变化的原重载链")
		}
	}
	return previous, next, nil
}

func sameUFWReloadImage(a, b []ufwReloadChain) bool {
	return slices.EqualFunc(a, b, func(x, y ufwReloadChain) bool {
		return x.Name == y.Name && x.Present == y.Present && slices.Equal(x.Rules, y.Rules)
	})
}

// --noflush rebuilds only declared user chains. Include the complete union in
// both directions; rollback also removes chains absent from the original image.
// No built-in chain, foreign table, rule counter or unrelated jump is replayed.
func ufwRestorePayload(material ufwReloadMaterial, target string) ([]byte, error) {
	if len(material.Before) == 0 || len(material.Before) > firewall.UFWReadBytes || len(material.After) == 0 || len(material.After) > firewall.UFWReadBytes || secure.Hash(material.Before) != material.BeforeHash || secure.Hash(material.After) != material.AfterHash {
		return nil, errors.New("UFW 原生材料摘要或大小无效")
	}
	before, after, err := ufwReloadImages(material.Before, material.After, material.Family, material.BeforeKernel)
	if err != nil || !sameUFWReloadImage(before, material.BeforeKernel) || !sameUFWReloadImage(after, material.AfterKernel) {
		return nil, errors.New("UFW 重载材料缺少完整的原状态与候选内核证明")
	}
	raw, image := material.After, after
	if target == "previous" {
		raw, image = material.Before, before
	} else if target != "candidate" {
		return nil, errors.New("UFW 重载目标无效")
	}
	var text strings.Builder
	text.WriteString("*filter\n")
	for index, chain := range image {
		if before[index].Present || after[index].Present {
			text.WriteString(":" + chain.Name + " - [0:0]\n")
		}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I ") {
			text.WriteString(line + "\n")
		}
	}
	for index, chain := range image {
		if !chain.Present && (before[index].Present || after[index].Present) {
			text.WriteString("-X " + chain.Name + "\n")
		}
	}
	text.WriteString("COMMIT\n")
	out := []byte(text.String())
	if len(out) > firewall.UFWReadBytes {
		return nil, errors.New("UFW 封闭重载程序超过 2 MiB")
	}
	return out, nil
}
