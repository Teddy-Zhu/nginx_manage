package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type ufwReloadChain struct {
	Name    string
	Present bool
	Rules   []string
}
type ufwReloadFamily struct {
	Family, Backend, ToolVersion, SaveVersion string
	Chains                                    []ufwReloadChain
}
type ufwReloadBaseline struct {
	Hash, Backend string
	Chains, Rules int
}

// prepend and delete can reload both enabled families through iptables-restore.
// Verify all chains the writer may declare, not only the new input selectors.
// The hash excludes counters and save timestamps; no raw host rules leave root.
func readUFWReloadBaseline(ctx context.Context, configuration ufwConfigurationSnapshot, ipv6 bool) (ufwReloadBaseline, error) {
	var out ufwReloadBaseline
	families := []ufwReloadFamily{}
	for _, item := range []struct{ family, source, tool string }{
		{"ipv4", "/etc/ufw/user.rules", "iptables"},
		{"ipv6", "/etc/ufw/user6.rules", "ip6tables"},
	} {
		if item.family == "ipv6" && !ipv6 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		version, err := firewallReadCommand(ctx, item.tool, "version", 1024, true)
		if err != nil {
			return out, errors.New("UFW 默认内核工具及后端不可核对")
		}
		backend, toolVersion, err := firewallVersion(version)
		if err != nil || out.Backend != "" && out.Backend != backend {
			return out, errors.New("UFW IPv4/IPv6 默认内核后端不一致或不可核对")
		}
		variant := map[string]string{"nftables": "nft", "legacy": "legacy"}[backend]
		save := item.tool + "-" + variant + "-save"
		version, err = firewallReadCommand(ctx, save, "version", 1024, true)
		if err != nil {
			return out, errors.New("UFW 内核规则导出工具版本不可核对")
		}
		saveBackend, saveVersion, err := firewallVersion(version)
		if err != nil || saveBackend != backend {
			return out, errors.New("UFW 默认命令与规则导出工具的后端不一致")
		}
		raw, err := firewallReadCommand(ctx, save, "rules", 1<<20, true)
		if err != nil {
			return out, errors.New("UFW 内核规则未完整读取或返回警告")
		}
		expected, err := ufwReloadConfigured(configuration.Contents[item.source], item.family)
		if err != nil {
			return out, err
		}
		chains, err := ufwReloadKernel(raw, item.family)
		if err != nil {
			return out, err
		}
		for _, chain := range chains {
			if !chain.Present && len(expected[chain.Name]) != 0 || !slices.Equal(chain.Rules, expected[chain.Name]) {
				return out, fmt.Errorf("UFW %s 重载范围的运行规则与原配置不一致：%s", item.family, chain.Name)
			}
			if chain.Present {
				out.Chains++
			}
			out.Rules += len(chain.Rules)
		}
		if out.Rules > firewall.MaxEntries {
			return out, errors.New("UFW 重载范围的运行规则合计超过 8192 条")
		}
		families = append(families, ufwReloadFamily{item.family, backend, toolVersion, saveVersion, chains})
		out.Backend = backend
	}
	raw, err := json.Marshal(families)
	if err != nil {
		return out, err
	}
	out.Hash = secure.Hash(append([]byte("ufw:reload-kernel:v1:\x00"), raw...))
	return out, nil
}

// Restore applies -I at the head of its chain, independently of where that
// expression appeared in the file. Tuple order alone cannot prove this scope.
func ufwReloadConfigured(raw []byte, family string) (map[string][]string, error) {
	if _, err := parseUFWNative(raw, family, true); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	inserted := map[string][]string{}
	for _, name := range ufwNativeChainNames(family) {
		out[name] = []string{}
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-I ") {
			continue
		}
		count++
		if count > firewall.MaxEntries {
			return nil, errors.New("UFW 重载源文件的报文规则超过 8192 条")
		}
		chain, key, insert, err := ufwKernelRuleKey(line, family, true)
		if err != nil {
			return nil, err
		}
		if _, known := out[chain]; !known {
			return nil, errors.New("UFW 用户文件写入了未知重载链")
		}
		if insert {
			inserted[chain] = append(inserted[chain], key)
		} else {
			out[chain] = append(out[chain], key)
		}
	}
	for chain, rules := range inserted {
		slices.Reverse(rules)
		out[chain] = append(rules, out[chain]...)
	}
	return out, nil
}

func ufwReloadKernel(raw []byte, family string) ([]ufwReloadChain, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return nil, errors.New("UFW 内核规则导出的大小或编码无效")
	}
	// Validate the entire export first. Incomplete foreign tables or a successful
	// prefix must not be used to claim a complete observation of the filter table.
	tables, err := xtablesInventory(raw, family)
	if err != nil {
		return nil, errors.New("UFW 内核规则导出结构不完整或超限")
	}
	indices := map[string]int{}
	out := []ufwReloadChain{}
	for _, name := range ufwNativeChainNames(family) {
		indices[name] = len(out)
		out = append(out, ufwReloadChain{Name: name, Rules: []string{}})
	}
	filter := false
	for _, table := range tables {
		if table.Name != "filter" {
			continue
		}
		filter = true
		for _, chain := range table.Chains {
			if index, known := indices[chain.Name]; known {
				if chain.Type != "" || chain.Policy != "-" {
					return nil, errors.New("UFW 重载链不是普通用户链")
				}
				out[index].Present = true
			}
		}
	}
	if !filter || len(out) == 0 || !out[0].Present {
		return nil, errors.New("UFW filter 表或用户入站链缺失")
	}
	current := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "*") {
			current = line[1:]
		} else if line == "COMMIT" {
			current = ""
		} else if current == "filter" && strings.HasPrefix(line, "-A ") {
			words, err := xtablesWords(line)
			if err != nil || len(words) < 3 {
				return nil, errors.New("UFW 内核规则无法完整分词")
			}
			index, known := indices[words[1]]
			if !known {
				continue
			}
			_, key, _, err := ufwKernelRuleKey(line, family, false)
			if err != nil {
				return nil, err
			}
			out[index].Rules = append(out[index].Rules, key)
		}
	}
	return out, nil
}
