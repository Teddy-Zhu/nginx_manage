package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/firewall"
)

const firewallObjectLimit = 16384

// Keep all five metadata views comfortably below the bounded IPC response.
// An oversized view is unavailable as a whole, never a successful prefix.
func boundedFirewallTables(tables []firewall.Table) error {
	raw, e := json.Marshal(tables)
	if e != nil || len(raw) > 384<<10 {
		return errors.New("firewall metadata exceeds budget")
	}
	return nil
}

func firewallAttribute(value string) bool {
	return value == "" || len(value) <= 32 && firewallName(value)
}

func firewallName(name string) bool {
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// Only structural metadata leaves root. Match expressions, IP sets, comments,
// counters and raw system rules are intentionally absent from the public model.
func nftInventory(raw []byte) ([]firewall.Table, error) {
	return nftInventoryReadback(raw, nil)
}

func nftInventoryReadback(raw []byte, budget *nftReadbackBudget) ([]firewall.Table, error) {
	var doc struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if len(raw) > nftRulesetReadBytes || json.Unmarshal(raw, &doc) != nil || doc.Objects == nil || len(doc.Objects) > firewallObjectLimit {
		return nil, errors.New("invalid nftables inventory")
	}
	capacity := nftReadbackBudget{}
	if budget != nil {
		capacity = nftReadbackBudget{Bytes: len(raw), NumberGrowth: nftNumberGrowth(raw), Objects: len(doc.Objects), Scopes: map[string]nftReadbackScope{}}
	}
	tables := []firewall.Table{}
	indices := map[string]int{}
	chains := map[string][2]int{}
	type identity struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
	}
	for _, item := range doc.Objects {
		if len(item) != 1 {
			return nil, errors.New("ambiguous nftables object")
		}
		if value, ok := item["metainfo"]; ok && budget != nil {
			var meta struct {
				Schema int `json:"json_schema_version"`
			}
			if json.Unmarshal(value, &meta) != nil || meta.Schema != 1 || capacity.Schema != 0 {
				capacity.Schema = -1
			} else {
				capacity.Schema = meta.Schema
			}
		}
		if value, ok := item["table"]; ok {
			var t identity
			if json.Unmarshal(value, &t) != nil || !firewallName(t.Family) || !firewallName(t.Name) {
				return nil, errors.New("invalid nftables table")
			}
			key := t.Family + "\x00" + t.Name
			if _, ok = indices[key]; ok {
				return nil, errors.New("duplicate nftables table")
			}
			indices[key] = len(tables)
			tables = append(tables, firewall.Table{Family: t.Family, Name: t.Name, Chains: []firewall.Chain{}})
		}
	}
	for _, item := range doc.Objects {
		if value, ok := item["chain"]; ok {
			var c struct {
				identity
				Type     string `json:"type"`
				Hook     string `json:"hook"`
				Priority *int64 `json:"prio"`
				Policy   string `json:"policy"`
			}
			if json.Unmarshal(value, &c) != nil || !firewallName(c.Name) || !firewallAttribute(c.Hook) || !firewallAttribute(c.Type) || !firewallAttribute(c.Policy) {
				return nil, errors.New("invalid nftables chain")
			}
			ti, exists := indices[c.Family+"\x00"+c.Table]
			if !exists {
				return nil, errors.New("orphan nftables chain")
			}
			key := c.Family + "\x00" + c.Table + "\x00" + c.Name
			if _, exists = chains[key]; exists {
				return nil, errors.New("duplicate nftables chain")
			}
			chains[key] = [2]int{ti, len(tables[ti].Chains)}
			tables[ti].Chains = append(tables[ti].Chains, firewall.Chain{Name: c.Name, Type: c.Type, Hook: c.Hook, Priority: c.Priority, Policy: c.Policy})
			if budget != nil {
				// The raw value plus the smallest possible outer JSON object
				// is a lower bound; separators/whitespace stay in the baseline.
				capacity.Scopes[key] = nftReadbackScope{Bytes: len(value) + len("chain") + 5, NumberGrowth: nftNumberGrowth(value), Objects: 1}
			}
		}
	}
	for _, item := range doc.Objects {
		if value, ok := item["rule"]; ok {
			var r struct {
				Family string                       `json:"family"`
				Table  string                       `json:"table"`
				Chain  string                       `json:"chain"`
				Expr   []map[string]json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(value, &r) != nil {
				return nil, errors.New("invalid nftables rule")
			}
			index, exists := chains[r.Family+"\x00"+r.Table+"\x00"+r.Chain]
			if !exists {
				return nil, errors.New("orphan nftables rule")
			}
			c := &tables[index[0]].Chains[index[1]]
			c.Rules++
			if budget != nil {
				key := nftReadbackKey(r.Family, r.Table, r.Chain)
				scope := capacity.Scopes[key]
				scope.Bytes += len(value) + len("rule") + 5
				scope.NumberGrowth += nftNumberGrowth(value)
				scope.Objects++
				scope.Rules++
				capacity.Scopes[key] = scope
			}
			for _, expr := range r.Expr {
				if jump, ok := expr["jump"]; ok {
					var target struct {
						Target string `json:"target"`
					}
					if json.Unmarshal(jump, &target) != nil {
						return nil, errors.New("invalid nftables jump")
					}
					c.DockerUserJump = c.DockerUserJump || target.Target == "DOCKER-USER"
				}
			}
		}
	}
	orderFirewallTables(tables)
	if e := boundedFirewallTables(tables); e != nil {
		return nil, e
	}
	if budget != nil {
		*budget = capacity
	}
	return tables, nil
}

func xtablesInventory(raw []byte, family string) ([]firewall.Table, error) {
	tables := []firewall.Table{}
	seen := map[string]bool{}
	chains := map[string]int{}
	current := -1
	objects := 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			// nft-save may report incompatible native tables in a comment
			// while exiting successfully; that is an incomplete view.
			if !strings.HasPrefix(line, "# Generated by ") && !strings.HasPrefix(line, "# Completed on ") {
				return nil, errors.New("xtables save reported an incomplete view")
			}
			continue
		}
		objects++
		if objects > firewallObjectLimit {
			return nil, errors.New("xtables inventory exceeds budget")
		}
		switch {
		case strings.HasPrefix(line, "*"):
			name := line[1:]
			if current != -1 || !firewallName(name) || seen[name] {
				return nil, errors.New("invalid xtables table")
			}
			seen[name] = true
			current = len(tables)
			chains = map[string]int{}
			tables = append(tables, firewall.Table{Family: family, Name: name, Chains: []firewall.Chain{}})
		case line == "COMMIT":
			if current < 0 {
				return nil, errors.New("orphan xtables commit")
			}
			current = -1
		case strings.HasPrefix(line, ":"):
			words := strings.Fields(line[1:])
			if current < 0 || len(words) != 3 || !firewallName(words[0]) || !slices.Contains([]string{"-", "ACCEPT", "DROP"}, words[1]) {
				return nil, errors.New("invalid xtables chain")
			}
			if _, ok := chains[words[0]]; ok {
				return nil, errors.New("duplicate xtables chain")
			}
			chains[words[0]] = len(tables[current].Chains)
			c := firewall.Chain{Name: words[0], Policy: strings.ToLower(words[1])}
			if words[1] != "-" {
				c.Type = "builtin"
				c.Hook = strings.ToLower(words[0])
			}
			tables[current].Chains = append(tables[current].Chains, c)
		case strings.HasPrefix(line, "-A "):
			words := strings.Fields(line)
			if current < 0 || len(words) < 3 {
				return nil, errors.New("invalid xtables rule")
			}
			ci, ok := chains[words[1]]
			if !ok {
				return nil, errors.New("orphan xtables rule")
			}
			c := &tables[current].Chains[ci]
			c.Rules++
			// The target must be a real argument, not quoted comment text. The
			// small tokenizer handles the quoting emitted by iptables-save.
			args, e := xtablesWords(line)
			if e != nil {
				return nil, e
			}
			for i := 2; i < len(args); i++ {
				if args[i] == "--comment" {
					i++
					continue
				}
				if (args[i] == "-j" || args[i] == "--jump") && i+1 < len(args) && args[i+1] == "DOCKER-USER" {
					c.DockerUserJump = true
				}
			}
		default:
			return nil, errors.New("unsupported xtables save syntax")
		}
	}
	if scanner.Err() != nil || current != -1 {
		return nil, errors.New("incomplete xtables inventory")
	}
	orderFirewallTables(tables)
	if e := boundedFirewallTables(tables); e != nil {
		return nil, e
	}
	return tables, nil
}

func xtablesWords(line string) ([]string, error) {
	return xtablesQuotedWords(line, false)
}

// UFW's native application comments use single quotes; save output uses double
// quotes. This is only a rule tokenizer, never shell evaluation or an argv API.
func xtablesQuotedWords(line string, singleQuotes bool) ([]string, error) {
	args := []string{}
	var word strings.Builder
	var quote rune
	escape := false
	started := false
	for _, r := range line {
		if escape {
			word.WriteRune(r)
			escape = false
			started = true
			continue
		}
		if r == '\\' {
			escape = true
			started = true
			continue
		}
		if r == '"' || singleQuotes && r == '\'' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			started = true
			continue
		}
		if quote == 0 && (r == ' ' || r == '\t') {
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		if r < 32 || r == 127 {
			return nil, errors.New("invalid xtables argument")
		}
		word.WriteRune(r)
		started = true
	}
	if quote != 0 || escape {
		return nil, errors.New("incomplete xtables quoting")
	}
	if started {
		args = append(args, word.String())
	}
	return args, nil
}

func orderFirewallTables(tables []firewall.Table) {
	for i := range tables {
		sort.Slice(tables[i].Chains, func(a, b int) bool { return tables[i].Chains[a].Name < tables[i].Chains[b].Name })
	}
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].Family != tables[j].Family {
			return tables[i].Family < tables[j].Family
		}
		return tables[i].Name < tables[j].Name
	})
}
func iptablesVersionTool(name string) string {
	for _, family := range []string{"iptables", "ip6tables"} {
		for _, suffix := range []string{"", "-save", "-restore"} {
			if name == family+suffix || name == family+"-nft"+suffix || name == family+"-legacy"+suffix {
				return family + suffix
			}
		}
	}
	return ""
}

func firewallVersion(raw []byte) (string, string, error) {
	version := strings.TrimSpace(string(raw))
	name, release, found := strings.Cut(version, " ")
	if len(version) > 256 || strings.ContainsAny(version, "\r\n\x00") || !found || iptablesVersionTool(name) == "" || !strings.HasPrefix(release, "v") {
		return "", "", errors.New("unknown xtables version output")
	}
	backend := "unknown"
	if strings.HasSuffix(version, "(nf_tables)") {
		backend = "nftables"
	} else if strings.HasSuffix(version, "(legacy)") {
		backend = "legacy"
	}
	if backend == "unknown" {
		return "", version, errors.New("xtables backend is unconfirmed")
	}
	return backend, version, nil
}
func readXtables(ctx context.Context, variant, family string, dockerHook *dockerFirewallHook) firewall.Ruleset {
	out := firewall.Ruleset{ID: "iptables-" + variant + "-" + family, Backend: map[string]string{"nft": "nftables", "legacy": "legacy"}[variant], Family: family, Tables: []firewall.Table{}, Reason: "工具或后端不可用"}
	name := "iptables-" + variant
	if family == "ipv6" {
		name = "ip6tables-" + variant
	}
	version, e := firewallRead(ctx, name, "version", 1024)
	if e != nil {
		return out
	}
	backend, text, e := firewallVersion(version)
	if e != nil || backend != out.Backend || !iptablesToolVersionMatches(name, text) {
		out.Reason = "工具后端、地址族或命令角色与声明不一致"
		return out
	}
	saveVersion, e := firewallRead(ctx, name+"-save", "version", 1024)
	if e != nil {
		out.Reason = "规则导出工具的后端无法确认"
		return out
	}
	saveBackend, text, e := firewallVersion(saveVersion)
	if e != nil || saveBackend != backend || !iptablesToolVersionMatches(name+"-save", text) {
		out.Reason = "规则导出工具与命令的后端或地址族不一致"
		return out
	}
	raw, e := firewallRead(ctx, name+"-save", "rules", 1<<20)
	if e != nil {
		out.Reason = "无法完整读取该地址族的内核规则"
		return out
	}
	out.Tables, e = xtablesInventory(raw, family)
	if e != nil {
		out.Tables = []firewall.Table{}
		out.Reason = "规则结构未能在预算内完整解析"
		return out
	}
	out.Available = true
	out.Reason = ""
	if dockerHook != nil {
		image, err := parseIPTablesImage(raw, family)
		if err != nil {
			*dockerHook = dockerFirewallHook{Reason: "原生规则未能完整核对 DOCKER-USER 挂接"}
		} else {
			*dockerHook = observeDockerFirewallHook(image)
		}
	}
	return out
}

func classifyFirewall(out *firewall.Observation) {
	nft, legacy, ufwMarker, firewalldMarker, dockerNFT, dockerIPT := false, false, false, false, false, false
	complete := len(out.Rulesets) == 5
	for _, ruleset := range out.Rulesets {
		complete = complete && ruleset.Available
		for _, table := range ruleset.Tables {
			if table.Name == "firewalld" {
				firewalldMarker = true
			}
			if table.Name == "docker-bridges" && ruleset.ID == "nftables" && slices.Contains([]string{"ip", "ip6"}, table.Family) {
				dockerNFT = true
				out.Docker.Evidence = append(out.Docker.Evidence, table.Family+" docker-bridges")
			}
			for _, c := range table.Chains {
				if strings.HasPrefix(c.Name, "ufw-") {
					ufwMarker = true
				}
				active := c.Rules > 0 || c.Policy == "drop" || c.Policy == "reject"
				if active && ruleset.Backend == "nftables" {
					nft = true
				}
				if active && ruleset.Backend == "legacy" {
					legacy = true
				}
				if table.Name == "filter" && c.Name == "DOCKER-USER" {
					dockerIPT = true
					linked := false
					for _, base := range table.Chains {
						linked = linked || base.Name == "FORWARD" && base.DockerUserJump
					}
					out.Docker.Evidence = append(out.Docker.Evidence, ruleset.ID+" / "+table.Family+" filter DOCKER-USER / FORWARD jump="+strconv.FormatBool(linked))
				}
			}
		}
	}
	switch {
	case nft && legacy:
		out.Backend = "mixed"
		out.Warnings = append(out.Warnings, "nftables 与 legacy 均有运行策略，不能混用写入后端")
	case nft:
		out.Backend = "nftables"
	case legacy:
		out.Backend = "legacy"
	default:
		out.Backend = "unknown"
	}
	if !complete {
		out.Warnings = append(out.Warnings, "部分内核规则视图不可用，已观察到的后端不代表已排除其他规则体系")
	}
	firewalldOn := out.Firewalld.Running != nil && *out.Firewalld.Running
	ufwOn := out.UFW.Enabled != nil && *out.UFW.Enabled || out.UFW.Active != nil && *out.UFW.Active
	switch {
	case firewalldOn && ufwOn:
		out.Manager = "conflict"
		out.Warnings = append(out.Warnings, "firewalld 与 UFW 同时启用，须先由本机核对所有权")
	case firewalldOn:
		out.Manager = "firewalld"
	case ufwOn:
		out.Manager = "ufw"
	case out.Firewalld.Running == nil || out.UFW.Enabled == nil && out.UFW.Installed || out.UFW.Active == nil && out.UFW.Installed:
		out.Manager = "unknown"
	case ufwMarker || firewalldMarker:
		out.Manager = "unknown"
		out.Warnings = append(out.Warnings, "存在管理器规则标记，但当前管理器状态不一致，不能视为可直接接管")
	default:
		out.Manager = "direct-candidate"
	}
	if out.UFW.Enabled != nil && out.UFW.Active != nil && *out.UFW.Enabled != *out.UFW.Active {
		out.Warnings = append(out.Warnings, "UFW 启用配置与当前状态不一致")
	}
	switch {
	case dockerNFT && dockerIPT:
		out.Docker.BackendHint = "mixed"
	case dockerNFT:
		out.Docker.BackendHint = "nftables"
	case dockerIPT:
		out.Docker.BackendHint = "iptables"
	}
	sort.Strings(out.Docker.Evidence)
	out.Docker.Evidence = slices.Compact(out.Docker.Evidence)
	out.Docker.Reason = "规则标记仅为线索；尚未核对 Docker 实例、原始目的地址及实际转发路径"
	if dockerNFT {
		out.Docker.Reason = "检测到 Docker 原生 nftables 表标记；该路径按实验适配保持只读，须核对实例与 hook/priority"
	}
	if dockerNFT && dockerIPT {
		out.Docker.Reason = "同时存在 Docker nftables 与 DOCKER-USER 标记，不能确认单一转发后端"
	}
	out.Reason = "当前仅支持读取；观测结果不能证明规则所有权或外部可达性"
}
