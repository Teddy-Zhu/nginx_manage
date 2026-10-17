package agent

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

func dockerIPTablesReserved(value string) bool {
	return strings.HasPrefix(value, firewall.IPTablesDockerChain) || strings.HasPrefix(value, "nginxpanel:docker:")
}

// Compare a rule image with a compiled expected generation. A live executor
// must additionally validate its local durable intent and grant; matching
// markers or an API-supplied program cannot supply execution authority.
func proveDockerIPTablesGeneration(image iptablesImage, generation *firewall.IPTablesGeneration) error {
	if generation == nil {
		return proveEmptyDockerNamespace(image)
	}
	prefix := firewall.IPTablesDockerChain + "-"
	if image.Family != generation.Family || !strings.HasPrefix(generation.Chain, prefix) || len(generation.Chain) != len(prefix)+10 || strings.Trim(generation.Chain[len(prefix):], "0123456789abcdef") != "" || len(generation.Rules) == 0 {
		return errors.New("Docker 预期代际地址族、身份或规则无效")
	}
	for _, table := range image.Tables {
		for _, chain := range table.Chains {
			owned := table.Name == "filter" && (chain.Name == firewall.IPTablesDockerChain || chain.Name == generation.Chain)
			if dockerIPTablesReserved(chain.Name) && !owned {
				return errors.New("存在未经原 Docker 代际证明的保留链，拒绝接管或删除")
			}
			if owned {
				if chain.Policy != "-" {
					return errors.New("Docker 受管链不是普通用户链")
				}
				if chain.Name == firewall.IPTablesDockerChain {
					if len(chain.Rules) != 1 || !slices.Equal(chain.Rules[0], generation.Pointer) {
						return errors.New("Docker 稳定入口的唯一指针与原代际不一致")
					}
					continue
				}
				if len(chain.Rules) != len(generation.Rules) {
					return errors.New("Docker 代际规则数量与原完整程序不一致")
				}
				for index, rule := range generation.Rules {
					expected, err := dockerIPTablesRuleKey(chain.Name, image.Family, rule.Arguments)
					if err != nil {
						return err
					}
					actual, err := dockerIPTablesRuleKey(chain.Name, image.Family, chain.Rules[index])
					if err != nil || actual != expected {
						return errors.New("Docker 代际的完整规则、顺序、条件或身份发生漂移")
					}
				}
				continue
			}
			for ordinal, rule := range chain.Rules {
				if table.Name == "filter" && chain.Name == "DOCKER-USER" && ordinal == 0 && slices.Equal(rule, generation.Hook) {
					continue
				}
				for _, arg := range rule {
					if dockerIPTablesReserved(arg) {
						return errors.New("其他链、位置或所有者引用 Docker 受管范围，保留现场")
					}
				}
			}
		}
	}
	entry, anchor, rules := image.chain("filter", "DOCKER-USER"), image.chain("filter", firewall.IPTablesDockerChain), image.chain("filter", generation.Chain)
	if entry == nil || entry.Policy != "-" || len(entry.Rules) == 0 || !slices.Equal(entry.Rules[0], generation.Hook) || anchor == nil || rules == nil {
		return errors.New("Docker 首位入口、稳定指针或完整代际链缺失")
	}
	return nil
}

func dockerIPTablesForeignImage(image iptablesImage, generation *firewall.IPTablesGeneration) (iptablesImage, error) {
	if err := proveDockerIPTablesGeneration(image, generation); err != nil {
		return iptablesImage{}, err
	}
	raw, err := json.Marshal(image)
	if err != nil {
		return iptablesImage{}, err
	}
	var foreign iptablesImage
	if err = json.Unmarshal(raw, &foreign); err != nil {
		return foreign, err
	}
	if generation != nil {
		for ti := range foreign.Tables {
			table := &foreign.Tables[ti]
			if table.Name != "filter" {
				continue
			}
			chains := []iptablesImageChain{}
			for _, chain := range table.Chains {
				if chain.Name == firewall.IPTablesDockerChain || chain.Name == generation.Chain {
					continue
				}
				if chain.Name == "DOCKER-USER" {
					chain.Rules = chain.Rules[1:]
				}
				chains = append(chains, chain)
			}
			table.Chains = chains
		}
	}
	return foreign, proveEmptyDockerNamespace(foreign)
}

func renderDockerIPTablesChange(before iptablesImage, old, next *firewall.IPTablesGeneration) (iptablesImage, []byte, error) {
	if next != nil {
		if hook := observeDockerFirewallHook(before); !hook.Observed {
			return iptablesImage{}, nil, errors.New("Docker 候选代际的原始挂接无法核对：" + hook.Reason)
		}
	}
	return renderIPTablesScopedChange(before, old, next, iptablesGenerationScope{Entry: "DOCKER-USER", Anchor: firewall.IPTablesDockerChain, UserEntry: true, Prove: proveDockerIPTablesGeneration})
}

func makeDockerIPTablesChangeMaterial(before iptablesImage, old, next *firewall.IPTablesGeneration) (iptablesChangeMaterial, error) {
	var out iptablesChangeMaterial
	after, candidate, err := renderDockerIPTablesChange(before, old, next)
	if err != nil {
		return out, err
	}
	restored, previous, err := renderDockerIPTablesChange(after, next, old)
	if err != nil {
		return out, err
	}
	originalForeign, err := dockerIPTablesForeignImage(before, old)
	if err != nil {
		return out, err
	}
	candidateForeign, err := dockerIPTablesForeignImage(after, next)
	if err != nil || candidateForeign.hash() != originalForeign.hash() {
		return out, errors.New("Docker 候选转换涉及其他规则，拒绝生成批次")
	}
	restoredForeign, err := dockerIPTablesForeignImage(restored, old)
	if err != nil || originalForeign.hash() != restoredForeign.hash() {
		return out, errors.New("Docker 正反向代际转换未完整还原原受管范围及其他规则")
	}
	if len(candidate) > firewall.IPTablesProgramBytes || len(previous) > firewall.IPTablesProgramBytes {
		return out, errors.New("Docker 候选或补偿批次超过 2 MiB")
	}
	binary := ""
	if next != nil {
		binary = next.Binary
	} else {
		binary = old.Binary
	}
	return iptablesChangeMaterial{Family: before.Family, Binary: binary, BeforeHash: before.hash(), AfterHash: after.hash(), CandidateHash: secure.Hash(candidate), PreviousHash: secure.Hash(previous), Before: before, After: after, Candidate: candidate, Previous: previous}, nil
}
