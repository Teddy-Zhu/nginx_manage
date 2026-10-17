package agent

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"nginxpanel/internal/firewall"
)

func ufwPolicyProgram(record *firewallPolicyRecord, owner string) (*firewall.UFWProgram, error) {
	if record == nil {
		return &firewall.UFWProgram{Rules: []firewall.UFWRule{}, Entries: []firewall.PreviewEntry{}}, nil
	}
	if !validID(record.OperationID) || !validID(record.PlanID) || record.Version < 1 || record.Policy.Backend != "ufw" || record.Marker != firewall.UFWCommentPrefix+owner+":"+record.PlanID+":" || validateFirewallProtectionBasis(record.ProtectionBasis) != nil {
		return nil, errors.New("UFW 已确认策略身份无效")
	}
	hash, err := firewall.PolicyDigest(record.Policy)
	program, programErr := firewall.CompileUFWRuntime(record.Policy, record.Protections, record.Action, owner, record.PlanID)
	if err != nil || hash != record.PolicyHash || programErr != nil || program.Hash != record.ProgramHash || len(program.Rules) > ufwDryRunCommands {
		return nil, errors.New("UFW 已确认策略程序无法重新核对")
	}
	return program, nil
}

func ufwNativeProgram(program *firewall.UFWProgram) ([]ufwNativeRule, error) {
	out := []ufwNativeRule{}
	for index, rule := range program.Rules {
		if index >= len(program.Entries) {
			return nil, errors.New("UFW 原生程序条目不完整")
		}
		entry, err := expectedUFWNative(rule, program.Entries[index])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if len(out) != len(program.Entries) {
		return nil, errors.New("UFW 原生程序条目不一致")
	}
	return out, nil
}

func hasUFWManagedMarker(text string) bool {
	return strings.Contains(text, "nginxpanel:host:") || strings.Contains(strings.ToLower(text), hex.EncodeToString([]byte("nginxpanel:host:")))
}

func sameUFWPolicyRecord(a, b *firewallPolicyRecord) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// A current typed packet block and the original root confirmation are both
// required. Foreign rules may surround owned blocks; numbering is never used.
func ufwUnownedRules(file *ufwNativeFile, family string, owned []ufwNativeRule) (*ufwNativeFile, error) {
	if file == nil {
		return nil, errors.New("UFW 原生文件缺失")
	}
	expected := []ufwNativeRule{}
	for _, rule := range owned {
		if rule.Family == family {
			expected = append(expected, rule)
		}
	}
	out := *file
	out.Rules = []ufwNativeRule{}
	index := 0
	for _, rule := range file.Rules {
		if index < len(expected) && ufwNativeRuleEqual(rule, expected[index]) {
			index++
			continue
		}
		if hasUFWManagedMarker(rule.Tuple) || hasUFWManagedMarker(strings.Join(rule.Packets, "\n")) {
			return nil, errors.New("UFW 受管标记或原生报文块与原确认回执不一致")
		}
		out.Rules = append(out.Rules, rule)
	}
	if index != len(expected) || hasUFWManagedMarker(strings.Join(file.Logging, "\n")) || hasUFWManagedMarker(strings.Join(file.Rate, "\n")) {
		return nil, errors.New("UFW 已确认规则缺失、重排或辅助段存在未知标记")
	}
	return &out, nil
}

func verifyUFWOwnedConfiguration(snapshot ufwConfigurationSnapshot, ipv6 bool, owned []ufwNativeRule) error {
	for path, raw := range snapshot.Contents {
		family := ""
		if path == "/etc/ufw/user.rules" {
			family = "ipv4"
		} else if path == "/etc/ufw/user6.rules" && ipv6 {
			family = "ipv6"
		}
		if family == "" {
			if hasUFWManagedMarker(string(raw)) {
				return errors.New("UFW 非受管源文件或未启用地址族存在本应用标记")
			}
			continue
		}
		file, err := parseUFWNative(raw, family, true)
		if err != nil {
			return err
		}
		if _, err = ufwUnownedRules(file, family, owned); err != nil {
			return err
		}
	}
	for _, rule := range owned {
		if rule.Family == "ipv6" && !ipv6 {
			return errors.New("UFW 已确认 IPv6 规则须在原地址族启用后移除")
		}
	}
	return nil
}

func ufwCurrentConfirmed(dataDir, owner string) (*firewallPolicyRecord, error) {
	v, err := loadUFWChange(dataDir)
	if err != nil || v == nil {
		return nil, err
	}
	r, err := loadUFWReceipt(dataDir, v.Operation.ID)
	if err != nil || !ufwChangeReceiptMatches(r, v) {
		return nil, errors.New("UFW 原业务回执无法完整核对")
	}
	if !slices.Contains([]string{"succeeded", "rolled_back", "failed"}, v.Operation.State) {
		return nil, errors.New("UFW 原业务操作尚未结束，禁止选择新的确认基线")
	}
	if v.Transition.Owner != owner {
		if v.Confirmed == nil || v.Confirmed.Action == "remove" {
			return nil, nil
		}
		return nil, errors.New("UFW 已确认受管规则属于其他本机授权")
	}
	return v.Confirmed, nil
}
