package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type FirewallInput struct {
	Mode        string            `json:"mode"`
	BaseVersion *int64            `json:"base_version,omitempty"`
	Backend     string            `json:"backend"`
	Interfaces  map[string]string `json:"interfaces"`
}
type FirewallInterface struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Resolved bool   `json:"resolved"`
	Observed bool   `json:"observed"`
}
type FirewallPlan struct {
	Mode           string              `json:"mode"`
	State          string              `json:"state"`
	SourceBackend  string              `json:"source_backend"`
	TargetBackend  string              `json:"target_backend"`
	BaseVersion    int64               `json:"base_version"`
	SavedVersion   int64               `json:"saved_version"`
	SourceRules    int                 `json:"source_rules"`
	PreservedRules int                 `json:"preserved_rules"`
	ReplacedRules  int                 `json:"replaced_rules"`
	TotalRules     int                 `json:"total_rules"`
	PolicyHash     string              `json:"policy_hash"`
	Interfaces     []FirewallInterface `json:"interfaces"`
	Entries        []firewall.Rule     `json:"entries"`
	Truncated      bool                `json:"truncated"`
	Warnings       []string            `json:"warnings"`
}
type firewallImportState struct {
	Input           FirewallInput       `json:"input"`
	Before          firewall.PolicyView `json:"before"`
	Candidate       firewall.Policy     `json:"candidate"`
	Resolved        bool                `json:"resolved"`
	ImportedVersion int64               `json:"imported_version"`
}

func (in FirewallInput) validate() error {
	if in.Mode == "" || in.Mode == "preserve" {
		if in.BaseVersion != nil || in.Backend != "" || len(in.Interfaces) > 0 {
			return fault.Invalid("保留目标防火墙时不能指定替换版本、后端或网卡映射")
		}
		return nil
	}
	if in.Mode != "merge" && in.Mode != "replace" {
		return fault.Invalid("防火墙迁入模式须为 preserve、merge 或 replace")
	}
	if in.BaseVersion != nil && (*in.BaseVersion < 0 || *in.BaseVersion == math.MaxInt64) {
		return fault.Invalid("防火墙基础版本无效")
	}
	if len(in.Interfaces) > 256 {
		return fault.Invalid("防火墙网卡映射最多 256 项")
	}
	for source, target := range in.Interfaces {
		if source == "" || len(source) > 15 || len(target) > 15 || strings.ContainsAny(source+target, "\x00\r\n") {
			return fault.Invalid("防火墙网卡映射无效")
		}
	}
	_, err := (firewall.Policy{Backend: in.Backend, Rules: []firewall.Rule{}}).Normalize()
	return err
}
func (s *Service) prepareFirewall(ctx context.Context, st *storedPlan, in FirewallInput) error {
	if err := in.validate(); err != nil {
		return err
	}
	if err := firewall.ValidateTransfer(st.Payload.Firewall); err != nil {
		return err
	}
	if in.Mode == "" || in.Mode == "preserve" {
		return nil
	}
	if st.Payload.Firewall == nil {
		return fault.Invalid("配置包未包含防火墙规则，不能合并或替换目标策略")
	}
	if s.Firewall == nil {
		return fault.Unavailable("防火墙策略服务未配置")
	}
	before, err := s.Firewall.Policy(ctx)
	if err != nil {
		return err
	}
	if before.Version == math.MaxInt64 {
		return fault.Conflict("目标防火墙版本已达上限，不能继续迁入")
	}
	if in.BaseVersion != nil && *in.BaseVersion != before.Version {
		return fault.Conflict("目标防火墙版本已变化，请重新读取并准备迁移")
	}
	if in.Mode == "merge" && len(before.Policy.Rules) > 0 && before.Policy.Backend != in.Backend {
		return fault.Conflict("合并须保留目标既有防火墙后端")
	}
	base := before.Version
	in.BaseVersion = &base
	st.Firewall = &firewallImportState{Input: in, Before: before, Resolved: true}
	sourcePolicy, err := (firewall.Policy{Backend: st.Payload.Firewall.SourceBackend, Rules: st.Payload.Firewall.Rules}).Normalize()
	if err != nil {
		return err
	}
	known := map[string]bool{}
	priorities := map[int]bool{}
	rules := []firewall.Rule{}
	if in.Mode == "merge" {
		rules = append(rules, before.Policy.Rules...)
		for _, rule := range before.Policy.Rules {
			priorities[rule.Priority] = true
		}
	}
	for index, source := range sourcePolicy.Rules {
		if priorities[source.Priority] {
			return fault.Conflict("源与目标防火墙规则优先级重叠，请调整顺序后重新准备合并")
		}
		rule := source
		// Preserve the canonical source order when priority ties use the new IDs.
		rule.ID = firewallRuleID(st.Plan.ID, index)
		if source.Interface != "" {
			known[source.Interface] = true
			mapped, ok := in.Interfaces[source.Interface]
			if ok {
				rule.Interface = mapped
			} else {
				st.Firewall.Resolved = false
			}
		}
		rules = append(rules, rule)
	}
	for name := range in.Interfaces {
		if !known[name] {
			return fault.Invalid("防火墙网卡映射未对应源规则的绑定接口")
		}
	}
	policy, err := (firewall.Policy{Backend: in.Backend, Rules: rules}).Normalize()
	if err != nil {
		return err
	}
	st.Firewall.Candidate = policy
	return nil
}
func firewallRuleID(planID string, index int) string {
	hash := secure.Hash([]byte(planID + "\x00firewall"))
	return fmt.Sprintf("%s-%04x-%s-%s-%s", hash[:8], index, hash[12:16], hash[16:20], hash[20:32])
}
func (s *Service) checkFirewallBase(ctx context.Context, q firewall.PolicyReader, st *storedPlan) error {
	if st.Firewall == nil {
		return nil
	}
	current, err := s.Firewall.ReadPolicy(ctx, q)
	if err != nil {
		return err
	}
	currentHash, err := firewall.PolicyDigest(current.Policy)
	if err != nil {
		return err
	}
	beforeHash, err := firewall.PolicyDigest(st.Firewall.Before.Policy)
	if err != nil {
		return err
	}
	if current.Version != st.Firewall.Before.Version || currentHash != beforeHash {
		return fault.Conflict("目标防火墙期望策略已变化，请重新准备迁移")
	}
	return nil
}
func (s *Service) inspectFirewall(ctx context.Context, st *storedPlan, add func(string, string, string, string)) error {
	source := st.Payload.Firewall
	if source == nil {
		st.Plan.Firewall = nil
		return nil
	}
	info := &FirewallPlan{Mode: "preserve", State: "preserved", SourceBackend: source.SourceBackend, SourceRules: len(source.Rules), Interfaces: []FirewallInterface{}, Entries: []firewall.Rule{}, Warnings: []string{}}
	st.Plan.Firewall = info
	mapped := []firewall.Rule{}
	names := map[string]bool{}
	for _, r := range source.Rules {
		if r.Interface != "" {
			names[r.Interface] = true
		}
	}
	ordered := []string{}
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	if state := st.Firewall; state != nil {
		info.Mode, info.State, info.TargetBackend, info.BaseVersion, info.SavedVersion = state.Input.Mode, "pending_import", state.Candidate.Backend, state.Before.Version, state.ImportedVersion
		info.TotalRules = len(state.Candidate.Rules)
		if state.Input.Mode == "merge" {
			info.PreservedRules = len(state.Before.Policy.Rules)
		} else {
			info.ReplacedRules = len(state.Before.Policy.Rules)
		}
		var err error
		info.PolicyHash, err = firewall.PolicyDigest(state.Candidate)
		if err != nil {
			return err
		}
		existing := map[string]bool{}
		if state.Input.Mode == "merge" {
			for _, r := range state.Before.Policy.Rules {
				existing[r.ID] = true
			}
		}
		for _, r := range state.Candidate.Rules {
			if !existing[r.ID] {
				mapped = append(mapped, r)
			}
		}
		if !state.Resolved {
			add("firewall", "interfaces", "blocked", "源绑定接口须显式映射至目标接口，或用空字符串明确解除绑定；草稿也不隐式沿用源接口")
		}
		if err = s.checkFirewallBase(ctx, s.DB, st); err != nil {
			var known *fault.Error
			if !errors.As(err, &known) || known.Code != "CONFLICT" {
				return err
			}
			add("firewall", "policy", "blocked", "目标防火墙期望版本已变化，须重新准备迁移")
		}
		var enabled bool
		if err = s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='firewall'").Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			info.Warnings = append(info.Warnings, "目标防火墙模块保持停用，迁移不自动启用")
		}
		if state.Candidate.Backend == "firewalld" {
			if _, err = firewall.CompileFirewalld(state.Candidate); err != nil {
				var known *fault.Error
				if !errors.As(err, &known) {
					return err
				}
				info.Warnings = append(info.Warnings, "firewalld 编译受阻："+known.Message)
			}
			info.Warnings = append(info.Warnings, "目标 firewalld 当前仅支持独立主机 policy 编译预览；迁入后仍是未应用期望")
		} else if _, err = firewall.CompileNFT(state.Candidate); err != nil {
			info.Warnings = append(info.Warnings, "目标所选后端或规则路径尚不能由当前执行器应用；可保存期望，生效须完成目标适配")
		}
		info.Warnings = append(info.Warnings, "迁移只保存防火墙期望策略；内核规则保持原状，须单独生成含入口保护的计划并用新连接确认")
		add("firewall", "policy", "review", fmt.Sprintf("%s：导入 %d 条规则，保留 %d 条，替换 %d 条；仅保存期望，不自动生效", state.Input.Mode, len(source.Rules), info.PreservedRules, info.ReplacedRules))
	} else {
		normalized, err := (firewall.Policy{Backend: source.SourceBackend, Rules: source.Rules}).Normalize()
		if err != nil {
			return err
		}
		mapped = normalized.Rules
		add("firewall", "policy", "review", "配置包含防火墙中立规则；当前选择保留目标期望及运行策略")
	}
	observed := map[string]bool{}
	if st.Firewall != nil && len(ordered) > 0 {
		reader, ok := s.Agent.(interface {
			ReadFirewall(context.Context) (firewall.Observation, error)
		})
		available := false
		if ok {
			call, cancel := context.WithTimeout(ctx, 8*time.Second)
			view, err := reader.ReadFirewall(call)
			cancel()
			if err == nil && view.Available && view.Scope == "host" {
				available = true
				for _, name := range view.Interfaces {
					observed[name] = true
				}
			}
		}
		if !available {
			info.Warnings = append(info.Warnings, "目标宿主机接口清单无法核对；保存不代表绑定可用，实际应用前仍须重新检测")
		}
	}
	for _, name := range ordered {
		item := FirewallInterface{Source: name}
		if st.Firewall != nil {
			item.Target, item.Resolved = st.Firewall.Input.Interfaces[name]
			item.Observed = item.Resolved && (item.Target == "" || observed[item.Target])
		}
		info.Interfaces = append(info.Interfaces, item)
	}
	used := 2
	for _, rule := range mapped {
		raw, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		if len(info.Entries) >= 64 || used+len(raw)+1 > 64<<10 {
			break
		}
		info.Entries = append(info.Entries, rule)
		used += len(raw) + 1
	}
	info.Truncated = len(info.Entries) < len(mapped)
	return nil
}
func (s *Service) importFirewall(ctx context.Context, tx *sql.Tx, st *storedPlan, principal, requestID string) error {
	if st.Firewall == nil {
		return nil
	}
	if !st.Firewall.Resolved {
		return fault.Conflict("防火墙网卡映射未完成")
	}
	if err := s.checkFirewallBase(ctx, tx, st); err != nil {
		return err
	}
	view, err := s.Firewall.StorePolicy(ctx, tx, st.Firewall.Before.Version, st.Firewall.Candidate)
	if err != nil {
		return err
	}
	st.Firewall.ImportedVersion = view.Version
	st.Plan.Firewall.SavedVersion, st.Plan.Firewall.State = view.Version, "saved_unapplied"
	return pushAudit(ctx, tx, principal, requestID, st.Plan.ID, "migration.firewall.import", "saved_unapplied")
}
func (s *Service) compensateFirewall(ctx context.Context, tx *sql.Tx, st *storedPlan, principal, requestID string) error {
	if st.Firewall == nil {
		return nil
	}
	if st.Firewall.ImportedVersion < 1 {
		return fault.Conflict("防火墙迁入版本缺失，不能补偿")
	}
	current, err := s.Firewall.ReadPolicy(ctx, tx)
	if err != nil {
		return err
	}
	currentHash, err := firewall.PolicyDigest(current.Policy)
	if err != nil {
		return err
	}
	candidateHash, err := firewall.PolicyDigest(st.Firewall.Candidate)
	if err != nil {
		return err
	}
	if current.Version != st.Firewall.ImportedVersion || currentHash != candidateHash {
		return fault.Conflict("防火墙期望策略已有其他变更，禁止覆盖")
	}
	if _, err = s.Firewall.StorePolicy(ctx, tx, current.Version, st.Firewall.Before.Policy); err != nil {
		return err
	}
	return pushAudit(ctx, tx, principal, requestID, st.Plan.ID, "migration.firewall.compensate", "restored")
}
func validateFirewallPreview(f *FirewallPlan) error {
	if f.Mode != "preserve" && f.Mode != "merge" && f.Mode != "replace" || f.BaseVersion < 0 || f.SavedVersion < 0 || f.SourceRules < 0 || f.SourceRules > 1000 || f.TotalRules < 0 || f.TotalRules > 1000 || f.PreservedRules < 0 || f.PreservedRules > 1000 || f.ReplacedRules < 0 || f.ReplacedRules > 1000 || len(f.Interfaces) > 1000 || len(f.Entries) > 64 || len(f.Warnings) > 8 || len(f.Entries) > f.SourceRules || f.Truncated != (len(f.Entries) < f.SourceRules) {
		return errors.New("invalid firewall migration preview")
	}
	switch f.State {
	case "preserved", "pending_import", "saved_unapplied", "restored", "recovery_required":
	default:
		return errors.New("invalid firewall migration state")
	}
	if _, err := (firewall.Policy{Backend: f.SourceBackend, Rules: []firewall.Rule{}}).Normalize(); err != nil {
		return err
	}
	backend := f.TargetBackend
	if f.Mode == "preserve" {
		if backend != "" || f.PolicyHash != "" || f.State != "preserved" || f.BaseVersion != 0 || f.SavedVersion != 0 || f.TotalRules != 0 || f.PreservedRules != 0 || f.ReplacedRules != 0 {
			return errors.New("invalid preserved firewall preview")
		}
		backend = f.SourceBackend
	} else {
		if len(f.PolicyHash) != 64 || strings.Trim(f.PolicyHash, "0123456789abcdef") != "" || f.BaseVersion == math.MaxInt64 {
			return errors.New("invalid firewall migration digest")
		}
	}
	if f.Mode == "merge" && (f.TotalRules != f.SourceRules+f.PreservedRules || f.ReplacedRules != 0) || f.Mode == "replace" && (f.TotalRules != f.SourceRules || f.PreservedRules != 0) {
		return errors.New("invalid firewall migration counts")
	}
	if _, err := (firewall.Policy{Backend: backend, Rules: f.Entries}).Normalize(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, item := range f.Interfaces {
		if item.Source == "" || len(item.Source) > 15 || len(item.Target) > 15 || seen[item.Source] || strings.ContainsAny(item.Source+item.Target, "\x00\r\n") {
			return errors.New("invalid firewall interface preview")
		}
		seen[item.Source] = true
	}
	for _, warning := range f.Warnings {
		if len(warning) > 1024 {
			return errors.New("invalid firewall migration warning")
		}
	}
	return nil
}

// The encrypted transfer and the first accepted target plan bind every retry.
func acceptPushFirewall(plan Plan, in PushInput, prior *Plan) error {
	f := plan.Firewall
	if in.Remote.Selection.Firewall != (f != nil) {
		return errors.New("target firewall selection mismatch")
	}
	if f == nil {
		return nil
	}
	mode := in.Firewall.Mode
	if mode == "" {
		mode = "preserve"
	}
	if f.Mode != mode {
		return errors.New("target firewall mode mismatch")
	}
	if mode == "preserve" {
		return nil
	}
	if f.TargetBackend != in.Firewall.Backend || in.Firewall.BaseVersion != nil && f.BaseVersion != *in.Firewall.BaseVersion {
		return errors.New("target firewall binding mismatch")
	}
	if prior != nil && (prior.Firewall == nil || f.BaseVersion != prior.Firewall.BaseVersion || f.PolicyHash != prior.Firewall.PolicyHash || f.SourceRules != prior.Firewall.SourceRules || f.TotalRules != prior.Firewall.TotalRules || f.PreservedRules != prior.Firewall.PreservedRules || f.ReplacedRules != prior.Firewall.ReplacedRules) {
		return errors.New("target firewall plan changed")
	}
	matched := 0
	for _, item := range f.Interfaces {
		target, ok := in.Firewall.Interfaces[item.Source]
		if item.Resolved != ok || item.Target != target {
			return errors.New("target firewall interface mismatch")
		}
		if ok {
			matched++
		}
	}
	if matched != len(in.Firewall.Interfaces) {
		return errors.New("target firewall interface omitted")
	}
	expectedState := "saved_unapplied"
	switch plan.State {
	case "planned", "failed":
		expectedState = "pending_import"
	case "rolled_back":
		expectedState = "restored"
	case "recovery_required":
		expectedState = "recovery_required"
	}
	if f.State != expectedState || expectedState == "pending_import" && f.SavedVersion != 0 || expectedState != "pending_import" && f.SavedVersion != f.BaseVersion+1 {
		return errors.New("target firewall result mismatch")
	}
	return nil
}
