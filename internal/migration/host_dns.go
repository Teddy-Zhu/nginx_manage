package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

type HostDNSInput struct {
	Mode     string                    `json:"mode"`
	Mappings map[string]HostDNSMapping `json:"mappings"`
}
type HostDNSMapping struct {
	Target *string         `json:"target"`
	Config *hostdns.Config `json:"config,omitempty"`
}
type HostDNSPlan struct {
	Mode        string        `json:"mode"`
	State       string        `json:"state"`
	SourceHash  string        `json:"source_hash"`
	MappingHash string        `json:"mapping_hash"`
	Entries     []HostDNSItem `json:"entries"`
}
type HostDNSItem struct {
	Source       string          `json:"source"`
	SourceConfig hostdns.Config  `json:"source_config"`
	Target       *string         `json:"target"`
	Config       *hostdns.Config `json:"config"`
	Readiness    string          `json:"readiness"`
	Reason       string          `json:"reason"`
}

func (in HostDNSInput) validate() error {
	if in.Mode == "" || in.Mode == "preserve" {
		if len(in.Mappings) != 0 {
			return fault.Invalid("保留目标主机 DNS 时不能指定映射")
		}
		return nil
	}
	if in.Mode != "map" || len(in.Mappings) > hostdns.MaxTransferTargets {
		return fault.Invalid("主机 DNS 迁入模式须为 preserve 或 map，最多 64 项映射")
	}
	seen := map[string]bool{}
	for source, mapping := range in.Mappings {
		if mapping.Target == nil {
			return fault.Invalid("每项 DNS 映射都须显式指定 target，受管文件使用空字符串")
		}
		target := *mapping.Target
		if source != "" && !hostdns.ValidTarget(source) || target != "" && !hostdns.ValidTarget(target) || seen[target] {
			return fault.Invalid("主机 DNS 映射无效或多个源指向同一目标")
		}
		seen[target] = true
		if mapping.Config != nil {
			if err := mapping.Config.Validate(target); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateHostDNSSelection(in HostDNSInput, selected bool) error {
	if err := in.validate(); err != nil {
		return err
	}
	if in.Mode == "map" && !selected {
		return fault.Invalid("主机 DNS 映射须选择导出已保存 DNS 配置")
	}
	return nil
}
func dnsHash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}
func mappedDNS(entry hostdns.TransferEntry, mapping HostDNSMapping) (hostdns.Config, error) {
	if mapping.Target == nil {
		return hostdns.Config{}, fault.Invalid("DNS 映射缺少目标")
	}
	target := *mapping.Target
	if mapping.Config != nil {
		if err := mapping.Config.Validate(target); err != nil {
			return hostdns.Config{}, err
		}
		return (hostdns.PlanInput{Target: target, Config: *mapping.Config}).Normalize().Config, nil
	}
	// Interface-scoped addresses refer to the source host, even when both hosts
	// use a regular resolv.conf. Their target configuration must be explicit.
	for _, server := range entry.Config.Servers {
		if ip, err := netip.ParseAddr(server); err == nil && ip.Zone() != "" {
			return hostdns.Config{}, fault.Invalid("带接口区域的源 DNS 地址须显式提供目标 config")
		}
	}
	if err := entry.Config.Validate(target); err != nil {
		return hostdns.Config{}, fault.Invalid("跨 DNS 配置类型迁移须显式提供适合目标的 config")
	}
	return (hostdns.PlanInput{Target: target, Config: entry.Config}).Normalize().Config, nil
}
func prepareHostDNS(st *storedPlan, in HostDNSInput) error {
	if err := validateHostDNSSelection(in, st.Payload.HostDNS != nil); err != nil {
		return err
	}
	if err := hostdns.ValidateTransfer(st.Payload.HostDNS); err != nil {
		return err
	}
	if in.Mode != "map" {
		return nil
	}
	if len(in.Mappings) != len(st.Payload.HostDNS.Entries) {
		return fault.Invalid("每个源 DNS 目标都须显式映射，不自动沿用源连接或网卡")
	}
	for _, entry := range st.Payload.HostDNS.Entries {
		mapping, ok := in.Mappings[entry.Target]
		if !ok {
			return fault.Invalid("源 DNS 目标缺少映射")
		}
		if _, err := mappedDNS(entry, mapping); err != nil {
			return err
		}
	}
	st.HostDNS = in
	return nil
}

func (s *Service) inspectHostDNS(ctx context.Context, st *storedPlan, add func(string, string, string, string)) error {
	if st.Payload.HostDNS == nil {
		st.Plan.HostDNS = nil
		return nil
	}
	sourceHash, err := dnsHash(st.Payload.HostDNS)
	if err != nil {
		return err
	}
	view := &HostDNSPlan{Mode: "preserve", State: "preserved", SourceHash: sourceHash, Entries: []HostDNSItem{}}
	st.Plan.HostDNS = view
	var observed hostdns.Observation
	reason := ""
	if st.HostDNS.Mode == "map" {
		view.Mode, view.State = "map", "pending_import"
		view.MappingHash, err = dnsHash(st.HostDNS)
		if err != nil {
			return err
		}
		if s.HostDNS == nil || s.HostDNS.Agent == nil {
			reason = "未连接主机 DNS 执行器"
		} else {
			call, cancel := context.WithTimeout(ctx, 3*time.Second)
			var err error
			observed, err = s.HostDNS.Agent.ReadHostDNS(call)
			cancel()
			if err != nil {
				reason = "无法读取目标主机 DNS 所有者与当前配置"
			}
		}
		var enabled bool
		if err := s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='host-dns'").Scan(&enabled); err != nil {
			return err
		}
		if !enabled && reason == "" {
			reason = "目标主机 DNS 模块未启用"
		}
	}
	for _, entry := range st.Payload.HostDNS.Entries {
		item := HostDNSItem{Source: entry.Target, SourceConfig: entry.Config, Readiness: "preserved", Reason: "保留目标运行 DNS 配置"}
		if view.Mode == "map" {
			mapping := st.HostDNS.Mappings[entry.Target]
			config, err := mappedDNS(entry, mapping)
			if err != nil {
				return err
			}
			item.Target, item.Config = mapping.Target, &config
			item.Readiness, item.Reason = "blocked", reason
			if reason == "" {
				item.Reason = dnsTargetReason(observed, *mapping.Target)
				if item.Reason == "" {
					item.Readiness = "ready"
				}
			}
		}
		view.Entries = append(view.Entries, item)
	}
	add("host-dns", "configuration", "review", fmt.Sprintf("包含 %d 个已保存 DNS 目标；运行配置保持目标值，映射材料须在目标单独生成 DNS 计划并确认", len(view.Entries)))
	return nil
}
func dnsTargetReason(observed hostdns.Observation, target string) string {
	if observed.Pending != nil {
		return "目标存在未完成的 DNS 操作"
	}
	if !observed.Writable {
		return "目标 DNS 所有者尚未授权或不支持写入"
	}
	if target == "" && observed.Owner == "regular-file" {
		return ""
	}
	if observed.Owner == "networkmanager" {
		for _, c := range observed.Connections {
			if c.Target == target {
				if c.Writable {
					return ""
				}
				return "目标 NetworkManager 连接不支持安全写入"
			}
		}
	}
	if observed.Owner == "networkd" {
		for _, link := range observed.Links {
			if link.Target == target {
				if link.Writable {
					return ""
				}
				return "目标 networkd 链路不支持安全写入"
			}
		}
	}
	return "映射目标不存在或与当前 DNS 所有者不匹配"
}
func reflectHostDNSState(plan *Plan) {
	if plan.HostDNS == nil || plan.HostDNS.Mode != "map" {
		return
	}
	plan.HostDNS.State = "staged"
	if plan.State == "planned" || plan.State == "failed" {
		plan.HostDNS.State = "pending_import"
	}
}

func validateHostDNSPreview(view *HostDNSPlan) error {
	if len(view.SourceHash) != 64 || len(view.Entries) > hostdns.MaxTransferTargets || view.Entries == nil {
		return errors.New("invalid host DNS preview")
	}
	source := &hostdns.Transfer{Entries: []hostdns.TransferEntry{}}
	seen := map[string]bool{}
	for _, item := range view.Entries {
		source.Entries = append(source.Entries, hostdns.TransferEntry{Target: item.Source, Config: item.SourceConfig})
		if len(item.Reason) > 512 {
			return errors.New("invalid host DNS readiness reason")
		}
		if view.Mode == "preserve" {
			if item.Target != nil || item.Config != nil || item.Readiness != "preserved" {
				return errors.New("invalid preserved host DNS item")
			}
		} else {
			if item.Target == nil || item.Config == nil || seen[*item.Target] || item.Config.Validate(*item.Target) != nil || item.Readiness != "ready" && item.Readiness != "blocked" {
				return errors.New("invalid mapped host DNS item")
			}
			seen[*item.Target] = true
		}
	}
	sourceHash, err := dnsHash(source)
	if err != nil || hostdns.ValidateTransfer(source) != nil || view.SourceHash != sourceHash {
		return errors.New("host DNS source digest mismatch")
	}
	if view.Mode == "preserve" {
		if view.State != "preserved" || view.MappingHash != "" {
			return errors.New("invalid preserved host DNS preview")
		}
	} else if view.Mode != "map" || len(view.MappingHash) != 64 || view.State != "pending_import" && view.State != "staged" {
		return errors.New("invalid mapped host DNS preview")
	}
	return nil
}
func acceptPushHostDNS(plan Plan, in PushInput, prior *Plan, sourceHash string) error {
	view := plan.HostDNS
	if in.Remote.Selection.HostDNS != (view != nil) {
		return errors.New("target host DNS selection mismatch")
	}
	if view == nil {
		return nil
	}
	mode := in.HostDNS.Mode
	if mode == "" {
		mode = "preserve"
	}
	if view.Mode != mode || view.SourceHash != sourceHash || prior != nil && (prior.HostDNS == nil || prior.HostDNS.SourceHash != view.SourceHash || prior.HostDNS.MappingHash != view.MappingHash) {
		return errors.New("target host DNS plan changed")
	}
	if mode == "preserve" {
		return nil
	}
	mappingHash, err := dnsHash(in.HostDNS)
	if err != nil || view.MappingHash != mappingHash || len(view.Entries) != len(in.HostDNS.Mappings) {
		return errors.New("target host DNS mapping mismatch")
	}
	for _, item := range view.Entries {
		mapping, ok := in.HostDNS.Mappings[item.Source]
		if !ok || item.Target == nil || item.Config == nil || mapping.Target == nil || *item.Target != *mapping.Target {
			return errors.New("target host DNS item mismatch")
		}
		config, err := mappedDNS(hostdns.TransferEntry{Target: item.Source, Config: item.SourceConfig}, mapping)
		if err != nil {
			return err
		}
		expectedHash, err := dnsHash(config)
		if err != nil {
			return err
		}
		actualHash, err := dnsHash(item.Config)
		if err != nil || expectedHash != actualHash {
			return errors.New("target host DNS configuration mismatch")
		}
	}
	expected := "staged"
	if plan.State == "planned" || plan.State == "failed" {
		expected = "pending_import"
	}
	if view.State != expected {
		return errors.New("target host DNS staging result mismatch")
	}
	return nil
}
