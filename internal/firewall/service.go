package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type Observer interface {
	ReadFirewall(context.Context) (Observation, error)
}
type Service struct {
	DB         *sql.DB
	Vault      *secure.Vault
	Agent      Observer
	previewing atomic.Bool
	geoIPBusy  atomic.Bool
	runtimeMu  sync.Mutex
}

func policyAAD(version int64) string { return fmt.Sprintf("firewall:policy:%d", version) }

type PolicyReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Service) Policy(ctx context.Context) (PolicyView, error) { return s.ReadPolicy(ctx, s.DB) }
func (s *Service) ReadPolicy(ctx context.Context, q PolicyReader) (PolicyView, error) {
	out := PolicyView{Policy: DefaultPolicy()}
	var sealed []byte
	e := q.QueryRowContext(ctx, "SELECT version,payload,updated_at FROM firewall_policy WHERE id=1").Scan(&out.Version, &sealed, &out.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	raw, e := s.Vault.Open(sealed, policyAAD(out.Version))
	if e != nil {
		return out, e
	}
	if e = json.Unmarshal(raw, &out.Policy); e != nil {
		return out, e
	}
	normalized, e := out.Policy.Normalize()
	if e != nil || normalized.Hash() != out.Policy.Hash() || out.Version < 1 {
		return PolicyView{}, fault.Unavailable("已保存的防火墙策略无效，须检查存储")
	}
	return out, nil
}
func (s *Service) Save(ctx context.Context, p auth.Principal, requestID, key string, in PolicyInput) (PolicyView, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out PolicyView
	if e := p.Require("security.write"); e != nil {
		return out, e
	}
	if in.BaseVersion < 0 || in.BaseVersion == math.MaxInt64 || key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("策略版本或幂等键无效")
	}
	normalized, e := in.Policy.Normalize()
	if e != nil {
		return out, e
	}
	in.Policy = normalized
	raw, e := json.Marshal(struct {
		Action string
		Input  PolicyInput
	}{"firewall.policy.save", in})
	if e != nil {
		return out, e
	}
	digest := secure.Hash(raw)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	e = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if e == nil {
		if prior != digest {
			return out, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, e := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
		if e != nil {
			return out, e
		}
		e = json.Unmarshal(plain, &out)
		return out, e
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	if e = s.migrationIdle(ctx, tx); e != nil {
		return out, e
	}
	current, e := s.ReadPolicy(ctx, tx)
	if e != nil {
		return out, e
	}
	if current.Version != in.BaseVersion {
		return out, fault.Conflict("防火墙策略版本已变化，请重新读取")
	}
	if conflicts := policyConflicts(normalized, current.Policy); len(conflicts) > 0 && !in.ConfirmConflicts {
		return out, fault.New(409, "FIREWALL_RULE_CONFLICT", conflictMessage(conflicts))
	}
	out, e = s.StorePolicy(ctx, tx, in.BaseVersion, in.Policy)
	if e != nil {
		return out, e
	}
	now := time.Now().Unix()
	response, e := json.Marshal(out)
	if e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,'firewall.policy.save','host','saved',?)", secure.ID(), requestID, p.ID, now); e != nil {
		return out, e
	}
	return out, tx.Commit()
}

func (s *Service) Preview(ctx context.Context, version int64) (Preview, error) {
	out := Preview{Version: version, Entries: []PreviewEntry{}, Errors: []string{}, Warnings: []string{}}
	if version < 1 {
		return out, fault.Invalid("须先保存防火墙策略并提供版本")
	}
	if !s.previewing.CompareAndSwap(false, true) {
		return out, fault.New(429, "FIREWALL_PREVIEW_BUSY", "规则预览正在生成，请稍后重试")
	}
	defer s.previewing.Store(false)
	view, e := s.Policy(ctx)
	if e != nil {
		return out, e
	}
	if view.Version != version {
		return out, fault.Conflict("防火墙策略版本已变化，请重新读取")
	}
	out.PolicyHash = view.Policy.Hash()
	out.Backend = view.Policy.Backend
	for _, r := range view.Policy.Rules {
		if r.Enabled {
			out.LogicalRules++
		}
	}
	var program *NFTProgram
	var managed *FirewalldProgram
	var ufw *UFWProgram
	var iptables *IPTablesProgram
	switch view.Policy.Backend {
	case "firewalld":
		managed, e = CompileFirewalld(view.Policy)
	case "ufw":
		ufw, e = CompileUFW(view.Policy)
	case "iptables-nft", "iptables-legacy":
		iptables, e = CompileIPTables(view.Policy)
	default:
		program, e = CompileNFT(view.Policy)
	}
	if e != nil {
		var known *fault.Error
		if errors.As(e, &known) {
			out.Errors = append(out.Errors, known.Message)
		} else {
			return out, e
		}
	} else if managed != nil {
		out.Compiled = true
		out.Firewalld = managed.Preview()
		out.Priority = FirewalldHostPriority
		out.DefaultPolicy = managed.Settings.Target
		out.GeneratedRules = len(managed.Settings.RichRules)
		out.ProgramHash = managed.Hash
		out.Entries = append(out.Entries, managed.Entries[:min(128, len(managed.Entries))]...)
		out.Truncated = len(managed.Entries) > len(out.Entries)
	} else if ufw != nil {
		out.Compiled = true
		out.Hook = "input"
		out.DefaultPolicy = "unchanged"
		out.GeneratedRules = len(ufw.Rules)
		out.ProgramHash = ufw.Hash
		out.Entries = append(out.Entries, ufw.Entries[:min(128, len(ufw.Entries))]...)
		out.Truncated = len(ufw.Entries) > len(out.Entries)
	} else if iptables != nil {
		out.Compiled = true
		out.IPTables = iptables.Preview()
		out.Table, out.Chain, out.Hook, out.DefaultPolicy = "filter", IPTablesHostChain, "INPUT", "RETURN"
		out.GeneratedRules = iptables.BaseRules + len(iptables.Entries)
		out.ProgramHash = iptables.Hash
		out.Entries = append(out.Entries, iptables.Entries[:min(128, len(iptables.Entries))]...)
		out.Truncated = len(iptables.Entries) > len(out.Entries)
	} else {
		out.Compiled = true
		out.Table = "inet " + NFTHostTable
		out.Chain = NFTHostChain
		out.Hook = "input"
		out.Priority = NFTHostPriority
		out.DefaultPolicy = "accept"
		out.GeneratedRules = len(program.Rules)
		out.ProgramHash = program.Hash
		out.Entries = append(out.Entries, program.Entries[:min(128, len(program.Entries))]...)
		out.Truncated = len(program.Entries) > len(out.Entries)
	}
	if s.Agent == nil {
		out.Errors = append(out.Errors, "未连接宿主机 Agent")
	} else {
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		observed, readErr := s.Agent.ReadFirewall(call)
		cancel()
		if readErr != nil {
			out.Errors = append(out.Errors, "宿主机防火墙状态无法读取")
		} else {
			out.ObservedAt = observed.At
			out.Kernel = observed.Kernel
			out.Warnings = append(out.Warnings, observed.Warnings...)
			if !observed.Available || observed.Scope != "host" {
				out.Errors = append(out.Errors, "宿主机观测范围未确认")
			}
			if view.Policy.Backend == "firewalld" {
				inspectFirewalldPreview(&out, observed)
			}
			if iptables != nil {
				errors, warnings := IPTablesEnvironment(observed, iptables)
				out.Errors = append(out.Errors, errors...)
				out.Warnings = append(out.Warnings, warnings...)
				grant := observed.IPTablesRegistration
				if grant.Backend != iptables.Backend || !grant.Registration.Verified {
					out.Errors = append(out.Errors, "目标尚未核对所选 iptables 后端的本机空命名空间授权，请检查本机登记")
				}
			}
			if view.Policy.Backend == "ufw" {
				if observed.Manager != "ufw" || observed.UFW.Active == nil || !*observed.UFW.Active || observed.UFW.Enabled == nil || !*observed.UFW.Enabled {
					out.Errors = append(out.Errors, "目标未确认由已启用的单一 UFW 管理，不能切换或接管管理器")
				}
				if !observed.UFW.RuleInventory.Available {
					out.Errors = append(out.Errors, "UFW 用户规则报告无法完整读取")
				}
				if observed.Backend == "mixed" {
					out.Errors = append(out.Errors, "观察到混合内核后端，须先核对规则所有权")
				}
				complete := len(observed.Rulesets) == 5
				for _, set := range observed.Rulesets {
					complete = complete && set.Available
				}
				if !complete {
					out.Errors = append(out.Errors, "部分内核后端视图不完整，不能排除其他规则体系")
				}
				if ufw != nil {
					for _, entry := range ufw.Entries {
						if entry.Family == "ipv6" && (observed.UFW.IPv6 == nil || !*observed.UFW.IPv6) {
							out.Errors = append(out.Errors, "目标 UFW 的 IPv6 配置未确认启用，不能承接 IPv6 规则")
							break
						}
					}
				}
			}
			if view.Policy.Backend == "direct-nftables" {
				if !observed.Kernel.Available {
					out.Errors = append(out.Errors, "未取得同一内核代次的目标表快照，不能核对规则变化")
				}
				if observed.Kernel.Available && observed.Kernel.TableExists {
					if observed.Registration.Verified {
						out.Warnings = append(out.Warnings, "受管登记已核对；执行须另外生成含入口保护项的应用计划")
					} else {
						out.Errors = append(out.Errors, "目标表存在但独立受管登记未核对通过，禁止接管")
					}
				}
				if observed.Manager != "direct-candidate" {
					out.Errors = append(out.Errors, "未能排除现有管理器，不能直接接管 nftables")
				}
				if program != nil && observed.Kernel.Available && !observed.Kernel.TableExists {
					batch, batchErr := PrepareNFTCreate(program, observed.Kernel)
					if batchErr != nil {
						var known *fault.Error
						if errors.As(batchErr, &known) {
							out.Errors = append(out.Errors, known.Message)
						} else {
							return out, batchErr
						}
					} else {
						out.TransactionHash = batch.Hash
						out.TransactionBytes = len(batch.Wire)
						out.TransactionMessages = batch.Messages
					}
				}
				if observed.Backend == "legacy" || observed.Backend == "mixed" {
					out.Errors = append(out.Errors, "观察到 legacy 或混合后端，须先核对规则所有权")
				}
				available := false
				for _, set := range observed.Rulesets {
					if set.ID == "nftables" && set.Available {
						available = true
					}
				}
				if !available {
					out.Errors = append(out.Errors, "nftables 规则视图不完整，不能确认执行环境")
				}
			}
			for _, r := range view.Policy.Rules {
				if r.Enabled && r.Interface != "" && !slices.Contains(observed.Interfaces, r.Interface) {
					out.Errors = append(out.Errors, "规则 "+r.ID+" 的目标接口未观察到")
				}
			}
		}
	}
	var current int64
	if e = s.DB.QueryRowContext(ctx, "SELECT version FROM firewall_policy WHERE id=1").Scan(&current); e != nil {
		return out, e
	}
	if current != version {
		return out, fault.Conflict("预览期间策略已变化，请重新生成")
	}
	out.Warnings = append(out.Warnings, "保存策略及编译结果均不代表内核生效；执行需生成应用计划并通过新连接确认")
	if view.Policy.Backend == "firewalld" {
		out.Warnings = append(out.Warnings, "独立 policy 使用 ANY → HOST、负优先级及 CONTINUE 默认目标；不代表接管现有 zone 或 policy", "allow 编译为 firewalld accept，可提前结束该管理器的后续过滤；其他内核基础链和云安全组仍可拒绝连接", "会话与回环处理由 firewalld 自身规则决定；rich rules 不显式限制 conntrack NEW，未跟踪流量也可能命中端口规则")
	} else if view.Policy.Backend == "ufw" {
		out.Warnings = append(out.Warnings, "UFW 逻辑预览不执行 dry-run；须先完成目标本机授权，再通过管理入口准备保护计划、应用并用新连接确认")
		out.Warnings = append(out.Warnings, "命令顺序仅表示中立策略内部顺序；尚未确定与现有 UFW 规则的插入关系，注释不构成所有权证明", "UFW 可更新相同匹配条件的既有规则，执行前必须排除第三方规则冲突，不能重放诊断报告", "默认策略、回环、已建立会话及其他 UFW 规则保持由管理器处理；allow 可能终止后续 UFW 判断，云安全组和其他内核链仍可拒绝连接")
	} else if slices.Contains([]string{"iptables-nft", "iptables-legacy"}, view.Policy.Backend) {
		out.Warnings = append(out.Warnings, "iptables 逻辑预览不执行官方预演；须先完成目标本机授权，再通过管理入口准备应用或移除计划，并用新连接确认")
		out.Warnings = append(out.Warnings, "allow 编译为 ACCEPT，可能结束后续 INPUT 规则判断；未匹配流量返回调用链，不修改全局默认策略，其他内核过滤与云安全组仍可拒绝连接", "每个使用的地址族包含回环及 ESTABLISHED/RELATED 返回规则；业务项仅匹配 conntrack NEW，不涉及 NAT、FORWARD 或 Docker 发布端口", "IPv4 与 IPv6 分别处理，不承诺全局原子性；编译不探测或加载内核扩展，也不证明工具可接受规则")
	} else {
		out.Warnings = append(out.Warnings, "allow 只终止本应用链的判断，其他基础链及云安全组仍可拒绝连接", "规则仅匹配 conntrack NEW；回环及已建立/关联会话保留，未跟踪流量不在此匹配范围")
	}
	return out, nil
}
