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
}

func policyAAD(version int64) string { return fmt.Sprintf("firewall:policy:%d", version) }

func (s *Service) Policy(ctx context.Context) (PolicyView, error) {
	out := PolicyView{Policy: DefaultPolicy()}
	var sealed []byte
	e := s.DB.QueryRowContext(ctx, "SELECT version,payload,updated_at FROM firewall_policy WHERE id=1").Scan(&out.Version, &sealed, &out.UpdatedAt)
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
	policy, e := json.Marshal(in.Policy)
	if e != nil {
		return out, e
	}
	now := time.Now().Unix()
	version := in.BaseVersion + 1
	var result sql.Result
	if in.BaseVersion == 0 {
		result, e = tx.ExecContext(ctx, "INSERT INTO firewall_policy(id,version,payload,updated_at) VALUES(1,?,?,?) ON CONFLICT(id) DO NOTHING", version, s.Vault.Seal(policy, policyAAD(version)), now)
	} else {
		result, e = tx.ExecContext(ctx, "UPDATE firewall_policy SET version=?,payload=?,updated_at=? WHERE id=1 AND version=?", version, s.Vault.Seal(policy, policyAAD(version)), now, in.BaseVersion)
	}
	if e != nil {
		return out, e
	}
	count, e := result.RowsAffected()
	if e != nil {
		return out, e
	}
	if count != 1 {
		return out, fault.Conflict("防火墙策略已更新，请重新读取后保存")
	}
	out = PolicyView{Version: version, Policy: in.Policy, UpdatedAt: now}
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
	program, e := CompileNFT(view.Policy)
	if e != nil {
		var known *fault.Error
		if errors.As(e, &known) {
			out.Errors = append(out.Errors, known.Message)
		} else {
			return out, e
		}
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
			if view.Policy.Backend == "direct-nftables" {
				if !observed.Kernel.Available {
					out.Errors = append(out.Errors, "未取得同一内核代次的目标表快照，不能核对规则变化")
				}
				if observed.Kernel.Available && observed.Kernel.TableExists {
					out.Errors = append(out.Errors, "目标表的内核快照已存在，须先核对独立受管登记")
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
	out.Warnings = append(out.Warnings, "保存策略及编译结果均不代表内核生效；当前应用入口不可用", "allow 只终止本应用链的判断，其他基础链及云安全组仍可拒绝连接", "规则仅匹配 conntrack NEW；回环及已建立/关联会话保留，未跟踪流量不在此匹配范围")
	return out, nil
}
