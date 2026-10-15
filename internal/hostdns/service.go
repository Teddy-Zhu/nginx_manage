package hostdns

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type Host interface {
	ReadHostDNS(context.Context) (Observation, error)
	PlanHostDNS(context.Context, PlanInput) (Plan, error)
	ApplyHostDNS(context.Context, string, Plan) (Status, error)
	HostDNSOperation(context.Context, string) (Status, error)
	DecideHostDNS(context.Context, string, string) (Status, error)
}
type Service struct {
	DB    *sql.DB
	Vault *secure.Vault
	Agent Host
}

func (s *Service) Overview(ctx context.Context) (Overview, error) {
	out := Overview{Observed: Observation{Connections: []Connection{}, Owner: "unknown", Source: "/etc/resolv.conf", Reason: "未连接宿主机 Agent", Current: Config{Servers: []string{}, Search: []string{}}}}
	var err error
	if s.Agent != nil {
		out.Observed, err = s.Agent.ReadHostDNS(ctx)
		if err != nil {
			return out, err
		}
	}
	out.Desired = []Desired{}
	rows, err := s.DB.QueryContext(ctx, "SELECT target,version,payload,source_hash,updated_at FROM host_dns_desired ORDER BY target")
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var raw []byte
		var desired Desired
		if err = rows.Scan(&desired.Target, &desired.Version, &raw, &desired.SourceHash, &desired.UpdatedAt); err != nil {
			rows.Close()
			return out, err
		}
		plain, e := s.Vault.Open(raw, "host-dns:desired:"+desired.Target)
		if e != nil {
			rows.Close()
			return out, e
		}
		if e = json.Unmarshal(plain, &desired.Config); e != nil {
			rows.Close()
			return out, e
		}
		out.Desired = append(out.Desired, desired)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	item := Task{}
	err = s.DB.QueryRowContext(ctx, "SELECT t.id,t.operation_id,t.state,t.stage,t.last_error,o.decision FROM tasks t JOIN host_dns_operations o ON o.task_id=t.id ORDER BY t.created_at DESC,t.id DESC LIMIT 1").Scan(&item.ID, &item.OperationID, &item.State, &item.Stage, &item.Error, &item.Decision)
	if err == nil {
		out.Task = &item
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	return out, nil
}
func (s *Service) write(ctx context.Context, p auth.Principal, requestID, key, action string, input any, apply func(*sql.Tx) (any, error)) ([]byte, error) {
	if err := p.Require("host.dns.write"); err != nil {
		return nil, err
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return nil, fault.Invalid("幂等键无效")
	}
	encoded, err := json.Marshal(struct {
		Action string
		Input  any
	}{action, input})
	if err != nil {
		return nil, err
	}
	digest := secure.Hash(encoded)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if err == nil {
		if prior != digest {
			return nil, fault.Conflict("同一幂等键不能用于不同请求")
		}
		return s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var enabled bool
	if err = tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='host-dns'").Scan(&enabled); err != nil {
		return nil, err
	}
	if !enabled && action != "host.dns.rollback" {
		return nil, fault.Conflict("须先启用主机 DNS 模块")
	}
	result, err := apply(tx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(raw, "idempotency:"+p.ID+":"+key), now); err != nil {
		return nil, err
	}
	resource := "host"
	if c, ok := result.(Change); ok {
		resource = c.TaskID
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'saved',?)", secure.ID(), requestID, p.ID, action, resource, now); err != nil {
		return nil, err
	}
	return raw, tx.Commit()
}
func (s *Service) CreatePlan(ctx context.Context, p auth.Principal, requestID, key string, input PlanInput) (Plan, error) {
	var out Plan
	if err := input.Validate(); err != nil {
		return out, err
	}
	input = input.Normalize()
	raw, err := s.write(ctx, p, requestID, key, "host.dns.plan", input, func(tx *sql.Tx) (any, error) {
		if s.Agent == nil {
			return nil, fault.Unavailable("未连接宿主机 Agent")
		}
		var desiredCount int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_dns_desired WHERE target!=?", input.Target).Scan(&desiredCount); e != nil {
			return nil, e
		}
		if desiredCount >= 64 {
			return nil, fault.Conflict("已保存 DNS 目标达到上限")
		}
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		plan, err := s.Agent.PlanHostDNS(call, input)
		if err != nil {
			return nil, err
		}
		if plan.ID != plan.Hash() || plan.Input.SourceHash != input.SourceHash {
			return nil, fault.Unavailable("DNS Agent 计划无效")
		}
		now := time.Now().Unix()
		if _, err = tx.ExecContext(ctx, "DELETE FROM host_dns_plans WHERE expires_at<=?", now); err != nil {
			return nil, err
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_dns_plans").Scan(&count); err != nil {
			return nil, err
		}
		if count >= 64 {
			return nil, fault.Conflict("有效 DNS 计划过多，请等待旧计划到期")
		}
		raw, err := json.Marshal(plan)
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO host_dns_plans(id,principal,payload,expires_at) VALUES(?,?,?,?) ON CONFLICT(principal,id) DO NOTHING", plan.ID, p.ID, s.Vault.Seal(raw, "host-dns:plan:"+p.ID+":"+plan.ID), plan.ExpiresAt)
		return plan, err
	})
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, err
}
func (s *Service) Apply(ctx context.Context, p auth.Principal, requestID, key, planID string) (Change, error) {
	var out Change
	raw, err := s.write(ctx, p, requestID, key, "host.dns.apply", planID, func(tx *sql.Tx) (any, error) {
		var sealed []byte
		var expires int64
		err := tx.QueryRowContext(ctx, "SELECT payload,expires_at FROM host_dns_plans WHERE principal=? AND id=?", p.ID, planID).Scan(&sealed, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fault.NotFound("DNS 计划不存在")
		}
		if err != nil {
			return nil, err
		}
		if time.Now().Unix() >= expires {
			return nil, fault.Conflict("DNS 计划已过期")
		}
		var pending int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE (kind='host.dns.apply' OR kind LIKE 'firewall.%' OR kind LIKE 'management.%') AND state IN ('queued','running','waiting_confirmation','compensating','recovery_required')").Scan(&pending); err != nil {
			return nil, err
		}
		if pending > 0 {
			return nil, fault.Conflict("存在未完成的可达性变更")
		}
		plain, err := s.Vault.Open(sealed, "host-dns:plan:"+p.ID+":"+planID)
		if err != nil {
			return nil, err
		}
		var plan Plan
		if err = json.Unmarshal(plain, &plan); err != nil {
			return nil, err
		}
		if plan.ID != planID || plan.ID != plan.Hash() {
			return nil, fault.Conflict("DNS 计划不匹配")
		}
		id, operationID, now := secure.ID(), secure.ID(), time.Now().Unix()
		if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'host.dns.apply','host','queued','queued',?,?,?)", id, operationID, now, now); err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO host_dns_operations(task_id,payload) VALUES(?,?)", id, s.Vault.Seal(plain, "host-dns:operation:"+id))
		return Change{TaskID: id}, err
	})
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, err
}
func (s *Service) Decide(ctx context.Context, p auth.Principal, requestID, key, id, action string) (Change, error) {
	var out Change
	if action != "confirm" && action != "rollback" {
		return out, fault.Invalid("DNS 确认动作无效")
	}
	raw, err := s.write(ctx, p, requestID, key, "host.dns."+action, id, func(tx *sql.Tx) (any, error) {
		var state, stage, prior string
		err := tx.QueryRowContext(ctx, "SELECT t.state,t.stage,o.decision FROM tasks t JOIN host_dns_operations o ON o.task_id=t.id WHERE t.id=? AND t.kind='host.dns.apply'", id).Scan(&state, &stage, &prior)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fault.NotFound("DNS 任务不存在")
		}
		if err != nil {
			return nil, err
		}
		if state == "queued" && action == "rollback" {
			_, err = tx.ExecContext(ctx, "UPDATE tasks SET state='cancelled',stage='cancelled',updated_at=? WHERE id=? AND state='queued'", time.Now().Unix(), id)
			return Change{TaskID: id}, err
		}
		if state != "running" && state != "waiting_confirmation" && state != "compensating" && state != "recovery_required" {
			return nil, fault.Conflict("DNS 任务不再等待确认或恢复")
		}
		if action == "confirm" && (state != "waiting_confirmation" || stage != "awaiting_confirmation") {
			return nil, fault.Conflict("DNS 尚未完成本机解析核验")
		}
		if prior != "" && prior != action {
			return nil, fault.Conflict("已提交其他确认动作，等待执行结果")
		}
		_, err = tx.ExecContext(ctx, "UPDATE host_dns_operations SET decision=? WHERE task_id=?", action, id)
		return Change{TaskID: id}, err
	})
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, err
}
