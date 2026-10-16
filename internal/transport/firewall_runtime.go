package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/remotelisten"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) firewallPrincipal(w http.ResponseWriter, r *http.Request, recent bool) (auth.Principal, bool) {
	if r.Header.Get(remoteapi.HopHeader) != "" {
		s.fail(w, r, fault.New(403, "REMOTE_FORWARDING_REJECTED", "防火墙执行管理须直接连接目标节点"))
		return auth.Principal{}, false
	}
	p, ok := s.authorize(w, r, recent, "read", "security.write")
	if !ok || !s.firewallReady(w, r) {
		return p, false
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("未连接宿主机 Agent"))
		return p, false
	}
	return p, true
}
func (s *Server) GetFirewallRuntime(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.firewallPrincipal(w, r, false); !ok {
		return
	}
	out, err := s.Agent.FirewallRuntime(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetFirewallOperation(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.firewallPrincipal(w, r, false); !ok {
		return
	}
	out, err := s.Agent.FirewallOperation(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) PlanFirewall(w http.ResponseWriter, r *http.Request, _ apigen.PlanFirewallParams) {
	p, ok := s.firewallPrincipal(w, r, true)
	if !ok {
		return
	}
	var in firewall.PlanInput
	if err := decodeLimit(w, r, &in, 1024); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Firewall.Plan(r.Context(), in, remotelisten.ConnectionID(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err = s.audit(r, p.ID, "firewall.plan", out.ID, out.Action+"_planned"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ApplyFirewall(w http.ResponseWriter, r *http.Request, params apigen.ApplyFirewallParams) {
	w.Header().Set("Connection", "close")
	p, ok := s.firewallPrincipal(w, r, true)
	if !ok {
		return
	}
	key := params.IdempotencyKey
	if len(key) < 1 || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		s.fail(w, r, fault.Invalid("需要 1–128 字节 Idempotency-Key"))
		return
	}
	var in firewall.ApplyInput
	if err := decodeLimit(w, r, &in, 1024); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Version < 1 || len(in.PlanID) != 36 || in.Action != "apply" && in.Action != "remove" {
		s.fail(w, r, fault.Invalid("策略版本或计划 ID 无效"))
		return
	}
	hash := sha256.Sum256([]byte(s.NodeID + "\x00" + p.ID + "\x00" + key))
	value := hex.EncodeToString(hash[:16])
	id := value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:]
	if err := s.audit(r, p.ID, "firewall."+in.Action, id, "sending"); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Firewall.Apply(r.Context(), id, in, remotelisten.ConnectionID(r.Context()))
	outcome := "unknown"
	if err == nil {
		outcome = out.State
	}
	if auditErr := s.audit(r, p.ID, "firewall."+in.Action, id, outcome); auditErr != nil {
		s.fail(w, r, fault.Unavailable("防火墙请求已发送，审计回执未保存；请查询原操作 "+id))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "防火墙操作已记录", out)
}
func (s *Server) ConfirmFirewall(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.ConfirmFirewallParams) {
	s.decideFirewall(w, r, id, "confirm")
}
func (s *Server) RollbackFirewall(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.RollbackFirewallParams) {
	s.decideFirewall(w, r, id, "rollback")
}
func (s *Server) decideFirewall(w http.ResponseWriter, r *http.Request, id, action string) {
	p, ok := s.firewallPrincipal(w, r, true)
	if !ok {
		return
	}
	if action == "confirm" && (r.TLS == nil || remotelisten.ConnectionID(r.Context()) == "") {
		s.fail(w, r, fault.Conflict("须通过规则生效后新建的目标管理 HTTPS 连接确认"))
		return
	}
	if err := s.audit(r, p.ID, "firewall."+action, id, "sending"); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Agent.DecideFirewall(r.Context(), id, action, remotelisten.ConnectionID(r.Context()))
	outcome := "unknown"
	if err == nil {
		outcome = out.State
	}
	if auditErr := s.audit(r, p.ID, "firewall."+action, id, outcome); auditErr != nil {
		s.fail(w, r, fault.Unavailable("防火墙决定已发送，审计回执未保存；请查询原操作"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
