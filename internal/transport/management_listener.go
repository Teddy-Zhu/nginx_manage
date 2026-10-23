package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/remotelisten"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) listenerPrincipal(w http.ResponseWriter, r *http.Request, recent bool) (auth.Principal, bool) {
	if r.Header.Get(remoteapi.HopHeader) != "" {
		s.fail(w, r, fault.New(403, "REMOTE_FORWARDING_REJECTED", "监听管理须直接连接目标节点"))
		return auth.Principal{}, false
	}
	return s.authorize(w, r, recent, "read", "system.write")
}
func (s *Server) GetManagementListener(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.listenerPrincipal(w, r, false); !ok {
		return
	}
	out, err := s.Agent.ManagementListener(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetManagementListenerOperation(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.listenerPrincipal(w, r, false); !ok {
		return
	}
	out, err := s.Agent.ListenerOperation(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ApplyManagementListener(w http.ResponseWriter, r *http.Request, params apigen.ApplyManagementListenerParams) {
	if remotelisten.ConnectionID(r.Context()) != "" {
		w.Header().Set("Connection", "close")
	}
	p, ok := s.listenerPrincipal(w, r, true)
	if !ok {
		return
	}
	if len(params.IdempotencyKey) == 0 || len(params.IdempotencyKey) > 128 {
		s.fail(w, r, fault.Invalid("需要 1–128 字节 Idempotency-Key"))
		return
	}
	var in remotelisten.Input
	if err := decodeLimit(w, r, &in, 40<<10); err != nil {
		s.fail(w, r, err)
		return
	}
	hash := sha256.Sum256([]byte(s.NodeID + "\x00" + p.ID + "\x00" + params.IdempotencyKey))
	value := hex.EncodeToString(hash[:16])
	id := value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:]
	if err := s.audit(r, p.ID, "management.listener.apply", id, "sending"); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Agent.ApplyListener(r.Context(), id, in, remotelisten.ConnectionID(r.Context()))
	outcome := "unknown"
	if err == nil {
		outcome = out.State
	}
	if auditErr := s.audit(r, p.ID, "management.listener.apply", id, outcome); auditErr != nil {
		s.fail(w, r, fault.Unavailable("监听请求已发送，审计回执未保存；请查询原操作"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "监听操作已记录", out)
}
func (s *Server) ConfirmManagementListener(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.ConfirmManagementListenerParams) {
	s.decideManagementListener(w, r, id, "confirm")
}
func (s *Server) RollbackManagementListener(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.RollbackManagementListenerParams) {
	s.decideManagementListener(w, r, id, "rollback")
}
func (s *Server) decideManagementListener(w http.ResponseWriter, r *http.Request, id, action string) {
	p, ok := s.listenerPrincipal(w, r, true)
	if !ok {
		return
	}
	// ConnectionID is injected by the application listener, never by HTTP
	// headers. A loopback connection or old keep-alive cannot prove reachability.
	if len(id) != 36 {
		s.fail(w, r, fault.Invalid("监听操作 ID 无效"))
		return
	}
	if action == "confirm" && remotelisten.ConnectionID(r.Context()) == "" {
		s.fail(w, r, fault.Conflict("请通过新远程入口建立连接后确认"))
		return
	}
	if err := s.audit(r, p.ID, "management.listener."+action, id, "sending"); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Agent.DecideListener(r.Context(), id, action, remotelisten.ConnectionID(r.Context()))
	outcome := "unknown"
	if err == nil {
		outcome = out.State
	}
	if auditErr := s.audit(r, p.ID, "management.listener."+action, id, outcome); auditErr != nil {
		s.fail(w, r, fault.Unavailable("监听决定已发送，审计回执未保存；请查询原操作"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
