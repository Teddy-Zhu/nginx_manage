package transport

import (
	"net"
	"net/http"
	"strconv"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) localAdministrator(w http.ResponseWriter, r *http.Request, scope string) (auth.Principal, bool) {
	p, ok := s.authorize(w, r, scope)
	if ok && (p.Machine || p.Delegated) {
		s.fail(w, r, fault.New(http.StatusForbidden, "DIRECT_SESSION_REQUIRED", "请直接登录本机面板后修改设置"))
		return p, false
	}
	return p, ok
}

func (s *Server) panelAccess() (apigen.PanelAccessInput, error) {
	if s.PanelRuntime != "native" || s.DataDir == "" {
		return apigen.PanelAccessInput{}, fault.Unavailable("仅支持修改已安装面板的访问设置")
	}
	d, err := panelruntime.ReadDeployment(s.DataDir)
	if err != nil {
		return apigen.PanelAccessInput{}, err
	}
	_, value, err := net.SplitHostPort(d.Listen)
	if err != nil {
		return apigen.PanelAccessInput{}, err
	}
	port, err := strconv.Atoi(value)
	return apigen.PanelAccessInput{Port: port, Protocol: apigen.PanelAccessInputProtocol(d.Protocol())}, err
}

func (s *Server) GetPanelAccess(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.localAdministrator(w, r, "system.write"); !ok {
		return
	}
	out, err := s.panelAccess()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) UpdatePanelAccess(w http.ResponseWriter, r *http.Request, _ apigen.UpdatePanelAccessParams) {
	p, ok := s.localAdministrator(w, r, "system.write")
	if !ok {
		return
	}
	var in apigen.PanelAccessInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	current, err := s.panelAccess()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if current == in {
		s.ok(w, r, current)
		return
	}
	if err := s.audit(r, p.ID, "system.panel_access", "panel", "requested"); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := agent.SchedulePanelAccess(r.Context(), s.DataDir, in.Port, string(in.Protocol)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "已安排面板重启", in)
}
