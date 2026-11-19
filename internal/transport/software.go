package transport

import (
	"context"
	"errors"
	"net/http"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/software"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) GetServiceLogs(w http.ResponseWriter, r *http.Request, params apigen.GetServiceLogsParams) {
	if _, ok := s.authorize(w, r, "read", "components.manage"); !ok {
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("软件管理服务未连接"))
		return
	}
	out, err := s.Agent.ServiceLogs(r.Context(), string(params.AppId))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.ok(w, r, out)
}

func (s *Server) ControlSoftware(w http.ResponseWriter, r *http.Request, _ apigen.ControlSoftwareParams) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok {
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("软件管理服务未连接"))
		return
	}
	var in software.Request
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.Validate(); err != nil {
		s.fail(w, r, fault.Invalid(err.Error()))
		return
	}
	if !in.Immediate() {
		s.fail(w, r, fault.Invalid("此操作需要通过软件任务执行"))
		return
	}
	if in.RequiresSecurity() {
		if err := p.Require("security.write"); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(software.ControlTimeout + 10*time.Second)); err != nil {
		s.fail(w, r, err)
		return
	}
	action, resource := in.Action, in.AppID
	switch action {
	case "container":
		action, resource = "container."+in.Container.Action, in.Container.ID
	case "fail2ban":
		action, resource = "fail2ban."+in.Fail2ban.Action, "fail2ban"
		if in.Fail2ban.JailID != "" {
			resource = in.Fail2ban.JailID + "/" + in.Fail2ban.Address
		}
	default:
		action = in.AppID + "." + action
	}
	action = "software." + action
	if err := s.audit(r, p.ID, action, resource, "requested"); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Agent.ControlSoftware(r.Context(), in)
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
		var known *fault.Error
		if !errors.As(err, &known) || known.Status >= 500 {
			outcome = "unknown"
		}
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	if auditErr := s.audit(r.WithContext(auditCtx), p.ID, action, resource, outcome); auditErr != nil {
		s.fail(w, r, errors.Join(err, auditErr))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Components != nil && s.Components.OnSoftwareChange != nil {
		s.Components.OnSoftwareChange(in)
	}
	s.ok(w, r, out)
}
