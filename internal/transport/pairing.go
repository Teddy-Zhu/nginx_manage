package transport

import (
	"net/http"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nodes"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/transport/apigen"
)

// Only the short-code exchange has body authentication. Browser sessions and
// forwarded management requests cannot enter this unauthenticated exception.
func pairingExchangeRequest(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	return r.Method == http.MethodPost && len(parts) == 7 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "remote" && parts[4] == "pairings" && parts[5] != "" && parts[6] == "exchange"
}

func (s *Server) pairingAdministrator(w http.ResponseWriter, r *http.Request, recent bool) (auth.Principal, bool) {
	p, ok := s.nodePrincipal(w, r, recent)
	if !ok {
		return p, false
	}
	if err := p.Require("auth.manage"); err != nil {
		s.fail(w, r, err)
		return p, false
	}
	return p, true
}

func (s *Server) ListPairings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.pairingAdministrator(w, r, false)
	if !ok {
		return
	}
	result, err := s.Nodes.ListPairings(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}
func (s *Server) CreatePairing(w http.ResponseWriter, r *http.Request, params apigen.CreatePairingParams) {
	p, ok := s.pairingAdministrator(w, r, true)
	if !ok {
		return
	}
	var in nodes.PairingInput
	if err := decodeLimit(w, r, &in, 8192); err != nil {
		s.fail(w, r, err)
		return
	}
	result, err := s.Nodes.CreatePairing(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusCreated, "OK", "配对授权已登记", result)
}
func (s *Server) RevokePairing(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.RevokePairingParams) {
	p, ok := s.pairingAdministrator(w, r, true)
	if !ok {
		return
	}
	result, err := s.Nodes.RevokePairing(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}
func (s *Server) pairingTarget(w http.ResponseWriter, r *http.Request, target string) bool {
	if target != s.NodeID || r.Header.Get(remoteapi.ProtocolHeader) != "1" {
		s.fail(w, r, fault.New(http.StatusConflict, "NODE_IDENTITY_CHANGED", "配对目标身份或协议不匹配"))
		return false
	}
	return true
}
func (s *Server) ExchangePairing(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ExchangePairingParams) {
	if !s.pairingTarget(w, r, params.XNginxpanelTargetNode) {
		return
	}
	var in nodes.PairingClaim
	if err := decodeLimit(w, r, &in, 2048); err != nil {
		s.fail(w, r, err)
		return
	}
	result, err := s.Nodes.ExchangePairing(r.Context(), r.Context().Value(requestIDKey).(string), id, auth.ClientIP(r), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}
func (s *Server) ConfirmPairing(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ConfirmPairingParams) {
	if !s.pairingTarget(w, r, params.XNginxpanelTargetNode) {
		return
	}
	if r.Header.Get(remoteapi.HopHeader) != "" {
		s.fail(w, r, auth.ErrForbidden)
		return
	}
	p, ok := s.authorize(w, r, false, "read")
	if !ok {
		return
	}
	if !p.Machine {
		s.fail(w, r, auth.ErrForbidden)
		return
	}
	var in nodes.PairingConfirmation
	if err := decodeLimit(w, r, &in, 1024); err != nil {
		s.fail(w, r, err)
		return
	}
	result, err := s.Nodes.ConfirmPairing(r.Context(), p, r.Context().Value(requestIDKey).(string), id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}
func (s *Server) ListPairingJobs(w http.ResponseWriter, r *http.Request) {
	p, ok := s.nodePrincipal(w, r, false)
	if !ok {
		return
	}
	result, err := s.Nodes.ListPairingJobs(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}
func (s *Server) GetPairingJob(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.nodePrincipal(w, r, false)
	if !ok {
		return
	}
	result, err := s.Nodes.GetPairingJob(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}
func (s *Server) StartPairing(w http.ResponseWriter, r *http.Request, params apigen.StartPairingParams) {
	p, ok := s.nodePrincipal(w, r, true)
	if !ok {
		return
	}
	var in nodes.PairingJobInput
	if err := decodeLimit(w, r, &in, 8192); err != nil {
		s.fail(w, r, err)
		return
	}
	result, err := s.Nodes.StartPairing(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "配对任务已受理", result)
}
func (s *Server) ResumePairing(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.ResumePairingParams) {
	p, ok := s.nodePrincipal(w, r, true)
	if !ok {
		return
	}
	result, err := s.Nodes.ResumePairing(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原配对已核对", result)
}
func (s *Server) AbandonPairing(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.AbandonPairingParams) {
	p, ok := s.nodePrincipal(w, r, true)
	if !ok {
		return
	}
	result, err := s.Nodes.AbandonPairing(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}
