package transport

import (
	"net/http"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) GetFail2banAddress(w http.ResponseWriter, r *http.Request, params apigen.GetFail2banAddressParams) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if !s.fail2banReady(w, r) {
		return
	}
	adoption := ""
	if params.AdoptionId != nil {
		adoption = *params.AdoptionId
	}
	if len(params.Jail) > 64 || len(params.Ip) > 45 || len(adoption) > 36 || len(params.EngineOwner) > 8 {
		s.fail(w, r, fault.Invalid("jail 或地址格式无效"))
		return
	}
	ip, err := fail2ban.Address(params.Ip)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Fail2ban.AddressRuntime(ctx, fail2ban.AddressQuery{EngineOwner: params.EngineOwner, AdoptionID: adoption, Jail: params.Jail, IP: ip})
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) ChangeFail2banAddress(w http.ResponseWriter, r *http.Request, params apigen.ChangeFail2banAddressParams) {
	p, ok := s.authorize(w, r, "security.write")
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	var in fail2ban.AddressInput
	if err := decodeLimit(w, r, &in, 2048); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Fail2ban.ChangeAddress(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "手动封禁操作任务已创建", out)
}

func (s *Server) GetFail2banAddressTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.AddressTasks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
