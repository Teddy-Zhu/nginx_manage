package transport

import (
	"net/http"

	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) SetNginxNativeModules(w http.ResponseWriter, r *http.Request, params apigen.SetNginxNativeModulesParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets", "security.write")
	if !ok {
		return
	}
	var in nginxconfig.NativeModulesRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.SetNativeModules(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 201, "OK", "模块选择已保存，应用后确认运行结果", out)
}
