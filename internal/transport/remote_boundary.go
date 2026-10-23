package transport

import (
	"net/http"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
)

// Target binding precedes every business handler. Only read-only initial
// identity discovery can omit the as-yet unknown permanent node ID.
func (s *Server) remoteBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{remoteapi.HopHeader, remoteapi.TargetHeader, remoteapi.ProtocolHeader, remoteapi.ScopesHeader, "Authorization"} {
			if len(r.Header.Values(name)) > 1 {
				s.fail(w, r, fault.Invalid("远程授权请求头重复"))
				return
			}
		}
		hop := r.Header.Get(remoteapi.HopHeader)
		if hop == "" {
			if r.Header.Get(remoteapi.ScopesHeader) != "" {
				s.fail(w, r, fault.Invalid("远程授权头缺少转发标识"))
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		discovery := r.Method == http.MethodGet && r.URL.Path == "/api/v1/remote/identity" && r.Header.Get(remoteapi.TargetHeader) == ""
		if hop != "1" || r.Header.Get(remoteapi.ProtocolHeader) != "1" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || len(r.Header.Values(remoteapi.ScopesHeader)) != 1 {
			s.fail(w, r, fault.New(http.StatusForbidden, "REMOTE_PROTOCOL_REJECTED", "远程授权协议无效"))
			return
		}
		if !discovery && r.Header.Get(remoteapi.TargetHeader) != s.NodeID {
			s.fail(w, r, fault.New(http.StatusConflict, "NODE_IDENTITY_CHANGED", "目标永久节点身份不匹配"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
