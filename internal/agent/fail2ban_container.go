package agent

import (
	"context"
	"net/http"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fail2bancontainer"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/software"
)

func (s *Server) manageContainerFail2ban(ctx context.Context, r software.Request, progress software.Progress) (software.Result, error) {
	if s.Dev || s.MetricsScope != "host" || s.MaintenanceScope != "host" {
		return software.Result{}, fault.Unavailable("当前环境不允许管理宿主机登录防护")
	}
	return fail2bancontainer.Run(ctx, s.DataDir, *r.Fail2ban, progress)
}
func (s *Server) fail2banContainerHandler(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/fail2ban/container", func(w http.ResponseWriter, r *http.Request) {
		if s.Dev || s.MetricsScope != "host" {
			componentReply(w, nil, fault.Unavailable("当前环境不允许管理宿主机登录防护"))
			return
		}
		status, err := fail2bancontainer.Status(r.Context(), s.DataDir)
		componentReply(w, status, err)
	})
}
func (c *Client) ReadFail2banContainer(ctx context.Context) (fail2ban.ContainerStatus, error) {
	var out fail2ban.ContainerStatus
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/container", nil, &out)
	return out, err
}
