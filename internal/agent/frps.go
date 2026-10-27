package agent

import (
	"context"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/frpscontainer"
	"nginxpanel/internal/software"
)

func (s *Server) manageFrps(ctx context.Context, r software.Request, progress software.Progress) (software.Result, error) {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return software.Result{}, fault.Unavailable("当前环境不允许管理宿主机 FRP 服务端")
	}
	return frpscontainer.Run(ctx, s.DataDir, *r.Frps, progress)
}
