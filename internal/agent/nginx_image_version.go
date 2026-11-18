package agent

import (
	"time"

	"nginxpanel/internal/components"
	"nginxpanel/internal/componentversions"
)

func (w *nginxImageWorker) recordVersion() error {
	i := w.r.NginxImage.Intent
	return componentversions.SaveState(i.Target.DataDir, "builtin", "nginx", componentversions.State{
		Current: components.NginxVersion(i.Target), Previous: components.NginxVersion(i.Before),
		Image: i.Target.Image, PreviousImage: i.Before.Image, UpdatedAt: time.Now().Unix(),
	})
}
