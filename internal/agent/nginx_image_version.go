package agent

import (
	"time"

	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/releases"
)

func nginxComponentVersion(b nginxcontainer.Binding) *componentversions.Version {
	version := b.SignedImage.Version
	if releases.VersionChannel(version) == "" {
		return nil
	}
	return &componentversions.Version{ID: "nginx-v" + version, Version: version, SoftwareVersion: b.Capabilities.Version, Channel: releases.VersionChannel(version)}
}
func (w *nginxImageWorker) recordVersion() error {
	i := w.r.NginxImage.Intent
	return componentversions.SaveState(i.Target.DataDir, "builtin", "nginx", componentversions.State{Current: nginxComponentVersion(i.Target), Previous: nginxComponentVersion(i.Before), Image: i.Target.Image, PreviousImage: i.Before.Image, UpdatedAt: time.Now().Unix()})
}
