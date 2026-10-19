package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
)

func runNginxImage(ctx context.Context, command string, args []string) error {
	allowed := map[string]map[string]bool{
		"nginx-image":        {"data-dir": true, "nginx-image-operation": true, "image": true, "release-plan": true, "release-prerelease": true, "image-manifest": true, "image-signature": true, "image-manifest-sha256": true, "maintenance-id": true, "maintenance-epoch": true, "allow-downtime": true},
		"nginx-image-resume": {"data-dir": true, "nginx-image-operation": true, "maintenance-epoch": true},
		"nginx-image-status": {"data-dir": true, "nginx-image-operation": true},
		"nginx-image-worker": {"data-dir": true, "nginx-image-operation": true},
	}
	accept, ok := allowed[command]
	if !ok {
		return errors.New("未知 Nginx 镜像命令")
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	defaultData := os.Getenv("NGINXPANEL_DATA_DIR")
	if defaultData == "" {
		defaultData = "/srv/nginxpanel"
	}
	data := f.String("data-dir", defaultData, "installed node data directory")
	id := f.String("nginx-image-operation", "", "independent Nginx image operation UUID")
	image := f.String("image", "", "locally available signed image repository@sha256")
	plan := f.String("release-plan", "", "signed panel preparation plan")
	prerelease := f.Bool("release-prerelease", false, "explicitly approve a prerelease")
	manifest := f.String("image-manifest", "", "root-owned offline release manifest")
	signature := f.String("image-signature", "", "root-owned detached manifest signature")
	manifestHash := f.String("image-manifest-sha256", "", "expected signed release manifest digest")
	maintenanceID := f.String("maintenance-id", "", "already held maintenance operation UUID")
	allowDowntime := f.Bool("allow-downtime", false, "explicitly allow Nginx interruption")
	epoch := f.String("maintenance-epoch", "", "current Agent maintenance epoch")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("Nginx 镜像命令不接受位置参数")
	}
	invalid := ""
	f.Visit(func(v *flag.Flag) {
		if !accept[v.Name] {
			invalid = v.Name
		}
	})
	if invalid != "" {
		return errors.New("此 Nginx 镜像命令不接受参数：" + invalid)
	}
	abs, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	var out agent.Record
	switch command {
	case "nginx-image":
		const trust = "/etc/nginxpanel/release-trust.json"
		out, err = agent.QueueNginxImage(ctx, agent.NginxImageInput{Stage: panelruntime.StageInput{DataDir: abs, PlanID: *plan, TrustPath: trust, AllowPrerelease: *prerelease}, Signature: releases.ImageInput{TrustPath: trust, ManifestPath: *manifest, SignaturePath: *signature, ExpectedManifestSHA256: *manifestHash, AllowPrerelease: *prerelease}, Image: *image, MaintenanceID: *maintenanceID, AllowDowntime: *allowDowntime}, *id, *epoch)
	case "nginx-image-resume":
		out, err = agent.ResumeNginxImage(ctx, abs, *id, *epoch)
	case "nginx-image-status":
		out, err = agent.NginxImageStatus(abs, *id)
	case "nginx-image-worker":
		out, err = agent.RunNginxImage(ctx, abs, *id)
	}
	if out.OperationID != "" {
		if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
			return errors.Join(err, encodeErr)
		}
	}
	return err
}
