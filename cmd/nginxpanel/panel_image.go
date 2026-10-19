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

func runPanelImage(ctx context.Context, command string, args []string) error {
	allowed := map[string]map[string]bool{
		"panel-image":        {"data-dir": true, "panel-image": true, "image": true, "release-plan": true, "release-prerelease": true, "image-manifest": true, "image-signature": true, "image-manifest-sha256": true, "maintenance-id": true, "maintenance-epoch": true},
		"panel-image-resume": {"data-dir": true, "panel-image": true, "maintenance-epoch": true},
		"panel-image-status": {"data-dir": true, "panel-image": true},
		"panel-image-worker": {"data-dir": true, "panel-image": true},
		"panel-image-probe":  {"data-dir": true, "maintenance-id": true},
	}
	accept, ok := allowed[command]
	if !ok {
		return errors.New("未知面板镜像命令")
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	defaultData := os.Getenv("NGINXPANEL_DATA_DIR")
	if defaultData == "" {
		defaultData = "/srv/nginxpanel"
	}
	data := f.String("data-dir", defaultData, "installed node data directory")
	id := f.String("panel-image", "", "independent panel image operation UUID")
	image := f.String("image", "", "locally available signed image repository@sha256")
	plan := f.String("release-plan", "", "signed panel preparation plan")
	prerelease := f.Bool("release-prerelease", false, "explicitly approve a prerelease")
	manifest := f.String("image-manifest", "", "root-owned offline release manifest")
	signature := f.String("image-signature", "", "root-owned detached manifest signature")
	manifestHash := f.String("image-manifest-sha256", "", "expected signed release manifest digest")
	maintenanceID := f.String("maintenance-id", "", "already held maintenance operation UUID")
	epoch := f.String("maintenance-epoch", "", "current Agent maintenance epoch")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("面板镜像命令不接受位置参数")
	}
	invalid := ""
	f.Visit(func(v *flag.Flag) {
		if !accept[v.Name] {
			invalid = v.Name
		}
	})
	if invalid != "" {
		return errors.New("此面板镜像命令不接受参数：" + invalid)
	}
	abs, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if command == "panel-image-probe" {
		out, err := agent.PanelImageProbe(ctx, abs, *maintenanceID)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	var out agent.Record
	switch command {
	case "panel-image":
		const trust = "/etc/nginxpanel/release-trust.json"
		out, err = agent.QueuePanelImage(ctx, agent.PanelImageInput{Stage: panelruntime.StageInput{DataDir: abs, PlanID: *plan, TrustPath: trust, AllowPrerelease: *prerelease}, Signature: releases.ImageInput{TrustPath: trust, ManifestPath: *manifest, SignaturePath: *signature, ExpectedManifestSHA256: *manifestHash, AllowPrerelease: *prerelease}, Image: *image, MaintenanceID: *maintenanceID}, *id, *epoch)
	case "panel-image-resume":
		out, err = agent.ResumePanelImage(ctx, abs, *id, *epoch)
	case "panel-image-status":
		out, err = agent.PanelImageStatus(abs, *id)
	case "panel-image-worker":
		out, err = agent.RunPanelImage(ctx, abs, *id)
	}
	if out.OperationID != "" {
		if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
			return errors.Join(err, encodeErr)
		}
	}
	return err
}
