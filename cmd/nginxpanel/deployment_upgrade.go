package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"

	"nginxpanel/internal/agent"
)

func runDeploymentUpgrade(ctx context.Context, command string, args []string) error {
	allowed := map[string]map[string]bool{
		"deployment-upgrade":         {"data-dir": true, "operation-id": true, "release-plan": true, "release-prerelease": true, "maintenance-id": true, "maintenance-epoch": true, "allow-downtime": true},
		"deployment-upgrade-resume":  {"data-dir": true, "operation-id": true, "maintenance-epoch": true, "foreground": true},
		"deployment-upgrade-status":  {"data-dir": true, "operation-id": true},
		"deployment-upgrade-inspect": {"data-dir": true, "maintenance-id": true},
	}
	accept, ok := allowed[command]
	if !ok {
		return errors.New("未知协调部署命令")
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	defaultData := os.Getenv("NGINXPANEL_DATA_DIR")
	if defaultData == "" {
		defaultData = "/srv/nginxpanel"
	}
	data := f.String("data-dir", defaultData, "installed data directory")
	id := f.String("operation-id", "", "original deployment operation UUID")
	plan := f.String("release-plan", "", "signed panel preparation plan")
	maintenance := f.String("maintenance-id", "", "held maintenance UUID")
	epoch := f.String("maintenance-epoch", "", "expected current maintenance epoch")
	prerelease := f.Bool("release-prerelease", false, "authorize signed prerelease")
	downtime := f.Bool("allow-downtime", false, "authorize coordinated panel and Agent interruption")
	foreground := f.Bool("foreground", false, "resume with this root-approved repair tool instead of the installed worker")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("协调部署不接受位置参数")
	}
	var invalid string
	f.Visit(func(v *flag.Flag) {
		if !accept[v.Name] {
			invalid = v.Name
		}
	})
	if invalid != "" {
		return errors.New("此协调部署命令不接受参数：" + invalid)
	}
	abs, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if command == "deployment-upgrade-inspect" {
		out, err := agent.InspectDeploymentUpgrade(ctx, abs, *maintenance)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	var out agent.Record
	if command == "deployment-upgrade-status" {
		out, err = agent.PanelUpdateStatus(abs, *id)
	} else {
		out, err = agent.QueueDeploymentUpgrade(ctx, abs, *id, *plan, *maintenance, *epoch, *prerelease, *downtime, command == "deployment-upgrade-resume", *foreground)
	}
	if out.OperationID != "" {
		if encoded := json.NewEncoder(os.Stdout).Encode(out); encoded != nil {
			return errors.Join(err, encoded)
		}
	}
	return err
}
