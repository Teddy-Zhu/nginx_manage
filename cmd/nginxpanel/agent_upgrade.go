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
)

func runAgentUpgrade(ctx context.Context, command string, args []string) error {
	allowed := map[string]map[string]bool{
		"agent-upgrade":        {"data-dir": true, "agent-upgrade": true, "release-plan": true, "release-trust": true, "release-prerelease": true, "maintenance-id": true, "maintenance-epoch": true},
		"agent-upgrade-resume": {"data-dir": true, "agent-upgrade": true},
		"agent-upgrade-status": {"data-dir": true, "agent-upgrade": true},
		"agent-upgrade-worker": {"data-dir": true, "agent-upgrade": true},
		"agent-upgrade-probe":  {"data-dir": true, "maintenance-id": true},
	}
	accept, ok := allowed[command]
	if !ok {
		return errors.New("未知 Agent 升级命令")
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	defaultData := os.Getenv("NGINXPANEL_DATA_DIR")
	if defaultData == "" {
		defaultData = "/srv/nginxpanel"
	}
	data := f.String("data-dir", defaultData, "installed node data directory")
	id := f.String("agent-upgrade", "", "independent Agent upgrade operation UUID")
	plan := f.String("release-plan", "", "exact signed panel preparation plan")
	trust := f.String("release-trust", "/etc/nginxpanel/release-trust.json", "fixed root-owned publisher trust")
	prerelease := f.Bool("release-prerelease", false, "explicitly approve a prerelease")
	maintenanceID := f.String("maintenance-id", "", "already held maintenance operation UUID")
	epoch := f.String("maintenance-epoch", "", "current Agent maintenance epoch for initial authorization")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("Agent 升级命令不接受位置参数")
	}
	var invalid string
	f.Visit(func(value *flag.Flag) {
		if !accept[value.Name] {
			invalid = value.Name
		}
	})
	if invalid != "" {
		return errors.New("此 Agent 升级命令不接受参数：" + invalid)
	}
	abs, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if command == "agent-upgrade-probe" {
		out, err := agent.AgentUpgradeProbe(ctx, abs, *maintenanceID)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	var out agent.Record
	switch command {
	case "agent-upgrade":
		out, err = agent.QueueAgentUpgrade(ctx, agent.AgentUpgradeInput{Stage: panelruntime.StageInput{DataDir: abs, PlanID: *plan, TrustPath: *trust, AllowPrerelease: *prerelease}, MaintenanceID: *maintenanceID}, *id, *epoch)
	case "agent-upgrade-resume":
		out, err = agent.ResumeAgentUpgrade(ctx, abs, *id)
	case "agent-upgrade-status":
		out, err = agent.AgentUpgradeStatus(abs, *id)
	case "agent-upgrade-worker":
		out, err = agent.RunAgentUpgrade(ctx, abs, *id)
	}
	if out.OperationID != "" {
		if encoded := json.NewEncoder(os.Stdout).Encode(out); encoded != nil {
			return errors.Join(err, encoded)
		}
	}
	return err
}
