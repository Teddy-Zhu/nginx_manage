package components

import (
	"context"
	"errors"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
)

func panelSelection(plan releases.Plan) (bool, error) {
	for _, asset := range plan.Assets {
		if asset.Component == "panel" || asset.Component == "web" {
			if len(plan.Assets) != 1 {
				return false, errors.New("面板和独立前端须分别准备，不能与其他组件共用更新计划")
			}
			return asset.Component == "panel", nil
		}
	}
	return false, nil
}

func (m *Manager) prepareRuntime(ctx context.Context, out *Operation, plan releases.Plan) error {
	panel, err := panelSelection(plan)
	if err != nil {
		return err
	}
	out.Panel = nil
	out.Frontend = nil
	if len(plan.Assets) == 1 && plan.Assets[0].Component == "web" {
		source, err := releases.Prepared(ctx, releases.Input{TrustPath: m.TrustPath, Assets: out.Input.Assets, AllowedComponents: []string{"web"}, AllowPrerelease: out.Input.Prerelease, Host: m.host(), Receiver: receiver()}, plan.ID)
		if err != nil {
			return err
		}
		staged, err := panelruntime.StageFrontend(ctx, m.DataDir, source)
		if err != nil {
			return err
		}
		out.Frontend = &FrontendResult{ReleaseID: staged.ID, Version: staged.Version}
		return nil
	}
	if !panel {
		return nil
	}
	staged, err := panelruntime.Stage(ctx, panelruntime.StageInput{DataDir: m.DataDir, PlanID: plan.ID, TrustPath: m.TrustPath, AllowPrerelease: out.Input.Prerelease})
	if err != nil {
		return err
	}
	if staged.Approval.ManifestSHA256 != out.Input.ManifestSHA256 || staged.Approval.TrustSHA256 != out.Input.TrustSHA256 {
		return errors.New("面板暂存与原签名计划不一致")
	}
	out.Panel = &PanelPreparation{ReleaseID: staged.Release.ID, DatabaseSchema: staged.Compatibility.DatabaseSchema, AutomaticRollback: staged.Compatibility.AutomaticRollback, AgentProtocol: staged.Release.AgentProtocol, LauncherVersion: staged.Release.LauncherVersion, RequiresCoordination: staged.RequireCurrent() != nil}
	return nil
}
