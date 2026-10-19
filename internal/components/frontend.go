package components

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
)

func (m *Manager) frontendCompatible(plan releases.Plan) error {
	if len(plan.Assets) != 1 || plan.Assets[0].Component != "web" {
		return nil
	}
	base, err := panelruntime.Read(m.DataDir)
	if err != nil {
		return err
	}
	if plan.Manifest.APIMajor != 1 || plan.Manifest.DatabaseSchema != base.Release.DatabaseSchema {
		return errors.New("独立前端的 API 或数据库合同与当前后端不匹配，须联合更新面板")
	}
	return nil
}
func (s *Service) validateFrontendParent(ctx context.Context, tx *sql.Tx, principal string, in CreateInput, now int64) error {
	var state string
	var sealed []byte
	err := tx.QueryRowContext(ctx, "SELECT t.state,o.result FROM component_operations o JOIN tasks t ON t.id=o.task_id WHERE o.task_id=? AND o.principal=? AND t.kind='component.prepare'", in.PrepareTaskID, principal).Scan(&state, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.NotFound("前端准备任务不存在")
	}
	if err != nil {
		return err
	}
	if state != "succeeded" || len(sealed) == 0 {
		return fault.Conflict("须先完成独立前端准备")
	}
	raw, err := s.Vault.Open(sealed, "components:result:"+in.PrepareTaskID)
	if err != nil {
		return err
	}
	var prepared Operation
	if err = json.Unmarshal(raw, &prepared); err != nil {
		return err
	}
	if err = prepared.Validate(Request{Protocol: prepared.Protocol, OperationID: prepared.ID, Input: prepared.Input}); err != nil {
		return err
	}
	r := prepared.Release
	if prepared.Input.Action != "prepare" || r == nil || prepared.Frontend == nil || prepared.State != "succeeded" || !prepared.RuntimeReady || len(r.Assets) != 1 || r.Assets[0].Component != "web" || r.ExpiresAt <= now || in.Input.OfflineID != prepared.Input.OfflineID || in.Input.Tag != r.Tag || in.Input.Prerelease != prepared.Input.Prerelease || in.Input.PlanID != r.PlanID || in.Input.ManifestSHA256 != r.ManifestSHA256 || in.Input.TrustSHA256 != r.TrustSHA256 || !sameAssets(in.Input.Assets, r.Selected) {
		return fault.Conflict("前端激活请求与本人准备结果不一致或签名授权已过期")
	}
	return nil
}
func (m *Manager) activateFrontend(ctx context.Context, out *Operation) error {
	in := out.Input
	source, err := releases.Prepared(ctx, releases.Input{TrustPath: m.TrustPath, Assets: in.Assets, AllowedComponents: []string{"web"}, AllowPrerelease: in.Prerelease, Host: m.host(), Receiver: receiver()}, in.PlanID)
	if err != nil {
		return err
	}
	p := source.Plan
	if len(p.Assets) != 1 || p.Assets[0].Component != "web" || p.ID != in.PlanID || p.ManifestSHA256 != in.ManifestSHA256 || p.TrustSHA256 != in.TrustSHA256 || "v"+p.Manifest.Version != in.Tag {
		return releases.ErrReleaseChanged
	}
	if err = m.frontendCompatible(p); err != nil {
		return err
	}
	staged, err := panelruntime.StageFrontend(ctx, m.DataDir, source)
	if err != nil {
		return err
	}
	r := release(p)
	out.Release = &r
	out.Frontend = &FrontendResult{ReleaseID: staged.ID, Version: staged.Version}
	out.Stage = "activating"
	if err = m.write(out); err != nil {
		return err
	}
	status, err := panelruntime.ActivateFrontend(ctx, m.DataDir, out.ID, in.FrontendBaseID, in.ExpectedFrontendID, staged)
	if err != nil {
		return err
	}
	out.Frontend, out.State, out.Stage, out.RuntimeReady = activatedFrontend(status), "succeeded", "activated", true
	return nil
}
func (m *Manager) reconcileFrontend(out *Operation) {
	status, err := panelruntime.ReconcileFrontendActivation(m.DataDir, out.ID)
	if err == nil {
		if out.Release == nil || out.Frontend == nil || status.CurrentID != out.Frontend.ReleaseID || status.BaseID != out.Input.FrontendBaseID || status.PreviousID != out.Input.ExpectedFrontendID {
			err = errors.New("前端选择与原组件操作回执不一致")
		} else {
			out.Frontend, out.State, out.Stage, out.ErrorCode, out.Error, out.RuntimeReady = activatedFrontend(status), "succeeded", "activated", "", "", true
			return
		}
	}
	if errors.Is(err, panelruntime.ErrFrontendNoActivation) {
		return
	}
	if errors.Is(err, panelruntime.ErrFrontendUnselected) {
		out.Stage = "frontend_restored"
		out.Error = "前端激活未完成，原前端选择已核对：" + bounded(out.Error)
		return
	}
	out.State, out.Stage, out.ErrorCode, out.Error = "recovery_required", "frontend_unconfirmed", "FRONTEND_SELECTION_UNCONFIRMED", "前端选择或原指针恢复未确认："+bounded(err.Error())
}
func activatedFrontend(s panelruntime.FrontendStatus) *FrontendResult {
	return &FrontendResult{ReleaseID: s.CurrentID, Version: s.Version, Activated: true, BaseID: s.BaseID, PreviousID: s.PreviousID}
}
