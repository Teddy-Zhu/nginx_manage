package components

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

func sameAssets(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
func (out Operation) Validate(req Request) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if req.Protocol <= 0 || !ValidID(req.OperationID) || req.Input.Validate() != nil || out.Protocol != req.Protocol || out.ID != req.OperationID || out.RequestHash != secure.Hash(raw) || out.CreatedAt <= 0 || out.UpdatedAt < out.CreatedAt || out.Deadline != out.CreatedAt+600 || !containsState(out.State) {
		return errors.New("组件操作身份或状态无效")
	}
	input, _ := json.Marshal(out.Input)
	expected, _ := json.Marshal(req.Input)
	if string(input) != string(expected) {
		return errors.New("组件操作输入不一致")
	}
	if out.Image != nil {
		if req.Input.Action != "pull" || out.Release == nil || out.Image.Choice.ID != req.Input.ImageID || !out.Image.Choice.valid(out.Release.Repository) || out.Image.ApprovedAt < out.CreatedAt || out.Image.ApprovedAt >= out.Deadline {
			return errors.New("镜像准备回执或批准时间无效")
		}
		matched := false
		for _, image := range out.Release.Images {
			if image == out.Image.Choice {
				matched = true
			}
		}
		if !matched {
			return errors.New("镜像准备目标与签名发行不一致")
		}
	}
	if a := out.Announcement; a != nil {
		if a.Validate() != nil || a.Receiver.APIMajor != 1 || a.ReceiverCompatible || out.State != "failed" || out.ErrorCode != "COMPONENT_RECEIVER_INCOMPATIBLE" || req.Input.Action == "activate" || req.Input.Action == "pull" || req.Input.OfflineID != "" || req.Input.Tag != "" && a.Tag != req.Input.Tag || a.Channel == "prerelease" && !req.Input.Prerelease || a.ExpiresAt <= out.CreatedAt || req.Input.ManifestSHA256 != "" && a.ManifestSHA256 != req.Input.ManifestSHA256 || req.Input.TrustSHA256 != "" && a.TrustSHA256 != req.Input.TrustSHA256 {
			return errors.New("组件失败结果的已验签说明不匹配")
		}
	}
	if out.State != "succeeded" {
		return nil
	}
	r := out.Release
	if r == nil || r.Requirements.Validate() != nil || !releases.ValidNotes(r.Notes) || r.Receiver.APIMajor != 1 || r.Receiver.AgentProtocol <= 0 || r.Receiver.Launcher <= 0 || r.StagingOnly != (len(r.Requirements.Incompatibilities(r.Receiver)) != 0) || !digest(r.PlanID) || !digest(r.ManifestSHA256) || !digest(r.TrustSHA256) || r.Repository == "" || r.KeyID == "" || r.Tag != "v"+r.Version || r.ExpiresAt <= out.CreatedAt || len(r.Selected) == 0 || len(r.Selected) > 2 || len(r.Assets) == 0 || len(r.Assets) > 2 || out.Error != "" || out.ErrorCode != "" {
		return errors.New("组件成功结果不完整")
	}
	if req.Input.Tag != "" && r.Tag != req.Input.Tag {
		return errors.New("组件发行标签不匹配")
	}
	if len(req.Input.Assets) != 0 && !sameAssets(req.Input.Assets, r.Selected) {
		return errors.New("组件发行资产不匹配")
	}
	found := map[string]string{}
	for _, a := range r.Assets {
		if (a.Component != "nginx" && a.Component != "fail2ban" && a.Component != "panel" && a.Component != "web") || found[a.Component] != "" || a.ID == "" || a.Version == "" {
			return errors.New("组件发行内容无效")
		}
		found[a.Component] = a.ID
	}
	if found["panel"] != "" && len(found) != 1 {
		return errors.New("面板须使用独立准备计划")
	}
	if r.StagingOnly && (found["panel"] == "" || len(r.Assets) != 1 || r.Assets[0].ABI != "static" || len(r.Assets[0].Dependencies) != 0 || r.Requirements.APIMajor != r.Receiver.APIMajor || req.Input.Action != "check" && req.Input.Action != "prepare" && (req.Input.Action != "pull" || req.Input.ImageID != "panel-launcher")) {
		return errors.New("不满足接收端要求的发行仅允许独立面板暂存及面板运行镜像准备")
	}
	if found["web"] != "" && len(found) != 1 {
		return errors.New("前端须使用独立准备计划")
	}
	if len(r.Images) != 0 && (found["panel"] == "" || len(r.Images) != 2) {
		return errors.New("签名镜像必须来自完整面板发行")
	}
	seenImages := map[string]bool{}
	for _, image := range r.Images {
		if !image.valid(r.Repository) || seenImages[image.ID] {
			return errors.New("签名镜像选择无效")
		}
		seenImages[image.ID] = true
	}
	if req.Input.Action != "check" && found["web"] != "" {
		if out.Frontend == nil || !digest(out.Frontend.ReleaseID) || out.Frontend.Version != r.Assets[0].Version || out.Frontend.Activated != (req.Input.Action == "activate") {
			return errors.New("前端操作缺少持久发布回执")
		}
		if req.Input.Action == "prepare" && (out.Frontend.BaseID != "" || out.Frontend.PreviousID != "") {
			return errors.New("前端准备不能包含激活目标")
		}
	} else if out.Frontend != nil {
		return errors.New("此组件操作不应包含前端发布回执")
	}
	if req.Input.Action == "prepare" && found["panel"] != "" {
		if out.Panel == nil || !digest(out.Panel.ReleaseID) || out.Panel.DatabaseSchema != r.Requirements.DatabaseSchema || out.Panel.AgentProtocol < r.Requirements.MinimumAgentProtocol || out.Panel.LauncherVersion < r.Requirements.MinimumLauncher || out.Panel.RequiresCoordination != (out.Panel.AgentProtocol != r.Receiver.AgentProtocol || out.Panel.LauncherVersion != r.Receiver.Launcher) {
			return errors.New("面板准备缺少持久版本暂存回执")
		}
	} else if out.Panel != nil {
		return errors.New("此组件操作不应包含面板暂存回执")
	}
	for _, id := range r.Selected {
		matched := false
		for _, asset := range found {
			if asset == id {
				matched = true
			}
		}
		if !matched {
			return errors.New("组件发行选择无效")
		}
	}
	for _, component := range req.Input.Components {
		if found[component] == "" {
			return errors.New("组件发行缺少所选组件")
		}
	}
	if req.Input.Action != "check" {
		stage := "prepared"
		if req.Input.Action == "pull" {
			stage = "image_ready"
			if found["panel"] == "" || out.Image == nil || out.Frontend != nil || out.Panel != nil {
				return errors.New("镜像拉取缺少持久准备回执")
			}
		}
		if req.Input.Action == "activate" {
			stage = "activated"
			if found["web"] == "" || out.Frontend == nil || out.Frontend.BaseID != req.Input.FrontendBaseID || out.Frontend.PreviousID != req.Input.ExpectedFrontendID {
				return errors.New("前端激活目标与原确认不一致")
			}
		}
		if out.Stage != stage || !out.RuntimeReady || r.PlanID != req.Input.PlanID || r.ManifestSHA256 != req.Input.ManifestSHA256 || r.TrustSHA256 != req.Input.TrustSHA256 {
			return errors.New("组件准备回执与计划不一致")
		}
	} else if out.Stage != "checked" {
		return errors.New("组件检查状态无效")
	}
	if r.Channel != "stable" && (r.Channel != "prerelease" || !req.Input.Prerelease) {
		return errors.New("组件发行渠道不匹配")
	}
	if strings.ContainsAny(r.Repository, "\r\n\x00") {
		return errors.New("组件发行来源无效")
	}
	return nil
}
