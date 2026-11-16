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
		if a.Validate() != nil || a.Receiver.APIMajor != 1 || a.ReceiverCompatible || out.State != "failed" || out.ErrorCode != "COMPONENT_RECEIVER_INCOMPATIBLE" || req.Input.Action == "pull" || req.Input.OfflineID != "" || req.Input.Tag != "" && a.Tag != req.Input.Tag || a.Channel == "beta" && !req.Input.Prerelease || a.ExpiresAt <= out.CreatedAt || req.Input.ManifestSHA256 != "" && a.ManifestSHA256 != req.Input.ManifestSHA256 || req.Input.TrustSHA256 != "" && a.TrustSHA256 != req.Input.TrustSHA256 {
			return errors.New("组件失败结果的已验签说明不匹配")
		}
	}
	if out.State != "succeeded" {
		return nil
	}
	if req.Input.Action == "software" {
		if out.Software == nil || out.Stage != "software_done" || out.Error != "" || out.ErrorCode != "" {
			return errors.New("软件操作结果不完整")
		}
		return nil
	}
	r := out.Release
	if r == nil || r.Requirements.Validate() != nil || !releases.ValidNotes(r.Notes) || r.Receiver.APIMajor != 1 || r.Receiver.AgentProtocol <= 0 || r.Receiver.Launcher <= 0 || r.StagingOnly != (len(r.Requirements.Incompatibilities(r.Receiver)) != 0) || !digest(r.PlanID) || !digest(r.ManifestSHA256) || !digest(r.TrustSHA256) || r.Repository == "" || r.KeyID == "" || r.Tag != releases.SelectionTag(r.Version, r.Selected) || r.ExpiresAt <= out.CreatedAt || len(r.Selected) == 0 || len(r.Selected) > 2 || len(r.Assets) > 2 || out.Error != "" || out.ErrorCode != "" {
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
		if (a.Component != "nginx" && a.Component != "fail2ban" && a.Component != "panel") || found[a.Component] != "" || a.ID == "" || a.Version == "" {
			return errors.New("组件发行内容无效")
		}
		found[a.Component] = a.ID
	}
	if found["panel"] != "" && len(found) != 1 {
		return errors.New("核心服务须使用独立准备计划")
	}
	if r.StagingOnly && (found["panel"] == "" || len(r.Assets) != 1 || r.Assets[0].ABI != "static" || len(r.Assets[0].Dependencies) != 0 || r.Requirements.APIMajor != r.Receiver.APIMajor || req.Input.Action != "check" && req.Input.Action != "prepare") {
		return errors.New("不满足当前核心要求的发行仅允许检查和核心程序暂存")
	}
	if len(r.Assets) == 0 {
		if len(r.Selected) != 1 || len(r.Images) != 1 || r.Selected[0] != "image-"+r.Images[0].ID {
			return errors.New("镜像须使用独立签名准备计划")
		}
	} else if len(r.Images) != 0 {
		return errors.New("镜像不能与程序资产混合准备")
	}
	seenImages := map[string]bool{}
	for _, image := range r.Images {
		if !image.valid(r.Repository) || seenImages[image.ID] {
			return errors.New("签名镜像选择无效")
		}
		seenImages[image.ID] = true
	}
	if req.Input.Action == "prepare" && found["panel"] != "" {
		if out.Panel == nil || !digest(out.Panel.ReleaseID) || out.Panel.DatabaseSchema != r.Requirements.DatabaseSchema || out.Panel.AgentProtocol < r.Requirements.MinimumAgentProtocol || out.Panel.LauncherVersion < r.Requirements.MinimumLauncher || out.Panel.RequiresCoordination != (out.Panel.LauncherVersion != r.Receiver.Launcher) {
			return errors.New("面板准备缺少持久版本暂存回执")
		}
	} else if out.Panel != nil {
		return errors.New("此组件操作不应包含面板暂存回执")
	}
	for _, id := range r.Selected {
		matched := false
		for _, image := range r.Images {
			if id == "image-"+image.ID {
				matched = true
			}
		}
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
			imageID := component
			if component == "panel-runtime" {
				imageID = "panel-launcher"
			}
			if !seenImages[imageID] {
				return errors.New("组件发行缺少所选组件")
			}
		}
	}
	if req.Input.Action != "check" {
		stage := "prepared"
		if req.Input.Action == "pull" {
			stage = "image_ready"
			if len(r.Assets) != 0 || len(r.Images) != 1 || out.Image == nil || out.Panel != nil {
				return errors.New("镜像拉取缺少持久准备回执")
			}
		}
		if out.Stage != stage || !out.RuntimeReady || r.PlanID != req.Input.PlanID || r.ManifestSHA256 != req.Input.ManifestSHA256 || r.TrustSHA256 != req.Input.TrustSHA256 {
			return errors.New("组件准备回执与计划不一致")
		}
	} else if out.Stage != "checked" {
		return errors.New("组件检查状态无效")
	}
	if !releases.ValidChannel(r.Version, r.Channel) || r.Channel == "beta" && !req.Input.Prerelease {
		return errors.New("组件发行渠道不匹配")
	}
	if strings.ContainsAny(r.Repository, "\r\n\x00") {
		return errors.New("组件发行来源无效")
	}
	return nil
}
