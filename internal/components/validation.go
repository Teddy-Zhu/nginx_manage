package components

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"nginxpanel/internal/protocol"
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
	if req.Protocol != protocol.Agent || !ValidID(req.OperationID) || req.Input.Validate() != nil || out.Protocol != req.Protocol || out.ID != req.OperationID || out.RequestHash != secure.Hash(raw) || out.CreatedAt <= 0 || out.UpdatedAt < out.CreatedAt || out.Deadline != out.CreatedAt+600 || !containsState(out.State) {
		return errors.New("组件操作身份或状态无效")
	}
	input, _ := json.Marshal(out.Input)
	expected, _ := json.Marshal(req.Input)
	if string(input) != string(expected) {
		return errors.New("组件操作输入不一致")
	}
	if out.State != "succeeded" {
		return nil
	}
	r := out.Release
	if r == nil || !digest(r.PlanID) || !digest(r.ManifestSHA256) || !digest(r.TrustSHA256) || r.Repository == "" || r.KeyID == "" || r.Tag != "v"+r.Version || r.ExpiresAt <= out.CreatedAt || len(r.Selected) == 0 || len(r.Selected) > 2 || len(r.Assets) == 0 || len(r.Assets) > 2 || out.Error != "" || out.ErrorCode != "" {
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
		if (a.Component != "nginx" && a.Component != "fail2ban") || found[a.Component] != "" || a.ID == "" || a.Version == "" {
			return errors.New("组件发行内容无效")
		}
		found[a.Component] = a.ID
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
	if req.Input.Action == "prepare" {
		if out.Stage != "prepared" || !out.RuntimeReady || r.PlanID != req.Input.PlanID || r.ManifestSHA256 != req.Input.ManifestSHA256 || r.TrustSHA256 != req.Input.TrustSHA256 {
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
