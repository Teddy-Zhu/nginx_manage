package releases

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var ErrReleaseChanged = errors.New("发行材料或本机信任已变化，请重新检查")

func ValidateOnlineSelection(in OnlineInput) error {
	if in.Tag != "" && (!strings.HasPrefix(in.Tag, "v") || !validVersion(strings.TrimPrefix(in.Tag, "v"))) || in.AllowPrerelease && in.Tag == "" {
		return errors.New("标签须为 v 开头的 SemVer，预发布须显式指定标签")
	}
	if err := selectors(in.Assets, in.Components); err != nil {
		return err
	}
	for _, expected := range []string{in.ExpectedPlanID, in.ExpectedManifestSHA256, in.ExpectedTrustSHA256} {
		if expected != "" && !validHash(expected) {
			return errors.New("发行材料期望散列无效")
		}
	}
	return nil
}

func selectors(assets, components []string) error {
	if (len(assets) == 0) == (len(components) == 0) || len(assets)+len(components) > 4 {
		return errors.New("须选择 1–4 个资产或组件，不能混用两种选择方式")
	}
	seen := map[string]bool{}
	for _, id := range append(slices.Clone(assets), components...) {
		if !identifier.MatchString(id) || seen[id] {
			return errors.New("所选资产或组件无效、重复")
		}
		seen[id] = true
	}
	for _, component := range components {
		if !slices.Contains([]string{"panel", "web", "nginx", "fail2ban"}, component) {
			return errors.New("未知组件")
		}
	}
	return nil
}
func hostAsset(a Asset, h Host) bool {
	return a.Maintenance == "maintained" && a.OS == h.OS && (a.Architecture == "any" || a.Architecture == h.Architecture) && (a.Distribution == "any" && a.DistributionVersion == "any" || a.Distribution != "any" && a.Distribution == h.Distribution && a.DistributionVersion == h.Version)
}
func selectAssets(m Manifest, host Host, explicit, components []string) ([]string, error) {
	if len(explicit) != 0 {
		return slices.Clone(explicit), nil
	}
	selected := []string{}
	for _, component := range components {
		candidates := []string{}
		for _, a := range m.Assets {
			if a.Component == component && hostAsset(a, host) {
				candidates = append(candidates, a.ID)
			}
		}
		slices.Sort(candidates)
		if len(candidates) == 0 {
			return nil, fmt.Errorf("组件 %s 没有匹配目标系统的受维护签名资产", component)
		}
		if len(candidates) != 1 {
			return nil, fmt.Errorf("组件 %s 存在多个匹配资产，须明确选择：%s", component, strings.Join(candidates, ", "))
		}
		selected = append(selected, candidates[0])
	}
	return selected, nil
}

type TrustInfo struct {
	Repository string   `json:"repository"`
	SHA256     string   `json:"sha256"`
	KeyIDs     []string `json:"key_ids"`
}

func InspectTrust(name string) (TrustInfo, error) {
	p, err := readTrust(name)
	if err != nil {
		return TrustInfo{}, err
	}
	info := TrustInfo{Repository: p.trust.Repository, SHA256: hash(p.raw), KeyIDs: []string{}}
	for _, key := range p.trust.Keys {
		info.KeyIDs = append(info.KeyIDs, key.ID)
	}
	slices.Sort(info.KeyIDs)
	return info, nil
}

// Prepared reauthenticates a recorded immutable preparation without networking.
// Missing or changed receipts never trigger an implicit replacement download.
func Prepared(ctx context.Context, in Input, id string) (Result, error) {
	return inspectPrepared(ctx, in, id, time.Now().Unix(), "")
}

// RuntimeReadiness only inspects runtime files of already authenticated assets.
func RuntimeReadiness(ctx context.Context, assets []Asset) error {
	for _, a := range assets {
		if err := validateAsset(a); err != nil {
			return err
		}
	}
	return checkRuntime(ctx, assets)
}
