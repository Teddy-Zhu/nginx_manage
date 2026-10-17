package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

// List only small root-owned ownership headers. Full captures and native proof
// are checked for the selected resource and again before every execution.
func (f *fail2banJailsExecutor) existingResources(ctx context.Context) ([]fail2ban.ExistingResource, error) {
	out := []fail2ban.ExistingResource{}
	dir := filepath.Join(fail2banExistingDir(f.server.DataDir), "current")
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	if err := existingRootDirectory(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > 64 {
		return nil, errors.New("已有 jail 接管目录超限")
	}
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if name == entry.Name() || !fail2banJailName.MatchString(name) || !entry.Type().IsRegular() {
			return nil, errors.New("已有 jail 接管目录含未知条目")
		}
		var pointer struct {
			ID string `json:"id"`
		}
		if err = readFail2banNginxJSON(filepath.Join(dir, entry.Name()), &pointer, 1024); err != nil {
			return nil, err
		}
		if !validID(pointer.ID) {
			return nil, errors.New("已有 jail 接管指针无效")
		}
		var grant fail2banExistingGrant
		if err = readFail2banNginxJSON(fail2banExistingGrantPath(f.server.DataDir, pointer.ID), &grant, 8192); err != nil {
			return nil, err
		}
		if grant.Schema != 1 || grant.ID != pointer.ID || grant.Name != name || !validID(grant.BindingID) || !validID(grant.AdoptionID) || grant.At <= 0 || grant.Action != "adopt" && grant.Action != "release" || grant.Action == "adopt" && grant.ID != grant.AdoptionID || grant.Action == "release" && grant.PreviousID != grant.AdoptionID {
			return nil, errors.New("已有 jail 接管元数据无效")
		}
		if grant.Action == "adopt" {
			out = append(out, fail2ban.ExistingResource{Name: name, AdoptionID: grant.AdoptionID, BindingID: grant.BindingID})
		}
	}
	return out, nil
}

func (f *fail2banJailsExecutor) existingResource(ctx context.Context, name string) (fail2ban.ExistingResourcePolicy, error) {
	var out fail2ban.ExistingResourcePolicy
	if !fail2banJailName.MatchString(name) {
		return out, fault.Invalid("已有 jail 名称无效")
	}
	leave, err := f.lock(false)
	if err != nil {
		return out, err
	}
	defer leave()
	grant, err := loadFail2banExistingGrant(f.server.DataDir, name)
	if err != nil {
		return out, err
	}
	if grant == nil || grant.Action != "adopt" {
		return out, fault.New(404, "FAIL2BAN_EXISTING_RESOURCE_MISSING", "此 jail 没有本机有效接管登记")
	}
	original, err := existingPolicyAdoption(f.server.DataDir, grant.AdoptionID)
	if err != nil {
		return out, err
	}
	selected, err := loadFail2banExistingPolicy(f.server.DataDir, original, grant.AdoptionID)
	if err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	out = fail2ban.ExistingResourcePolicy{ExistingResource: fail2ban.ExistingResource{Name: name, AdoptionID: grant.AdoptionID, BindingID: grant.BindingID}, SelectedID: selected.ID, Profile: original.Plan.Profile, Policy: selected.Policy}
	return out, nil
}
