package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/panelupdates"
)

const panelUpdateTemplate = "nginxpanel-update@.service"

func panelUpdateUnit(id string) string { return "nginxpanel-update@" + id + ".service" }

// Both the root-owned fragment and systemd's loaded instance must match the
// installation. A modified drop-in or a pending daemon reload fails closed.
func panelUpdateHost(ctx context.Context, data, id string) (active, failed bool, err error) {
	if !validID(id) {
		return false, false, errors.New("更新服务实例标识无效")
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return false, false, err
	}
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != "native-install-v10\n" || !strings.HasPrefix(string(intent), "native-install-v10\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") {
		return false, false, errors.New("更新服务缺少匹配的本机安装登记")
	}
	raw, err := nginxmodules.ReadTrusted("/etc/systemd/system/"+panelUpdateTemplate, 64<<10)
	if err != nil {
		return false, false, err
	}
	expected := "ExecStart=/opt/nginxpanel/current/nginxpanel panel-update-worker --data-dir " + data + " --panel-update %i"
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != expected {
				return false, false, errors.New("独立更新服务入口与本机登记不一致")
			}
		}
	}
	if count != 1 {
		return false, false, errors.New("独立更新服务入口无效")
	}
	rawState, err := installationSystemctl(ctx, "show", "--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode,ActiveState", panelUpdateUnit(id))
	if err != nil {
		return false, false, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(rawState), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false, false, errors.New("更新服务实际属性无效")
		}
		if _, exists := values[key]; exists {
			return false, false, errors.New("更新服务实际属性重复")
		}
		values[key] = value
	}
	if len(values) != 10 || values["LoadState"] != "loaded" || values["FragmentPath"] != "/etc/systemd/system/"+panelUpdateTemplate || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" || values["User"] != "root" || values["Group"] != "nginxpanel-ipc" || values["Type"] != "exec" || values["Restart"] != "no" || values["KillMode"] != "mixed" {
		return false, false, errors.New("systemd 实际加载的独立更新服务与登记不一致")
	}
	switch values["ActiveState"] {
	case "active", "activating", "deactivating", "reloading":
		return true, false, nil
	case "inactive":
		return false, false, nil
	case "failed":
		return false, true, nil
	default:
		return false, false, errors.New("独立更新服务状态无法核实")
	}
}

func panelUpdateAPIInput(in PanelUpdateInput) panelupdates.Input {
	return panelupdates.Input{MaintenanceID: in.MaintenanceID, PlanID: in.Stage.PlanID, Prerelease: in.Stage.AllowPrerelease}
}

// Checked again inside the worker lock so a delayed service cannot consume a
// replacement authorization. Expiration limits dispatch, not compensation.
func authorizePanelUpdate(r Record, req *panelupdates.Request) error {
	a := r.PanelUpdate.Authorizations
	if len(a) == 0 && req == nil {
		return nil
	}
	if len(a) == 0 || req == nil || a[len(a)-1].Request != *req {
		return errors.New("托管更新须使用最后一次持久化的原操作授权")
	}
	if !panelUpdateFinalized(r) && (req.AuthorizationUntil <= time.Now().Unix() || a[len(a)-1].ClaimedAt != 0) {
		return errors.New("独立更新启动授权已过期或已使用，须显式续办原操作")
	}
	return nil
}

func RunPanelUpdate(ctx context.Context, data, id string) (Record, error) {
	if os.Geteuid() != 0 || !validID(id) {
		return Record{}, errors.New("独立更新服务身份或标识无效")
	}
	if _, err := installationExecutable(); err != nil {
		return Record{}, err
	}
	if _, _, err := panelUpdateHost(ctx, data, id); err != nil {
		return Record{}, err
	}
	r, err := panelUpdateRecord(data, id)
	if err != nil {
		return r, err
	}
	a := r.PanelUpdate.Authorizations
	if len(a) == 0 {
		return r, errors.New("独立更新服务缺少原 API 授权")
	}
	req := a[len(a)-1].Request
	return updatePanel(ctx, r.PanelUpdate.Intent.Input, id, req.Epoch, &req)
}
