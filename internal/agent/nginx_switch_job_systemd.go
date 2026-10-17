package agent

import (
	"context"
	"errors"
	"strings"

	"nginxpanel/internal/nginxmodules"
)

func switchJobUnit(id string) string { return "nginxpanel-switch@" + id + ".service" }

func nginxSwitchServiceTemplate(data string) error {
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != "native-install-v12\n" {
		return errors.New("原生切换服务缺少完成安装登记")
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil || !strings.HasPrefix(string(intent), "native-install-v12\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") || !strings.Contains(string(intent), "\nnginx_image=\n") {
		return errors.New("原生切换服务不属于本机安装")
	}
	raw, err := nginxmodules.ReadTrusted("/etc/systemd/system/"+nginxSwitchTemplate, 64<<10)
	if err != nil {
		return err
	}
	expected := "ExecStart=/opt/nginxpanel/current/nginxpanel nginx-switch-worker --data-dir " + data + " --nginx-switch-operation %i"
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != expected {
				return errors.New("独立切换服务入口已变化")
			}
		}
	}
	if count != 1 {
		return errors.New("独立切换服务入口无效")
	}
	return nil
}

func switchJobHost(ctx context.Context, data, id string) (active, failed bool, err error) {
	if !validID(id) {
		return false, false, errors.New("切换服务实例标识无效")
	}
	if err = nginxSwitchServiceTemplate(data); err != nil {
		return false, false, err
	}
	raw, err := installationSystemctl(ctx, "show", "--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode,ActiveState", switchJobUnit(id))
	if err != nil {
		return false, false, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false, false, errors.New("切换服务观测格式无效")
		}
		if _, exists := values[key]; exists {
			return false, false, errors.New("切换服务观测包含重复字段")
		}
		values[key] = value
	}
	if len(values) != 10 || values["LoadState"] != "loaded" || values["FragmentPath"] != "/etc/systemd/system/"+nginxSwitchTemplate || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" || values["User"] != "root" || values["Group"] != "nginxpanel-ipc" || values["Type"] != "exec" || values["Restart"] != "no" || values["KillMode"] != "mixed" {
		return false, false, errors.New("systemd 实际切换服务与安装登记不一致")
	}
	switch values["ActiveState"] {
	case "active", "activating", "deactivating", "reloading":
		return true, false, nil
	case "inactive":
		return false, false, nil
	case "failed":
		return false, true, nil
	default:
		return false, false, errors.New("切换服务状态无法确认")
	}
}
