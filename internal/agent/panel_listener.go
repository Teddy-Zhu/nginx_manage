package agent

import (
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/storage"
)

func SetPanelListen(data, address string) error { return SetPanelAccess(data, address, "") }

func SetPanelAccess(data, address, protocol string) error {
	if os.Geteuid() != 0 {
		return errors.New("修改管理地址需要本机 root")
	}
	d, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.maintenanceLock()
	if err != nil {
		return err
	}
	defer unlock()
	g := &maintenanceGate{journal: j}
	records, err := g.rawRecords()
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.Kind == "maintenance.lock" && !(r.State == "succeeded" && r.Stage == "released") {
			return errors.New("存在未结束的维护任务，请沿原任务处理后再修改端口")
		}
	}
	release, err := storage.LockWriter(data, d.GID)
	if err != nil {
		return err
	}
	defer release()
	return panelruntime.SetAccess(data, address, protocol)
}
