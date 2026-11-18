package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/storage"
)

const coreUpdateKind = "core.update"

// The complete core (Agent, API and embedded UI) is selected together. The
// updater is a short-lived systemd worker so replacing the core cannot kill it.
type CoreUpdateIntent struct {
	Source panelruntime.StageInput `json:"source"`
	Before string                  `json:"before"`
	Target string                  `json:"target"`
}

func coreUpdateRecord(j *Journal, id, data string) (Record, error) {
	r, err := j.Get(id)
	if err != nil {
		return r, err
	}
	i := r.CoreUpdate
	if !validID(id) || r.OperationID != id || r.Kind != coreUpdateKind || i == nil || i.Source.DataDir != data || !panelSelectionDigest.MatchString(i.Before) || !panelSelectionDigest.MatchString(i.Target) || i.Before == i.Target || r.RequestHash != selectionValueHash(i) || (r.State != "running" && r.State != "succeeded" && r.State != "failed") {
		return r, errors.New("核心更新记录与原操作不一致")
	}
	return r, nil
}

func coreUpdateUnit(ctx context.Context, data, id string) error {
	if err := panelNativeUnit(data); err != nil {
		return err
	}
	raw, err := nginxmodules.ReadTrusted("/etc/systemd/system/nginxpanel-core-update@.service", 64<<10)
	if err != nil {
		return err
	}
	want := "ExecStart=/opt/nginxpanel/current/nginxpanel core-update-worker --data-dir " + data + " --core-update %i"
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != want {
				return errors.New("核心更新执行器入口不匹配")
			}
		}
	}
	if count != 1 {
		return errors.New("核心更新执行器未登记")
	}
	v, err := agentUpgradeProperties(ctx, "nginxpanel-core-update@"+id+".service", "LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart")
	if err != nil {
		return err
	}
	if v["LoadState"] != "loaded" || v["FragmentPath"] != "/etc/systemd/system/nginxpanel-core-update@.service" || v["DropInPaths"] != "" || v["NeedDaemonReload"] != "no" || v["User"] != "root" || v["Group"] != "root" || v["Type"] != "exec" || v["Restart"] != "no" {
		return errors.New("核心更新执行器的实际服务属性不匹配")
	}
	return nil
}

func (s *Server) queueCoreUpdate(ctx context.Context, id string, source panelruntime.StageInput) error {
	if os.Geteuid() != 0 || !validID(id) {
		return errors.New("核心更新需要本机管理权限与有效操作标识")
	}
	unlock, err := s.Journal.rootLock(".core-update-queue.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if existing, err := coreUpdateRecord(s.Journal, id, s.DataDir); err == nil {
		if existing.CoreUpdate.Source != source {
			return errors.New("核心更新来源与原任务不一致")
		}
		if existing.State != "running" {
			return nil
		}
		if err := coreUpdateUnit(ctx, s.DataDir, id); err != nil {
			return err
		}
		_, err = installationSystemctl(ctx, "start", "--no-block", "nginxpanel-core-update@"+id+".service")
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := coreUpdateUnit(ctx, s.DataDir, id); err != nil {
		return err
	}
	staged, err := panelruntime.Staged(ctx, source)
	if err != nil {
		return err
	}
	if err := staged.RequireCurrent(); err != nil {
		return err
	}
	before, err := panelruntime.Read(s.DataDir)
	if err != nil {
		return err
	}
	if before.Deployment.Mode != "native" || before.Deployment.UID != 0 {
		return errors.New("核心更新仅支持已安装的宿主机单服务")
	}
	if staged.Release.DatabaseSchema < before.Release.DatabaseSchema {
		return errors.New("目标版本早于当前数据格式，无法直接降级")
	}
	if before.Release.ID == staged.Release.ID {
		return nil
	}
	if comparison, err := releases.CompareVersions(before.Release.Version, staged.Release.Version); err != nil || comparison >= 0 {
		return errors.New("目标版本须高于当前运行版本，请重新检查")
	}
	i := &CoreUpdateIntent{Source: source, Before: before.Release.ID, Target: staged.Release.ID}
	r := Record{OperationID: id, Kind: coreUpdateKind, State: "running", Stage: "queued", RequestHash: selectionValueHash(i), CoreUpdate: i}
	if err = s.Journal.Put(r); err != nil {
		return err
	}
	if _, err = installationSystemctl(ctx, "start", "--no-block", "nginxpanel-core-update@"+id+".service"); err != nil {
		r.State, r.Stage, r.Error = "failed", "dispatch_failed", err.Error()
		return errors.Join(err, s.Journal.Put(r))
	}
	return nil
}

// RunCoreUpdate consumes only an existing signed/root-owned intent. It never
// accepts a binary path, shell command, download URL or unsigned application.
func RunCoreUpdate(parent context.Context, data, id string) (resultErr error) {
	if os.Geteuid() != 0 || !validID(id) {
		return errors.New("核心更新执行器身份无效")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".core-update.lock")
	if err != nil {
		return err
	}
	defer unlock()
	r, err := coreUpdateRecord(j, id, data)
	if err != nil {
		return err
	}
	if r.State == "succeeded" {
		return nil
	}
	if r.State == "failed" {
		return errors.New(r.Error)
	}
	if err = coreUpdateUnit(ctx, data, id); err != nil {
		return err
	}
	if err = verifySystemdWorker(ctx, "nginxpanel-core-update@"+id+".service"); err != nil {
		return err
	}
	i := r.CoreUpdate
	stage := func(value string) error { r.Stage = value; return j.Put(r) }
	defer func() {
		if resultErr == nil {
			return
		}
		r.State, r.Stage, r.Error = "failed", "failed", resultErr.Error()
		resultErr = errors.Join(resultErr, j.Put(r))
	}()
	installer, err := (&Journal{Dir: "/run/nginxpanel-install"}).rootLock("lock")
	if err != nil {
		return err
	}
	defer installer()
	staged, err := panelruntime.Staged(ctx, i.Source)
	if err != nil {
		return err
	}
	if staged.Release.ID != i.Target {
		return errors.New("核心更新来源已变化")
	}
	if err = staged.RequireCurrent(); err != nil {
		return err
	}
	if err = activateCore(ctx, data, id, i.Before, staged.Release, stage); err != nil {
		return err
	}
	r.State, r.Stage, r.Error = "succeeded", "committed", ""
	return j.Put(r)
}

func activateCore(ctx context.Context, data, id, before string, target panelruntime.Release, stage func(string) error) (err error) {
	current, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	if target.DatabaseSchema < current.Release.DatabaseSchema {
		return errors.New("目标版本早于当前数据格式，无法直接降级")
	}
	if current.Release.ID != before && current.Release.ID != target.ID {
		return errors.New("核心版本偏离原更新任务")
	}
	if current.Release.ID == target.ID {
		if ready, _, _ := panelreadyForSoftware(ctx, current); ready {
			return nil
		}
	}
	if err = stage("stopping"); err != nil {
		return err
	}
	// Even a cancelled stop request may have reached systemd.
	defer func() {
		if err != nil {
			recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, startErr := installationSystemctl(recovery, "start", "nginxpanel.service")
			err = errors.Join(err, startErr)
		}
	}()
	if _, err = installationSystemctl(ctx, "stop", "nginxpanel.service"); err != nil {
		return err
	}
	if err = stage("selecting"); err != nil {
		return err
	}
	writer, err := storage.LockWriter(data, 0)
	if err != nil {
		return err
	}
	if before != target.ID {
		err = panelruntime.SwitchCurrent(data, before, target.ID, id)
	}
	writer()
	if err != nil {
		return err
	}
	if err = stage("starting"); err != nil {
		return err
	}
	if _, err = installationSystemctl(ctx, "start", "nginxpanel.service"); err != nil {
		return err
	}
	if err = stage("checking"); err != nil {
		return err
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastCheckErr error
	for {
		s, readErr := panelruntime.Read(data)
		checkErr := readErr
		if checkErr == nil {
			if s.Release.ID != target.ID {
				checkErr = errors.New("当前核心版本与升级目标不一致")
			} else if ready, _, readyErr := panelreadyForSoftware(ctx, s); readyErr != nil {
				checkErr = readyErr
			} else if ready {
				return nil
			} else {
				checkErr = errors.New("当前数据版本与升级目标不一致")
			}
		}
		if ctx.Err() == nil || lastCheckErr == nil {
			lastCheckErr = checkErr
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("面板就绪检查未完成（%v）：%w", ctx.Err(), lastCheckErr)
		case <-tick.C:
		}
	}
}
