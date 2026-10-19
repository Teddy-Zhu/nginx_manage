package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxruntime"
)

// InstallNginx runs in an independent root process, not in the Agent being
// restarted. Every replay uses the same receipt and locally approved assets.
func InstallNginx(ctx context.Context, opts NginxInstallOptions) (Record, error) {
	var r Record
	in := opts.Input
	if os.Geteuid() != 0 || !validID(opts.OperationID) || !validID(in.MaintenanceID) || !validID(opts.Epoch) || opts.Resume && opts.Abort || in.Source.Binary != "" || in.Source.Uninstalled || in.Source.PlanID == "" || in.Source.AssetID == "" {
		return r, errors.New("独立 Nginx 首次安装参数无效")
	}
	if err := in.Source.Validate(); err != nil {
		return r, err
	}
	encoded, err := json.Marshal(in)
	if err != nil {
		return r, err
	}
	if len(encoded) > 64<<10 {
		return r, errors.New("安装意图超过 64 KiB")
	}
	if _, _, err = nginxruntime.Selection(ctx, in.Source.DataDir); err != nil {
		return r, err
	}
	j := &Journal{Dir: filepath.Join(in.Source.DataDir, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".nginx-install.lock")
	if err != nil {
		return r, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return r, err
	}
	if err = installGrant(j, in.MaintenanceID, opts.Epoch, false); err != nil {
		access()
		return r, err
	}
	r, err = j.Get(opts.OperationID)
	if err == nil {
		if validInstallRecord(r) != nil || r.RequestHash != installHash(opts.OperationID, in) {
			access()
			return r, errors.New("原安装记录与请求不一致")
		}
		if installTerminal(r.State) {
			access()
			return r, nil
		}
		if !opts.Resume && !opts.Abort {
			access()
			return r, errors.New("原安装尚未结束，请以同一操作标识明确续办或取消")
		}
	} else if os.IsNotExist(err) {
		if opts.Resume || opts.Abort {
			access()
			return r, errors.New("原安装记录不存在，不能重建")
		}
		records, e := (&maintenanceGate{journal: j}).records()
		if e != nil {
			access()
			return r, e
		}
		for _, prior := range records {
			if prior.Kind == panelUpdateKind {
				settled, e := settledPanelUpdate(prior, in.MaintenanceID)
				if e != nil {
					access()
					return r, e
				}
				if !settled {
					access()
					return r, errors.New("面板更新占用原维护会话，不能同时安装 Nginx")
				}
			}
			if prior.Kind == nginxInstallKind {
				if e = validInstallRecord(prior); e != nil {
					access()
					return r, e
				}
				if !installTerminal(prior.State) {
					access()
					return r, errors.New("已有原生 Nginx 安装执行中或待恢复")
				}
			}
		}
		current, info, e := nginxruntime.Selection(ctx, in.Source.DataDir)
		if e != nil {
			access()
			return r, e
		}
		if info != nil || current.Owner != "uninstalled" {
			access()
			return r, errors.New("仅可安装到明确未安装的 Nginx 登记，不能替换已有实例")
		}
		r = Record{OperationID: opts.OperationID, RequestHash: installHash(opts.OperationID, in), Kind: nginxInstallKind, State: "running", Stage: "validating", NginxInstall: &NginxInstallIntent{Input: in, Before: &current}}
	} else {
		access()
		return r, err
	}
	if in.API != nil && (r.State != "queued" || !opts.Resume || opts.Abort || r.Deadline <= time.Now().Unix()) {
		access()
		return r, errors.New("独立服务只执行原 API 已排队且未过期的安装授权")
	}
	if opts.Abort {
		current, info, e := nginxruntime.Selection(ctx, in.Source.DataDir)
		if e != nil {
			access()
			return r, e
		}
		if info != nil || r.NginxInstall.Before == nil || nginxruntime.SelectionHash(current) != nginxruntime.SelectionHash(*r.NginxInstall.Before) {
			access()
			return r, errors.New("安装绑定已发布或状态不明，不能按未安装取消")
		}
		r.State, r.Stage, r.Error = "cancelled", "cancelled_before_binding", "已取消未发布绑定的安装；已生成的受管基线保留"
		err = j.Put(r)
		access()
		return r, err
	}
	if in.API == nil {
		r.Deadline = time.Now().Add(10 * time.Minute).Unix()
	}
	r.State, r.Error, r.MaintenanceEpoch = "running", "", opts.Epoch
	if err = j.Put(r); err != nil {
		access()
		return r, err
	}
	access()
	call, cancel := context.WithDeadline(ctx, time.Unix(r.Deadline, 0))
	defer cancel()
	err = runNginxInstallation(call, j, &r)
	if err != nil {
		r.State, r.Error = "recovery_required", "安装未确认完成；保留原记录和维护锁，请核对失败阶段后续办原操作"
		if put := j.Put(r); put != nil {
			return r, errors.Join(err, put)
		}
		return r, err
	}
	r.State, r.Error = "succeeded", ""
	r.Stage = "installed"
	if r.NginxInstall.Running {
		r.Stage = "running"
	}
	if err = j.Put(r); err != nil {
		return r, err
	}
	return r, nil
}

func installGrant(j *Journal, id, epoch string, allowClosing bool) error {
	return installGrantForOperation(j, id, epoch, allowClosing, "")
}

func installGrantForOperation(j *Journal, id, epoch string, allowClosing bool, operationID string) error {
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		return err
	}
	for _, prior := range records {
		if prior.Kind == panelImageKind {
			if err := validPanelImage(prior); err != nil {
				return err
			}
			if !panelImageTerminal(prior) && prior.OperationID != operationID {
				return errors.New("面板镜像替换尚未完成，不能执行其他维护动作")
			}
		}
		if prior.Kind == agentUpgradeKind {
			if err := validAgentUpgrade(prior); err != nil {
				return err
			}
			if !agentUpgradeTerminal(prior) && prior.OperationID != operationID {
				return errors.New("Agent 独立升级尚未完成，不能执行其他维护动作")
			}
		}
		if prior.Kind == runtimeHistoryKind {
			if err := validRuntimeHistory(prior); err != nil {
				return err
			}
			if !historyTerminal(prior) {
				return errors.New("运行材料清理尚未结束，须先续办原操作")
			}
		}
	}
	r, err := j.Get(id)
	if err != nil {
		return err
	}
	if r.Kind != "maintenance.lock" || r.OperationID != id || r.RequestHash != maintenanceHash(maintenance.RootRequest{Protocol: Protocol, OperationID: id}) || !(r.State == "waiting_confirmation" && r.Stage == "held" || allowClosing && r.State == "running" && r.Stage == "closing") || !validID(r.MaintenanceEpoch) || epoch != "" && r.MaintenanceEpoch != epoch {
		return errors.New("须取得同一节点已确认的独立维护锁")
	}
	return nil
}
func installationStage(ctx context.Context, j *Journal, r *Record, stage string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err = installGrant(j, r.NginxInstall.Input.MaintenanceID, "", stage == "confirming"); err != nil {
		return err
	}
	r.Stage = stage
	return j.Put(*r)
}
func runNginxInstallation(ctx context.Context, j *Journal, r *Record) error {
	spec := r.NginxInstall
	in := spec.Input
	if _, err := installationExecutable(); err != nil {
		return err
	}
	for _, unit := range []string{"nginxpanel-nginx.service", "nginxpanel-agent.service"} {
		if err := installationUnit(ctx, unit, in.Source.DataDir, in.WorkerUser); err != nil {
			return err
		}
	}
	current, info, err := nginxruntime.Selection(ctx, in.Source.DataDir)
	if err != nil {
		return err
	}
	if info == nil {
		if spec.Before == nil || nginxruntime.SelectionHash(current) != nginxruntime.SelectionHash(*spec.Before) {
			return errors.New("未安装登记已变化")
		}
		candidate, e := nginxruntime.Admit(ctx, in.Source)
		if e != nil {
			return e
		}
		if api := in.API; api != nil && (candidate.Signed == nil || candidate.Signed.ManifestSHA256 != api.ManifestSHA256 || candidate.Signed.TrustSHA256 != api.TrustSHA256) {
			return errors.New("安装资产的清单或信任与原准备任务不一致")
		}
		if spec.Candidate != nil && nginxruntime.CandidateHash(candidate) != nginxruntime.CandidateHash(*spec.Candidate) {
			return errors.New("准备资产与原安装候选不一致")
		}
		if spec.Candidate == nil {
			spec.Candidate = &candidate
		}
		if err = installationStage(ctx, j, r, "initializing"); err != nil {
			return err
		}
		n := &Nginx{DataDir: in.Source.DataDir, Binary: candidate.Binary, WorkerUser: in.WorkerUser, Policy: in.Policy, Modules: in.Modules, Journal: j}
		if err = initializeInstallation(ctx, n); err != nil {
			return err
		}
		if err = installationStage(ctx, j, r, "binding"); err != nil {
			return err
		}
		current, err = nginxruntime.InstallPrepared(ctx, in.Source, r.OperationID, nginxruntime.SelectionHash(*spec.Before), *spec.Candidate)
		if err != nil {
			return err
		}
	} else if current.OperationID != r.OperationID || spec.Candidate == nil || nginxruntime.CandidateHash(current) != nginxruntime.CandidateHash(*spec.Candidate) {
		return errors.New("当前安装不属于原操作，停止继续安装")
	}
	if in.Enable {
		if err = installationStage(ctx, j, r, "enabling"); err != nil {
			return err
		}
		if _, err = installationSystemctl(ctx, "enable", "nginxpanel-nginx.service"); err != nil {
			return err
		}
	}
	if in.Start {
		if err = installationStage(ctx, j, r, "starting"); err != nil {
			return err
		}
		if _, err = installationSystemctl(ctx, "start", "nginxpanel-nginx.service"); err != nil {
			return err
		}
	}
	if err = installationStage(ctx, j, r, "restarting_agent"); err != nil {
		return err
	}
	if _, err = installationSystemctl(ctx, "restart", "nginxpanel-agent.service"); err != nil {
		return err
	}
	if err = installationStage(ctx, j, r, "confirming"); err != nil {
		return err
	}
	result, err := waitInstallationProbe(ctx, in.Source.DataDir, current, in.Start)
	if err != nil {
		return err
	}
	spec.Installation, spec.Running = result.Components.Installation, result.Runtime.Running
	return nil
}
func initializeInstallation(ctx context.Context, n *Nginx) error {
	if err := n.Open(); err != nil {
		return err
	}
	defer n.Close()
	if err := n.Initialize(); err != nil {
		return err
	}
	dir, m, err := n.active()
	if err != nil {
		return err
	}
	parsed, err := nginxconfig.Parse(nginxconfig.InitialFiles(), n.Policy)
	if err != nil {
		return err
	}
	if dir != "bootstrap" || m.RevisionID != "" || m.SourceHash != n.sourceHash(parsed) {
		return errors.New("已有配置不是此专用实例的受管空基线，停止接管")
	}
	call, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err = n.test(call, dir); err != nil {
		return errors.Join(errors.New("候选 Nginx 未通过受管空基线配置检查"), err)
	}
	return nil
}
