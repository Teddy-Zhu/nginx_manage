package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelrecovery"
)

type RestoreInput struct {
	AdoptionSHA256 string `json:"adoption_sha256"`
	PlanID         string `json:"plan_id"`
	PlanSHA256     string `json:"plan_sha256"`
	Epoch          string `json:"epoch"`
}

// RestoreAdoption installs a previously approved generation or continues its
// explicit compensation. Source admission is serialized with adoption cleanup.
func RestoreAdoption(ctx context.Context, data, id string, in RestoreInput, rollback bool) (out agent.Record, err error) {
	if !validID.MatchString(id) || !validID.MatchString(in.Epoch) || !validHash.MatchString(in.AdoptionSHA256) {
		return out, errors.New("独立恢复须指定原接入批准摘要和当前维护 epoch")
	}
	call, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return out, err
	}
	defer unlock()
	if rollback {
		i, err := panelrecovery.ReadDisasterIntent(data, id)
		if err != nil {
			return out, err
		}
		if i.AdoptionSHA256 != in.AdoptionSHA256 {
			return out, errors.New("补偿摘要与原独立安装批准不一致")
		}
		if in.PlanID != "" && in.PlanID != i.PlanID || in.PlanSHA256 != "" && in.PlanSHA256 != i.PlanSHA256 {
			return out, errors.New("补偿请求指定了不同的原目标计划")
		}
		status, e := agent.DisasterRuntime(data, id)
		if e != nil {
			return out, e
		}
		if status.Restore.DisasterActivation != nil {
			return status.Restore, errors.New("恢复已提交激活，须续办 backup-restore-activate，不能覆盖新数据库")
		}
		if (strings.HasPrefix(status.Restore.Stage, "runtime_") || strings.HasPrefix(status.Restore.Stage, "data_") || status.Restore.Stage == "files_installed" && status.Nginx != nil) && status.Restore.Stage != "runtime_compensated" {
			status, e = advanceRestorationRuntime(call, data, id, in, true)
			if e != nil {
				return status.Restore, e
			}
			if status.Restore.Stage != "runtime_compensated" {
				return status.Restore, nil
			}
		} else if status.Restore.Stage == "files_installed" || status.Restore.Stage == "runtime_compensated" || status.Nginx != nil && status.Restore.Stage != "files_compensated" {
			if e = agent.AuthorizeDisasterRuntime(call, data, id, in.Epoch, true); e != nil {
				return status.Restore, e
			}
		}
		return agent.RestoreDisaster(call, data, id, in.Epoch, i, true)
	}
	status, err := readAdoptionStatus(call, data, id)
	if err != nil {
		return out, err
	}
	if status.State != "adopted" || status.Adoption == nil {
		return out, errors.New("独立恢复需要已固定并核对的接入材料")
	}
	a := status.Adoption
	if a.SHA256 != in.AdoptionSHA256 {
		return out, errors.New("独立恢复须明确指定原接入批准摘要")
	}
	plan, err := readRestorePlan(data, in.PlanID)
	if err != nil {
		return out, err
	}
	if !validHash.MatchString(in.PlanSHA256) || plan.SHA256 != in.PlanSHA256 {
		return out, errors.New("安装须明确指定原恢复计划摘要")
	}
	if err = matchRestorePlan(plan, *a); err != nil {
		return out, err
	}
	if !plan.Preview.CanInstall {
		return out, errors.New("恢复计划仍有阻塞项，不能安装文件")
	}
	if existing, e := panelrecovery.ReadDisasterIntent(data, id); e == nil {
		if existing.PlanID != plan.ID || existing.PlanSHA256 != plan.SHA256 {
			return out, errors.New("原恢复安装已绑定其他目标计划")
		}
	} else if !os.IsNotExist(e) {
		return out, e
	} else if plan.ExpiresAt <= time.Now().Unix() {
		return out, errors.New("恢复计划已到期，须在安装前生成新的计划")
	}
	i := a.Intent
	files := make([]panelrecovery.File, len(resources))
	for index, file := range i.Preparation.Files {
		if index == 0 {
			file = plan.Preview.Publication.File
		}
		files[index] = panelrecovery.File{Name: i.Rollback.Manifest.Files[index].Name, Size: file.Size, SHA256: file.SHA256}
	}
	input := panelrecovery.DisasterIntent{Schema: 1, DataDir: data, OperationID: id, AdoptionSHA256: a.SHA256, PlanID: plan.ID, PlanSHA256: plan.SHA256, NginxRequest: panelrecovery.File{Name: plan.Preview.Publication.NginxRequest.Name, Size: plan.Preview.Publication.NginxRequest.Size, SHA256: plan.Preview.Publication.NginxRequest.SHA256}, NginxBeforeRevision: plan.Preview.Runtime.RevisionID, NginxBeforeDeployment: plan.Preview.Runtime.DeploymentID, NginxCapabilitiesSHA256: plan.Preview.CapabilitiesSHA256, Stop: i.Stop, Rollback: i.Rollback, Files: files, Before: i.Before, ReleaseID: i.Preparation.Target.ReleaseID, BinarySHA256: i.BinarySHA256, ExpiresAt: i.ExpiresAt}
	return agent.RestoreDisaster(call, data, id, in.Epoch, input, false)
}

// An interrupted install may have durable approval before its fence exists.
// Keep its source until the original independent compensation is complete.
func adoptionRestoreSettled(data, id string) error {
	if _, err := panelrecovery.ReadDisasterIntent(data, id); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if _, e := os.Lstat(filepath.Join(data, "agent", "operations", id+".json")); os.IsNotExist(e) {
			return nil
		} else if e != nil {
			return e
		}
		return errors.New("原独立恢复记录的安装意图缺失，保留材料供本机恢复")
	}
	r, err := agent.DisasterRestoreStatus(data, id)
	if err != nil {
		return errors.Join(errors.New("已有独立安装意图，须先完成原恢复补偿"), err)
	}
	if r.State == "succeeded" && r.Stage == "committed" && r.DisasterActivation != nil && r.DisasterActivation.ReleaseAcknowledged {
		return nil
	}
	if r.State != "rolled_back" || r.Stage != "files_compensated" {
		return errors.New("原恢复安装尚未补偿，不能删除固定材料")
	}
	return nil
}
