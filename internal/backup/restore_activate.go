package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
)

type RestoreActivateInput struct {
	RestoreInput
	ReconciliationSHA256   string `json:"reconciliation_sha256"`
	AcceptActivationCommit bool   `json:"accept_activation_commit"`
}

func ActivateRestoration(ctx context.Context, data, id string, in RestoreActivateInput) (out agent.DisasterRuntimeStatus, err error) {
	if os.Geteuid() != 0 || !validID.MatchString(id) || !validID.MatchString(in.Epoch) || !validHash.MatchString(in.AdoptionSHA256) || !validID.MatchString(in.PlanID) || !validHash.MatchString(in.PlanSHA256) || !validHash.MatchString(in.ReconciliationSHA256) || !in.AcceptActivationCommit {
		return out, errors.New("激活须由本机 root 指定原批准摘要，并明确接受启动数据库后的不可回退提交")
	}
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return out, err
	}
	defer unlock()
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err != nil {
		return out, err
	}
	if i.AdoptionSHA256 != in.AdoptionSHA256 || i.PlanID != in.PlanID || i.PlanSHA256 != in.PlanSHA256 {
		return out, errors.New("激活指定了其他安装批准")
	}
	r, err := panelrecovery.ReadDisasterReconciliation(i)
	if err != nil {
		return out, err
	}
	if r.SHA256() != in.ReconciliationSHA256 {
		return out, errors.New("激活须明确指定原对账摘要")
	}
	if _, err = panelrecovery.ReadDisasterReconciliationProof(i, r); err != nil {
		return out, err
	}
	_, err = agent.ActivateDisaster(ctx, data, id, in.Epoch, func(ctx context.Context, original panelrecovery.DisasterIntent) (retErr error) {
		if original.SHA256() != i.SHA256() {
			return errors.New("激活安装意图已变化")
		}
		status, e := readAdoptionStatus(ctx, data, id)
		if e != nil {
			return e
		}
		if status.State != "adopted" || status.Adoption == nil {
			return errors.New("激活准备需要原固定接入材料")
		}
		adoption := *status.Adoption
		p, e := readRestorePlan(data, i.PlanID)
		if e != nil {
			return e
		}
		if e = matchRestorePlan(p, adoption); e != nil {
			return e
		}
		if p.SHA256 != i.PlanSHA256 || adoption.SHA256 != i.AdoptionSHA256 || p.Preview.Publication == nil {
			return errors.New("激活准备引用的原计划已变化")
		}
		a, e := panelrecovery.ReadDisasterActivation(i)
		fresh := os.IsNotExist(e)
		if e != nil && !fresh {
			return e
		}
		if fresh {
			if time.Now().Unix() >= i.ExpiresAt {
				return errors.New("原恢复授权已到期，不能新增激活准备")
			}
			a = panelrecovery.DisasterActivation{Schema: 1, OperationID: id, IntentSHA256: i.SHA256(), ReconciliationSHA256: r.SHA256(), Epoch: in.Epoch, PreparedAt: time.Now().Unix(), StartID: secure.ID(), File: panelrecovery.File{Name: i.Files[0].Name}}
		}
		input := RestoreActivateMaterialInput{RestoreReconcileMaterialInput: RestoreReconcileMaterialInput{Preparation: adoption.Intent.Preparation, Plan: p, Reconciliation: r}, Activation: a, MaintenanceID: i.Stop.MaintenanceID}
		pub := p.Preview.Publication
		sourceDir := filepath.Join(data, "agent", "disaster-recovery", id)
		if fresh {
			var prepared panelrecovery.DisasterActivation
			if e = callRestorationMaterialHelper(ctx, data, id, sourceDir, adoption.Intent, "backup-restore-activate-data", input, &prepared, &pub.File, restorePublicationPath(data, p.ID), ""); e != nil {
				return e
			}
			expected := a
			expected.File = prepared.File
			report, e := activationReport(input)
			if e != nil {
				return e
			}
			expected.ReportSHA256 = secure.Hash(report)
			if prepared.SHA256() != expected.SHA256() {
				return errors.New("激活助手改变了原批准身份或报告")
			}
			a = prepared
		}
		if e = a.Validate(i, r); e != nil {
			return e
		}
		var source *os.File
		if f, _, openErr := openRestorationWorkFile(data, p.ID, "panel.db", File{Name: a.File.Name, Size: a.File.Size, SHA256: a.File.SHA256}, adoption.Intent); openErr == nil {
			source = f
			defer f.Close()
		} else if !os.IsNotExist(openErr) {
			return openErr
		}
		if e = panelrecovery.FreezeDisasterActivation(ctx, i, a, source); e != nil {
			return e
		}
		defer func() {
			var result struct {
				OperationID string `json:"operation_id"`
				Cleaned     bool   `json:"cleaned"`
			}
			e := runPreparationHelper(ctx, data, "backup-restore-plan-cleanup-data", p.ID, nil, nil, &result)
			if e == nil && (result.OperationID != p.ID || !result.Cleaned) {
				e = errors.New("激活暂存清理未确认原计划")
			}
			retErr = errors.Join(retErr, e)
		}()
		input.Activation = a
		intent := adoption.Intent
		intent.Preparation.Files = append([]File(nil), intent.Preparation.Files...)
		intent.Preparation.Files[0] = File{Name: a.File.Name, Size: a.File.Size, SHA256: a.File.SHA256}
		fixed := filepath.Join(data, "agent", "disaster-restores", id, "activated.db")
		if e = prepareAdoptionCheck(ctx, data, p.ID, fixed, intent); e != nil {
			return e
		}
		defer func() { retErr = errors.Join(retErr, cleanupAdoptionCheck(data, p.ID, adoption.Intent.GID)) }()
		var proof panelrecovery.DisasterActivationProof
		if e = callRestorationMaterialHelper(ctx, data, id, sourceDir, adoption.Intent, "backup-restore-activate-verify-data", input, &proof, &pub.File, restorePublicationPath(data, p.ID), ""); e != nil {
			return e
		}
		if proof.ActivationSHA256 != a.SHA256() {
			return errors.New("激活只读助手没有核对原固定副本")
		}
		if _, e = panelrecovery.ReadDisasterActivationProof(i, a); e == nil {
			return nil
		} else if !os.IsNotExist(e) {
			return e
		}
		return panelrecovery.ApproveDisasterActivation(i, a, proof)
	})
	status, statusErr := agent.DisasterRuntime(data, id)
	return status, errors.Join(err, statusErr)
}
