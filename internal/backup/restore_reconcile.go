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

type RestoreReconcileInput struct {
	RestoreInput
	Review panelrecovery.DisasterReview `json:"review"`
}

func ReconcileRestoration(ctx context.Context, data, id string, in RestoreReconcileInput) (out agent.DisasterRuntimeStatus, err error) {
	if os.Geteuid() != 0 || !validID.MatchString(id) || !validID.MatchString(in.Epoch) || !validHash.MatchString(in.AdoptionSHA256) || !validID.MatchString(in.PlanID) || !validHash.MatchString(in.PlanSHA256) {
		return out, errors.New("恢复对账须明确指定原接入、计划与当前维护授权")
	}
	if err = in.Review.Validate(); err != nil {
		return out, err
	}
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return out, err
	}
	defer unlock()
	call, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	_, err = agent.ReconcileDisaster(call, data, id, in.Epoch, func(ctx context.Context, i panelrecovery.DisasterIntent) (retErr error) {
		if i.AdoptionSHA256 != in.AdoptionSHA256 || i.PlanID != in.PlanID || i.PlanSHA256 != in.PlanSHA256 {
			return errors.New("恢复对账指定了不同原批准")
		}
		status, e := readAdoptionStatus(ctx, data, id)
		if e != nil {
			return e
		}
		if status.State != "adopted" || status.Adoption == nil {
			return errors.New("恢复对账需要原固定接入材料")
		}
		a := *status.Adoption
		p, e := readRestorePlan(data, i.PlanID)
		if e != nil {
			return e
		}
		if e = matchRestorePlan(p, a); e != nil {
			return e
		}
		if p.SHA256 != i.PlanSHA256 || a.SHA256 != i.AdoptionSHA256 || p.Preview.Publication == nil {
			return errors.New("恢复对账的计划或接入摘要不一致")
		}
		pub := *p.Preview.Publication
		if pub.File.Size != i.Files[0].Size || pub.File.SHA256 != i.Files[0].SHA256 {
			return errors.New("恢复对账源数据库与安装意图不同")
		}
		r, e := panelrecovery.ReadDisasterReconciliation(i)
		fresh := os.IsNotExist(e)
		if e != nil && !fresh {
			return e
		}
		if fresh {
			if time.Now().Unix() >= i.ExpiresAt {
				return errors.New("原安装授权已到期，不能新增数据对账")
			}
			r = panelrecovery.DisasterReconciliation{Schema: 1, OperationID: id, IntentSHA256: i.SHA256(), PlanSHA256: i.PlanSHA256, Epoch: in.Epoch, PreparedAt: time.Now().Unix(), Review: in.Review, File: panelrecovery.File{Name: i.Files[0].Name}, Database: panelrecovery.Database{SchemaVersion: pub.Database.SchemaVersion, NodeID: pub.Database.NodeID, DesiredRevision: p.ID, AppliedRevision: p.ID, HeadVersion: pub.Database.HeadVersion}}
		} else if r.Review != in.Review {
			return errors.New("原恢复已有不同的源任务或外部结果处理批准")
		}
		input := RestoreReconcileMaterialInput{Preparation: a.Intent.Preparation, Plan: p, Reconciliation: r}
		sourceDir := filepath.Join(data, "agent", "disaster-recovery", id)
		if fresh {
			var prepared panelrecovery.DisasterReconciliation
			if e = callRestorationMaterialHelper(ctx, data, id, sourceDir, a.Intent, "backup-restore-reconcile-data", input, &prepared, &pub.File, restorePublicationPath(data, p.ID), ""); e != nil {
				return e
			}
			expected := r
			expected.File = prepared.File
			report, e := reconciliationReport(input)
			if e != nil {
				return e
			}
			expected.ReportSHA256 = secure.Hash(report)
			if prepared.SHA256() != expected.SHA256() {
				return errors.New("恢复对账助手改变了原批准的身份、处理策略或报告")
			}
			r = prepared
		}
		if e = r.Validate(i); e != nil {
			return e
		}
		var source *os.File
		if f, _, openErr := openRestorationWorkFile(data, p.ID, "panel.db", File{Name: r.File.Name, Size: r.File.Size, SHA256: r.File.SHA256}, a.Intent); openErr == nil {
			source = f
			defer f.Close()
		} else if !os.IsNotExist(openErr) {
			return openErr
		}
		if e = panelrecovery.FreezeDisasterReconciliation(ctx, i, r, source); e != nil {
			return e
		}
		defer func() {
			var result struct {
				OperationID string `json:"operation_id"`
				Cleaned     bool   `json:"cleaned"`
			}
			cleanupErr := runPreparationHelper(ctx, data, "backup-restore-plan-cleanup-data", p.ID, nil, nil, &result)
			if cleanupErr == nil && (result.OperationID != p.ID || !result.Cleaned) {
				cleanupErr = errors.New("恢复对账暂存清理未确认原计划")
			}
			retErr = errors.Join(retErr, cleanupErr)
		}()
		input.Reconciliation = r
		intent := a.Intent
		intent.Preparation.Files = append([]File(nil), intent.Preparation.Files...)
		intent.Preparation.Files[0] = File{Name: r.File.Name, Size: r.File.Size, SHA256: r.File.SHA256}
		fixed := filepath.Join(data, "agent", "disaster-restores", id, "reconciled.db")
		if e = prepareAdoptionCheck(ctx, data, p.ID, fixed, intent); e != nil {
			return e
		}
		defer func() { retErr = errors.Join(retErr, cleanupAdoptionCheck(data, p.ID, a.Intent.GID)) }()
		var proof panelrecovery.DisasterReconciliationProof
		if e = callRestorationMaterialHelper(ctx, data, id, sourceDir, a.Intent, "backup-restore-reconcile-verify-data", input, &proof, &pub.File, restorePublicationPath(data, p.ID), ""); e != nil {
			return e
		}
		if proof.ReconciliationSHA256 != r.SHA256() {
			return errors.New("对账只读助手没有核对原固定副本")
		}
		if _, e = panelrecovery.ReadDisasterReconciliationProof(i, r); e == nil {
			return nil
		} else if !os.IsNotExist(e) {
			return e
		}
		return panelrecovery.ApproveDisasterReconciliation(i, r, proof)
	})
	if err != nil {
		return out, err
	}
	return agent.DisasterRuntime(data, id)
}
