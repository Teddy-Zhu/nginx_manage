package backup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type RestorePlanInput struct {
	PlanID         string            `json:"plan_id"`
	AdoptionSHA256 string            `json:"adoption_sha256"`
	Epoch          string            `json:"epoch"`
	Mappings       map[string]string `json:"mappings"`
}

type RestorePlan struct {
	Schema            int                   `json:"schema"`
	ID                string                `json:"id"`
	OperationID       string                `json:"operation_id"`
	AdoptionSHA256    string                `json:"adoption_sha256"`
	PreparationSHA256 string                `json:"preparation_sha256"`
	ApprovalEpoch     string                `json:"approval_epoch"`
	Mappings          map[string]string     `json:"mappings"`
	Preview           RestorePreview        `json:"preview"`
	PublicationProof  *MaterialVerification `json:"publication_proof,omitempty"`
	CreatedAt         int64                 `json:"created_at"`
	ExpiresAt         int64                 `json:"expires_at"`
	SHA256            string                `json:"sha256"`
}
type RestorePlanStatus struct {
	Plan                 RestorePlan `json:"plan"`
	Expired              bool        `json:"expired"`
	PublicationAvailable bool        `json:"publication_available"`
}

func (p RestorePlan) hash() (string, error) { p.SHA256 = ""; return adoptionValueHash(p) }
func (p RestorePlan) validate() error {
	if p.Schema != 1 || !validID.MatchString(p.ID) || !validID.MatchString(p.OperationID) || p.ID == p.OperationID || !validID.MatchString(p.ApprovalEpoch) || !validHash.MatchString(p.AdoptionSHA256) || !validHash.MatchString(p.PreparationSHA256) || p.CreatedAt <= 0 || p.CreatedAt > time.Now().Unix()+300 || p.ExpiresAt <= p.CreatedAt || p.ExpiresAt > p.CreatedAt+1800 || len(p.Mappings) > 256 {
		return errors.New("恢复目标计划身份无效")
	}
	v := p.Preview
	if v.Verification.OperationID != p.OperationID || v.Verification.PreparationSHA256 != p.PreparationSHA256 || v.Verification.VerifiedAt != p.CreatedAt || !validHash.MatchString(v.CandidateSHA256) || !validHash.MatchString(v.CapabilitiesSHA256) || !validHash.MatchString(v.PolicySHA256) || v.CanInstall && !validHash.MatchString(v.MaterialsSHA256) || v.FileCount < 1 || v.FileCount > 128 || v.StepCount < 1 || len(v.Steps) > 65 {
		return errors.New("恢复目标计划缺少有界材料或目标观测")
	}
	for _, step := range v.Steps {
		if v.CanInstall && (step.State == "blocked" || step.State == "unavailable") {
			return errors.New("恢复目标计划准入与阻塞步骤不一致")
		}
	}
	policyHash, err := adoptionValueHash(v.Policy)
	if err != nil || policyHash != v.PolicySHA256 {
		return errors.New("恢复计划策略摘要不一致")
	}
	if v.CanInstall {
		proof, pub := p.PublicationProof, v.Publication
		if pub == nil || pub.RevisionID != p.ID || proof == nil || proof.OperationID != p.OperationID || proof.PreparationSHA256 != p.PreparationSHA256 || proof.Database != pub.Database || proof.VerifiedAt < p.CreatedAt || proof.VerifiedAt > p.ExpiresAt || pub.CreatedAt > p.CreatedAt {
			return errors.New("恢复计划缺少固定发布副本的只读核对")
		}
	} else if v.Publication != nil || p.PublicationProof != nil {
		return errors.New("存在阻塞项的计划不能批准安装副本")
	}
	hash, err := p.hash()
	if err != nil {
		return err
	}
	if p.SHA256 != hash {
		return errors.New("恢复目标计划摘要不一致")
	}
	return nil
}

func restorePlanRoot(data string, create bool) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("恢复目标计划仅供本机 root 使用")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return "", err
	}
	root := filepath.Join(data, "agent", "disaster-plans")
	if err := privateAdoptionDirectory(root, create); err != nil {
		return "", err
	}
	return root, nil
}
func readRestorePlan(data, id string) (out RestorePlan, err error) {
	if !validID.MatchString(id) {
		return out, errors.New("恢复目标计划标识无效")
	}
	root, err := restorePlanRoot(data, false)
	if err != nil {
		return out, err
	}
	if err = readAdoptionJSON(filepath.Join(root, id+".json"), &out); err != nil {
		return out, err
	}
	if out.ID != id {
		return out, errors.New("恢复目标计划标识不一致")
	}
	return out, out.validate()
}
func QueryRestorePlan(data, id string) (RestorePlanStatus, error) {
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return RestorePlanStatus{}, err
	}
	defer unlock()
	p, err := readRestorePlan(data, id)
	if err != nil {
		return RestorePlanStatus{}, err
	}
	return restorationPlanStatus(data, p)
}

func matchRestorePlan(p RestorePlan, a Adoption) error {
	i := a.Intent
	if p.OperationID != i.Preparation.OperationID || p.AdoptionSHA256 != a.SHA256 || p.PreparationSHA256 != i.PreparationSHA256 || p.Preview.Verification.Database != i.Preparation.Database || p.CreatedAt < i.CreatedAt || p.ExpiresAt > i.ExpiresAt {
		return errors.New("恢复目标计划与原接入批准不一致")
	}
	if p.Preview.Publication != nil {
		return p.Preview.Publication.validate(i.Preparation)
	}
	return nil
}

func CreateRestorePlan(ctx context.Context, data, id string, in RestorePlanInput) (out RestorePlanStatus, err error) {
	if in.Mappings == nil {
		in.Mappings = map[string]string{}
	}
	mappingsRaw, e := json.Marshal(in.Mappings)
	if e != nil {
		return out, e
	}
	if len(mappingsRaw) > 32<<10 {
		return out, errors.New("恢复映射超过 32 KiB")
	}
	if !validID.MatchString(id) || !validID.MatchString(in.PlanID) || in.PlanID == id || !validID.MatchString(in.Epoch) || !validHash.MatchString(in.AdoptionSHA256) || len(in.Mappings) > 256 {
		return out, errors.New("恢复计划须指定独立计划标识、原接入摘要和当前维护 epoch")
	}
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return out, err
	}
	defer unlock()
	if previous, e := readRestorePlan(data, in.PlanID); e == nil {
		if previous.OperationID != id || previous.AdoptionSHA256 != in.AdoptionSHA256 || !sameAdoptionValue(previous.Mappings, in.Mappings) {
			return out, errors.New("原恢复计划标识已有不同材料或映射")
		}
		return restorationPlanStatus(data, previous)
	} else if !os.IsNotExist(e) {
		return out, e
	}
	call, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	status, err := readAdoptionStatus(call, data, id)
	if err != nil {
		return out, err
	}
	if status.State != "adopted" || status.Adoption == nil || status.Expired || status.Adoption.SHA256 != in.AdoptionSHA256 {
		return out, errors.New("恢复计划需要有效的原固定材料接入批准")
	}
	a := *status.Adoption
	i := a.Intent
	if in.PlanID == i.Rollback.Manifest.OperationID || in.PlanID == i.Stop.MaintenanceID {
		return out, errors.New("恢复计划标识不能复用快照或维护标识")
	}
	err = agent.WithCheckedPanelSnapshot(call, data, i.Rollback.Manifest.OperationID, i.Stop.MaintenanceID, in.Epoch, func(snapshot panelrecovery.Result) (callbackErr error) {
		running, e := panelruntime.Read(data)
		if e != nil {
			return e
		}
		hold, e := storage.ReadServiceHold(data)
		if e != nil {
			return e
		}
		if e = matchAdoptionInput(i, AdoptInput{PreparationSHA256: i.PreparationSHA256, SnapshotID: i.Rollback.Manifest.OperationID, MaintenanceID: i.Stop.MaintenanceID, Epoch: in.Epoch}, hold, running, snapshot.Receipt); e != nil {
			return e
		}
		unlockWriter, e := storage.LockWriterForMaintenance(data, i.GID)
		if e != nil {
			return e
		}
		defer unlockWriter()
		before, e := panelrecovery.ObserveTarget(call, i.Rollback)
		if e != nil {
			return e
		}
		if !sameAdoptionValue(before, i.Before) {
			return errors.New("目标已偏离原接入依据，不能生成新的恢复计划")
		}
		dir, _ := adoptionDirectory(data, id, false)
		var preview RestorePreview
		input := RestorePreviewInput{PlanID: in.PlanID, Preparation: i.Preparation, ExpectedApplied: i.Rollback.Manifest.Database.AppliedRevision, Mappings: in.Mappings}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			callbackErr = errors.Join(callbackErr, cleanupRestorationHelper(cleanup, data, in.PlanID))
		}()
		if e = callAdoptionMaterialHelper(call, data, id, dir, i, "backup-restore-plan-data", input, &preview); e != nil {
			return e
		}
		p := RestorePlan{Schema: 1, ID: in.PlanID, OperationID: id, AdoptionSHA256: a.SHA256, PreparationSHA256: i.PreparationSHA256, ApprovalEpoch: in.Epoch, Mappings: in.Mappings, Preview: preview, CreatedAt: preview.Verification.VerifiedAt, ExpiresAt: min(preview.Verification.VerifiedAt+1800, i.ExpiresAt)}
		if preview.CanInstall {
			if preview.Publication == nil || preview.Publication.RevisionID != in.PlanID {
				return errors.New("恢复计划助手缺少原计划的发布副本")
			}
			if e = freezeRestorationPublication(call, data, *preview.Publication, i); e != nil {
				return e
			}
			var proof MaterialVerification
			verifyInput := RestorePublicationInput{Preparation: i.Preparation, Preview: preview, Mappings: in.Mappings}
			if e = callRestorationMaterialHelper(call, data, id, dir, i, "backup-restore-plan-verify-data", verifyInput, &proof, &preview.Publication.File, restorePublicationPath(data, in.PlanID), filepath.Join(filepath.Dir(restorePublicationPath(data, in.PlanID)), "nginx.json")); e != nil {
				return e
			}
			p.PublicationProof = &proof
		}
		p.SHA256, e = p.hash()
		if e != nil {
			return e
		}
		if e = p.validate(); e != nil {
			return e
		}
		if e = matchRestorePlan(p, a); e != nil {
			return e
		}
		after, e := panelrecovery.ObserveTarget(call, i.Rollback)
		if e != nil {
			return e
		}
		if !sameAdoptionValue(after, i.Before) {
			return errors.New("恢复计划生成期间目标文件发生变化")
		}
		current, e := panelruntime.Read(data)
		if e != nil {
			return e
		}
		currentHold, e := storage.ReadServiceHold(data)
		if e != nil {
			return e
		}
		if currentHold != hold || !sameAdoptionValue(current, running) {
			return errors.New("恢复计划生成期间批准程序或原停机发生变化")
		}
		root, e := restorePlanRoot(data, true)
		if e != nil {
			return e
		}
		items, e := boundedEntries(root, 129)
		if e != nil {
			return e
		}
		count := 0
		for _, item := range items {
			if item.Name() == ".json-copy" {
				f, info, e := secure.OpenRootFile(filepath.Join(root, item.Name()), adoptionRecordMax)
				if e != nil {
					return e
				}
				f.Close()
				if info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 {
					return errors.New("恢复计划暂存权限无效")
				}
				continue
			}
			if !strings.HasSuffix(item.Name(), ".json") || !validID.MatchString(strings.TrimSuffix(item.Name(), ".json")) {
				return errors.New("恢复计划存储存在未知文件")
			}
			f, info, e := secure.OpenRootFile(filepath.Join(root, item.Name()), adoptionRecordMax)
			if e != nil {
				return e
			}
			f.Close()
			if info.Mode().Perm() != 0400 {
				return errors.New("恢复计划须为 root 只读记录")
			}
			count++
		}
		if count >= 128 {
			return errors.New("恢复计划达到 128 项保留上限，未删除已有审批")
		}
		if e = writeAdoptionJSON(filepath.Join(root, p.ID+".json"), p); e != nil {
			return e
		}
		out, e = restorationPlanStatus(data, p)
		return e
	})
	return out, err
}
