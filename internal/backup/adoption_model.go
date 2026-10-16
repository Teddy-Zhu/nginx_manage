package backup

import (
	"encoding/json"
	"errors"
	"time"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

const AdoptionMax = 2
const AdoptionRecordMax = 128
const AdoptionLifetime = int64(24 * 60 * 60)
const adoptionRecordMax = int64(160 << 10)

type AdoptInput struct {
	PreparationSHA256 string `json:"preparation_sha256"`
	SnapshotID        string `json:"snapshot_id"`
	MaintenanceID     string `json:"maintenance_id"`
	Epoch             string `json:"epoch"`
}

func (in AdoptInput) validate(id string) error {
	if !validID.MatchString(id) || !validID.MatchString(in.SnapshotID) || !validID.MatchString(in.MaintenanceID) || !validID.MatchString(in.Epoch) || !validHash.MatchString(in.PreparationSHA256) || id == in.SnapshotID || id == in.MaintenanceID || in.SnapshotID == in.MaintenanceID {
		return errors.New("恢复接入须指定独立标识、准备摘要、目标回退快照及当前维护授权")
	}
	return nil
}

type AdoptionIntent struct {
	Schema            int                      `json:"schema"`
	DataDir           string                   `json:"data_dir"`
	PreparationSHA256 string                   `json:"preparation_sha256"`
	Preparation       Preparation              `json:"preparation"`
	Stop              storage.ServiceHold      `json:"stop"`
	Rollback          panelrecovery.Receipt    `json:"rollback"`
	Before            []panelrecovery.Original `json:"before"`
	UID               int                      `json:"uid"`
	GID               int                      `json:"gid"`
	BinarySHA256      string                   `json:"binary_sha256"`
	ApprovalEpoch     string                   `json:"approval_epoch"`
	CreatedAt         int64                    `json:"created_at"`
	ExpiresAt         int64                    `json:"expires_at"`
}

type Adoption struct {
	Intent       AdoptionIntent       `json:"intent"`
	Verification MaterialVerification `json:"verification"`
	Epoch        string               `json:"epoch"`
	SHA256       string               `json:"sha256"`
}
type AdoptionStatus struct {
	State    string           `json:"state"`
	Adoption *Adoption        `json:"adoption,omitempty"`
	Intent   *AdoptionIntent  `json:"intent,omitempty"`
	Expired  bool             `json:"expired"`
	Cleanup  *AdoptionCleanup `json:"cleanup,omitempty"`
}

func (i AdoptionIntent) Validate(data, id string) error {
	if _, err := panelruntime.Root(data); err != nil {
		return err
	}
	p := i.Preparation
	if !validID.MatchString(i.ApprovalEpoch) {
		return errors.New("恢复接入原审批 epoch 无效")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	hash, err := preparationHash(p)
	if err != nil {
		return err
	}
	h := i.Stop
	if i.Schema != 1 || i.DataDir != data || p.OperationID != id || i.PreparationSHA256 != hash || i.CreatedAt < p.PreparedAt || i.CreatedAt >= p.ExpiresAt || i.CreatedAt > time.Now().Unix()+300 || i.ExpiresAt != min(i.CreatedAt+AdoptionLifetime, i.Rollback.Manifest.ExpiresAt) || !validHash.MatchString(i.BinarySHA256) || h.Schema != 1 || !validID.MatchString(h.OperationID) || h.OperationID == id || h.OperationID == i.Rollback.Manifest.OperationID || !validHash.MatchString(h.RequestSHA256) || !validHash.MatchString(h.BindingSHA256) || h.MaintenanceID != p.MaintenanceID || h.ReleaseID != p.Target.ReleaseID {
		return errors.New("恢复接入意图或原停机依据无效")
	}
	if err = i.Rollback.Validate(data, i.Rollback.Manifest.OperationID); err != nil {
		return err
	}
	m := i.Rollback.Manifest
	if m.OperationID == id || m.OperationID == h.MaintenanceID || m.MaintenanceID != h.MaintenanceID || m.UID != i.UID || m.GID != i.GID || m.CaptureBinarySHA256 != i.BinarySHA256 || m.CreatedAt > i.CreatedAt || m.ExpiresAt <= i.CreatedAt {
		return errors.New("恢复接入缺少匹配的目标回退快照")
	}
	if err = matchAdoptionRollback(p, m); err != nil {
		return err
	}
	if err = panelrecovery.ValidateOriginals(i.Before); err != nil {
		return err
	}
	return matchAdoptionBefore(p, i.Before)
}

func matchAdoptionRollback(p Preparation, m panelrecovery.Manifest) error {
	expected := p.Target.Database
	if m.Database != (panelrecovery.Database{SchemaVersion: expected.SchemaVersion, NodeID: expected.NodeID, DesiredRevision: expected.DesiredRevision, AppliedRevision: expected.AppliedRevision, HeadVersion: expected.HeadVersion}) {
		return errors.New("目标回退快照的数据库与恢复准备依据不一致")
	}
	for i := 1; i < len(resources); i++ {
		if m.Files[i].Size != p.Target.Files[i].Size || m.Files[i].SHA256 != p.Target.Files[i].SHA256 {
			return errors.New("目标回退快照的密钥或 TLS 与恢复准备依据不一致")
		}
	}
	return nil
}

func matchAdoptionBefore(p Preparation, before []panelrecovery.Original) error {
	if err := panelrecovery.ValidateOriginals(before); err != nil {
		return err
	}
	for i, index := range []int{5, 2, 3, 4} {
		actual, expected := before[index], p.Target.Files[i]
		if !actual.Present || actual.Size != expected.Size || actual.SHA256 != expected.SHA256 {
			return errors.New("当前目标资源与原恢复准备依据已不一致")
		}
	}
	wal := before[0]
	if len(p.Target.Files) == 4 {
		if wal.Present {
			return errors.New("目标 WAL 在恢复准备后出现")
		}
	} else {
		expected := p.Target.Files[4]
		if !wal.Present || wal.Size != expected.Size || wal.SHA256 != expected.SHA256 {
			return errors.New("目标 WAL 在恢复准备后变化")
		}
	}
	return nil
}

func adoptionHash(a Adoption) (string, error) {
	a.SHA256 = ""
	raw, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}
func (a Adoption) Validate(data, id string) error {
	if err := a.Intent.Validate(data, id); err != nil {
		return err
	}
	v := a.Verification
	hash, err := adoptionHash(a)
	if err != nil {
		return err
	}
	if !validID.MatchString(a.Epoch) || !validHash.MatchString(a.SHA256) || a.SHA256 != hash || v.OperationID != id || v.PreparationSHA256 != a.Intent.PreparationSHA256 || v.Database != a.Intent.Preparation.Database || v.VerifiedAt < a.Intent.CreatedAt || v.VerifiedAt > time.Now().Unix()+300 || v.VerifiedAt >= a.Intent.ExpiresAt {
		return errors.New("恢复接入批准记录与固定副本核对结果不一致")
	}
	return nil
}
