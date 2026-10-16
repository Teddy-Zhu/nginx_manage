package backup

import (
	"errors"
	"time"
)

const PreparationMax = 2
const PreparationLifetime = int64(15 * 60)
const AuditMergeMax = int64(64 << 20)

type PrepareInput struct {
	Mode                   string             `json:"mode"`
	SourceNodeID           string             `json:"source_node_id"`
	TargetNodeID           string             `json:"target_node_id"`
	ArchiveSHA256          string             `json:"archive_sha256"`
	MaintenanceID          string             `json:"maintenance_id"`
	PreserveNodeIdentity   bool               `json:"preserve_node_identity"`
	SourceOfflineConfirmed bool               `json:"source_offline_confirmed"`
	Credentials            InspectCredentials `json:"credentials"`
}

func (in PrepareInput) validate() error {
	if (in.Mode != "clone" && in.Mode != "disaster") || !validID.MatchString(in.SourceNodeID) || !validID.MatchString(in.TargetNodeID) || !validID.MatchString(in.MaintenanceID) || !validHash.MatchString(in.ArchiveSHA256) {
		return errors.New("恢复模式、节点、维护或加密文件身份无效")
	}
	if in.Mode == "clone" && (in.PreserveNodeIdentity || in.SourceOfflineConfirmed) {
		return errors.New("克隆不能保留源节点身份")
	}
	if in.PreserveNodeIdentity && !in.SourceOfflineConfirmed {
		return errors.New("保留灾备节点身份前须明确确认原实例已停止")
	}
	return nil
}

type RestoreTarget struct {
	Database     Database `json:"database"`
	ReleaseID    string   `json:"release_id"`
	Runtime      string   `json:"runtime"`
	AdminSHA256  string   `json:"admin_sha256"`
	SessionEpoch int64    `json:"session_epoch"`
	Files        []File   `json:"files"`
}
type RestoreIsolation struct {
	Tasks             int64 `json:"tasks"`
	Sessions          int64 `json:"sessions"`
	Credentials       int64 `json:"credentials"`
	Connections       int64 `json:"connections"`
	Deliveries        int64 `json:"deliveries"`
	DNSRecords        int64 `json:"dns_records"`
	ImportedAudits    int64 `json:"imported_audits"`
	TargetAudits      int64 `json:"target_audits"`
	AddedTargetAudits int64 `json:"added_target_audits"`
}
type Preparation struct {
	Schema                 int              `json:"schema"`
	OperationID            string           `json:"operation_id"`
	MaintenanceID          string           `json:"maintenance_id"`
	Mode                   string           `json:"mode"`
	PreparedAt             int64            `json:"prepared_at"`
	ExpiresAt              int64            `json:"expires_at"`
	ArchiveSHA256          string           `json:"archive_sha256"`
	Source                 Manifest         `json:"source"`
	Target                 RestoreTarget    `json:"target"`
	Database               Database         `json:"database"`
	Files                  []File           `json:"files"`
	PreserveNodeIdentity   bool             `json:"preserve_node_identity"`
	SourceOfflineConfirmed bool             `json:"source_offline_confirmed"`
	SessionEpoch           int64            `json:"session_epoch"`
	Isolation              RestoreIsolation `json:"isolation"`
	DisabledModules        []string         `json:"disabled_modules"`
	PendingChecks          []string         `json:"pending_checks"`
}

func (p Preparation) Validate() error {
	if p.Schema != 1 || !validID.MatchString(p.OperationID) || !validID.MatchString(p.MaintenanceID) || (p.Mode != "clone" && p.Mode != "disaster") || p.PreparedAt <= 0 || p.PreparedAt > time.Now().Unix()+300 || p.ExpiresAt != p.PreparedAt+PreparationLifetime || !validHash.MatchString(p.ArchiveSHA256) || p.Source.Validate() != nil || !validHash.MatchString(p.Target.ReleaseID) || !validHash.MatchString(p.Target.AdminSHA256) || (p.Target.Runtime != "native" && p.Target.Runtime != "docker") || !validID.MatchString(p.Target.Database.NodeID) || !validID.MatchString(p.Database.NodeID) || p.Database.AppliedRevision != "" || p.Database.SchemaVersion != p.Source.Database.SchemaVersion || p.Database.DesiredRevision != p.Source.Database.DesiredRevision || p.Database.HeadVersion != p.Source.Database.HeadVersion || len(p.Files) != len(resources) || len(p.PendingChecks) == 0 {
		return errors.New("恢复准备报告或身份无效")
	}
	if p.Target.SessionEpoch < 1 || p.Target.SessionEpoch >= 1<<62 || p.SessionEpoch <= p.Target.SessionEpoch || p.SessionEpoch > 1<<62 {
		return errors.New("恢复账户安全代次无效")
	}
	if p.Target.Database.SchemaVersion != p.Database.SchemaVersion || p.Target.Database.HeadVersion < 0 || p.Database.HeadVersion < 0 || p.Mode == "clone" && (p.PreserveNodeIdentity || p.SourceOfflineConfirmed) {
		return errors.New("恢复目标结构或身份策略无效")
	}
	for _, count := range []int64{p.Isolation.Tasks, p.Isolation.Sessions, p.Isolation.Credentials, p.Isolation.Connections, p.Isolation.Deliveries, p.Isolation.DNSRecords, p.Isolation.ImportedAudits, p.Isolation.TargetAudits, p.Isolation.AddedTargetAudits} {
		if count < 0 {
			return errors.New("恢复隔离计数无效")
		}
	}
	if p.Isolation.AddedTargetAudits > p.Isolation.TargetAudits || len(p.DisabledModules) > 64 || len(p.PendingChecks) > 16 {
		return errors.New("恢复隔离报告超过限制")
	}
	if p.PreserveNodeIdentity {
		if p.Mode != "disaster" || !p.SourceOfflineConfirmed || p.Database.NodeID != p.Source.Database.NodeID {
			return errors.New("灾备身份保留策略无效")
		}
	} else if p.Database.NodeID == p.Source.Database.NodeID || p.Database.NodeID == p.Target.Database.NodeID {
		return errors.New("克隆身份未重新生成")
	}
	for i, r := range resources {
		file := p.Files[i]
		if file.Name != r.name || file.Size < 1 || file.Size > r.limit || !validHash.MatchString(file.SHA256) {
			return errors.New("恢复准备资源清单无效")
		}
	}
	if p.Files[1] != p.Source.Files[1] || len(p.Target.Files) < 4 || len(p.Target.Files) > 5 {
		return errors.New("恢复准备缺少原业务密钥或目标入口依据")
	}
	for i, r := range resources {
		f := p.Target.Files[i]
		if f.Name != r.name || f.Size < 1 || f.Size > r.limit || !validHash.MatchString(f.SHA256) {
			return errors.New("恢复目标文件身份无效")
		}
	}
	if p.Files[2] != p.Target.Files[2] || p.Files[3] != p.Target.Files[3] {
		return errors.New("恢复准备未保留目标管理入口 TLS")
	}
	if len(p.Target.Files) == 5 {
		f := p.Target.Files[4]
		if f.Name != "database/panel.db-wal" || f.Size < 0 || f.Size > 2*DatabaseMax || !validHash.MatchString(f.SHA256) {
			return errors.New("恢复目标 WAL 身份无效")
		}
	}
	return nil
}
