package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

const dockerRegistrationKind = "docker_firewall_registration"

// This additional grant is bound to the original host claim and daemon.
// No source migration, INPUT grant, matching chain or comment can supply it.
type dockerRegistrationCheckpoint struct {
	Schema                    int    `json:"schema"`
	DataDir                   string `json:"data_dir"`
	MachineHash               string `json:"machine_hash"`
	BootID                    string `json:"boot_id"`
	Owner                     string `json:"owner"`
	ParentOwner               string `json:"parent_owner"`
	ParentOperationID         string `json:"parent_operation_id"`
	ParentRequestHash         string `json:"parent_request_hash"`
	Backend                   string `json:"backend"`
	EngineHash                string `json:"engine_hash"`
	OperationID               string `json:"operation_id"`
	PreviousOperationID       string `json:"previous_operation_id"`
	PreviousReceiptHash       string `json:"previous_receipt_hash"`
	Action                    string `json:"action"`
	State                     string `json:"state"`
	OperationState            string `json:"operation_state"`
	ConfigurationHash         string `json:"configuration_hash"`
	ToolHash                  string `json:"tool_hash"`
	VerifiedConfigurationHash string `json:"verified_configuration_hash"`
	RequestHash               string `json:"request_hash"`
	UpdatedAt                 int64  `json:"updated_at"`
	Error                     string `json:"error"`
}

func dockerRegistrationPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "docker-registration.json")
}

func dockerRegistrationHash(v *dockerRegistrationCheckpoint) string {
	copy := *v
	copy.State, copy.OperationState, copy.VerifiedConfigurationHash, copy.RequestHash, copy.Error, copy.UpdatedAt = "", "", "", "", "", 0
	raw, _ := json.Marshal(copy)
	return secure.Hash(append([]byte("docker:firewall-registration:v1:\x00"), raw...))
}

func dockerRegistrationReceiptHash(v *dockerRegistrationCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(raw)
}

func validDockerRegistration(v *dockerRegistrationCheckpoint) bool {
	if v == nil || v.Schema != 1 || !filepath.IsAbs(v.DataDir) || filepath.Clean(v.DataDir) != v.DataDir || !dockerFirewallText(v.DataDir, 4096) || !firewalldDigest(v.MachineHash) || !validID(v.BootID) || !validID(v.Owner) || !validID(v.ParentOwner) || v.Owner == v.ParentOwner || !validID(v.ParentOperationID) || !firewalldDigest(v.ParentRequestHash) || !validIPTablesBackend(v.Backend) || !firewalldDigest(v.EngineHash) || !validID(v.OperationID) || v.OperationID == v.ParentOperationID || v.OperationID == v.Owner || !firewalldDigest(v.ConfigurationHash) || !firewalldDigest(v.ToolHash) || v.VerifiedConfigurationHash != "" && !firewalldDigest(v.VerifiedConfigurationHash) || v.PreviousOperationID == "" && v.PreviousReceiptHash != "" || v.PreviousOperationID != "" && (!validID(v.PreviousOperationID) || v.PreviousOperationID == v.OperationID || !firewalldDigest(v.PreviousReceiptHash)) || v.UpdatedAt <= 0 || len(v.Error) > 4096 || v.RequestHash != dockerRegistrationHash(v) || v.Action != "init" && v.Action != "remove" {
		return false
	}
	if v.Action == "remove" && v.PreviousOperationID == "" {
		return false
	}
	if v.State == "preparing" {
		return v.OperationState == "running" || v.OperationState == "recovery_required"
	}
	if v.State == "registered" {
		return v.Action == "init" && v.OperationState == "succeeded" && v.VerifiedConfigurationHash != "" && v.Error == ""
	}
	if v.State == "released" {
		return v.VerifiedConfigurationHash != "" && (v.Action == "remove" && v.OperationState == "succeeded" && v.Error == "" || v.Action == "init" && v.OperationState == "failed" && v.Error != "")
	}
	return false
}

func loadDockerRegistration(dataDir string) (*dockerRegistrationCheckpoint, error) {
	var v dockerRegistrationCheckpoint
	present, err := readIPTablesPrivate(dockerRegistrationPath(dataDir), &v)
	if err != nil || !present {
		return nil, err
	}
	if !validDockerRegistration(&v) || v.DataDir != dataDir {
		return nil, errors.New("Docker 本机授权记录无效")
	}
	return &v, nil
}

func dockerRegistrationReceiptMatches(record Record, v *dockerRegistrationCheckpoint) bool {
	return validDockerRegistration(v) && record.Kind == dockerRegistrationKind && record.OperationID == v.OperationID && record.RelatedOperationID == v.PreviousOperationID && record.RequestHash == v.RequestHash && record.State == v.OperationState && record.Stage == v.State && record.Error == v.Error && record.CandidateHash == dockerRegistrationReceiptHash(v) && validDockerRegistration(record.DockerRegistration) && dockerRegistrationReceiptHash(record.DockerRegistration) == record.CandidateHash
}

func dockerRegistrationReceipt(dataDir string, v *dockerRegistrationCheckpoint) error {
	record, err := loadIPTablesReceipt(dataDir, v.OperationID)
	if err != nil {
		return err
	}
	if !dockerRegistrationReceiptMatches(record, v) {
		return errors.New("Docker 本机授权与独立回执不一致")
	}
	return dockerRegistrationPrevious(dataDir, v)
}

func dockerRegistrationPrevious(dataDir string, v *dockerRegistrationCheckpoint) error {
	if v.PreviousOperationID == "" {
		if v.Action != "init" {
			return errors.New("Docker 释放意图缺少原授权回执")
		}
		return nil
	}
	prior, err := loadIPTablesReceipt(dataDir, v.PreviousOperationID)
	if err != nil {
		return err
	}
	old := prior.DockerRegistration
	if !dockerRegistrationReceiptMatches(prior, old) || prior.CandidateHash != v.PreviousReceiptHash || old.DataDir != v.DataDir || old.MachineHash != v.MachineHash {
		return errors.New("Docker 原授权终态回执无法核对")
	}
	if v.Action == "init" {
		if old.State != "released" || old.Owner == v.Owner {
			return errors.New("Docker 新授权须接续原释放终态并使用新所有者")
		}
	} else if old.State != "registered" || old.Owner != v.Owner || old.EngineHash != v.EngineHash || old.Backend != v.Backend || old.ParentOwner != v.ParentOwner || old.ParentOperationID != v.ParentOperationID || old.ParentRequestHash != v.ParentRequestHash {
		return errors.New("Docker 释放意图与原授权范围不一致")
	}
	return nil
}

func saveDockerRegistration(dataDir string, v *dockerRegistrationCheckpoint) error {
	// A terminal receipt is immutable, including its timestamp.
	if v.UpdatedAt == 0 {
		v.UpdatedAt = time.Now().Unix()
	}
	if !validDockerRegistration(v) || v.DataDir != dataDir {
		return errors.New("拒绝保存无效 Docker 本机授权")
	}
	if err := dockerRegistrationPrevious(dataDir, v); err != nil {
		return err
	}
	prior, err := loadIPTablesReceipt(dataDir, v.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && (prior.Kind != dockerRegistrationKind || prior.RequestHash != v.RequestHash || (prior.State == "succeeded" || prior.State == "failed") && !dockerRegistrationReceiptMatches(prior, v)) {
		return errors.New("Docker 原授权回执冲突，拒绝覆盖终态")
	}
	j := iptablesRegistrationJournal(dataDir)
	if err = secure.RootDirectory(j.Dir, 0700); err != nil {
		return err
	}
	if err = listenerWrite(dockerRegistrationPath(dataDir), v); err != nil {
		return err
	}
	copy := *v
	return j.Put(Record{OperationID: v.OperationID, RelatedOperationID: v.PreviousOperationID, RequestHash: v.RequestHash, Kind: dockerRegistrationKind, State: v.OperationState, Stage: v.State, CandidateHash: dockerRegistrationReceiptHash(v), Error: v.Error, DockerRegistration: &copy})
}

func dockerRegistrationParent(v *dockerRegistrationCheckpoint, parent *iptablesRegistrationCheckpoint) bool {
	return parent != nil && v.ParentOwner == parent.NextClaim.Owner && v.ParentOperationID == parent.NextClaim.OperationID && v.ParentRequestHash == parent.RequestHash && v.MachineHash == parent.NextClaim.MachineHash && v.Backend == parent.NextClaim.Backend
}

// The parent has already been checked against the local global claim. A
// logical policy or a matching daemon report cannot supply the child grant.
func dockerRegistrationAuthority(dataDir string, parent *iptablesRegistrationCheckpoint, engineHash string) (*dockerRegistrationCheckpoint, error) {
	v, err := loadDockerRegistration(dataDir)
	if err != nil {
		return nil, err
	}
	if v == nil || v.State != "registered" || !dockerRegistrationParent(v, parent) || v.EngineHash != engineHash || dockerRegistrationReceipt(dataDir, v) != nil {
		return nil, errors.New("Docker 代际计划需要与当前父登记及实例一致的独立本机授权，请检查 docker-firewall-registration")
	}
	return v, nil
}

func forbidDockerRegistration(dataDir string) error {
	v, err := loadDockerRegistration(dataDir)
	if err != nil {
		return err
	}
	if v != nil && (v.State != "released" || dockerRegistrationReceipt(dataDir, v) != nil) {
		return errors.New("请先由原数据目录释放或恢复 Docker 转发授权，再释放 iptables 宿主机登记")
	}
	return nil
}

func dockerRegistrationPending(dataDir string) bool {
	v, err := loadDockerRegistration(dataDir)
	return err != nil || v != nil && (v.State == "preparing" || dockerRegistrationReceipt(dataDir, v) != nil)
}

// Until an independent Docker executor can prove ownership, every reserved
// object must be absent. The check covers all tables/backends/families.
func proveEmptyDockerNamespace(image iptablesImage) error {
	for _, table := range image.Tables {
		for _, chain := range table.Chains {
			if dockerIPTablesReserved(chain.Name) {
				return errors.New("存在未经 Docker 独立回执证明的保留链，拒绝接管或删除")
			}
			for _, rule := range chain.Rules {
				for _, arg := range rule {
					if dockerIPTablesReserved(arg) {
						return errors.New("存在未经 Docker 独立回执证明的引用或标记，拒绝接管或删除")
					}
				}
			}
		}
	}
	return nil
}
