package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const ufwRepairKind = "firewall.ufw.repair"

// Only this bounded summary enters the independent operation journal. Native
// snapshots remain in the root checkpoint and never enter portable archives.
type ufwRepairStatus struct {
	ID                string `json:"id"`
	SourceOperationID string `json:"source_operation_id"`
	SourceHash        string `json:"source_hash"`
	ProgramHash       string `json:"program_hash"`
	IntentHash        string `json:"intent_hash"`
	State             string `json:"state"`
	Error             string `json:"error"`
	ResolutionHash    string `json:"resolution_hash"`
	UpdatedAt         int64  `json:"updated_at"`
}

type ufwRepairFamily struct {
	Family  string
	Raw     []byte
	Before  []ufwReloadChain
	CallIDs []string
}

type ufwRepairCheckpoint struct {
	Schema            int                  `json:"schema"`
	Status            ufwRepairStatus      `json:"status"`
	Owner             string               `json:"owner"`
	Policy            firewallPolicyRecord `json:"policy"`
	IPv6              bool                 `json:"ipv6"`
	ToolchainHash     string               `json:"toolchain_hash"`
	ConfigurationHash string               `json:"configuration_hash"`
	Files             []ufwFileSnapshot    `json:"files"`
	Families          []ufwRepairFamily    `json:"families"`
}

func ufwRepairPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "ufw-repair.json")
}

func ufwRepairHash(v *ufwRepairCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("ufw:repair:v1:\x00"), raw...))
}

func ufwRepairIntentHash(v *ufwRepairCheckpoint) string {
	copy := *v
	copy.Status.IntentHash, copy.Status.State, copy.Status.Error, copy.Status.ResolutionHash, copy.Status.UpdatedAt = "", "", "", "", 0
	return ufwRepairHash(&copy)
}

func ufwRepairTerminal(v *ufwRepairCheckpoint) bool {
	return v != nil && slices.Contains([]string{"succeeded", "superseded"}, v.Status.State)
}

func validUFWRepairStatus(v *ufwRepairStatus) bool {
	if v == nil || !validID(v.ID) || !validID(v.SourceOperationID) || v.ID == v.SourceOperationID || !firewalldDigest(v.SourceHash) || !firewalldDigest(v.ProgramHash) || !firewalldDigest(v.IntentHash) || v.UpdatedAt <= 0 || len(v.Error) > 512 {
		return false
	}
	switch v.State {
	case "running", "recovery_required":
		return v.ResolutionHash == "" && (v.State == "running" && v.Error == "" || v.State == "recovery_required" && v.Error != "")
	case "succeeded":
		return firewalldDigest(v.ResolutionHash) && v.Error == ""
	case "superseded":
		return firewalldDigest(v.ResolutionHash) && v.Error != ""
	}
	return false
}

func validateUFWRepair(v *ufwRepairCheckpoint) error {
	invalid := errors.New("UFW 确认规则修复意图无效")
	if v == nil || v.Schema != 1 || !validUFWRepairStatus(&v.Status) || !validID(v.Owner) || !firewalldDigest(v.ToolchainHash) || !firewalldDigest(v.ConfigurationHash) || v.Policy.Action != "apply" || v.Policy.ProgramHash != v.Status.ProgramHash || v.Status.IntentHash != ufwRepairIntentHash(v) || len(v.Files) == 0 {
		return invalid
	}
	program, err := ufwPolicyProgram(&v.Policy, v.Owner)
	if err != nil {
		return err
	}
	owned, err := ufwNativeProgram(program)
	if err != nil {
		return err
	}
	sources := ufwConfigurationSources(v.Files[0].Path, v.IPv6)
	if len(sources) != len(v.Files) {
		return invalid
	}
	files := map[string]ufwFileSnapshot{}
	var total int64
	for index, source := range sources {
		file := v.Files[index]
		if file.Path != source.path || source.required && !file.Present || !validUFWFileSnapshot(file, index == 0, firewall.UFWReadBytes) {
			return invalid
		}
		files[file.Path], total = file, total+file.Bytes
	}
	raw, _ := json.Marshal(v.Files)
	if secure.Hash(raw) != v.ConfigurationHash || total > 4<<20 {
		return invalid
	}
	families := []string{"ipv4"}
	if v.IPv6 {
		families = append(families, "ipv6")
	}
	if len(v.Families) != len(families) {
		return invalid
	}
	ids := map[string]bool{v.Status.ID: true, v.Status.SourceOperationID: true, v.Owner: true, v.Policy.OperationID: true, v.Policy.PlanID: true}
	missing := false
	for index, family := range v.Families {
		file := files[ufwRepairUserPath(family.Family)]
		if family.Family != families[index] || len(family.Raw) > firewall.UFWReadBytes || int64(len(family.Raw)) != file.Bytes || secure.Hash(family.Raw) != file.Hash || len(family.CallIDs) != 3 {
			return invalid
		}
		_, payload, err := ufwRepairProjection(family.Raw, family.Family, family.Before, owned)
		if err != nil {
			return err
		}
		missing = missing || len(payload) != 0
		for _, id := range family.CallIDs {
			if !validID(id) || ids[id] {
				return invalid
			}
			ids[id] = true
		}
	}
	if !missing {
		return invalid
	}
	return nil
}

func loadUFWRepair(dataDir string) (*ufwRepairCheckpoint, error) {
	raw, err := listenerRead(ufwRepairPath(dataDir), ufwChangeBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v ufwRepairCheckpoint
	if ufwToolJSON(raw, &v) != nil {
		return nil, errors.New("UFW 修复检查点不可读取")
	}
	if err = validateUFWRepair(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

func ufwRepairRecordState(v *ufwRepairStatus) string {
	if v.State == "superseded" {
		return "cancelled"
	}
	return v.State
}

func ufwRepairReceiptMatches(record Record, status *ufwRepairStatus) bool {
	return validUFWRepairStatus(status) && validUFWRepairStatus(record.UFWRepair) && *record.UFWRepair == *status && record.Kind == ufwRepairKind && record.OperationID == status.ID && record.RelatedOperationID == status.SourceOperationID && record.RequestHash == status.IntentHash && firewalldDigest(record.CandidateHash) && record.State == ufwRepairRecordState(status) && record.Stage == status.State && record.Error == status.Error
}

func ufwRepairPending(dataDir string) bool {
	v, err := loadUFWRepair(dataDir)
	if err != nil || v == nil {
		return err != nil
	}
	r, err := loadUFWReceipt(dataDir, v.Status.ID)
	return err != nil || !ufwRepairReceiptMatches(r, &v.Status) || r.CandidateHash != ufwRepairHash(v) || !ufwRepairTerminal(v)
}

func saveUFWRepair(dataDir string, v *ufwRepairCheckpoint) error {
	v.Status.UpdatedAt = time.Now().Unix()
	if err := validateUFWRepair(v); err != nil {
		return err
	}
	current, err := loadUFWRepair(dataDir)
	if err != nil {
		return err
	}
	if current != nil {
		if current.Status.ID == v.Status.ID {
			if current.Status.IntentHash != v.Status.IntentHash || ufwRepairTerminal(current) && (current.Status.State != v.Status.State || current.Status.Error != v.Status.Error || current.Status.ResolutionHash != v.Status.ResolutionHash) {
				return errors.New("UFW 原修复意图或终态禁止覆盖")
			}
		} else if ufwRepairPending(dataDir) {
			return errors.New("UFW 原修复尚未完成，禁止替换恢复材料")
		}
	}
	old, err := loadUFWReceipt(dataDir, v.Status.ID)
	if err == nil {
		if current == nil || current.Status.ID != v.Status.ID || !ufwRepairReceiptMatches(old, old.UFWRepair) || old.RequestHash != v.Status.IntentHash || slices.Contains([]string{"succeeded", "cancelled"}, old.State) && (old.Stage != v.Status.State || old.UFWRepair.ResolutionHash != v.Status.ResolutionHash) {
			return errors.New("UFW 修复独立回执身份或终态冲突")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = secure.RootDirectory(filepath.Dir(ufwRepairPath(dataDir)), 0700); err != nil {
		return err
	}
	if err = rootJSONWrite(ufwRepairPath(dataDir), v, ufwChangeBytes); err != nil {
		return err
	}
	status := v.Status
	return ufwRegistrationJournal(dataDir).Put(Record{OperationID: status.ID, RelatedOperationID: status.SourceOperationID, Kind: ufwRepairKind, RequestHash: status.IntentHash, CandidateHash: ufwRepairHash(v), State: ufwRepairRecordState(&status), Stage: status.State, Error: status.Error, UFWRepair: &status})
}
