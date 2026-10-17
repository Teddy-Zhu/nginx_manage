package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
)

const iptablesRetirementKind = "firewall.iptables.retirement"
const iptablesRetirementBytes = 3 * iptablesChangeBytes

// Local retirement records the operator's disposal of an empty owned scope.
// The original operation, uncertain results and receipts remain unchanged.
type iptablesRetirement struct {
	Schema            int                       `json:"schema"`
	ID                string                    `json:"id"`
	RequestedAt       int64                     `json:"requested_at"`
	ConfigurationHash string                    `json:"configuration_hash"`
	ToolHash          string                    `json:"tool_hash"`
	Business          iptablesChangeCheckpoint  `json:"business"`
	BusinessJournal   Record                    `json:"business_journal"`
	Repair            *iptablesRepairCheckpoint `json:"repair"`
	RepairJournal     *Record                   `json:"repair_journal"`
	Child             *iptablesRestoreReceipt   `json:"child"`
	ChildJournal      *Record                   `json:"child_journal"`
}

type iptablesRetirementReceipt struct {
	Schema            int    `json:"schema"`
	ID                string `json:"id"`
	IntentHash        string `json:"intent_hash"`
	ConfigurationHash string `json:"configuration_hash"`
	ToolHash          string `json:"tool_hash"`
	CompletedAt       int64  `json:"completed_at"`
}

type IPTablesRetirementStatus struct {
	ID                  string `json:"id"`
	BusinessOperationID string `json:"business_operation_id"`
	State               string `json:"state"`
	CompletedAt         int64  `json:"completed_at"`
	Reason              string `json:"reason"`
}

func iptablesRetirementDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "iptables-retirements")
}

func (r *iptablesRetirement) path(dataDir string) string {
	return filepath.Join(iptablesRetirementDir(dataDir), r.Business.Operation.ID+".json")
}

func (r *iptablesRetirement) receiptPath(dataDir string) string {
	return filepath.Join(iptablesRetirementDir(dataDir), "receipts", r.ID+".json")
}

func (r *iptablesRetirement) hash() string {
	raw, _ := json.Marshal(r)
	return secure.Hash(append([]byte("iptables:retirement:v1:\x00"), raw...))
}

func sameIPTablesRetirementRecord(a, b Record) bool {
	a.UpdatedAt, b.UpdatedAt = 0, 0
	return sameIPTablesValue(a, b)
}

func (r *iptablesRetirement) valid() error {
	if r == nil || r.Schema != 1 || !validID(r.ID) || r.RequestedAt <= 0 || !firewalldDigest(r.ConfigurationHash) || !firewalldDigest(r.ToolHash) || validateIPTablesChange(&r.Business) != nil || !iptablesChangeReceiptMatches(r.BusinessJournal, &r.Business) {
		return errors.New("iptables 本机退役意图无效")
	}
	ids := map[string]bool{r.Business.Operation.ID: true, r.Business.Policy.PlanID: true, r.Business.Transition.Owner: true, r.Business.Transition.RegistrationOperationID: true}
	for _, step := range r.Business.Steps {
		ids[step.ID] = true
	}
	if r.Repair != nil {
		if validateIPTablesRepair(r.Repair) != nil || iptablesRepairTerminal(r.Repair) || !iptablesPolicySourceMatches(r.Repair, &r.Business) || r.RepairJournal == nil || !iptablesRepairReceiptMatches(*r.RepairJournal, r.Repair) {
			return errors.New("iptables 退役的原修复意图或回执无效")
		}
		ids[r.Repair.Status.ID] = true
		for _, step := range r.Repair.Steps {
			ids[step.ID] = true
		}
	} else if r.RepairJournal != nil {
		return errors.New("iptables 退役包含无来源修复回执")
	}
	if r.Child != nil {
		if !validIPTablesRestore(r.Child) || r.Child.Phase != "ended" || r.Child.MachineHash != r.Business.Transition.MachineHash || r.ChildJournal == nil || !iptablesRestoreRecordMatches(*r.ChildJournal, r.Child) {
			return errors.New("iptables 退役缺少原执行进程的结束回执")
		}
		ids[r.Child.ID] = true
	} else if r.ChildJournal != nil {
		return errors.New("iptables 退役包含无来源执行回执")
	}
	if ids[r.ID] {
		return errors.New("iptables 退役操作标识与原操作冲突")
	}
	return nil
}

func loadIPTablesRetirement(dataDir, businessID string) (*iptablesRetirement, error) {
	if !validID(businessID) {
		return nil, errors.New("iptables 退役业务标识无效")
	}
	raw, err := listenerRead(filepath.Join(iptablesRetirementDir(dataDir), businessID+".json"), iptablesRetirementBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r iptablesRetirement
	if ufwToolJSON(raw, &r) != nil || r.Business.Operation.ID != businessID {
		return nil, errors.New("iptables 退役文件与原业务不一致")
	}
	return &r, r.valid()
}

func loadIPTablesRepairRetirement(dataDir, repairID string) (*iptablesRetirement, error) {
	if !validID(repairID) {
		return nil, errors.New("iptables 退役修复标识无效")
	}
	var link struct {
		BusinessID string `json:"business_id"`
	}
	raw, err := listenerRead(filepath.Join(iptablesRetirementDir(dataDir), "repairs", repairID+".json"), 1024)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ufwToolJSON(raw, &link) != nil || !validID(link.BusinessID) {
		return nil, errors.New("iptables 退役修复引用无效")
	}
	r, err := loadIPTablesRetirement(dataDir, link.BusinessID)
	if err != nil || r == nil || r.Repair == nil || r.Repair.Status.ID != repairID {
		return nil, errors.Join(errors.New("iptables 退役修复来源无法核对"), err)
	}
	return r, nil
}

func (r *iptablesRetirement) journal(state string, receipt *iptablesRetirementReceipt) Record {
	out := Record{Kind: iptablesRetirementKind, OperationID: r.ID, RelatedOperationID: r.Business.Operation.ID, RequestHash: secure.Hash([]byte("iptables:retire:" + r.ID + ":" + r.Business.Operation.ID)), CandidateHash: r.hash(), State: state, Stage: "retiring_empty_scope"}
	if receipt != nil {
		out.Stage = "scope_retired"
		raw, _ := json.Marshal(receipt)
		out.ObservedRevision = secure.Hash(raw)
	}
	return out
}

func (r *iptablesRetirement) record(dataDir string) (Record, *iptablesRetirementReceipt, error) {
	actual, err := loadIPTablesReceipt(dataDir, r.ID)
	if err != nil {
		return Record{}, nil, err
	}
	var receipt *iptablesRetirementReceipt
	if actual.State == "succeeded" {
		raw, e := listenerRead(r.receiptPath(dataDir), 4096)
		if e != nil {
			return Record{}, nil, e
		}
		receipt = new(iptablesRetirementReceipt)
		if ufwToolJSON(raw, receipt) != nil || receipt.Schema != 1 || receipt.ID != r.ID || receipt.IntentHash != r.hash() || !firewalldDigest(receipt.ConfigurationHash) || receipt.ToolHash != r.ToolHash || receipt.CompletedAt < r.RequestedAt {
			return Record{}, nil, errors.New("iptables 退役完成证明无效")
		}
	}
	if actual.State != "running" && actual.State != "succeeded" || !sameIPTablesRetirementRecord(actual, r.journal(actual.State, receipt)) {
		return Record{}, nil, errors.New("iptables 退役独立回执无法核对")
	}
	for _, expected := range []*Record{&r.BusinessJournal, r.RepairJournal, r.ChildJournal} {
		if expected == nil {
			continue
		}
		current, e := loadIPTablesReceipt(dataDir, expected.OperationID)
		if e != nil || !sameIPTablesRetirementRecord(current, *expected) {
			return Record{}, nil, errors.New("iptables 退役保存的原审计回执已变化")
		}
	}
	if source := iptablesPolicySourceFor(&r.Business); source != nil {
		if err = verifyIPTablesSource(dataDir, source); err != nil {
			return Record{}, nil, err
		}
	}
	return actual, receipt, nil
}

func retiredIPTablesChange(dataDir string, v *iptablesChangeCheckpoint) (bool, error) {
	if v == nil {
		return false, nil
	}
	r, err := loadIPTablesRetirement(dataDir, v.Operation.ID)
	if err != nil || r == nil {
		return false, err
	}
	if !sameIPTablesValue(r.Business, *v) {
		return false, errors.New("iptables 退役期间原业务检查点已变化")
	}
	record, _, err := r.record(dataDir)
	if err != nil {
		return false, err
	}
	if record.State != "succeeded" {
		return false, errors.New("iptables 本机退役尚未完成，须沿原操作续办")
	}
	return true, nil
}

func retiredIPTablesRepair(dataDir string, repair *iptablesRepairCheckpoint) (bool, error) {
	r, err := loadIPTablesRepairRetirement(dataDir, repair.Status.ID)
	if err != nil || r == nil {
		return false, err
	}
	if !sameIPTablesValue(r.Repair, repair) {
		return false, errors.New("iptables 退役期间原修复检查点已变化")
	}
	record, _, err := r.record(dataDir)
	return err == nil && record.State == "succeeded", err
}

func retiredIPTablesChild(dataDir string, child *iptablesRestoreReceipt) (bool, error) {
	r, err := loadIPTablesRetirement(dataDir, child.OperationID)
	if err != nil {
		return false, err
	}
	if r == nil {
		// A repair or an unstarted update can leave the previous confirmed
		// operation's child as the latest process. Retirement freezes that
		// exact child together with the current business checkpoint.
		current, readErr := loadIPTablesChangeRaw(dataDir)
		if readErr != nil {
			return false, readErr
		}
		if current != nil && current.Operation.ID != child.OperationID {
			r, err = loadIPTablesRetirement(dataDir, current.Operation.ID)
			if err != nil {
				return false, err
			}
			if r != nil && !sameIPTablesValue(r.Business, *current) {
				return false, errors.New("iptables 退役期间原业务检查点已变化")
			}
		}
	}
	if r == nil {
		return false, nil
	}
	if !sameIPTablesValue(child, r.Child) {
		return false, errors.New("iptables 退役后原子进程检查点已变化")
	}
	record, _, err := r.record(dataDir)
	return err == nil && record.State == "succeeded", err
}

func retiredIPTablesRecord(dataDir string, record Record) (bool, error) {
	var r *iptablesRetirement
	var expected *Record
	var err error
	switch record.Kind {
	case firewallOperationKind:
		r, err = loadIPTablesRetirement(dataDir, record.OperationID)
		if r != nil {
			expected = &r.BusinessJournal
		}
	case iptablesRepairKind:
		r, err = loadIPTablesRepairRetirement(dataDir, record.OperationID)
		if r != nil {
			expected = r.RepairJournal
		}
	default:
		return false, nil
	}
	if err != nil || r == nil {
		return false, err
	}
	if expected == nil || !sameIPTablesRetirementRecord(record, *expected) {
		return false, errors.New("iptables 已退役操作与原审计记录冲突")
	}
	current, _, err := r.record(dataDir)
	return err == nil && current.State == "succeeded", err
}
