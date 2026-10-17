package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/remotelisten"
	"nginxpanel/internal/secure"
)

// Journal is separate from the business database and must never be included in
// a business restore. Future reachability operations persist their deadline and
// recovery snapshot before applying any side effect.
type Record struct {
	Fail2banPythonPlanning    *fail2banPythonPlanning       `json:"fail2ban_python_planning,omitempty"`
	Fail2banPython            *fail2banPythonIntent         `json:"fail2ban_python,omitempty"`
	Fail2banLifecycle         *fail2banLifecycleIntent      `json:"fail2ban_lifecycle,omitempty"`
	Fail2banAddress           *fail2banAddressIntent        `json:"fail2ban_address,omitempty"`
	Fail2banJails             *fail2banJailIntent           `json:"fail2ban_jails,omitempty"`
	Fail2banExisting          *fail2banExistingIntent       `json:"fail2ban_existing,omitempty"`
	Fail2banExistingPolicy    *fail2banExistingPolicyIntent `json:"fail2ban_existing_policy,omitempty"`
	Fail2banExistingPolicyJob *fail2banExistingPolicyJob    `json:"fail2ban_existing_policy_job,omitempty"`
	ClientDeny                *clientDenyIntent             `json:"client_deny,omitempty"`
	Firewall                  *firewall.Operation           `json:"firewall,omitempty"`
	RelatedOperationID        string                        `json:"related_operation_id,omitempty"`
	DisasterActivation        *DisasterActivationOperation  `json:"disaster_activation,omitempty"`
	DisasterRestoreID         string                        `json:"disaster_restore_id,omitempty"`

	RemoteListener           *remotelisten.Operation `json:"remote_listener,omitempty"`
	PanelUpdate              *PanelUpdateOperation   `json:"panel_update,omitempty"`
	PanelService             *PanelServiceOperation  `json:"panel_service,omitempty"`
	PanelSelection           *PanelSelectionIntent   `json:"panel_selection,omitempty"`
	PanelRestore             *PanelRestoreIntent     `json:"panel_restore,omitempty"`
	NginxInstall             *NginxInstallIntent     `json:"nginx_install,omitempty"`
	NginxSwitch              *NginxSwitchIntent      `json:"nginx_switch,omitempty"`
	NginxSwitchJob           *nginxSwitchJob         `json:"nginx_switch_job,omitempty"`
	MaintenanceEpoch         string                  `json:"maintenance_epoch,omitempty"`
	OperationID              string                  `json:"operation_id"`
	Fail2banHostRetirementID string                  `json:"fail2ban_host_retirement_id,omitempty"`
	RequestHash              string                  `json:"request_hash"`
	Kind                     string                  `json:"kind"`
	State                    string                  `json:"state"`
	Stage                    string                  `json:"stage"`
	BeforeRevision           string                  `json:"before_revision,omitempty"`
	AfterRevision            string                  `json:"after_revision,omitempty"`
	Deadline                 int64                   `json:"deadline,omitempty"`
	UpdatedAt                int64                   `json:"updated_at"`
	DiagnosticsCount         int                     `json:"diagnostics_count"`
	BeforeDir                string                  `json:"before_dir,omitempty"`
	AfterDir                 string                  `json:"after_dir,omitempty"`
	RestoreSnapshot          string                  `json:"restore_snapshot,omitempty"`
	CandidateHash            string                  `json:"candidate_hash,omitempty"`
	ObservedRevision         string                  `json:"observed_revision"`
	Error                    string                  `json:"error"`
	LogPolicy                *logs.Policy            `json:"log_policy,omitempty"`
	LogPolicyBase            int64                   `json:"log_policy_base,omitempty"`
	LogPolicyVersion         int64                   `json:"log_policy_version,omitempty"`
}
type Journal struct {
	Dir string
	mu  sync.Mutex
}

func (j *Journal) Get(id string) (Record, error) {
	if !validID(id) {
		return Record{}, errors.New("invalid operation ID")
	}
	b, err := os.ReadFile(filepath.Join(j.Dir, id+".json"))
	if err != nil {
		return Record{}, err
	}
	var r Record
	err = json.Unmarshal(b, &r)
	return r, err
}
func (j *Journal) Put(r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !validID(r.OperationID) {
		return errors.New("invalid operation ID")
	}
	if err := os.MkdirAll(j.Dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(j.Dir)
	if err != nil {
		return err
	}
	if len(entries) >= 2048 {
		if _, err := os.Stat(filepath.Join(j.Dir, r.OperationID+".json")); err != nil {
			return errors.New("agent journal capacity reached; local maintenance required")
		}
	}
	r.UpdatedAt = time.Now().Unix()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := filepath.Join(j.Dir, ".tmp-"+secure.ID())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, filepath.Join(j.Dir, r.OperationID+".json")); err != nil {
		return err
	}
	dir, err := os.Open(j.Dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (j *Journal) List() ([]Record, error) {
	entries, err := os.ReadDir(j.Dir)
	if os.IsNotExist(err) {
		return []Record{}, nil
	}
	if err != nil {
		return nil, err
	}
	records := []Record{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		record, err := j.Get(id)
		if err != nil {
			return nil, err
		}
		if record.OperationID != id {
			return nil, errors.New("journal identity mismatch")
		}
		records = append(records, record)
	}
	return records, nil
}
