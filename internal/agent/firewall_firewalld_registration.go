package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const firewalldRegistrationKind = "firewalld_registration"

// Root recovery material, never portable configuration. The fixed marker is
// only meaningful together with this pre-write intent and its local receipt.
type firewalldRegistrationCheckpoint struct {
	Schema              int             `json:"schema"`
	Owner               string          `json:"owner"`
	OperationID         string          `json:"operation_id"`
	PreviousOperationID string          `json:"previous_operation_id"`
	MachineHash         string          `json:"machine_hash"`
	BootID              string          `json:"boot_id"`
	BusID               string          `json:"bus_id"`
	BusOwner            string          `json:"bus_owner"`
	Peer                networkdProcess `json:"peer"`
	Action              string          `json:"action"`
	State               string          `json:"state"`
	OperationState      string          `json:"operation_state"`
	RequestHash         string          `json:"request_hash"`
	BaselineHash        string          `json:"baseline_hash"`
	SettingsHash        string          `json:"settings_hash"`
	Acknowledged        bool            `json:"acknowledged"`
	ReplyError          string          `json:"reply_error"`
	Resolved            bool            `json:"resolved"`
	Submitted           bool            `json:"submitted"`
	UpdatedAt           int64           `json:"updated_at"`
	Error               string          `json:"error"`
}

func firewalldRegistrationPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "firewalld-registration.json")
}
func firewalldHostIdentity() (string, string, error) {
	return hostBootIdentity("nginxpanel:firewalld-host-machine:v1:")
}
func firewalldDigest(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }

func firewalldRegistrationHash(v *firewalldRegistrationCheckpoint) string {
	request := struct {
		Schema                                                                                              int
		Owner, OperationID, PreviousOperationID, MachineHash, BootID, BusID, BusOwner, Action, BaselineHash string
		Policy, Description, Target                                                                         string
		Priority                                                                                            int32
		Ingress, Egress                                                                                     []string
		Peer                                                                                                networkdProcess
	}{v.Schema, v.Owner, v.OperationID, v.PreviousOperationID, v.MachineHash, v.BootID, v.BusID, v.BusOwner, v.Action, v.BaselineHash,
		firewall.FirewalldHostPolicy, "nginxpanel:firewalld:v1:" + v.Owner, "CONTINUE", firewall.FirewalldHostPriority, []string{"ANY"}, []string{"HOST"}, v.Peer}
	raw, _ := json.Marshal(request)
	return secure.Hash(append([]byte("nginxpanel:firewalld-registration:v1:\x00"), raw...))
}
func firewalldReceiptHash(v *firewalldRegistrationCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("nginxpanel:firewalld-registration-receipt:v1:\x00"), raw...))
}
func validFirewalldRegistration(v *firewalldRegistrationCheckpoint) bool {
	if v == nil || v.Schema != 1 || !validID(v.Owner) || !validID(v.OperationID) || v.PreviousOperationID != "" && (!validID(v.PreviousOperationID) || v.PreviousOperationID == v.OperationID) || !firewalldDigest(v.MachineHash) || !validID(v.BootID) || !validFirewalldBusID(v.BusID) || !validFirewalldBusOwner(v.BusOwner) || v.UpdatedAt <= 0 || len(v.Error) > 4096 || v.RequestHash != firewalldRegistrationHash(v) {
		return false
	}
	if v.SettingsHash != "" && !firewalldDigest(v.SettingsHash) {
		return false
	}
	if v.Peer.PID < 2 || v.Peer.Boot != v.BootID {
		return false
	}
	if start, err := strconv.ParseUint(v.Peer.Start, 10, 64); err != nil || start == 0 || strconv.FormatUint(start, 10) != v.Peer.Start {
		return false
	}
	if v.Acknowledged && (!v.Submitted || !v.Resolved) {
		return false
	}
	if v.ReplyError != "" && (!v.Acknowledged || !slices.Contains([]string{firewalldName + ".Exception", firewalldName + ".NotAuthorizedException"}, v.ReplyError)) {
		return false
	}
	if v.Action == "init" {
		if v.BaselineHash != "" {
			return false
		}
	} else if v.Action == "remove" {
		if !firewalldDigest(v.BaselineHash) || v.SettingsHash != v.BaselineHash || v.PreviousOperationID == "" {
			return false
		}
	} else {
		return false
	}
	switch v.State {
	case "creating":
		return v.Action == "init" && (v.OperationState == "running" || v.OperationState == "recovery_required")
	case "prepared":
		return v.Action == "init" && v.Submitted && v.SettingsHash != "" && v.Resolved && v.OperationState == "waiting_confirmation"
	case "registered":
		return v.SettingsHash != "" && v.Resolved && (v.Action == "init" && v.Submitted && v.OperationState == "succeeded" || v.Action == "remove" && (!v.Submitted || v.ReplyError != "") && v.OperationState == "failed")
	case "removing":
		return v.Action == "remove" && (v.OperationState == "running" || v.OperationState == "recovery_required")
	case "releasing":
		return v.Action == "remove" && v.Submitted && v.Resolved && v.OperationState == "waiting_confirmation"
	case "released":
		return v.Resolved && (v.Action == "remove" && v.Submitted && v.OperationState == "succeeded" || v.Action == "init" && v.OperationState == "failed")
	}
	return false
}
func loadFirewalldRegistration(dataDir string) (*firewalldRegistrationCheckpoint, error) {
	raw, err := listenerRead(firewalldRegistrationPath(dataDir), 16<<10)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v firewalldRegistrationCheckpoint
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&v); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF || !validFirewalldRegistration(&v) {
		return nil, errors.New("firewalld root 登记记录无效")
	}
	return &v, nil
}
func firewalldRegistrationJournal(dataDir string) *Journal {
	return &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
}
func firewalldRegistrationReceipt(dataDir string, v *firewalldRegistrationCheckpoint) error {
	r, err := firewalldRegistrationJournal(dataDir).Get(v.OperationID)
	if err != nil {
		return err
	}
	if r.Kind != firewalldRegistrationKind || r.RequestHash != v.RequestHash || r.State != v.OperationState || r.Stage != v.State || r.RelatedOperationID != v.PreviousOperationID || r.CandidateHash != firewalldReceiptHash(v) || !validFirewalldRegistration(r.FirewalldRegistration) || firewalldReceiptHash(r.FirewalldRegistration) != r.CandidateHash || r.Error != v.Error {
		return errors.New("firewalld root 登记与独立回执不一致")
	}
	return nil
}
func saveFirewalldRegistration(dataDir string, v *firewalldRegistrationCheckpoint) error {
	v.UpdatedAt = time.Now().Unix()
	if !validFirewalldRegistration(v) {
		return errors.New("拒绝保存无效 firewalld 登记")
	}
	j := firewalldRegistrationJournal(dataDir)
	if err := secure.RootDirectory(j.Dir, 0700); err != nil {
		return err
	}
	prior, err := j.Get(v.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && (prior.Kind != firewalldRegistrationKind || prior.RequestHash != v.RequestHash) {
		return errors.New("firewalld 登记操作身份冲突")
	}
	if err = listenerWrite(firewalldRegistrationPath(dataDir), v); err != nil {
		return err
	}
	copy := *v
	return j.Put(Record{OperationID: v.OperationID, RelatedOperationID: v.PreviousOperationID, RequestHash: v.RequestHash, Kind: firewalldRegistrationKind, State: v.OperationState, Stage: v.State, CandidateHash: firewalldReceiptHash(v), Error: v.Error, FirewalldRegistration: &copy})
}

func firewalldRegistrationView(dataDir string, inventory firewall.FirewalldPolicyInventory) firewall.RegistrationView {
	out := firewall.RegistrationView{State: "unavailable", ObservedAt: time.Now().Unix()}
	v, err := loadFirewalldRegistration(dataDir)
	if err != nil {
		out.Reason = "firewalld root 登记无法读取，须本机处理"
		return out
	}
	var policy *firewall.FirewalldPolicy
	for i := range inventory.Policies {
		if inventory.Policies[i].Name == firewall.FirewalldHostPolicy {
			policy = &inventory.Policies[i]
			break
		}
	}
	if v == nil {
		out.State = "unregistered"
		if inventory.Available && policy != nil {
			out.Reason = "存在未登记同名 policy，禁止接管"
		}
		return out
	}
	out.OperationID = v.OperationID
	machine, _, err := firewalldHostIdentity()
	if err != nil || machine != v.MachineHash {
		out.Reason = "firewalld 登记的宿主机身份无法核对"
		return out
	}
	if err = firewalldRegistrationReceipt(dataDir, v); err != nil {
		out.State = "recovery_required"
		out.Reason = "firewalld 独立回执待本机恢复核对"
		return out
	}
	if v.State != "registered" && v.State != "released" {
		out.State = "recovery_required"
		out.Reason = v.Error
		if out.Reason == "" {
			out.Reason = "firewalld 登记意图尚未完成，请本机执行 firewalld-recover"
		}
		return out
	}
	if !inventory.Available {
		out.Reason = "firewalld policy 清单不完整，不能核对登记"
		return out
	}
	managed, err := loadFirewalldState(dataDir)
	if err != nil {
		out.State, out.Reason = "recovery_required", "firewalld 业务恢复记录无法核对"
		return out
	}
	if managed != nil {
		if managed.Owner != v.Owner || managed.MachineHash != machine || managed.RegistrationOperationID != v.OperationID || v.State != "registered" {
			out.State, out.Reason = "drifted", "firewalld 业务记录与原空 policy 登记不一致"
			return out
		}
		if firewalldStateReceipt(dataDir, managed) != nil {
			out.State, out.Reason = "recovery_required", "firewalld 业务独立回执尚未核对"
			return out
		}
		if managed.Candidate != nil || managed.Call != nil {
			out.State, out.Reason = "recovery_required", "firewalld 业务变更待确认或待恢复"
			return out
		}
		if policy == nil || policy.Runtime == nil || policy.Permanent == nil {
			out.State, out.Reason = "missing", "原 firewalld 运行或永久 policy 缺失"
			return out
		}
		if policy.Runtime.Hash != managed.RuntimeHash || policy.Permanent.Hash != managed.PermanentHash || !policy.Active || !slices.Equal(policy.ActiveIngressZones, []string{"ANY"}) || !slices.Equal(policy.ActiveEgressZones, []string{"HOST"}) {
			out.State, out.Reason = "drifted", "firewalld 业务完整配置或活动绑定发生变化"
			return out
		}
		out.State, out.Verified = "managed", true
		return out
	}
	if v.State == "released" {
		out.State = "released"
		if policy != nil {
			out.State = "drifted"
			out.Reason = "释放后再次出现同名 policy，禁止接管"
		}
		return out
	}
	if policy == nil || policy.Runtime == nil || policy.Permanent == nil {
		out.State = "missing"
		out.Reason = "登记的运行或永久 policy 缺失"
		return out
	}
	if policy.Runtime.Hash != v.SettingsHash || policy.Permanent.Hash != v.SettingsHash || !policy.Active || !slices.Equal(policy.ActiveIngressZones, []string{"ANY"}) || !slices.Equal(policy.ActiveEgressZones, []string{"HOST"}) {
		out.State = "drifted"
		out.Reason = "登记的完整设置或活动绑定发生变化"
		return out
	}
	out.State, out.Verified = "registered", true
	return out
}

func forbidFirewalldRegistration(dataDir string) error {
	managed, err := loadFirewalldState(dataDir)
	if err != nil {
		return err
	}
	if managed != nil {
		return errors.New("存在 firewalld 业务恢复材料，禁止切换为直接 nftables")
	}
	v, err := loadFirewalldRegistration(dataDir)
	if err != nil {
		return err
	}
	if v != nil {
		if err = firewalldRegistrationReceipt(dataDir, v); err != nil {
			return err
		}
	}
	if v != nil && v.State != "released" {
		return errors.New("存在 firewalld root 登记或待恢复意图，禁止直接 nftables 登记或执行")
	}
	return nil
}

func validFirewalldRegistrationView(v firewall.RegistrationView, inventory firewall.FirewalldPolicyInventory) bool {
	if !slices.Contains([]string{"unavailable", "unregistered", "registered", "managed", "released", "missing", "drifted", "recovery_required"}, v.State) || v.ObservedAt < 0 || v.OperationID != "" && !validID(v.OperationID) {
		return false
	}
	if !v.Verified {
		return v.State != "registered" && v.State != "managed"
	}
	if v.State != "registered" && v.State != "managed" || !validID(v.OperationID) || v.ObservedAt <= 0 || !inventory.Available || v.Reason != "" {
		return false
	}
	for _, p := range inventory.Policies {
		if p.Name != firewall.FirewalldHostPolicy {
			continue
		}
		if !p.Active || p.Runtime == nil || p.Permanent == nil || v.State == "registered" && p.Runtime.Hash != p.Permanent.Hash || !slices.Equal(p.ActiveIngressZones, []string{"ANY"}) || !slices.Equal(p.ActiveEgressZones, []string{"HOST"}) {
			return false
		}
		for _, s := range []*firewall.FirewalldPolicySettings{p.Runtime, p.Permanent} {
			if s.Target != "CONTINUE" || s.Priority == nil || *s.Priority != firewall.FirewalldHostPriority || s.Entries != s.RichRules || v.State == "registered" && s.RichRules != 0 || p.Runtime.RichRules != p.Permanent.RichRules || !slices.Equal(s.IngressZones, []string{"ANY"}) || !slices.Equal(s.EgressZones, []string{"HOST"}) || s.Masquerade != nil && *s.Masquerade {
				return false
			}
		}
		return true
	}
	return false
}
