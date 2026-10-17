package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const iptablesRegistrationKind = "iptables_registration"
const iptablesHostClaimPath = "/var/lib/nginxpanel-host/iptables-owner.json"

// The durable host claim prevents different data directories from separately
// granting an iptables namespace while the process-scoped host lock is not held.
type iptablesHostClaim struct {
	Schema      int    `json:"schema"`
	Owner       string `json:"owner"`
	OperationID string `json:"operation_id"`
	DataDir     string `json:"data_dir"`
	MachineHash string `json:"machine_hash"`
	Backend     string `json:"backend"`
	State       string `json:"state"`
}

// Registration authorizes an empty namespace only. It creates no iptables rule;
// neither this record nor a matching comment proves any rule was installed.
type iptablesRegistrationCheckpoint struct {
	Schema                    int                `json:"schema"`
	PreviousOperationID       string             `json:"previous_operation_id"`
	BootID                    string             `json:"boot_id"`
	Action                    string             `json:"action"`
	State                     string             `json:"state"`
	OperationState            string             `json:"operation_state"`
	PreviousClaim             *iptablesHostClaim `json:"previous_claim"`
	NextClaim                 iptablesHostClaim  `json:"next_claim"`
	ConfigurationHash         string             `json:"configuration_hash"`
	ToolHash                  string             `json:"tool_hash"`
	VerifiedConfigurationHash string             `json:"verified_configuration_hash"`
	RequestHash               string             `json:"request_hash"`
	UpdatedAt                 int64              `json:"updated_at"`
	Error                     string             `json:"error"`
}

func iptablesRegistrationPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "iptables-registration.json")
}
func iptablesHostIdentity() (string, string, error) {
	return hostBootIdentity("nginxpanel:iptables-host-machine:v1:")
}
func iptablesClaimHash(v *iptablesHostClaim) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("nginxpanel:iptables-claim:v1:\x00"), raw...))
}
func validIPTablesClaim(v *iptablesHostClaim) bool {
	return v != nil && v.Schema == 1 && validID(v.Owner) && validID(v.OperationID) && filepath.IsAbs(v.DataDir) && filepath.Clean(v.DataDir) == v.DataDir && len(v.DataDir) <= 4096 && utf8.ValidString(v.DataDir) && firewalldDigest(v.MachineHash) && validIPTablesBackend(v.Backend) && (v.State == "registered" || v.State == "releasing" || v.State == "released")
}
func iptablesRegistrationHash(v *iptablesRegistrationCheckpoint) string {
	raw, _ := json.Marshal(struct {
		Schema                                                           int
		PreviousOperationID, BootID, Action, ConfigurationHash, ToolHash string
		PreviousClaim                                                    *iptablesHostClaim
		NextClaim                                                        iptablesHostClaim
	}{v.Schema, v.PreviousOperationID, v.BootID, v.Action, v.ConfigurationHash, v.ToolHash, v.PreviousClaim, v.NextClaim})
	return secure.Hash(append([]byte("nginxpanel:iptables-registration:v1:\x00"), raw...))
}
func iptablesRegistrationReceiptHash(v *iptablesRegistrationCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(raw)
}
func validIPTablesRegistration(v *iptablesRegistrationCheckpoint) bool {
	if v == nil || v.Schema != 1 || !validIPTablesClaim(&v.NextClaim) || !validID(v.BootID) || v.UpdatedAt <= 0 || len(v.Error) > 4096 || v.PreviousOperationID != "" && (!validID(v.PreviousOperationID) || v.PreviousOperationID == v.NextClaim.OperationID) || !firewalldDigest(v.ConfigurationHash) || !firewalldDigest(v.ToolHash) || v.VerifiedConfigurationHash != "" && !firewalldDigest(v.VerifiedConfigurationHash) || v.RequestHash != iptablesRegistrationHash(v) {
		return false
	}
	if v.PreviousClaim != nil && (!validIPTablesClaim(v.PreviousClaim) || v.PreviousClaim.MachineHash != v.NextClaim.MachineHash || v.Action == "remove" && v.PreviousClaim.Backend != v.NextClaim.Backend || v.PreviousClaim.OperationID == v.NextClaim.OperationID) {
		return false
	}
	if v.Action == "init" {
		if v.NextClaim.State != "registered" || v.PreviousClaim != nil && (v.PreviousClaim.State != "released" || v.PreviousClaim.Owner == v.NextClaim.Owner) {
			return false
		}
	} else if v.Action == "remove" {
		if v.NextClaim.State != "released" || v.PreviousClaim == nil || v.PreviousClaim.State != "registered" || v.PreviousClaim.Owner != v.NextClaim.Owner || v.PreviousClaim.DataDir != v.NextClaim.DataDir || v.PreviousOperationID != v.PreviousClaim.OperationID {
			return false
		}
	} else {
		return false
	}
	if v.State == v.NextClaim.State {
		return v.OperationState == "succeeded" && v.VerifiedConfigurationHash != "" && v.Error == ""
	}
	return v.State == "preparing" && (v.OperationState == "running" || v.OperationState == "recovery_required")
}

func readIPTablesPrivate(path string, value any) (bool, error) {
	raw, err := listenerRead(path, 64<<10)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(value); err != nil {
		return false, err
	}
	if d.Decode(new(any)) != io.EOF {
		return false, errors.New("IPTables 私有记录包含多余内容")
	}
	return true, nil
}
func loadIPTablesHostClaim() (*iptablesHostClaim, error) {
	var v iptablesHostClaim
	present, err := readIPTablesPrivate(iptablesHostClaimPath, &v)
	if err != nil || !present {
		return nil, err
	}
	if !validIPTablesClaim(&v) {
		return nil, errors.New("IPTables 宿主机占用记录无效")
	}
	return &v, nil
}
func loadIPTablesRegistration(dataDir string) (*iptablesRegistrationCheckpoint, error) {
	var v iptablesRegistrationCheckpoint
	present, err := readIPTablesPrivate(iptablesRegistrationPath(dataDir), &v)
	if err != nil || !present {
		return nil, err
	}
	if !validIPTablesRegistration(&v) || v.NextClaim.DataDir != dataDir {
		return nil, errors.New("IPTables 本机授权登记无效")
	}
	return &v, nil
}
func iptablesRegistrationJournal(dataDir string) *Journal {
	return &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
}
func loadIPTablesReceipt(dataDir, operationID string) (Record, error) {
	var out Record
	if !validID(operationID) {
		return out, errors.New("IPTables 回执操作身份无效")
	}
	raw, err := listenerRead(filepath.Join(iptablesRegistrationJournal(dataDir).Dir, operationID+".json"), 128<<10)
	if err != nil {
		return out, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&out); err != nil {
		return out, err
	}
	if d.Decode(new(any)) != io.EOF {
		return out, errors.New("IPTables 回执包含多余内容")
	}
	return out, nil
}
func iptablesRegistrationReceiptMatches(r Record, v *iptablesRegistrationCheckpoint) bool {
	return validIPTablesRegistration(v) && r.Kind == iptablesRegistrationKind && r.OperationID == v.NextClaim.OperationID && r.RequestHash == v.RequestHash && r.State == v.OperationState && r.Stage == v.State && r.RelatedOperationID == v.PreviousOperationID && r.CandidateHash == iptablesRegistrationReceiptHash(v) && validIPTablesRegistration(r.IPTablesRegistration) && iptablesRegistrationReceiptHash(r.IPTablesRegistration) == r.CandidateHash && r.Error == v.Error
}
func iptablesRegistrationReceipt(dataDir string, v *iptablesRegistrationCheckpoint) error {
	r, err := loadIPTablesReceipt(dataDir, v.NextClaim.OperationID)
	if err != nil {
		return err
	}
	if !iptablesRegistrationReceiptMatches(r, v) {
		return errors.New("IPTables 授权登记与独立回执不一致")
	}
	return nil
}
func saveIPTablesRegistration(dataDir string, v *iptablesRegistrationCheckpoint) error {
	v.UpdatedAt = time.Now().Unix()
	if !validIPTablesRegistration(v) || v.NextClaim.DataDir != dataDir {
		return errors.New("拒绝保存无效 IPTables 授权登记")
	}
	j := iptablesRegistrationJournal(dataDir)
	if err := secure.RootDirectory(j.Dir, 0700); err != nil {
		return err
	}
	prior, err := loadIPTablesReceipt(dataDir, v.NextClaim.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && (prior.Kind != iptablesRegistrationKind || prior.RequestHash != v.RequestHash) {
		return errors.New("IPTables 登记操作身份冲突")
	}
	if err = listenerWrite(iptablesRegistrationPath(dataDir), v); err != nil {
		return err
	}
	copy := *v
	return j.Put(Record{OperationID: v.NextClaim.OperationID, RelatedOperationID: v.PreviousOperationID, RequestHash: v.RequestHash, Kind: iptablesRegistrationKind, State: v.OperationState, Stage: v.State, CandidateHash: iptablesRegistrationReceiptHash(v), Error: v.Error, IPTablesRegistration: &copy})
}

// A released tombstone is published only after the terminal local receipt.
// The releasing state fences a crash in between, without making future host
// reuse depend on retaining another installation's data directory.
func iptablesReleasedClaim(v *iptablesHostClaim) error {
	if v == nil {
		return nil
	}
	if !validIPTablesClaim(v) || v.State != "released" {
		return errors.New("宿主机已有 IPTables 授权占用，须先由原数据目录释放")
	}
	return nil
}
func iptablesPublishingClaim(v *iptablesRegistrationCheckpoint) iptablesHostClaim {
	out := v.NextClaim
	if v.Action == "remove" {
		out.State = "releasing"
	}
	return out
}
func forbidIPTablesRegistration(dataDir string) error {
	if err := forbidDockerRegistration(dataDir); err != nil {
		return err
	}
	v, err := loadIPTablesHostClaim()
	if err != nil {
		return err
	}
	if err = iptablesReleasedClaim(v); err != nil {
		return err
	}
	local, err := loadIPTablesRegistration(dataDir)
	if err != nil {
		return err
	}
	if local != nil && (local.State != "released" || iptablesRegistrationReceipt(dataDir, local) != nil) {
		return errors.New("原数据目录的 iptables 授权意图尚未释放或核对完成")
	}
	return nil
}
func iptablesRegistrationAuthority(dataDir string) (*iptablesRegistrationCheckpoint, error) {
	v, err := loadIPTablesRegistration(dataDir)
	if err != nil {
		return nil, err
	}
	if v == nil || v.State != "registered" {
		return nil, errors.New("须先由本机 root 完成 IPTables 初始授权登记")
	}
	if err = iptablesRegistrationReceipt(dataDir, v); err != nil {
		return nil, err
	}
	machine, _, err := iptablesHostIdentity()
	if err != nil || machine != v.NextClaim.MachineHash {
		return nil, errors.New("IPTables 登记属于其他宿主机或当前身份无法核对")
	}
	claim, err := loadIPTablesHostClaim()
	if err != nil || iptablesClaimHash(claim) != iptablesClaimHash(&v.NextClaim) {
		return nil, errors.New("IPTables 宿主机占用与原登记不一致")
	}
	return v, nil
}

func iptablesRegistrationPending(dataDir string) bool {
	if iptablesBusinessPending(dataDir) {
		return true
	}
	v, err := loadIPTablesRegistration(dataDir)
	if err != nil || v != nil && (v.State == "preparing" || iptablesRegistrationReceipt(dataDir, v) != nil) {
		return true
	}
	if v == nil {
		claim, err := loadIPTablesHostClaim()
		return err != nil || claim != nil && claim.DataDir == dataDir && claim.State != "released"
	}
	if v != nil && v.State == "released" {
		claim, err := loadIPTablesHostClaim()
		publishing := iptablesPublishingClaim(v)
		return err != nil || iptablesClaimHash(claim) == iptablesClaimHash(&publishing)
	}
	return false
}

func iptablesRegistrationView(ctx context.Context, dataDir string, observed firewall.Observation) firewall.IPTablesRegistrationView {
	out := firewall.IPTablesRegistrationView{Registration: firewall.RegistrationView{State: "unavailable", ObservedAt: time.Now().Unix()}}
	v, err := loadIPTablesRegistration(dataDir)
	if err != nil {
		out.Registration.Reason = "iptables 本机授权登记无法读取"
		return out
	}
	if v != nil {
		out.Backend, out.Registration.OperationID = v.NextClaim.Backend, v.NextClaim.OperationID
	}
	if business, err := loadIPTablesChange(dataDir); err != nil {
		if v != nil {
			out.Registration.State = "recovery_required"
		}
		out.Registration.Reason = "iptables 原业务快照无法读取"
		return out
	} else if source := iptablesPolicySourceFor(business); source != nil && source.Policy.Action == "apply" {
		if v == nil {
			out.Backend, out.Registration.OperationID = source.Policy.Policy.Backend, source.RegistrationOperationID
		}
		if v == nil || verifyIPTablesSource(dataDir, source) != nil || source.Owner != v.NextClaim.Owner || source.MachineHash != v.NextClaim.MachineHash || source.RegistrationOperationID != v.NextClaim.OperationID || source.RegistrationRequestHash != v.RequestHash || source.Policy.Policy.Backend != v.NextClaim.Backend || source.Tools.verify(ctx) != nil {
			out.Registration.State, out.Registration.Reason = "drifted", "iptables 已确认策略、原授权或固定工具无法核对"
			return out
		}
		program, err := firewall.CompileIPTablesRuntime(firewall.HostPolicy(source.Policy.Policy), source.Policy.Protections, source.Owner, source.Policy.PlanID, source.Policy.Action)
		if err != nil {
			out.Registration.State, out.Registration.Reason = "drifted", "iptables 已确认程序无法核对"
			return out
		}
		snapshot, err := snapshotIPTablesTransition(ctx, v.NextClaim.Backend, observed, program)
		if err != nil || snapshot.ToolHash != source.ToolHash {
			out.Registration.State, out.Registration.Reason = "drifted", "iptables 已确认代际或当前环境无法完整核对，请本机恢复"
			return out
		}
		for _, generation := range program.Families {
			if snapshot.States[generation.Family] != "candidate" {
				out.Registration.State, out.Registration.Reason = "recovery_required", "iptables 已确认地址族规则缺失"
				return out
			}
		}
		out.Registration.State, out.Registration.Verified, out.Registration.Reason = "managed", true, "iptables 已确认代际及原独立回执已核对"
		return out
	}
	claim, err := loadIPTablesHostClaim()
	if err != nil {
		out.Registration.Reason = "iptables 宿主机占用无法读取"
		return out
	}
	if v == nil {
		out.Registration.State = "unregistered"
		if claim != nil && claim.State != "released" {
			out.Backend = claim.Backend
			out.Registration.Reason = "宿主机已有 iptables 授权占用或待完成释放，须由原数据目录核对"
		}
		return out
	}
	if v.State == "preparing" || iptablesRegistrationReceipt(dataDir, v) != nil {
		out.Registration.State, out.Registration.Reason = "recovery_required", "iptables 原授权操作尚未核对完成，请本机执行 iptables-recover"
		return out
	}
	machine, _, err := iptablesHostIdentity()
	if err != nil || machine != v.NextClaim.MachineHash {
		out.Registration.Reason = "iptables 登记的宿主机身份无法核对，不能导入源机 root 授权"
		return out
	}
	if v.State == "released" {
		publishing := iptablesPublishingClaim(v)
		if iptablesClaimHash(claim) == iptablesClaimHash(&publishing) {
			out.Registration.State, out.Registration.Reason = "recovery_required", "iptables 释放回执已保存，宿主机释放尚待原操作核对"
		} else if claim != nil && claim.OperationID == v.NextClaim.OperationID && iptablesClaimHash(claim) != iptablesClaimHash(&v.NextClaim) {
			out.Registration.State, out.Registration.Reason = "drifted", "iptables 原释放占用记录变化"
		} else {
			out.Registration.State = "released"
		}
		return out
	}
	if _, err = iptablesRegistrationAuthority(dataDir); err != nil {
		out.Registration.State, out.Registration.Reason = "drifted", "iptables 宿主机占用与原授权登记不一致"
		return out
	}
	if iptablesBusinessPending(dataDir) {
		out.Registration.State, out.Registration.Reason = "recovery_required", "iptables 原业务或子进程尚未完成核对，请本机执行 iptables-recover"
		return out
	}
	if _, err = snapshotIPTablesRegistration(ctx, v.NextClaim.Backend, observed); err != nil {
		out.Registration.State, out.Registration.Reason = "drifted", "iptables 空命名空间、显式工具或目标环境无法核对；保留现场，请本机检查"
		return out
	}
	out.Registration.State, out.Registration.Verified, out.Registration.Reason = "registered", true, "iptables 本机空命名空间授权已核对；未安装业务规则"
	return out
}

func validIPTablesRegistrationView(v firewall.IPTablesRegistrationView) bool {
	r := v.Registration
	if v.Backend != "" && !validIPTablesBackend(v.Backend) || r.ObservedAt < 0 || r.OperationID != "" && !validID(r.OperationID) || len(r.Reason) > 4096 {
		return false
	}
	switch r.State {
	case "unavailable", "unregistered":
	case "registered", "managed", "released", "drifted", "recovery_required":
		if !validIPTablesBackend(v.Backend) || !validID(r.OperationID) || r.ObservedAt <= 0 {
			return false
		}
	default:
		return false
	}
	return !r.Verified || (r.State == "registered" || r.State == "managed") && validIPTablesBackend(v.Backend) && validID(r.OperationID) && r.ObservedAt > 0
}
