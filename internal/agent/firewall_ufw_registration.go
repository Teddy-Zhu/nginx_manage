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

const ufwRegistrationKind = "ufw_registration"
const ufwHostClaimPath = "/var/lib/nginxpanel-host/ufw-owner.json"

// The durable host claim prevents different data directories from separately
// granting a UFW namespace while the process-scoped host lock is not held.
type ufwHostClaim struct {
	Schema      int    `json:"schema"`
	Owner       string `json:"owner"`
	OperationID string `json:"operation_id"`
	DataDir     string `json:"data_dir"`
	MachineHash string `json:"machine_hash"`
	State       string `json:"state"`
}

// Registration authorizes an empty namespace only. It creates no UFW rule;
// neither this record nor a matching comment proves any rule was installed.
type ufwRegistrationCheckpoint struct {
	Schema                    int           `json:"schema"`
	PreviousOperationID       string        `json:"previous_operation_id"`
	BootID                    string        `json:"boot_id"`
	Action                    string        `json:"action"`
	State                     string        `json:"state"`
	OperationState            string        `json:"operation_state"`
	PreviousClaim             *ufwHostClaim `json:"previous_claim"`
	NextClaim                 ufwHostClaim  `json:"next_claim"`
	ConfigurationHash         string        `json:"configuration_hash"`
	ToolHash                  string        `json:"tool_hash"`
	VerifiedConfigurationHash string        `json:"verified_configuration_hash"`
	RequestHash               string        `json:"request_hash"`
	UpdatedAt                 int64         `json:"updated_at"`
	Error                     string        `json:"error"`
}

func ufwRegistrationPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "ufw-registration.json")
}
func ufwHostIdentity() (string, string, error) {
	return hostBootIdentity("nginxpanel:ufw-host-machine:v1:")
}
func ufwClaimHash(v *ufwHostClaim) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("nginxpanel:ufw-claim:v1:\x00"), raw...))
}
func validUFWClaim(v *ufwHostClaim) bool {
	return v != nil && v.Schema == 1 && validID(v.Owner) && validID(v.OperationID) && filepath.IsAbs(v.DataDir) && filepath.Clean(v.DataDir) == v.DataDir && len(v.DataDir) <= 4096 && utf8.ValidString(v.DataDir) && firewalldDigest(v.MachineHash) && (v.State == "registered" || v.State == "releasing" || v.State == "released")
}
func ufwRegistrationHash(v *ufwRegistrationCheckpoint) string {
	raw, _ := json.Marshal(struct {
		Schema                                                           int
		PreviousOperationID, BootID, Action, ConfigurationHash, ToolHash string
		PreviousClaim                                                    *ufwHostClaim
		NextClaim                                                        ufwHostClaim
	}{v.Schema, v.PreviousOperationID, v.BootID, v.Action, v.ConfigurationHash, v.ToolHash, v.PreviousClaim, v.NextClaim})
	return secure.Hash(append([]byte("nginxpanel:ufw-registration:v1:\x00"), raw...))
}
func ufwRegistrationReceiptHash(v *ufwRegistrationCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(raw)
}
func validUFWRegistration(v *ufwRegistrationCheckpoint) bool {
	if v == nil || v.Schema != 1 || !validUFWClaim(&v.NextClaim) || !validID(v.BootID) || v.UpdatedAt <= 0 || len(v.Error) > 4096 || v.PreviousOperationID != "" && (!validID(v.PreviousOperationID) || v.PreviousOperationID == v.NextClaim.OperationID) || !firewalldDigest(v.ConfigurationHash) || !firewalldDigest(v.ToolHash) || v.VerifiedConfigurationHash != "" && !firewalldDigest(v.VerifiedConfigurationHash) || v.RequestHash != ufwRegistrationHash(v) {
		return false
	}
	if v.PreviousClaim != nil && (!validUFWClaim(v.PreviousClaim) || v.PreviousClaim.MachineHash != v.NextClaim.MachineHash || v.PreviousClaim.OperationID == v.NextClaim.OperationID) {
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

func readUFWPrivate(path string, value any) (bool, error) {
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
		return false, errors.New("UFW 私有记录包含多余内容")
	}
	return true, nil
}
func loadUFWHostClaim() (*ufwHostClaim, error) {
	var v ufwHostClaim
	present, err := readUFWPrivate(ufwHostClaimPath, &v)
	if err != nil || !present {
		return nil, err
	}
	if !validUFWClaim(&v) {
		return nil, errors.New("UFW 宿主机占用记录无效")
	}
	return &v, nil
}
func loadUFWRegistration(dataDir string) (*ufwRegistrationCheckpoint, error) {
	var v ufwRegistrationCheckpoint
	present, err := readUFWPrivate(ufwRegistrationPath(dataDir), &v)
	if err != nil || !present {
		return nil, err
	}
	if !validUFWRegistration(&v) || v.NextClaim.DataDir != dataDir {
		return nil, errors.New("UFW 本机授权登记无效")
	}
	return &v, nil
}
func ufwRegistrationJournal(dataDir string) *Journal {
	return &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
}
func loadUFWReceipt(dataDir, operationID string) (Record, error) {
	var out Record
	if !validID(operationID) {
		return out, errors.New("UFW 回执操作身份无效")
	}
	raw, err := listenerRead(filepath.Join(ufwRegistrationJournal(dataDir).Dir, operationID+".json"), 128<<10)
	if err != nil {
		return out, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&out); err != nil {
		return out, err
	}
	if d.Decode(new(any)) != io.EOF {
		return out, errors.New("UFW 回执包含多余内容")
	}
	return out, nil
}
func ufwRegistrationReceiptMatches(r Record, v *ufwRegistrationCheckpoint) bool {
	return validUFWRegistration(v) && r.Kind == ufwRegistrationKind && r.OperationID == v.NextClaim.OperationID && r.RequestHash == v.RequestHash && r.State == v.OperationState && r.Stage == v.State && r.RelatedOperationID == v.PreviousOperationID && r.CandidateHash == ufwRegistrationReceiptHash(v) && validUFWRegistration(r.UFWRegistration) && ufwRegistrationReceiptHash(r.UFWRegistration) == r.CandidateHash && r.Error == v.Error
}
func ufwRegistrationReceipt(dataDir string, v *ufwRegistrationCheckpoint) error {
	r, err := loadUFWReceipt(dataDir, v.NextClaim.OperationID)
	if err != nil {
		return err
	}
	if !ufwRegistrationReceiptMatches(r, v) {
		return errors.New("UFW 授权登记与独立回执不一致")
	}
	return nil
}
func saveUFWRegistration(dataDir string, v *ufwRegistrationCheckpoint) error {
	v.UpdatedAt = time.Now().Unix()
	if !validUFWRegistration(v) || v.NextClaim.DataDir != dataDir {
		return errors.New("拒绝保存无效 UFW 授权登记")
	}
	j := ufwRegistrationJournal(dataDir)
	if err := secure.RootDirectory(j.Dir, 0700); err != nil {
		return err
	}
	prior, err := loadUFWReceipt(dataDir, v.NextClaim.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && (prior.Kind != ufwRegistrationKind || prior.RequestHash != v.RequestHash) {
		return errors.New("UFW 登记操作身份冲突")
	}
	if err = listenerWrite(ufwRegistrationPath(dataDir), v); err != nil {
		return err
	}
	copy := *v
	return j.Put(Record{OperationID: v.NextClaim.OperationID, RelatedOperationID: v.PreviousOperationID, RequestHash: v.RequestHash, Kind: ufwRegistrationKind, State: v.OperationState, Stage: v.State, CandidateHash: ufwRegistrationReceiptHash(v), Error: v.Error, UFWRegistration: &copy})
}

// A released tombstone is published only after the terminal local receipt.
// The releasing state fences a crash in between, without making future host
// reuse depend on retaining another installation's data directory.
func ufwReleasedClaim(v *ufwHostClaim) error {
	if v == nil {
		return nil
	}
	if !validUFWClaim(v) || v.State != "released" {
		return errors.New("宿主机已有 UFW 授权占用，须先由原数据目录释放")
	}
	return nil
}
func ufwPublishingClaim(v *ufwRegistrationCheckpoint) ufwHostClaim {
	out := v.NextClaim
	if v.Action == "remove" {
		out.State = "releasing"
	}
	return out
}
func forbidUFWRegistration() error {
	v, err := loadUFWHostClaim()
	if err != nil {
		return err
	}
	return ufwReleasedClaim(v)
}
func ufwRegistrationAuthority(dataDir string) (*ufwRegistrationCheckpoint, error) {
	v, err := loadUFWRegistration(dataDir)
	if err != nil {
		return nil, err
	}
	if v == nil || v.State != "registered" {
		return nil, errors.New("须先由本机 root 完成 UFW 初始授权登记")
	}
	if err = ufwRegistrationReceipt(dataDir, v); err != nil {
		return nil, err
	}
	machine, _, err := ufwHostIdentity()
	if err != nil || machine != v.NextClaim.MachineHash {
		return nil, errors.New("UFW 登记属于其他宿主机或当前身份无法核对")
	}
	claim, err := loadUFWHostClaim()
	if err != nil || ufwClaimHash(claim) != ufwClaimHash(&v.NextClaim) {
		return nil, errors.New("UFW 宿主机占用与原登记不一致")
	}
	return v, nil
}
func ufwRegistrationView(ctx context.Context, dataDir string, observed firewall.UFW) firewall.RegistrationView {
	out := firewall.RegistrationView{State: "unavailable", ObservedAt: time.Now().Unix()}
	v, err := loadUFWRegistration(dataDir)
	if err != nil {
		out.Reason = "UFW root 授权登记无法读取"
		return out
	}
	if v == nil {
		claim, err := loadUFWHostClaim()
		if err != nil {
			out.Reason = "UFW 宿主机占用记录无法读取"
			return out
		}
		out.State = "unregistered"
		if claim != nil && claim.State != "released" {
			out.Reason = "宿主机已有 UFW 授权占用或待完成释放，须由原数据目录核对"
		}
		return out
	}
	out.OperationID = v.NextClaim.OperationID
	if err = ufwRegistrationReceipt(dataDir, v); err != nil || v.State == "preparing" {
		out.State, out.Reason = "recovery_required", "UFW 原授权操作尚未核对完成，请本机执行 ufw-recover"
		return out
	}
	machine, _, err := ufwHostIdentity()
	if err != nil || machine != v.NextClaim.MachineHash {
		out.Reason = "UFW 登记的宿主机身份无法核对"
		return out
	}
	if v.State == "released" {
		claim, err := loadUFWHostClaim()
		if err != nil {
			out.Reason = "UFW 宿主机占用无法核对"
			return out
		}
		publishing := ufwPublishingClaim(v)
		if ufwClaimHash(claim) == ufwClaimHash(&publishing) {
			out.State, out.Reason = "recovery_required", "UFW 释放回执已保存，宿主机释放尚待原操作核对"
			return out
		}
		if claim != nil && claim.OperationID == v.NextClaim.OperationID && ufwClaimHash(claim) != ufwClaimHash(&v.NextClaim) {
			out.State, out.Reason = "drifted", "UFW 原释放占用记录发生变化"
			return out
		}
		out.State = "released"
		return out
	}
	if _, err = ufwRegistrationAuthority(dataDir); err != nil {
		out.State, out.Reason = "drifted", "UFW 宿主机占用与原授权登记不一致"
		return out
	}
	if !observed.Installed || observed.IPv6 == nil || !observed.RuleInventory.Available {
		out.Reason = "UFW 固定配置或完整用户规则报告不可用"
		return out
	}
	binary, err := ufwTool()
	if err != nil {
		out.Reason = "UFW 受信工具不可用"
		return out
	}
	snapshot, err := readUFWConfiguration(ctx, binary, *observed.IPv6)
	if err != nil {
		out.Reason = "UFW 固定配置无法完整读取"
		return out
	}
	if snapshot.HasManagedMarkers {
		out.State, out.Reason = "drifted", "存在本应用标记但尚无规则写入回执，禁止接管或删除"
		return out
	}
	out.State, out.Verified, out.Reason = "registered", true, "UFW 本机授权已核对；尚无已确认规则，未开放业务写入"
	return out
}

func ufwRegistrationPending(dataDir string) bool {
	v, err := loadUFWRegistration(dataDir)
	if err != nil || v != nil && (v.State == "preparing" || ufwRegistrationReceipt(dataDir, v) != nil) {
		return true
	}
	if v != nil && v.State == "released" {
		claim, err := loadUFWHostClaim()
		publishing := ufwPublishingClaim(v)
		return err != nil || ufwClaimHash(claim) == ufwClaimHash(&publishing)
	}
	return false
}

func validUFWRegistrationView(v firewall.RegistrationView) bool {
	if v.ObservedAt < 0 || v.OperationID != "" && !validID(v.OperationID) {
		return false
	}
	switch v.State {
	case "unavailable", "unregistered", "registered", "released", "drifted", "recovery_required":
	default:
		return false
	}
	return !v.Verified || v.State == "registered" && validID(v.OperationID) && v.ObservedAt > 0
}
