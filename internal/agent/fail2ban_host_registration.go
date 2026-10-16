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

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const fail2banHostRegistrationKind = "fail2ban_host_registration"

// Ownership belongs to this host and root journal, never to an imported jail
// policy. The empty table has no hook and cannot enforce any bans.
type fail2banHostRegistration struct {
	Schema          int                 `json:"schema"`
	Owner           string              `json:"owner"`
	OperationID     string              `json:"operation_id"`
	BaseOperationID string              `json:"base_operation_id"`
	Action          string              `json:"action"`
	State           string              `json:"state"`
	OperationState  string              `json:"operation_state"`
	RequestHash     string              `json:"request_hash"`
	TransactionHash string              `json:"transaction_hash"`
	RetirementID    string              `json:"retirement_id"`
	Baseline        firewall.KernelView `json:"baseline"`
	Confirmed       firewall.KernelView `json:"confirmed"`
	UpdatedAt       int64               `json:"updated_at"`
	Error           string              `json:"error"`
}

func fail2banHostRegistrationPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "fail2ban", "host-input-registration.json")
}

func fail2banHostRegistrationRequest(action, operationID, base string) string {
	return secure.Hash([]byte("nginxpanel:fail2ban-host-registration:v1:" + action + ":" + operationID + ":" + base))
}

func fail2banHostDetachHash(v *fail2banHostRegistration) string {
	return secure.Hash([]byte("nginxpanel:fail2ban-host-detach:v1:" + v.Owner + ":" + v.BaseOperationID + ":" + v.Baseline.NamespaceID + ":" + v.Baseline.Fingerprint))
}

func loadFail2banHostRegistration(dataDir string) (*fail2banHostRegistration, error) {
	raw, err := listenerRead(fail2banHostRegistrationPath(dataDir), 16<<10)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeFail2banHostRegistration(dataDir, raw)
}

func decodeFail2banHostRegistration(dataDir string, raw []byte) (*fail2banHostRegistration, error) {
	var v fail2banHostRegistration
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	validKernel := func(k firewall.KernelView) bool {
		return k.Available && k.Generation != 0 && len(k.NamespaceID) == 64 && len(k.Fingerprint) == 64 && k.ObservedAt > 0 && k.Bytes > 0 && k.Bytes <= nftReadBytes && k.Chains == 0 && k.Rules == 0 && k.Reason == ""
	}
	if d.Decode(new(any)) != io.EOF || v.Schema != 1 || !validID(v.Owner) || !validID(v.OperationID) || v.BaseOperationID != "" && !validID(v.BaseOperationID) || v.BaseOperationID == v.OperationID || v.UpdatedAt <= 0 || len(v.Error) > 1024 || (v.OperationState == "failed" || v.OperationState == "recovery_required") && v.Error == "" || !validKernel(v.Baseline) || v.RequestHash != fail2banHostRegistrationRequest(v.Action, v.OperationID, v.BaseOperationID) {
		return nil, errors.New("宿主机动作独立登记无效")
	}
	switch v.Action {
	case "init", "remove":
		if v.RetirementID != "" {
			return nil, errors.New("普通登记不接受退役材料")
		}
		batch, e := prepareNFTTargetRegistration(firewall.NFTFail2banInput, v.Baseline, v.Owner, v.Action == "remove")
		if e != nil || batch.hash != v.TransactionHash {
			return nil, errors.New("宿主机动作登记事务不匹配")
		}
		if v.Action == "remove" && (v.BaseOperationID == "" || !validKernel(v.Confirmed) || !v.Confirmed.TableExists || v.Confirmed.NamespaceID != v.Baseline.NamespaceID || v.Confirmed.Fingerprint != v.Baseline.Fingerprint) {
			return nil, errors.New("宿主机动作移除缺少原所有权证明")
		}
		if v.Action == "init" && v.State != "registered" && v.Confirmed != (firewall.KernelView{}) {
			return nil, errors.New("未确认的新建意图包含所有权回执")
		}
	case "detach":
		if v.RetirementID != "" || v.BaseOperationID == "" || v.State != "released" || v.OperationState != "succeeded" || v.Baseline.TableExists || v.TransactionHash != fail2banHostDetachHash(&v) || !validKernel(v.Confirmed) || !v.Confirmed.TableExists {
			return nil, errors.New("宿主机动作释放登记无效")
		}
	case "retire":
		r, e := loadFail2banHostRetirementEvent(dataDir, v.RetirementID)
		if e != nil {
			return nil, e
		}
		actual := v
		actual.UpdatedAt = 0
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(r.released())
		if !bytes.Equal(a, b) {
			return nil, errors.New("退役登记与原冻结材料不一致")
		}
	default:
		return nil, errors.New("未知宿主机动作登记类型")
	}
	switch v.State {
	case "creating", "removing":
		if v.State == "creating" && v.Action != "init" || v.State == "removing" && v.Action != "remove" || v.OperationState != "running" && v.OperationState != "recovery_required" {
			return nil, errors.New("宿主机动作登记意图状态无效")
		}
	case "registered":
		if !validKernel(v.Confirmed) || !v.Confirmed.TableExists || v.Confirmed.NamespaceID != v.Baseline.NamespaceID || v.Action == "init" && v.OperationState != "succeeded" || v.Action == "remove" && v.OperationState != "failed" || v.Action != "init" && v.Action != "remove" {
			return nil, errors.New("宿主机动作已确认登记无效")
		}
	case "released":
		if v.OperationState != "succeeded" && v.OperationState != "failed" || v.Action == "init" && v.OperationState != "failed" {
			return nil, errors.New("宿主机动作已释放登记无效")
		}
	default:
		return nil, errors.New("未知宿主机动作登记状态")
	}
	return &v, nil
}

func saveFail2banHostRegistration(dataDir string, v *fail2banHostRegistration) error {
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	if err := secure.RootDirectory(j.Dir, 0700); err != nil {
		return err
	}
	previous, err := j.Get(v.OperationID)
	if err == nil && (previous.Kind != fail2banHostRegistrationKind || previous.RequestHash != v.RequestHash || previous.RelatedOperationID != v.BaseOperationID) {
		return errors.New("宿主机动作操作标识已被其他请求使用")
	}
	if err == nil && (previous.State == "succeeded" || previous.State == "failed") && (previous.State != v.OperationState || previous.Stage != v.State || previous.CandidateHash != v.TransactionHash || previous.ObservedRevision != v.Confirmed.Fingerprint || previous.Error != v.Error) {
		return errors.New("已终结登记回执与当前记录冲突，禁止改写原审计，须本机检查")
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	v.UpdatedAt = time.Now().Unix()
	if err = rootJSONWrite(fail2banHostRegistrationPath(dataDir), v, 16<<10); err != nil {
		return err
	}
	return j.Put(Record{Kind: fail2banHostRegistrationKind, OperationID: v.OperationID, RelatedOperationID: v.BaseOperationID, RequestHash: v.RequestHash, State: v.OperationState, Stage: v.State, CandidateHash: v.TransactionHash, ObservedRevision: v.Confirmed.Fingerprint, Error: v.Error})
}

func fail2banHostRegistrationReceipt(dataDir string, v *fail2banHostRegistration) bool {
	r, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(v.OperationID)
	return err == nil && r.Kind == fail2banHostRegistrationKind && r.OperationID == v.OperationID && r.RelatedOperationID == v.BaseOperationID && r.RequestHash == v.RequestHash && r.State == v.OperationState && r.Stage == v.State && r.CandidateHash == v.TransactionHash && r.ObservedRevision == v.Confirmed.Fingerprint && r.Error == v.Error
}

func fail2banHostRegistrationView(dataDir string, kernel firewall.KernelView) firewall.RegistrationView {
	v, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return firewall.RegistrationView{State: "unavailable", ObservedAt: kernel.ObservedAt, Reason: "宿主机动作 root 登记无法读取，须本机检查"}
	}
	return fail2banHostRegistrationViewRecord(dataDir, kernel, v)
}

func fail2banHostRegistrationViewRecord(dataDir string, kernel firewall.KernelView, v *fail2banHostRegistration) firewall.RegistrationView {
	out := firewall.RegistrationView{State: "unavailable", ObservedAt: kernel.ObservedAt}
	if v == nil {
		out.State = "unregistered"
		if kernel.Available && kernel.TableExists {
			out.Reason = "存在未登记的宿主机动作同名表，禁止接管"
		}
		return out
	}
	out.OperationID, out.State, out.Reason = v.OperationID, v.State, v.Error
	if v.State == "creating" || v.State == "removing" || !fail2banHostRegistrationReceipt(dataDir, v) {
		out.State, out.Reason = "recovery_required", "独立登记意图或回执未核对完成，须本机恢复原操作"
		return out
	}
	if !kernel.Available {
		out.State, out.Reason = "unavailable", "内核快照不可用，无法核对宿主机动作登记"
		return out
	}
	if v.State == "released" {
		if kernel.TableExists {
			out.State, out.Reason = "drifted", "登记已释放但存在同名表，禁止接管"
		}
		return out
	}
	if !kernel.TableExists {
		out.State, out.Reason = "missing", "宿主机动作登记表缺失，不会自动重建"
		return out
	}
	expected, err := fail2banHostOwnedKernel(dataDir, v)
	if err != nil {
		out.State, out.Reason = "recovery_required", "独立宿主机运行意图或回执待核对，须先恢复运行操作"
		return out
	}
	if kernel.NamespaceID != expected.NamespaceID || kernel.Fingerprint != expected.Fingerprint {
		out.State, out.Reason = "drifted", "宿主机动作登记的命名空间或对象已变化，禁止覆盖"
		return out
	}
	out.Verified = true
	return out
}

func snapshotFail2banHostRegistration(ctx context.Context, owner string) (firewall.KernelView, error) {
	marker, err := nftTargetRegistrationMarker(firewall.NFTFail2banInput, owner)
	if err != nil {
		return firewall.KernelView{}, err
	}
	return snapshotNFTTargetProgram(ctx, firewall.NFTFail2banInput, nil, marker)
}

func fail2banHostRegistrationSnapshotDetached(owner string) (firewall.KernelView, error) {
	call, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return snapshotFail2banHostRegistration(call, owner)
}
