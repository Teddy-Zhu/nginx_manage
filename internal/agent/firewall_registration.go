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

const nftRegistrationKind = "firewall_registration"

// This record is root-owned, separate from the business DB, backups and
// logical migrations. The random owner is created before the exclusive write;
// an existing table or a marker on its own never grants ownership.
type nftRegistrationCheckpoint struct {
	Schema              int                 `json:"schema"`
	Owner               string              `json:"owner"`
	OperationID         string              `json:"operation_id"`
	PreviousOperationID string              `json:"previous_operation_id"`
	Action              string              `json:"action"`
	State               string              `json:"state"`
	OperationState      string              `json:"operation_state"`
	TransactionHash     string              `json:"transaction_hash"`
	Baseline            firewall.KernelView `json:"baseline"`
	Confirmed           firewall.KernelView `json:"confirmed"`
	UpdatedAt           int64               `json:"updated_at"`
	Error               string              `json:"error"`
}

type FirewallRegistrationStatus struct {
	Registration firewall.RegistrationView `json:"registration"`
	Kernel       firewall.KernelView       `json:"kernel"`
}

func nftRegistrationPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "registration.json")
}

func loadNFTRegistration(dataDir string) (*nftRegistrationCheckpoint, error) {
	raw, err := listenerRead(nftRegistrationPath(dataDir), 16<<10)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value nftRegistrationCheckpoint
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&value); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("防火墙独立登记包含多余内容")
	}
	validKernel := func(k firewall.KernelView) bool {
		return k.Available && k.Generation != 0 && len(k.NamespaceID) == 64 && len(k.Fingerprint) == 64 && k.Chains == 0 && k.Rules == 0 && k.ObservedAt > 0 && k.Bytes > 0 && k.Bytes <= nftReadBytes && k.Reason == ""
	}
	if value.Schema != 1 || !validID(value.Owner) || !validID(value.OperationID) || len(value.TransactionHash) != 64 || value.UpdatedAt <= 0 || !validKernel(value.Baseline) || (value.Action != "init" && value.Action != "remove" && value.Action != "detach") || value.Action == "init" && value.Baseline.TableExists || value.Action == "remove" && !value.Baseline.TableExists {
		return nil, errors.New("防火墙独立登记无效")
	}
	if value.Action == "detach" {
		if value.State != "released" || !validID(value.PreviousOperationID) || value.Baseline.TableExists || value.TransactionHash != nftDetachHash(&value) {
			return nil, errors.New("防火墙释放登记无效")
		}
	} else {
		batch, err := prepareNFTRegistration(value.Baseline, value.Owner, value.Action == "remove")
		if err != nil || batch.hash != value.TransactionHash || value.PreviousOperationID != "" {
			return nil, errors.New("防火墙登记事务摘要不匹配")
		}
		if value.Action == "remove" && (!validKernel(value.Confirmed) || !value.Confirmed.TableExists || value.Baseline.NamespaceID != value.Confirmed.NamespaceID || value.Baseline.Fingerprint != value.Confirmed.Fingerprint) {
			return nil, errors.New("防火墙移除基线与确认登记不匹配")
		}
	}
	switch value.State {
	case "creating":
		if value.Action != "init" || value.OperationState != "running" && value.OperationState != "recovery_required" {
			return nil, errors.New("防火墙新建意图状态无效")
		}
	case "removing":
		if value.Action != "remove" || value.OperationState != "running" && value.OperationState != "recovery_required" {
			return nil, errors.New("防火墙移除意图状态无效")
		}
	case "registered":
		if !validKernel(value.Confirmed) || !value.Confirmed.TableExists || value.Confirmed.NamespaceID != value.Baseline.NamespaceID || value.OperationState != "succeeded" && value.OperationState != "failed" {
			return nil, errors.New("防火墙已确认登记无效")
		}
	case "released":
		if value.OperationState != "succeeded" && value.OperationState != "failed" {
			return nil, errors.New("防火墙已释放登记无效")
		}
	default:
		return nil, errors.New("未知防火墙登记状态")
	}
	return &value, nil
}

func saveNFTRegistration(dataDir string, value *nftRegistrationCheckpoint) error {
	value.UpdatedAt = time.Now().Unix()
	if err := listenerWrite(nftRegistrationPath(dataDir), value); err != nil {
		return err
	}
	journal := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	if err := secure.RootDirectory(journal.Dir, 0700); err != nil {
		return err
	}
	return journal.Put(Record{RelatedOperationID: value.PreviousOperationID, OperationID: value.OperationID, RequestHash: value.TransactionHash, Kind: nftRegistrationKind, State: value.OperationState, Stage: value.State, CandidateHash: value.Confirmed.Fingerprint, Error: value.Error})
}

func nftRegistrationView(dataDir string, kernel firewall.KernelView) firewall.RegistrationView {
	out := firewall.RegistrationView{State: "unavailable", ObservedAt: kernel.ObservedAt}
	value, err := loadNFTRegistration(dataDir)
	if err != nil {
		out.Reason = "root 独立登记无法读取，须本机检查"
		return out
	}
	if value == nil {
		out.State = "unregistered"
		if kernel.Available && kernel.TableExists {
			out.Reason = "存在未登记同名表，禁止接管"
		}
		return out
	}
	runtime, runtimeErr := loadFirewallState(dataDir)
	if runtimeErr != nil {
		out.State = "recovery_required"
		out.Reason = "root 运行恢复记录无法读取"
		return out
	}
	if runtime != nil {
		if runtime.Owner != value.Owner || value.State != "registered" {
			out.State = "drifted"
			out.Reason = "独立登记与运行所有者不一致"
			return out
		}
		out.OperationID = value.OperationID
		if runtime.Operation != nil {
			out.OperationID = runtime.Operation.ID
		}
		if runtime.Candidate != nil || runtime.RestoreIntent != nil {
			out.State = "recovery_required"
			out.Reason = "存在待确认或待恢复的防火墙运行操作"
			return out
		}
		if !kernel.Available {
			out.State = "unavailable"
			out.Reason = "内核快照不可用"
			return out
		}
		if !kernel.TableExists {
			out.State = "missing"
			out.Reason = "受管表缺失，等待独立执行器核对恢复"
			return out
		}
		if kernel.NamespaceID != runtime.CurrentKernel.NamespaceID || kernel.Fingerprint != runtime.CurrentKernel.Fingerprint {
			out.State = "drifted"
			out.Reason = "内核对象与独立运行回执不一致"
			return out
		}
		if op := runtime.Operation; op != nil {
			record, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(op.ID)
			expected, _ := json.Marshal(op)
			actual, _ := json.Marshal(record.Firewall)
			if err != nil || record.Kind != firewallOperationKind || record.RequestHash != runtime.RequestHash || record.State != op.State || !bytes.Equal(expected, actual) {
				out.State = "recovery_required"
				out.Reason = "独立运行回执与操作日志不一致"
				return out
			}
		}
		out.State = "registered"
		if runtime.Confirmed != nil && runtime.Confirmed.Action == "apply" {
			out.State = "managed"
		}
		out.Verified = true
		return out
	}
	out.OperationID = value.OperationID
	out.State, out.Reason = value.State, value.Error
	if value.State == "creating" || value.State == "removing" {
		out.State = "recovery_required"
		out.Reason = "独立登记操作未核对完成，须本机恢复原操作"
		return out
	}
	if value.State == "released" {
		if kernel.Available && kernel.TableExists {
			out.State, out.Reason = "drifted", "登记已释放但存在同名表，禁止接管"
		}
		return out
	}
	if !kernel.Available {
		out.State = "unavailable"
		out.Reason = "内核快照不可用，无法核对登记"
		return out
	}
	if !kernel.TableExists {
		out.State = "missing"
		out.Reason = "已登记表不存在，须本机核对；不会自动重建"
		return out
	}
	if kernel.NamespaceID != value.Confirmed.NamespaceID || kernel.Fingerprint != value.Confirmed.Fingerprint {
		out.State = "drifted"
		out.Reason = "网络命名空间或已登记对象发生变化，禁止覆盖"
		return out
	}
	journal, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(value.OperationID)
	if err != nil || journal.Kind != nftRegistrationKind || journal.RequestHash != value.TransactionHash || journal.State != value.OperationState || journal.Stage != value.State || journal.CandidateHash != value.Confirmed.Fingerprint || journal.RelatedOperationID != value.PreviousOperationID {
		out.State = "recovery_required"
		out.Reason = "独立登记与操作回执不一致，须本机恢复原操作"
		return out
	}
	out.Verified = true
	return out
}

// ManageFirewallRegistration is a local root entry point, never registered on
// IPC/HTTP. Host-scope opt-in is separate from the metrics read authorization.
// Commands only initialize, inspect, reconcile or remove an empty owned table.
func ManageFirewallRegistration(ctx context.Context, dataDir, scope, action string) (FirewallRegistrationStatus, error) {
	var out FirewallRegistrationStatus
	if action != "init" && action != "status" && action != "recover" && action != "remove" {
		return out, errors.New("未知防火墙登记操作")
	}
	if os.Geteuid() != 0 || scope != "host" {
		return out, errors.New("防火墙登记须本机 root 明确指定 --firewall-scope=host")
	}
	if reason := (&HostDNS{Scope: scope}).hostScopeReason(); reason != "" {
		return out, errors.New("容器或未确认的宿主机范围不允许防火墙登记")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("防火墙登记数据目录须为规范绝对路径")
	}
	if action == "status" {
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		kernel, err := snapshotNFTKernel(call)
		if err != nil {
			return out, err
		}
		return FirewallRegistrationStatus{Kernel: kernel, Registration: nftRegistrationView(dataDir, kernel)}, nil
	}
	// The fixed host lock serializes registrations even across different data
	// directories. The marker and independent intent prevent cross-node adoption.
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if action != "recover" {
		if err = forbidUFWRegistration(); err != nil {
			return out, err
		}
	}
	if err := forbidFirewalldRegistration(dataDir); err != nil {
		return out, err
	}
	dir := filepath.Dir(nftRegistrationPath(dataDir))
	if err = secure.RootDirectory(dir, 0700); err != nil {
		return out, err
	}
	runtime, err := loadFirewallState(dataDir)
	if err != nil {
		return out, err
	}
	if runtime != nil {
		return out, errors.New("登记已交给独立运行执行器；请使用运行状态与原策略回滚入口")
	}
	value, err := loadNFTRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if action == "recover" {
		return recoverNFTRegistration(dataDir, value)
	}
	// Admission shares the root maintenance lock: an updater/importer cannot
	// acquire maintenance between this check and the durable result record.
	journal := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	maintenanceUnlock, err := journal.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer maintenanceUnlock()
	records, err := journal.List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" {
			return out, errors.New("独立维护正在进行，禁止新建或移除防火墙登记")
		}
	}
	if value != nil && (value.State == "creating" || value.State == "removing") {
		return out, errors.New("存在未完成登记意图，请先执行 firewall-recover 核对")
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	var kernel firewall.KernelView
	if value != nil && value.State == "registered" {
		kernel, err = snapshotNFTRegistration(call, value.Owner)
	} else {
		kernel, err = snapshotNFTKernel(call)
	}
	cancel()
	if err != nil {
		return out, err
	}
	if action == "init" {
		if value != nil && value.State == "registered" {
			out = FirewallRegistrationStatus{Kernel: kernel, Registration: nftRegistrationView(dataDir, kernel)}
			if !out.Registration.Verified {
				return out, errors.New(out.Registration.Reason)
			}
			return out, nil
		}
		if kernel.TableExists {
			return out, errors.New("同名目标表已存在，禁止接管")
		}
		value = &nftRegistrationCheckpoint{Schema: 1, Owner: secure.ID(), OperationID: secure.ID(), Action: "init", State: "creating", OperationState: "running", Baseline: kernel}
	} else {
		if value == nil || value.State != "registered" {
			return out, errors.New("不存在已确认的空表登记")
		}
		if !kernel.TableExists || kernel.NamespaceID != value.Confirmed.NamespaceID || kernel.Fingerprint != value.Confirmed.Fingerprint {
			return out, errors.New("登记对象缺失或变化，禁止删除")
		}
		value.OperationID, value.Action, value.State, value.OperationState = secure.ID(), "remove", "removing", "running"
		value.Baseline, value.Error = kernel, ""
	}
	batch, err := prepareNFTRegistration(value.Baseline, value.Owner, action == "remove")
	if err != nil {
		return out, err
	}
	value.TransactionHash = batch.hash
	// Both the durable recovery direction and root journal precede any write.
	if err = saveNFTRegistration(dataDir, value); err != nil {
		return out, err
	}
	call, cancel = context.WithTimeout(ctx, 3*time.Second)
	// Namespace is rechecked immediately before submit. A concurrent ruleset
	// change is rejected by NFNL_BATCH_GENID inside the kernel commit lock.
	namespace, err := nftNamespace()
	if err == nil && namespace != value.Baseline.NamespaceID {
		err = errors.New("提交前网络命名空间变化")
	}
	if err == nil {
		err = submitNFTRegistration(call, batch)
	}
	cancel()
	// Complete the result check independently of CLI cancellation. A missing
	// ACK is never retried or presented as success; root recovery reconciles it.
	post, postErr := registrationSnapshotDetached(value.Owner)
	wantGeneration := value.Baseline.Generation + 1
	if wantGeneration == 0 {
		wantGeneration = 1
	}
	if err == nil && postErr == nil && post.NamespaceID == value.Baseline.NamespaceID && post.Generation == wantGeneration && post.TableExists == (action == "init") {
		if action == "init" {
			value.State, value.Confirmed = "registered", post
		} else {
			value.State = "released"
		}
		value.OperationState, value.Error = "succeeded", ""
		if err = saveNFTRegistration(dataDir, value); err != nil {
			return out, err
		}
		return FirewallRegistrationStatus{Kernel: post, Registration: nftRegistrationView(dataDir, post)}, nil
	}
	value.OperationState, value.Error = "recovery_required", "事务结果未能完整证明，保留原登记意图，须本机执行 firewall-recover"
	if saveErr := saveNFTRegistration(dataDir, value); saveErr != nil {
		return out, saveErr
	}
	return FirewallRegistrationStatus{Kernel: post, Registration: nftRegistrationView(dataDir, post)}, errors.Join(errors.New(value.Error), err, postErr)
}

func registrationSnapshotDetached(owner string) (firewall.KernelView, error) {
	call, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return snapshotNFTRegistration(call, owner)
}

// Recovery only observes and updates the original root record. It never sends
// a new transaction, adopts an existing unrelated table or restores a snapshot.
func recoverNFTRegistration(dataDir string, value *nftRegistrationCheckpoint) (FirewallRegistrationStatus, error) {
	var out FirewallRegistrationStatus
	if value == nil {
		return out, errors.New("不存在可恢复的防火墙登记")
	}
	kernel, err := registrationSnapshotDetached(value.Owner)
	if err != nil {
		return out, err
	}
	out.Kernel = kernel
	if value.State == "released" {
		if kernel.TableExists {
			return out, errors.New("已释放登记但存在同名表，禁止接管")
		}
		if err = saveNFTRegistration(dataDir, value); err != nil {
			return out, err
		}
		out.Registration = nftRegistrationView(dataDir, kernel)
		return out, nil
	}
	if kernel.NamespaceID != value.Baseline.NamespaceID {
		if kernel.TableExists {
			return out, errors.New("命名空间已变化且存在目标表，禁止接管")
		}
		// A local operator may detach an obsolete boot/namespace registration.
		// This is not proof of deletion elsewhere; completed journals are retained.
		if value.State == "registered" {
			value = detachNFTRegistration(value, kernel, "本机已释放旧命名空间登记，未修改旧命名空间对象")
		} else {
			value.State, value.OperationState, value.Error = "released", "failed", "本机已释放旧命名空间登记，未修改旧命名空间对象"
		}
	} else {
		switch value.State {
		case "creating":
			if kernel.TableExists {
				value.State, value.Confirmed, value.OperationState, value.Error = "registered", kernel, "succeeded", ""
			} else {
				value.State, value.OperationState, value.Error = "released", "failed", "未观察到原新建事务的目标表，未重试提交"
			}
		case "removing":
			if !kernel.TableExists {
				value.State, value.OperationState, value.Error = "released", "succeeded", ""
			} else {
				if kernel.Fingerprint != value.Confirmed.Fingerprint {
					return out, errors.New("移除结果不明且登记对象已变化，禁止覆盖")
				}
				value.State, value.OperationState, value.Error = "registered", "failed", "原登记表仍存在，移除未完成，未重试提交"
			}
		case "registered":
			if !kernel.TableExists {
				value = detachNFTRegistration(value, kernel, "已登记表缺失，释放登记但不自动重建")
			} else if kernel.Fingerprint != value.Confirmed.Fingerprint {
				return out, errors.New("登记对象已变化，禁止更新所有权证明")
			}
		}
	}
	if err = saveNFTRegistration(dataDir, value); err != nil {
		return out, err
	}
	out.Registration = nftRegistrationView(dataDir, kernel)
	return out, nil
}

func nftDetachHash(value *nftRegistrationCheckpoint) string {
	return secure.Hash([]byte("nginxpanel:nft-detach:v1:" + value.Owner + ":" + value.PreviousOperationID + ":" + value.Baseline.NamespaceID + ":" + value.Baseline.Fingerprint))
}

func detachNFTRegistration(previous *nftRegistrationCheckpoint, kernel firewall.KernelView, reason string) *nftRegistrationCheckpoint {
	value := &nftRegistrationCheckpoint{Schema: 1, Owner: previous.Owner, PreviousOperationID: previous.OperationID, OperationID: secure.ID(), Action: "detach", State: "released", OperationState: "succeeded", Baseline: kernel, Confirmed: previous.Confirmed, Error: reason}
	value.TransactionHash = nftDetachHash(value)
	return value
}
