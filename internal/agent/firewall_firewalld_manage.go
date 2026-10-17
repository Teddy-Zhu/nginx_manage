package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/godbus/dbus/v5"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type FirewalldRegistrationStatus struct {
	Registration    firewall.RegistrationView         `json:"registration"`
	PolicyInventory firewall.FirewalldPolicyInventory `json:"policy_inventory"`
}

func firewalldRegistrationStatus(dataDir string, s firewalldRegistrationSnapshot) FirewalldRegistrationStatus {
	return FirewalldRegistrationStatus{Registration: firewalldRegistrationView(dataDir, s.Inventory), PolicyInventory: s.Inventory}
}

// These commands only prepare or retire an empty policy. They deliberately
// never reload firewalld or apply business rules through the registration path.
func ManageFirewalldRegistration(ctx context.Context, dataDir, scope, action string) (FirewalldRegistrationStatus, error) {
	var out FirewalldRegistrationStatus
	if !slices.Contains([]string{"init", "status", "recover", "remove"}, action) {
		return out, errors.New("未知 firewalld 登记操作")
	}
	if os.Geteuid() != 0 || scope != "host" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("firewalld 登记须本机 root、规范绝对数据目录及 --firewall-scope=host")
	}
	machine, boot, err := firewalldHostIdentity()
	if err != nil {
		return out, err
	}
	if action == "status" {
		observed := readFirewalld(ctx)
		return FirewalldRegistrationStatus{Registration: firewalldRegistrationView(dataDir, observed.PolicyInventory), PolicyInventory: observed.PolicyInventory}, nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = secure.RootDirectory(filepath.Dir(firewalldRegistrationPath(dataDir)), 0700); err != nil {
		return out, err
	}
	j := firewalldRegistrationJournal(dataDir)
	maintenanceUnlock, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer maintenanceUnlock()
	v, err := loadFirewalldRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if v != nil && v.MachineHash != machine {
		return out, errors.New("firewalld root 登记属于其他宿主机，禁止迁移或接管")
	}
	if action == "recover" {
		if v == nil {
			return out, errors.New("没有可恢复的 firewalld 登记意图")
		}
		// A crash between checkpoint rename and receipt publication can be
		// repaired from the original trusted intent; no D-Bus write is replayed.
		if err = firewalldRegistrationReceipt(dataDir, v); err != nil {
			if err = saveFirewalldRegistration(dataDir, v); err != nil {
				return out, err
			}
		}
		return reconcileFirewalldRegistration(ctx, dataDir, v)
	}
	if v != nil {
		if err = firewalldRegistrationReceipt(dataDir, v); err != nil {
			return out, errors.New("firewalld 独立回执未完成，请先执行 firewalld-recover")
		}
		if v.State != "registered" && v.State != "released" {
			return out, errors.New("firewalld 存在未完成登记意图，请先执行 firewalld-recover")
		}
	}
	records, err := j.List()
	if err != nil {
		return out, err
	}
	for _, r := range records {
		if r.Kind == "maintenance.lock" && r.State != "succeeded" {
			return out, errors.New("独立维护正在进行，禁止 firewalld 新建或移除登记")
		}
	}
	if err = firewalldRegistrationAdmission(ctx, dataDir, scope); err != nil {
		return out, err
	}
	b, err := openFirewalldBus(ctx)
	if err != nil {
		return out, err
	}
	defer func() {
		if b != nil {
			b.close()
		}
	}()
	snapshot, err := b.registrationSnapshot()
	if err != nil {
		return out, err
	}
	if action == "init" && v != nil && v.State == "registered" {
		out = firewalldRegistrationStatus(dataDir, snapshot)
		if !out.Registration.Verified {
			return out, errors.New(out.Registration.Reason)
		}
		return out, nil
	}
	if action == "remove" && v != nil && v.State == "released" {
		out = firewalldRegistrationStatus(dataDir, snapshot)
		if out.Registration.State != "released" {
			return out, errors.New(out.Registration.Reason)
		}
		return out, nil
	}
	if b.process.Boot != boot {
		return out, errors.New("firewalld 进程与宿主机启动身份不一致")
	}
	next := &firewalldRegistrationCheckpoint{Schema: 1, Owner: secure.ID(), OperationID: secure.ID(), MachineHash: machine, BootID: boot, BusID: b.busID, BusOwner: b.owner, Peer: b.process, Action: action, State: "creating", OperationState: "running"}
	if v != nil {
		next.PreviousOperationID = v.OperationID
	}
	if action == "init" {
		if snapshot.Policy.Runtime != nil || snapshot.Policy.Permanent != nil {
			return out, errors.New("存在同名 runtime 或 permanent policy，禁止接管")
		}
	} else {
		if v == nil || v.State != "registered" || !firewalldRegistrationView(dataDir, snapshot.Inventory).Verified || !firewalldEmptyMatches(snapshot.Runtime, v.Owner) || !firewalldEmptyMatches(snapshot.Permanent, v.Owner) {
			return out, errors.New("只能移除原 root 登记且完整核对一致的空 policy")
		}
		next.Owner, next.State, next.BaselineHash, next.SettingsHash = v.Owner, "removing", v.SettingsHash, v.SettingsHash
	}
	next.RequestHash = firewalldRegistrationHash(next)
	if err = saveFirewalldRegistration(dataDir, next); err != nil {
		return out, err
	}
	// Pin identity and read the fixed object again immediately before the
	// single official mutation. firewalld offers no compare-and-swap method.
	current, err := b.registrationSnapshot()
	if err == nil {
		if action == "init" && (current.Policy.Runtime != nil || current.Policy.Permanent != nil) {
			err = errors.New("登记前同名 policy 已出现")
		}
		if action == "remove" && (!firewalldEmptyMatches(current.Runtime, next.Owner) || !firewalldEmptyMatches(current.Permanent, next.Owner) || current.Policy.Runtime.Hash != next.BaselineHash || current.Policy.Permanent.Hash != next.BaselineHash) {
			err = errors.New("移除前 policy 已变化")
		}
	}
	if err != nil {
		settleFirewalldUnsubmitted(next)
		saveErr := saveFirewalldRegistration(dataDir, next)
		return firewalldRegistrationStatus(dataDir, current), errors.Join(err, saveErr)
	}
	next.Submitted = true
	if err = saveFirewalldRegistration(dataDir, next); err != nil {
		return out, err
	}
	if err = b.unchangedOwner(); err != nil {
		next.Submitted = false
		settleFirewalldUnsubmitted(next)
		saveErr := saveFirewalldRegistration(dataDir, next)
		return firewalldRegistrationStatus(dataDir, current), errors.Join(err, saveErr)
	}
	if action == "init" {
		var path dbus.ObjectPath
		err = b.call(dbus.ObjectPath(string(firewalldRoot)+"/config"), firewalldName+".config.addPolicy", firewall.FirewalldHostPolicy, firewalldEmptySettings(next.Owner)).Store(&path)
		if err == nil && (!path.IsValid() || len(path) == 0) {
			err = errors.New("firewalld 新建回执路径无效")
		}
	} else {
		err = b.call(current.Path, firewalldName+".config.policy.remove").Err
	}
	if err == nil {
		next.Acknowledged, next.Resolved = true, true
	} else if reply := firewalldCompletedError(err); reply != "" {
		next.Acknowledged, next.Resolved, next.ReplyError = true, true, reply
	}
	if err != nil {
		next.OperationState, next.Error = "recovery_required", "firewalld 原操作未取得完整回执，请执行 firewalld-recover；禁止重放写入"
	}
	// Persist ACK before any detached observation; an uncertain save leaves
	// the durable pre-write intent available for conservative recovery.
	if saveErr := saveFirewalldRegistration(dataDir, next); saveErr != nil {
		return out, errors.Join(err, saveErr)
	}
	b.close()
	b = nil
	// Do not abandon receipt reconciliation when the caller disconnects.
	post, postErr := reconcileFirewalldRegistration(context.Background(), dataDir, next)
	return post, errors.Join(err, postErr)
}

func firewalldRegistrationAdmission(ctx context.Context, dataDir, scope string) error {
	_, err := inspectFirewalldRegistration(ctx, dataDir, scope)
	return err
}

func inspectFirewalldRegistration(ctx context.Context, dataDir, scope string) (firewall.Observation, error) {
	var observed firewall.Observation
	runtime, err := loadFirewallState(dataDir)
	if err != nil {
		return observed, err
	}
	if runtime != nil {
		return observed, errors.New("直接 nftables 独立执行器已有恢复材料，禁止 firewalld 登记")
	}
	nft, err := loadNFTRegistration(dataDir)
	if err != nil {
		return observed, err
	}
	if nft != nil && nft.State != "released" {
		return observed, errors.New("存在直接 nftables 登记或待恢复意图，禁止切换所有者")
	}
	call, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	observed = (&firewallObserver{scope: scope, dataDir: dataDir}).collect(call)
	if !observed.Available || observed.Manager != "firewalld" || observed.Backend == "mixed" || observed.Firewalld.Running == nil || !*observed.Firewalld.Running || observed.Firewalld.Panic == nil || *observed.Firewalld.Panic || observed.Firewalld.ConfiguredBackend == "" || !observed.Firewalld.PolicyInventory.Available || !observed.Kernel.Available || observed.Kernel.TableExists || len(observed.Rulesets) != 5 {
		return observed, errors.New("须先完整确认单一 firewalld 管理器、非 panic 状态及无直接 nftables 目标表")
	}
	for _, set := range observed.Rulesets {
		if !set.Available {
			return observed, errors.New("部分内核后端视图不完整，禁止 firewalld 登记变更")
		}
	}
	return observed, nil
}

func reconcileFirewalldRegistration(ctx context.Context, dataDir string, v *firewalldRegistrationCheckpoint) (FirewalldRegistrationStatus, error) {
	var out FirewalldRegistrationStatus
	if !v.Submitted && v.State != "registered" && v.State != "released" {
		settleFirewalldUnsubmitted(v)
		if err := saveFirewalldRegistration(dataDir, v); err != nil {
			return out, err
		}
	}
	b, err := openFirewalldBus(ctx)
	if err != nil {
		return out, err
	}
	defer b.close()
	s, err := b.registrationSnapshot()
	if err != nil {
		return out, err
	}
	if v.State == "registered" || v.State == "released" {
		out = firewalldRegistrationStatus(dataDir, s)
		if v.State == "registered" && !out.Registration.Verified || v.State == "released" && out.Registration.State != "released" {
			return out, errors.New(out.Registration.Reason)
		}
		return out, nil
	}
	// Changing a bus name alone does not terminate an in-flight handler.
	// Reuse the bounded host boot/PID/start-time proof from DNS recovery.
	peerGone := networkdCallEnded(v.Peer)
	absent := s.Policy.Runtime == nil && s.Policy.Permanent == nil
	if v.Action == "init" {
		if absent && (v.Acknowledged || peerGone) {
			v.State, v.OperationState, v.Resolved, v.Error = "released", "failed", true, "新建意图已结束，未保留目标 policy"
		} else if s.Policy.Permanent != nil && firewalldEmptyMatches(s.Permanent, v.Owner) && (s.Policy.Runtime == nil || firewalldEmptyMatches(s.Runtime, v.Owner) && s.Policy.Runtime.Hash == s.Policy.Permanent.Hash) && (v.SettingsHash == "" || v.SettingsHash == s.Policy.Permanent.Hash) {
			v.SettingsHash, v.Resolved = s.Policy.Permanent.Hash, true
			v.State, v.OperationState, v.Error = "prepared", "waiting_confirmation", "永久空 policy 已准备；须本机审核其他永久配置并自行 reload，再执行 firewalld-recover"
			if s.Policy.Runtime != nil && s.Policy.Active && slices.Equal(s.Policy.ActiveIngressZones, []string{"ANY"}) && slices.Equal(s.Policy.ActiveEgressZones, []string{"HOST"}) {
				v.State, v.OperationState, v.Error = "registered", "succeeded", ""
			}
		} else {
			v.State, v.OperationState, v.Error = "creating", "recovery_required", "未能核对原意图的空 policy；结果未知时不重放，须本机检查；原服务进程未结束时对象缺失不能判为完成"
		}
	} else {
		if v.ReplyError != "" && s.Policy.Runtime != nil && s.Policy.Permanent != nil && s.Policy.Runtime.Hash == v.BaselineHash && s.Policy.Permanent.Hash == v.BaselineHash && firewalldEmptyMatches(s.Runtime, v.Owner) && firewalldEmptyMatches(s.Permanent, v.Owner) {
			v.State, v.OperationState, v.Error = "registered", "failed", "firewalld 返回明确错误，原空 policy 保持登记；未完成移除"
		} else if s.Policy.Permanent == nil && (s.Policy.Runtime == nil || firewalldEmptyMatches(s.Runtime, v.Owner) && s.Policy.Runtime.Hash == v.BaselineHash) && (v.Resolved || v.Acknowledged || peerGone) {
			v.Resolved = true
			v.State, v.OperationState, v.Error = "releasing", "waiting_confirmation", "永久空 policy 已移除；须本机审核其他永久配置并自行 reload，再执行 firewalld-recover"
			if absent {
				v.State, v.OperationState, v.Error = "released", "succeeded", ""
			}
		} else {
			v.State, v.OperationState, v.Error = "removing", "recovery_required", "移除结果尚未完整核对或原对象已变化；禁止重放删除，须本机检查"
		}
	}
	if err = saveFirewalldRegistration(dataDir, v); err != nil {
		return out, err
	}
	out = firewalldRegistrationStatus(dataDir, s)
	if v.OperationState == "recovery_required" || v.OperationState == "failed" {
		return out, errors.New(v.Error)
	}
	return out, nil
}

func settleFirewalldUnsubmitted(v *firewalldRegistrationCheckpoint) {
	v.Resolved, v.OperationState, v.Error = true, "failed", "原意图未提交到 firewalld，未执行写入"
	v.State = "released"
	if v.Action == "remove" {
		v.State = "registered"
	}
}

// Only firewalld's own completed exception replies prove its handler ended.
// Generic bus timeouts, NoReply and connection errors do not provide this proof.
func firewalldCompletedError(err error) string {
	var reply dbus.Error
	if errors.As(err, &reply) && slices.Contains([]string{firewalldName + ".Exception", firewalldName + ".NotAuthorizedException"}, reply.Name) {
		return reply.Name
	}
	return ""
}
