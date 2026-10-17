package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

const iptablesRestoreKind = "firewall.iptables.restore"

type iptablesRestoreRequest struct{ ID, OperationID, Target string }

type iptablesRestoreReceipt struct {
	Schema                  int              `json:"schema"`
	ID                      string           `json:"id"`
	OperationID             string           `json:"operation_id"`
	RepairID                string           `json:"repair_id"`
	Owner                   string           `json:"owner"`
	MachineHash             string           `json:"machine_hash"`
	RegistrationOperationID string           `json:"registration_operation_id"`
	ParentIntentHash        string           `json:"parent_intent_hash"`
	ProgramHash             string           `json:"program_hash"`
	ToolchainHash           string           `json:"toolchain_hash"`
	Target                  string           `json:"target"`
	Family                  string           `json:"family"`
	InputHash               string           `json:"input_hash"`
	InputBytes              int              `json:"input_bytes"`
	Helper                  ufwBoundFile     `json:"helper"`
	Restore                 ufwBoundFile     `json:"restore"`
	Blocker                 ufwBoundFile     `json:"blocker"`
	GuardVersion            int              `json:"guard_version"`
	RequestHash             string           `json:"request_hash"`
	Phase                   string           `json:"phase"`
	Process                 *networkdProcess `json:"process"`
	Outcome                 string           `json:"outcome"`
	ExitCode                int              `json:"exit_code"`
	OutputHash              string           `json:"output_hash"`
	DiagnosticHash          string           `json:"diagnostic_hash"`
	OutputBytes             int              `json:"output_bytes"`
	DiagnosticBytes         int              `json:"diagnostic_bytes"`
	Error                   string           `json:"error"`
	UpdatedAt               int64            `json:"updated_at"`
}

func iptablesRestorePath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "iptables-execution.json")
}

func iptablesRestoreHash(r iptablesRestoreReceipt) string {
	raw, _ := json.Marshal(r)
	return secure.Hash(append([]byte("iptables:restore-receipt:v2:\x00"), raw...))
}

func iptablesRestoreRequestHash(r iptablesRestoreReceipt) string {
	r.RequestHash, r.Phase, r.Process, r.Outcome = "", "", nil, ""
	r.ExitCode, r.OutputHash, r.DiagnosticHash, r.OutputBytes, r.DiagnosticBytes, r.Error, r.UpdatedAt = 0, "", "", 0, 0, "", 0
	raw, _ := json.Marshal(r)
	return secure.Hash(append([]byte("iptables:restore-request:v2:\x00"), raw...))
}

func validIPTablesRestore(r *iptablesRestoreReceipt) bool {
	if r == nil || r.Schema != 2 || r.GuardVersion != 1 || !validID(r.ID) || !validID(r.OperationID) || !validID(r.Owner) || !validID(r.RegistrationOperationID) || !firewalldDigest(r.MachineHash) || !firewalldDigest(r.ParentIntentHash) || !firewalldDigest(r.ProgramHash) || !firewalldDigest(r.ToolchainHash) || !firewalldDigest(r.InputHash) || r.InputBytes < 1 || r.InputBytes > 4<<20 || r.RequestHash != iptablesRestoreRequestHash(*r) || r.UpdatedAt <= 0 || len(r.Error) > 512 || !slices.Contains([]string{"candidate", "previous", "repair"}, r.Target) || !slices.Contains([]string{"ipv4", "ipv6"}, r.Family) || !validIPTablesBoundFile(r.Helper, iptablesHelperBytes) || r.Helper.Role != "nginxpanel" || !validIPTablesBoundFile(r.Restore, 16<<20) || !validIPTablesBoundFile(r.Blocker, 16<<20) || r.Blocker.Role != "false" || filepath.Base(r.Blocker.Invoked) != "false" {
		return false
	}
	if r.Target == "repair" {
		if !validID(r.RepairID) || r.RepairID == r.ID || r.RepairID == r.OperationID {
			return false
		}
	} else if r.RepairID != "" {
		return false
	}
	roles := []string{"iptables-nft-restore", "iptables-legacy-restore"}
	if r.Family == "ipv6" {
		roles = []string{"ip6tables-nft-restore", "ip6tables-legacy-restore"}
	}
	if !slices.Contains(roles, r.Restore.Role) || filepath.Base(r.Restore.Invoked) != r.Restore.Role || r.Process != nil && !validDNSProcess(*r.Process) {
		return false
	}
	if r.Phase == "prepared" || r.Phase == "permitted" {
		return (r.Phase == "prepared" && r.Process == nil || r.Phase == "permitted" && r.Process != nil) && r.Outcome == "" && r.ExitCode == 0 && r.OutputHash == "" && r.DiagnosticHash == "" && r.OutputBytes == 0 && r.DiagnosticBytes == 0 && r.Error == ""
	}
	if r.Phase != "ended" {
		return false
	}
	if r.Outcome == "exit" {
		return r.Process != nil && r.ExitCode >= 0 && r.ExitCode <= 255 && firewalldDigest(r.OutputHash) && firewalldDigest(r.DiagnosticHash) && r.OutputBytes >= 0 && r.OutputBytes <= 8<<10 && r.DiagnosticBytes >= 0 && r.DiagnosticBytes <= 8<<10
	}
	return slices.Contains([]string{"unknown", "not_started"}, r.Outcome) && (r.Outcome != "unknown" || r.Process != nil) && r.ExitCode == -1 && r.OutputHash == "" && r.DiagnosticHash == "" && r.OutputBytes == 0 && r.DiagnosticBytes == 0 && r.Error != ""
}

func loadIPTablesRestore(dataDir string) (*iptablesRestoreReceipt, error) {
	raw, err := listenerRead(iptablesRestorePath(dataDir), 32<<10)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r iptablesRestoreReceipt
	if err = ufwToolJSON(raw, &r); err != nil {
		return nil, err
	}
	if !validIPTablesRestore(&r) {
		return nil, errors.New("iptables 子进程回执无效")
	}
	return &r, nil
}

func iptablesRestoreRecordMatches(record Record, r *iptablesRestoreReceipt) bool {
	if !validIPTablesRestore(r) || record.Kind != iptablesRestoreKind || record.OperationID != r.ID || record.RelatedOperationID != r.OperationID || record.RequestHash != r.RequestHash || record.CandidateHash != iptablesRestoreHash(*r) || record.Stage != r.Phase || record.Error != r.Error || !validIPTablesRestore(record.IPTablesRestore) || !sameIPTablesValue(record.IPTablesRestore, r) {
		return false
	}
	wanted := "running"
	if r.Phase == "ended" {
		wanted = "failed"
		if iptablesRestoreResult(r) == nil {
			wanted = "succeeded"
		}
	}
	return record.State == wanted
}

func iptablesRestoreResult(r *iptablesRestoreReceipt) error {
	if !validIPTablesRestore(r) || r.Phase != "ended" || r.Outcome != "exit" || r.ExitCode != 0 || r.Error != "" || r.OutputBytes != 0 || r.DiagnosticBytes != 0 || r.OutputHash != secure.Hash(nil) || r.DiagnosticHash != secure.Hash(nil) {
		return errors.New("iptables 原固定调用未取得无警告的成功回执，禁止重放")
	}
	return nil
}

func compatibleIPTablesRestore(old, next *iptablesRestoreReceipt) bool {
	if !validIPTablesRestore(old) || old.RequestHash != next.RequestHash || old.ID != next.ID || old.Phase == "ended" && !sameIPTablesValue(old, next) || old.Phase == "permitted" && next.Phase == "prepared" || old.Process != nil && (next.Process == nil || *old.Process != *next.Process) {
		return false
	}
	return true
}

func saveIPTablesRestore(dataDir string, r *iptablesRestoreReceipt) error {
	current, err := loadIPTablesRestore(dataDir)
	if err != nil {
		return err
	}
	if current == nil || current.ID != r.ID || current.Phase != "ended" {
		r.UpdatedAt = time.Now().Unix()
	}
	if !validIPTablesRestore(r) {
		return errors.New("iptables 子进程持久回执无效")
	}
	if current != nil && current.ID == r.ID && !compatibleIPTablesRestore(current, r) {
		return errors.New("iptables 原子进程检查点发生冲突")
	}
	if current != nil && current.ID != r.ID {
		old, err := loadIPTablesReceipt(dataDir, current.ID)
		if err != nil || current.Phase != "ended" || !iptablesRestoreRecordMatches(old, current) {
			return errors.New("iptables 前一子进程尚未结束或回执缺失")
		}
	}
	if old, err := loadIPTablesReceipt(dataDir, r.ID); err == nil {
		if !iptablesRestoreRecordMatches(old, old.IPTablesRestore) || !compatibleIPTablesRestore(old.IPTablesRestore, r) {
			return errors.New("iptables 子进程独立回执发生冲突")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = secure.RootDirectory(filepath.Dir(iptablesRestorePath(dataDir)), 0700); err != nil {
		return err
	}
	if err = rootJSONWrite(iptablesRestorePath(dataDir), r, 32<<10); err != nil {
		return err
	}
	state := "running"
	if r.Phase == "ended" {
		state = "failed"
		if iptablesRestoreResult(r) == nil {
			state = "succeeded"
		}
	}
	journal := iptablesRegistrationJournal(dataDir)
	if err = secure.RootDirectory(journal.Dir, 0700); err != nil {
		return err
	}
	return journal.Put(Record{OperationID: r.ID, RelatedOperationID: r.OperationID, Kind: iptablesRestoreKind, RequestHash: r.RequestHash, State: state, Stage: r.Phase, Error: r.Error, IPTablesRestore: r, CandidateHash: iptablesRestoreHash(*r)})
}

func iptablesRestorePending(dataDir string) bool {
	r, err := loadIPTablesRestore(dataDir)
	if err != nil {
		return true
	}
	if r == nil {
		return false
	}
	old, err := loadIPTablesReceipt(dataDir, r.ID)
	return err != nil || r.Phase != "ended" || !iptablesRestoreRecordMatches(old, r)
}

// This lock is distinct from the official xtables lock. Its open description
// stays inherited by the native process, including after a parent crash.
func openIPTablesExecutionLock() (*os.File, error) {
	dir := "/run/nginxpanel-host"
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, "iptables-child.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "iptables-child.lock")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err == nil && (stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600) {
		err = errors.New("iptables 子进程锁属性无效")
	}
	if err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func iptablesRestoreMaterial(v *iptablesChangeCheckpoint, request iptablesRestoreRequest) (*iptablesChangeMaterial, error) {
	if v.Operation.ID != request.OperationID {
		return nil, errors.New("iptables 调用不属于原父操作")
	}
	for _, step := range v.Steps {
		if step.ID == request.ID && step.Target == request.Target {
			for index := range v.Transition.Materials {
				if v.Transition.Materials[index].Family == step.Family {
					return &v.Transition.Materials[index], nil
				}
			}
		}
	}
	return nil, errors.New("iptables 调用缺少原父操作冻结许可")
}

func iptablesRestoreMatchesChange(r *iptablesRestoreReceipt, v *iptablesChangeCheckpoint) bool {
	if !validIPTablesRestore(r) || v == nil || r.OperationID != v.Operation.ID || r.ParentIntentHash != iptablesChangeIntentHash(v) || r.ProgramHash != v.Policy.ProgramHash || r.ToolchainHash != v.Transition.Tools.Hash || r.Owner != v.Transition.Owner || r.MachineHash != v.Transition.MachineHash || r.RegistrationOperationID != v.Transition.RegistrationOperationID {
		return false
	}
	material, err := iptablesRestoreMaterial(v, iptablesRestoreRequest{ID: r.ID, OperationID: r.OperationID, Target: r.Target})
	if err != nil || r.Family != material.Family {
		return false
	}
	input := material.Candidate
	if r.Target == "previous" {
		input = material.Previous
	}
	restore, err := v.Transition.Tools.tool(material.Binary + "-restore")
	if err != nil {
		return false
	}
	blocker, err := v.Transition.Tools.tool("false")
	return err == nil && r.InputHash == secure.Hash(input) && r.InputBytes == len(input) && sameIPTablesValue(r.Helper, v.Transition.Tools.Helper) && sameIPTablesValue(r.Restore, restore) && sameIPTablesValue(r.Blocker, blocker)
}

func iptablesCandidateReceipt(dataDir string, v *iptablesChangeCheckpoint, family string) error {
	for _, step := range v.Steps {
		if step.Family != family || step.Target != "candidate" {
			continue
		}
		r, err := loadIPTablesReceipt(dataDir, step.ID)
		if err != nil || !iptablesRestoreRecordMatches(r, r.IPTablesRestore) {
			return errors.New("iptables 代际规则缺少原候选调用回执")
		}
		child := r.IPTablesRestore
		if !iptablesRestoreMatchesChange(child, v) || child.Target != "candidate" || child.Family != family || child.Process == nil || child.Phase != "ended" || !networkdCallEnded(*child.Process) {
			return errors.New("iptables 代际规则与原候选进程无法关联")
		}
		return nil
	}
	return errors.New("iptables 原候选调用许可缺失")
}

// Caller holds iptables-business.lock through invocation and parent publication.
func runIPTablesRestore(ctx context.Context, dataDir string, request iptablesRestoreRequest) (*iptablesRestoreReceipt, error) {
	if request.Target == "repair" {
		return runIPTablesRepairRestore(ctx, dataDir, request)
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || !slices.Contains([]string{"candidate", "previous"}, request.Target) {
		return nil, errors.New("iptables 执行范围或方向无效")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	unlockProcess, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-process.lock")
	if err != nil {
		return nil, err
	}
	defer unlockProcess()
	v, err := loadIPTablesChange(dataDir)
	if err != nil || v == nil || iptablesChangeTerminal(v) {
		return nil, errors.New("iptables 原业务快照不可执行")
	}
	parent, err := loadIPTablesReceipt(dataDir, v.Operation.ID)
	if err != nil || !iptablesChangeReceiptMatches(parent, v) {
		return nil, errors.New("iptables 原业务独立回执尚未发布")
	}
	material, err := iptablesRestoreMaterial(v, request)
	if err != nil {
		return nil, err
	}
	if old, err := loadIPTablesReceipt(dataDir, request.ID); err == nil {
		if !iptablesRestoreRecordMatches(old, old.IPTablesRestore) || !iptablesRestoreMatchesChange(old.IPTablesRestore, v) || old.IPTablesRestore.Target != request.Target || old.IPTablesRestore.Family != material.Family {
			return nil, errors.New("iptables 原调用标识冲突")
		}
		return old.IPTablesRestore, iptablesRestoreResult(old.IPTablesRestore)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if iptablesRestorePending(dataDir) {
		return nil, errors.New("iptables 原子进程尚未完成核对")
	}
	if latest, err := loadIPTablesRestore(dataDir); err != nil {
		return nil, err
	} else if latest != nil && latest.OperationID != v.Operation.ID {
		parent, err := loadIPTablesReceipt(dataDir, latest.OperationID)
		if err != nil || parent.Kind != firewallOperationKind || parent.Firewall == nil || parent.Firewall.ID != latest.OperationID || parent.Firewall.ProgramHash != latest.ProgramHash || parent.Firewall.State != parent.State || !slices.Contains([]string{"succeeded", "rolled_back", "failed"}, parent.State) {
			return nil, errors.New("iptables 前一子进程的父业务尚未结束")
		}
	}
	guard, err := openIPTablesExecutionLock()
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	current, err := inspectIPTablesChangeScope(ctx, dataDir, v, request.Target == "previous")
	if err != nil {
		return nil, err
	}
	input := material.Previous
	if request.Target == "candidate" {
		if v.Policy.Action == "apply" {
			if err = checkIPTablesInterfaces(v.Policy.Policy, current.Observed); err != nil {
				return nil, err
			}
		}
		if v.Rollback || v.Operation.State != "running" || time.Now().Unix() >= v.Operation.Deadline || current.Hash != v.Transition.ConfigurationHash || current.States[material.Family] != "previous" {
			return nil, errors.New("iptables 原候选基线或执行窗口已变化")
		}
		for family, state := range current.States {
			if state == "candidate" {
				if err = iptablesCandidateReceipt(dataDir, v, family); err != nil {
					return nil, err
				}
			}
		}
		input = material.Candidate
	} else {
		if !v.Rollback || v.Operation.State != "compensating" || current.States[material.Family] != "candidate" {
			return nil, errors.New("iptables 恢复方向或完整原代际规则无法核对")
		}
		if err = iptablesCandidateReceipt(dataDir, v, material.Family); err != nil {
			return nil, err
		}
	}
	restore, err := v.Transition.Tools.tool(material.Binary + "-restore")
	if err != nil {
		return nil, err
	}
	blocker, err := v.Transition.Tools.tool("false")
	if err != nil {
		return nil, err
	}
	r := &iptablesRestoreReceipt{Schema: 2, ID: request.ID, OperationID: request.OperationID, Owner: v.Transition.Owner, MachineHash: v.Transition.MachineHash, RegistrationOperationID: v.Transition.RegistrationOperationID, ParentIntentHash: iptablesChangeIntentHash(v), ProgramHash: v.Policy.ProgramHash, ToolchainHash: v.Transition.Tools.Hash, Target: request.Target, Family: material.Family, InputHash: secure.Hash(input), InputBytes: len(input), Helper: v.Transition.Tools.Helper, Restore: restore, Blocker: blocker, GuardVersion: 1, Phase: "prepared"}
	r.RequestHash = iptablesRestoreRequestHash(*r)
	if err = saveIPTablesRestore(dataDir, r); err != nil {
		return nil, err
	}
	return launchIPTablesRestore(ctx, dataDir, r, input, guard)
}

func launchIPTablesRestore(ctx context.Context, dataDir string, r *iptablesRestoreReceipt, input []byte, guard *os.File) (_ *iptablesRestoreReceipt, resultErr error) {
	started := false
	defer func() {
		if !started {
			r.Phase, r.Outcome, r.ExitCode, r.Error = "ended", "not_started", -1, "固定工具未获得执行许可"
			resultErr = errors.Join(resultErr, saveIPTablesRestore(dataDir, r))
		}
	}()
	helper, err := openFirewallELF(r.Helper, iptablesHelperBytes)
	if err != nil {
		return r, err
	}
	defer helper.Close()
	restore, err := openUFWRestoreELF(r.Restore)
	if err != nil {
		return r, err
	}
	defer restore.Close()
	blocker, err := openUFWRestoreELF(r.Blocker)
	if err != nil {
		return r, err
	}
	defer blocker.Close()
	gate, grant, err := os.Pipe()
	if err != nil {
		return r, err
	}
	defer gate.Close()
	defer grant.Close()
	parent, err := networkProcess(uint32(os.Getpid()))
	if err != nil {
		return r, err
	}
	encoded, err := json.Marshal(iptablesGateRequest{Version: 1, Parent: parent, Grant: r.RequestHash, Restore: r.Restore})
	if err != nil {
		return r, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(call, "/proc/self/fd/5", "_iptables-restore", string(encoded))
	command.Args[0] = r.Helper.Invoked
	command.ExtraFiles = []*os.File{gate, restore, helper, blocker, guard}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	command.Stdin = bytes.NewReader(input)
	stdout, stderr := firewallOutput{limit: 8 << 10}, firewallOutput{limit: 8 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 250 * time.Millisecond
	if err = command.Start(); err != nil {
		return r, err
	}
	started = true
	gate.Close()
	identity, err := networkProcess(uint32(command.Process.Pid))
	if err == nil {
		r.Process, r.Phase = &identity, "permitted"
		err = saveIPTablesRestore(dataDir, r)
	}
	if err == nil {
		err = call.Err()
	}
	permitted := false
	if err == nil {
		var n int
		n, err = io.WriteString(grant, r.RequestHash)
		permitted = n == 64
		if err == nil && !permitted {
			err = io.ErrShortWrite
		}
	}
	grant.Close()
	if err != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if command.ProcessState == nil {
		return r, errors.Join(err, waitErr, errors.New("iptables 原进程结束状态不可核对"))
	}
	r.Phase, r.ExitCode = "ended", command.ProcessState.ExitCode()
	if permitted && r.ExitCode >= 0 {
		r.Outcome, r.OutputHash, r.DiagnosticHash = "exit", secure.Hash(stdout.data.Bytes()), secure.Hash(stderr.data.Bytes())
		r.OutputBytes, r.DiagnosticBytes = stdout.data.Len(), stderr.data.Len()
		if err != nil || waitErr != nil || call.Err() != nil || stdout.exceeded || stderr.exceeded || r.OutputBytes != 0 || r.DiagnosticBytes != 0 {
			r.Error = "iptables 固定工具失败、超时、输出或返回警告"
		}
	} else {
		r.Outcome, r.ExitCode, r.Error = "unknown", -1, "原进程已结束但执行结果未知，禁止重放"
		if !permitted {
			r.Outcome, r.Error = "not_started", "固定工具未获得完整执行许可"
		}
	}
	return r, errors.Join(err, waitErr, saveIPTablesRestore(dataDir, r), iptablesRestoreResult(r))
}

func recoverIPTablesRestore(ctx context.Context, dataDir string) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-process.lock")
	if err != nil {
		return err
	}
	defer unlock()
	r, err := loadIPTablesRestore(dataDir)
	if err != nil || r == nil {
		return err
	}
	machine, _, err := iptablesHostIdentity()
	if err != nil || machine != r.MachineHash {
		return errors.New("iptables 原子进程不属于本机")
	}
	if old, err := loadIPTablesReceipt(dataDir, r.ID); err == nil {
		if !iptablesRestoreRecordMatches(old, old.IPTablesRestore) || !compatibleIPTablesRestore(old.IPTablesRestore, r) {
			return errors.New("iptables 原子进程检查点与回执冲突")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if r.Phase == "ended" {
		return saveIPTablesRestore(dataDir, r)
	}
	v, err := loadIPTablesChange(dataDir)
	matched := err == nil && iptablesRestoreMatchesChange(r, v)
	if err == nil && r.Target == "repair" {
		repair, repairErr := loadIPTablesRepair(dataDir)
		matched = repairErr == nil && repair != nil && iptablesPolicySourceMatches(repair, v) && iptablesRestoreMatchesRepair(r, repair)
	}
	if !matched {
		return errors.New("iptables 原进程缺少对应的原 root 业务意图")
	}
	if r.Process != nil && !networkdCallEnded(*r.Process) {
		fd, err := unix.PidfdOpen(int(r.Process.PID), 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		current, err := networkProcess(r.Process.PID)
		if err != nil || current != *r.Process {
			return errors.New("iptables 原 PID 实例变化，拒绝终止其他进程")
		}
		if err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			if err = ctx.Err(); err != nil {
				return err
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, err = unix.Poll(fds, 100)
			if err != nil && !errors.Is(err, unix.EINTR) {
				return err
			}
			if fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
				break
			}
			if !time.Now().Before(deadline) {
				return errors.New("iptables 原进程尚未确认结束")
			}
		}
	}
	r.Phase, r.Outcome, r.ExitCode, r.Error = "ended", "not_started", -1, "原执行许可未发布，未重放工具"
	if r.Process != nil {
		r.Outcome, r.Error = "unknown", "原进程已结束，须由原业务核对并补偿"
	}
	return saveIPTablesRestore(dataDir, r)
}
