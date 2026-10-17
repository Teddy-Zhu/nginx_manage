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
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const ufwRestoreKind = "firewall.ufw.restore"
const ufwRestoreReceiptBytes = 32 << 10
const ufwProcessProblem = "UFW 原业务或重载进程尚未完成核对："

// The pipe is a one-use execution grant, not an API. Until the durable PID
// identity has been published, EOF or a parent crash cannot execute the tool.
// execve keeps that PID and start identity; the target is a pinned ELF file.
const ufwRestoreGate = `import os,sys,json
request=json.loads(sys.argv[1])
if os.execve not in os.supports_fd:
 sys.exit(126)
grant=b''
while len(grant)<64:
 part=os.read(3,64-len(grant))
 if not part:
  sys.exit(125)
 grant+=part
os.close(3)
if grant.decode('ascii')!=request['grant'] or os.geteuid()!=0:
 sys.exit(125)
os.set_inheritable(4,False)
os.set_inheritable(5,False)
os.execve(4,request['argv'],os.environ)
`

// Only material from the complete official dry-run batch reaches the private
// plan. Retaining it grants neither application nor ownership of old rules.
type ufwReloadMaterial struct {
	Family, BeforeHash, AfterHash string
	Before, After                 []byte
	Python, Restore, Blocker      ufwBoundFile
	BeforeKernel, AfterKernel     []ufwReloadChain
}

type ufwRestoreRequest struct {
	ID, OperationID, Target string
}

type ufwRestoreReceipt struct {
	Schema                  int              `json:"schema"`
	ID                      string           `json:"id"`
	OperationID             string           `json:"operation_id"`
	Owner                   string           `json:"owner"`
	MachineHash             string           `json:"machine_hash"`
	RegistrationOperationID string           `json:"registration_operation_id"`
	BatchHash               string           `json:"batch_hash"`
	ProgramHash             string           `json:"program_hash"`
	ToolchainHash           string           `json:"toolchain_hash"`
	Target                  string           `json:"target"`
	Family                  string           `json:"family"`
	InputHash               string           `json:"input_hash"`
	InputBytes              int              `json:"input_bytes"`
	Python                  ufwBoundFile     `json:"python"`
	Restore                 ufwBoundFile     `json:"restore"`
	Blocker                 ufwBoundFile     `json:"blocker"`
	GuardHash               string           `json:"guard_hash"`
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

func ufwRestorePath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "ufw-execution.json")
}

func ufwRestoreRequestHash(r ufwRestoreReceipt) string {
	r.RequestHash, r.Phase, r.Process, r.Outcome = "", "", nil, ""
	r.ExitCode, r.OutputHash, r.DiagnosticHash, r.OutputBytes, r.DiagnosticBytes, r.Error, r.UpdatedAt = 0, "", "", 0, 0, "", 0
	raw, _ := json.Marshal(r)
	return secure.Hash(append([]byte("ufw:restore-request:v1:\x00"), raw...))
}

func ufwRestoreReceiptHash(r ufwRestoreReceipt) string {
	raw, _ := json.Marshal(r)
	return secure.Hash(append([]byte("ufw:restore-receipt:v1:\x00"), raw...))
}

func ufwRestoreRecordMatches(record Record, r *ufwRestoreReceipt) bool {
	if !validUFWRestoreReceipt(r) || record.Kind != ufwRestoreKind || record.OperationID != r.ID || record.RelatedOperationID != r.OperationID || record.RequestHash != r.RequestHash || record.CandidateHash != ufwRestoreReceiptHash(*r) || record.Stage != r.Phase || record.Error != r.Error || record.UFWRestore == nil || !validUFWRestoreReceipt(record.UFWRestore) || ufwRestoreReceiptHash(*record.UFWRestore) != record.CandidateHash {
		return false
	}
	state := "running"
	if r.Phase == "ended" {
		state = "failed"
		if r.Outcome == "exit" && r.ExitCode == 0 && r.Error == "" {
			state = "succeeded"
		}
	}
	return record.State == state
}

func validUFWRestoreReceipt(r *ufwRestoreReceipt) bool {
	if r == nil || r.Schema != 1 || !validID(r.ID) || !validID(r.OperationID) || r.ID == r.OperationID || !validID(r.Owner) || !validID(r.RegistrationOperationID) || !firewalldDigest(r.MachineHash) || !firewalldDigest(r.BatchHash) || !firewalldDigest(r.ProgramHash) || !firewalldDigest(r.ToolchainHash) || !firewalldDigest(r.InputHash) || r.InputBytes < 1 || r.InputBytes > firewall.UFWReadBytes || !slices.Contains([]string{"candidate", "previous"}, r.Target) || !slices.Contains([]string{"ipv4", "ipv6"}, r.Family) || r.GuardHash != secure.Hash([]byte(ufwRestoreGate)) || r.RequestHash != ufwRestoreRequestHash(*r) || r.UpdatedAt <= 0 || len(r.Error) > 512 {
		return false
	}
	role := "iptables-restore"
	if r.Family == "ipv6" {
		role = "ip6tables-restore"
	}
	for index, tool := range []ufwBoundFile{r.Python, r.Restore, r.Blocker} {
		f := tool.File
		if tool.Role != []string{"python", role, "false"}[index] || !tool.Executable || len(tool.Raw) != 0 || !filepath.IsAbs(tool.Invoked) || filepath.Clean(tool.Invoked) != tool.Invoked || !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || len(tool.Invoked) > 4096 || len(f.Path) > 4096 || strings.ContainsAny(tool.Invoked+f.Path, "\x00\r\n") || !f.Present || !firewalldDigest(f.Hash) || f.Bytes < 4 || f.Bytes > 16<<20 || f.Inode == 0 || os.FileMode(f.Mode)&(os.ModeType|os.ModeSetuid|os.ModeSetgid) != 0 || os.FileMode(f.Mode).Perm()&0111 == 0 || os.FileMode(f.Mode).Perm()&0022 != 0 {
			return false
		}
	}
	if r.Process != nil && !validDNSProcess(*r.Process) || r.OutputBytes < 0 || r.OutputBytes > 8<<10 || r.DiagnosticBytes < 0 || r.DiagnosticBytes > 8<<10 {
		return false
	}
	switch r.Phase {
	case "prepared":
		return r.Process == nil && r.Outcome == "" && r.ExitCode == -1 && r.OutputHash == "" && r.DiagnosticHash == "" && r.OutputBytes == 0 && r.DiagnosticBytes == 0 && r.Error == ""
	case "permitted":
		return r.Process != nil && r.Outcome == "" && r.ExitCode == -1 && r.OutputHash == "" && r.DiagnosticHash == "" && r.OutputBytes == 0 && r.DiagnosticBytes == 0 && r.Error == ""
	case "ended":
		if r.Outcome == "exit" {
			return r.Process != nil && r.ExitCode >= 0 && r.ExitCode <= 255 && firewalldDigest(r.OutputHash) && firewalldDigest(r.DiagnosticHash) && (r.Error != "" || r.ExitCode == 0 && r.OutputBytes == 0 && r.DiagnosticBytes == 0)
		}
		return slices.Contains([]string{"not_started", "unknown"}, r.Outcome) && r.ExitCode == -1 && r.Error != "" && r.OutputHash == "" && r.DiagnosticHash == "" && r.OutputBytes == 0 && r.DiagnosticBytes == 0 && (r.Outcome != "unknown" || r.Process != nil)
	}
	return false
}

func loadUFWRestore(dataDir string) (*ufwRestoreReceipt, error) {
	raw, err := listenerRead(ufwRestorePath(dataDir), ufwRestoreReceiptBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r ufwRestoreReceipt
	if ufwToolJSON(raw, &r) != nil || !validUFWRestoreReceipt(&r) {
		return nil, errors.New("UFW 子进程独立执行回执无效")
	}
	return &r, nil
}

func saveUFWRestore(dataDir string, r *ufwRestoreReceipt) error {
	r.UpdatedAt = time.Now().Unix()
	if !validUFWRestoreReceipt(r) {
		return errors.New("UFW 子进程执行状态不可保存")
	}
	j := ufwRegistrationJournal(dataDir)
	old, err := loadUFWReceipt(dataDir, r.ID)
	if err == nil && (old.RequestHash != r.RequestHash || !ufwRestoreRecordMatches(old, old.UFWRestore)) {
		return errors.New("UFW 子进程回执 ID 已用于其他操作")
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = rootJSONWrite(ufwRestorePath(dataDir), r, ufwRestoreReceiptBytes); err != nil {
		return err
	}
	state := "running"
	if r.Phase == "ended" {
		state = "failed"
		if r.Outcome == "exit" && r.ExitCode == 0 && r.Error == "" {
			state = "succeeded"
		}
	}
	copy := *r
	return j.Put(Record{OperationID: r.ID, RelatedOperationID: r.OperationID, Kind: ufwRestoreKind, RequestHash: r.RequestHash, CandidateHash: ufwRestoreReceiptHash(*r), State: state, Stage: r.Phase, Error: r.Error, UFWRestore: &copy})
}

func ufwRestoreProcessPending(dataDir string) bool {
	r, err := loadUFWRestore(dataDir)
	if err != nil || r != nil && r.Phase != "ended" {
		return true
	}
	if r == nil {
		return false
	}
	old, err := loadUFWReceipt(dataDir, r.ID)
	return err != nil || !ufwRestoreRecordMatches(old, r)
}

func ufwRestorePending(dataDir string) bool {
	if ufwChangePending(dataDir) || ufwRestoreProcessPending(dataDir) {
		return true
	}
	r, err := loadUFWRestore(dataDir)
	if err != nil || r == nil {
		return err != nil
	}
	return ufwRestoreParentPending(dataDir, r)
}

func ufwRestoreParentPending(dataDir string, r *ufwRestoreReceipt) bool {
	parent, err := loadUFWReceipt(dataDir, r.OperationID)
	return err != nil || parent.Kind != firewallOperationKind || parent.Firewall == nil || parent.Firewall.ID != r.OperationID || parent.Firewall.ProgramHash != r.ProgramHash || parent.RequestHash != firewallRequestHash(parent.Firewall.PlanID, parent.Firewall.Action) || parent.Firewall.State != parent.State || !slices.Contains([]string{"succeeded", "rolled_back", "failed"}, parent.State)
}

// Pin the already hashed inode. Set-id executables and file capabilities can
// clear the parent-death signal across exec, so this transport rejects them.
func openUFWRestoreELF(tool ufwBoundFile) (*os.File, error) {
	current, err := readUFWBoundFile(tool.Role, tool.Invoked, true, 16<<20)
	if err != nil || current.File != tool.File || len(current.Raw) < 4 || !bytes.Equal(current.Raw[:4], []byte{0x7f, 'E', 'L', 'F'}) || os.FileMode(current.File.Mode)&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("UFW 子进程工具必须是未漂移的普通受信 ELF")
	}
	fd, err := unix.Open(tool.File.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), tool.File.Path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != tool.File.Device || stat.Ino != tool.File.Inode || info.Size() != tool.File.Bytes || uint32(info.Mode()) != tool.File.Mode || info.ModTime().UnixNano() != tool.File.Modified || stat.Ctim.Sec*1e9+stat.Ctim.Nsec != tool.File.Changed {
		f.Close()
		return nil, errors.New("UFW 子进程工具在固定描述符时变化")
	}
	if _, err = unix.Fgetxattr(fd, "security.capability", nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		f.Close()
		return nil, errors.New("UFW 子进程工具存在文件能力或能力属性无法核对")
	}
	return f, nil
}

// The caller must first persist its old/new rule transition. The transport
// acquires the host registration and official UFW locks, then checks the closed
// source/kernel inputs. Completion still requires the parent's post-observation.
func runUFWRestore(ctx context.Context, dataDir string, request ufwRestoreRequest) (*ufwRestoreReceipt, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || request.Target != "candidate" && request.Target != "previous" {
		return nil, errors.New("UFW 子进程执行范围或目标无效")
	}
	registrationUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return nil, err
	}
	defer registrationUnlock()
	authority, err := ufwRegistrationAuthority(dataDir)
	if err != nil {
		return nil, err
	}
	change, err := loadUFWChange(dataDir)
	if err != nil || change == nil || change.Operation.ID != request.OperationID || change.Transition.Owner != authority.NextClaim.Owner || change.Transition.MachineHash != authority.NextClaim.MachineHash || change.Transition.RegistrationOperationID != authority.NextClaim.OperationID {
		return nil, errors.New("UFW 原生执行缺少原 root 业务转换快照")
	}
	var material *ufwReloadMaterial
	for _, step := range change.Steps {
		if step.ID == request.ID && step.Target == request.Target {
			for index := range change.Transition.Materials {
				if change.Transition.Materials[index].Family == step.Family {
					material = &change.Transition.Materials[index]
				}
			}
		}
	}
	if material == nil {
		return nil, errors.New("UFW 子进程不属于原业务预先固定的地址族与执行方向")
	}
	raw, err := ufwRestorePayload(*material, request.Target)
	if err != nil {
		return nil, err
	}
	r := &ufwRestoreReceipt{Schema: 1, ID: request.ID, OperationID: request.OperationID, Owner: authority.NextClaim.Owner, MachineHash: authority.NextClaim.MachineHash, RegistrationOperationID: authority.NextClaim.OperationID, BatchHash: change.Transition.BatchHash, ProgramHash: change.Policy.ProgramHash, ToolchainHash: change.Transition.Tools.Hash, Target: request.Target, Family: material.Family, InputHash: secure.Hash(raw), InputBytes: len(raw), Python: material.Python, Restore: material.Restore, Blocker: material.Blocker, GuardHash: secure.Hash([]byte(ufwRestoreGate)), Phase: "prepared", ExitCode: -1, UpdatedAt: time.Now().Unix()}
	r.RequestHash = ufwRestoreRequestHash(*r)
	if !validUFWRestoreReceipt(r) {
		return nil, errors.New("UFW 原生执行意图无效")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-execution.lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if old, err := loadUFWReceipt(dataDir, r.ID); err == nil {
		if old.RequestHash != r.RequestHash || !ufwRestoreRecordMatches(old, old.UFWRestore) {
			return nil, errors.New("UFW 子进程幂等键已用于其他请求或回执无效")
		}
		return old.UFWRestore, ufwRestoreResult(old.UFWRestore)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	previous, err := loadUFWRestore(dataDir)
	if err != nil {
		return nil, err
	}
	if ufwRestoreProcessPending(dataDir) || previous != nil && previous.OperationID != r.OperationID && ufwRestoreParentPending(dataDir, previous) {
		return nil, errors.New("原 UFW 子进程尚未完成核对，禁止重放或补偿")
	}
	parent, err := loadUFWReceipt(dataDir, r.OperationID)
	if err != nil || !ufwChangeReceiptMatches(parent, change) {
		return nil, errors.New("UFW 原生执行缺少已接受的 root 业务操作")
	}
	op := parent.Firewall
	if op.ID != r.OperationID || !validID(op.PlanID) || op.Version < 1 || !firewalldDigest(op.PolicyHash) || op.ProgramHash != r.ProgramHash || !slices.Contains([]string{"apply", "remove"}, op.Action) || parent.RequestHash != firewallRequestHash(op.PlanID, op.Action) || op.State != parent.State || op.Deadline <= 0 || r.Target == "candidate" && (parent.State != "running" || op.Deadline <= time.Now().Unix()) || r.Target == "previous" && !slices.Contains([]string{"compensating", "recovery_required"}, parent.State) {
		return nil, errors.New("UFW 原生执行缺少已接受的 root 业务操作")
	}
	if r.Target == "candidate" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Unix(parent.Firewall.Deadline, 0))
		defer cancel()
	}
	managerLock, err := lockUFWManager()
	if err != nil {
		return nil, err
	}
	defer managerLock.Close()
	if err = checkUFWChangeSources(ctx, dataDir, change); err != nil {
		return nil, err
	}
	for _, family := range change.Transition.Materials {
		image, err := readUFWTransitionKernel(ctx, &change.Transition, family.Family, dataDir)
		before, after := sameUFWReloadImage(image, family.BeforeKernel), sameUFWReloadImage(image, family.AfterKernel)
		if err != nil || !before && !after || r.Target == "candidate" && family.Family == r.Family && !before {
			return nil, errors.New("UFW 当前重载范围不属于原状态或原候选，禁止提交和覆盖")
		}
	}
	if err = secure.RootDirectory(filepath.Dir(ufwRestorePath(dataDir)), 0700); err != nil {
		return nil, err
	}
	if err = saveUFWRestore(dataDir, r); err != nil {
		return r, err
	}
	return executeUFWRestore(ctx, dataDir, r, raw, managerLock)
}

func ufwRestoreResult(r *ufwRestoreReceipt) error {
	if r.Phase != "ended" {
		return errors.New("UFW 原进程结果尚未核对，禁止重放")
	}
	if r.Outcome != "exit" || r.ExitCode != 0 || r.Error != "" {
		return errors.New("UFW 原进程未取得无警告的成功退出回执，须核对原业务操作")
	}
	return nil
}

func executeUFWRestore(ctx context.Context, dataDir string, r *ufwRestoreReceipt, input []byte, managerLock *os.File) (_ *ufwRestoreReceipt, resultErr error) {
	// This thread remains alive for Pdeathsig throughout the child lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	started, permitted := false, false
	defer func() {
		if !started {
			r.Phase, r.Outcome, r.Error = "ended", "not_started", "固定工具尚未获得执行许可"
			resultErr = errors.Join(resultErr, saveUFWRestore(dataDir, r))
		}
	}()
	python, err := openUFWRestoreELF(r.Python)
	if err != nil {
		return r, err
	}
	defer python.Close()
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
	encoded, err := json.Marshal(struct {
		Grant string   `json:"grant"`
		Argv  []string `json:"argv"`
	}{r.RequestHash, []string{r.Restore.Invoked, "--noflush", "--wait", "1", "--modprobe", "/proc/self/fd/6"}})
	if err != nil {
		return r, err
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(call, "/proc/self/fd/5", "-I", "-S", "-B", "-c", ufwRestoreGate, string(encoded))
	command.Args[0] = r.Python.Invoked
	command.ExtraFiles = []*os.File{gate, restore, python, blocker, managerLock}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONDONTWRITEBYTECODE=1"}
	command.Stdin = bytes.NewReader(input)
	stdout, stderr := firewallOutput{limit: 8 << 10}, firewallOutput{limit: 8 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 250 * time.Millisecond
	if err = command.Start(); err != nil {
		return r, err
	}
	started = true
	gate.Close()
	identity, err := networkProcess(uint32(command.Process.Pid))
	if err == nil {
		r.Process, r.Phase = &identity, "permitted"
		err = saveUFWRestore(dataDir, r)
	}
	if err == nil {
		err = call.Err()
	}
	if err == nil {
		err = verifyUFWManagerLock(managerLock)
	}
	if err == nil {
		var n int
		n, err = io.WriteString(grant, r.RequestHash)
		permitted = n == len(r.RequestHash)
		if err == nil && !permitted {
			err = io.ErrShortWrite
		}
	}
	grant.Close()
	if err != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if permitted && command.ProcessState == nil {
		return r, errors.Join(err, waitErr, errors.New("UFW 原进程尚未确认结束，保留原执行许可待核对"))
	}
	r.Phase, r.ExitCode = "ended", -1
	if command.ProcessState != nil {
		r.ExitCode = command.ProcessState.ExitCode()
	}
	if permitted && r.ExitCode >= 0 {
		r.Outcome, r.OutputHash, r.DiagnosticHash = "exit", secure.Hash(stdout.data.Bytes()), secure.Hash(stderr.data.Bytes())
		r.OutputBytes, r.DiagnosticBytes = stdout.data.Len(), stderr.data.Len()
		if err != nil || waitErr != nil || call.Err() != nil || stdout.exceeded || stderr.exceeded || r.OutputBytes != 0 || r.DiagnosticBytes != 0 {
			r.Error = "UFW 固定重载进程失败、超时、返回输出或警告"
		}
	} else {
		r.Outcome, r.ExitCode, r.Error = "unknown", -1, "原 UFW 进程已经结束，但未取得成功结果；禁止重放"
		if !permitted {
			r.Outcome, r.Error = "not_started", "固定工具未获得完整执行许可"
		}
	}
	return r, errors.Join(err, waitErr, saveUFWRestore(dataDir, r), ufwRestoreResult(r))
}

// Killing a proven original PID removes delayed writes; it is not a rollback
// receipt. Unknown outcomes stay unknown and the parent transition still needs
// kernel inspection and compensation. A different boot/PID start is never killed.
func recoverUFWRestore(ctx context.Context, dataDir string) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-execution.lock")
	if err != nil {
		return err
	}
	defer unlock()
	r, err := loadUFWRestore(dataDir)
	if err != nil || r == nil {
		return err
	}
	machine, _, err := ufwHostIdentity()
	if err != nil || machine != r.MachineHash {
		return errors.New("UFW 子进程回执属于其他宿主机或主机范围不可核对")
	}
	if old, err := loadUFWReceipt(dataDir, r.ID); err == nil {
		if old.RequestHash != r.RequestHash || !ufwRestoreRecordMatches(old, old.UFWRestore) || r.Phase == "prepared" && old.UFWRestore.Phase != "prepared" || r.Phase != "ended" && old.UFWRestore.Phase == "ended" || r.Process != nil && old.UFWRestore.Process != nil && *r.Process != *old.UFWRestore.Process {
			return errors.New("UFW 私有检查点与原进程审计回执冲突")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if r.Phase == "ended" {
		return saveUFWRestore(dataDir, r)
	}
	if r.Process != nil && !networkdCallEnded(*r.Process) {
		fd, err := unix.PidfdOpen(int(r.Process.PID), 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		current, err := networkProcess(r.Process.PID)
		if err != nil || current != *r.Process {
			return errors.New("UFW 原进程身份变化，请重新核对同一回执")
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
				return errors.New("UFW 原进程尚未确认结束，不允许补偿")
			}
		}
	}
	r.Phase, r.ExitCode = "ended", -1
	r.Outcome, r.Error = "not_started", "原执行许可未发布，未重放固定工具"
	if r.Process != nil {
		r.Outcome, r.Error = "unknown", "原 UFW 进程已结束，执行结果未知；须由原业务操作核对与补偿"
	}
	return saveUFWRestore(dataDir, r)
}

func (f *hostFirewall) recoverUFWProcess(ctx context.Context) error {
	if err := recoverUFWChange(ctx, f.dataDir); err != nil {
		f.problem = ufwProcessProblem + err.Error()
		return err
	}
	if err := recoverUFWRestore(ctx, f.dataDir); err != nil {
		f.problem = ufwProcessProblem + err.Error()
		return err
	}
	if ufwRestorePending(f.dataDir) {
		err := errors.New("原 UFW 业务操作回执仍未完成，禁止新写入")
		f.problem = ufwProcessProblem + err.Error()
		return err
	}
	if strings.HasPrefix(f.problem, ufwProcessProblem) {
		f.problem = ""
	}
	return nil
}
