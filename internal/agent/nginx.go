package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
)

var ErrBusy = errors.New("仍有 Nginx 操作等待完成或恢复")
var ErrExternalChange = errors.New("受管配置存在外部修改，已停止应用")
var ErrRuntimeUnavailable = errors.New("专用 Nginx 实例未初始化或未运行")

// These paths and identities come only from the local root service definition.
// An API request cannot select an executable, prefix, worker identity or PID.
type Nginx struct {
	maintenance                 *maintenanceGate
	DataDir, Binary, WorkerUser string
	LogOwner                    string
	Policy                      nginxconfig.Policy
	Modules                     []nginxmodules.Approval
	Container                   *nginxcontainer.Runtime
	Journal                     *Journal
	mu                          sync.Mutex
	workers                     sync.WaitGroup
	closed                      bool
	observationOnly             bool
	disasterBusy                string
	unlock                      *os.File
	gid                         int
	uid                         int
	workerGroup                 string
	tempModules                 []string
	http01                      *http01Store
	logs                        *managedLogs
}

type ApplyRequest struct {
	Protocol         int                     `json:"protocol"`
	OperationID      string                  `json:"operation_id"`
	RevisionID       string                  `json:"revision_id"`
	ExpectedRevision string                  `json:"expected_revision"`
	ValidateOnly     bool                    `json:"validate_only"`
	Files            []nginxconfig.File      `json:"files"`
	Certificates     []certificates.Material `json:"certificates"`
	RestoreSnapshot  string                  `json:"restore_snapshot"`
	PreviousFiles    []nginxconfig.File      `json:"previous_files"`
}

type NginxState struct {
	Installed      bool   `json:"installed"`
	Available      bool   `json:"available"`
	RevisionID     string `json:"revision_id"`
	Integrity      bool   `json:"integrity"`
	Running        bool   `json:"running"`
	Reason         string `json:"reason"`
	ExternalChange bool   `json:"external_change"`
	DeploymentID   string `json:"deployment_id"`
}

type manifest struct {
	ClientDeny   map[string][]string         `json:"client_deny"`
	RevisionID   string                      `json:"revision_id"`
	DeploymentID string                      `json:"deployment_id"`
	SourceHash   string                      `json:"source_hash"`
	Probe        string                      `json:"probe"`
	Files        map[string]string           `json:"files"`
	Listeners    []listener                  `json:"listeners"`
	TLS          []tlsProbe                  `json:"tls"`
	Dependencies map[string]string           `json:"dependencies"`
	Modules      map[string]ModuleDependency `json:"modules"`
	HTTP01       map[string][]listener       `json:"http01"`
	Logs         []logSource                 `json:"logs"`
}

func (n *Nginx) configPath(dir string) string {
	return filepath.Join(n.DataDir, "nginx", "revisions", dir, "nginx.conf")
}
func (n *Nginx) activePath() string { return filepath.Join(n.DataDir, "nginx", "active") }
func revisionDir(id string) string {
	if id == "" {
		return "bootstrap"
	}
	return id
}

func trustedFile(name string, executable bool) (string, error) {
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("trusted file is unavailable")
	}
	if err := existingRootDirectory(filepath.Dir(resolved)); err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || (executable && info.Mode().Perm()&0111 == 0) {
		return "", errors.New("untrusted file ownership or permissions")
	}
	return resolved, nil
}

func (n *Nginx) setup() error {
	if os.Geteuid() != 0 {
		return errors.New("Nginx execution requires the root agent")
	}
	if !filepath.IsAbs(n.DataDir) || strings.ContainsAny(n.DataDir, " \t\x00\r\n\"\\") {
		return errors.New("invalid Nginx data directory")
	}
	var err error
	if n.Container == nil {
		n.Binary, err = trustedFile(n.Binary, true)
		if err != nil {
			return err
		}
	} else if n.Binary != "" || len(n.Modules) != 0 || len(n.Policy.ModulePaths) != 0 {
		return errors.New("容器 Nginx 不能同时接入宿主机程序或动态模块")
	}
	if n.WorkerUser == "" || strings.Trim(n.WorkerUser, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
		return errors.New("invalid Nginx worker identity")
	}
	identity, err := user.Lookup(n.WorkerUser)
	if err != nil || (identity.Uid == "0" || identity.Gid == "0") {
		return errors.New("a dedicated non-root Nginx worker account is required")
	}
	n.uid, err = strconv.Atoi(identity.Uid)
	if err != nil {
		return err
	}
	group, err := user.LookupGroupId(identity.Gid)
	if err != nil || strings.Trim(group.Name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
		return errors.New("invalid worker group")
	}
	n.workerGroup = group.Name
	n.gid, err = strconv.Atoi(identity.Gid)
	if err != nil {
		return err
	}
	if n.Container != nil {
		binding, err := nginxcontainer.Read(n.DataDir)
		if err != nil {
			return err
		}
		if !sameContainerBinding(binding, n.Container.Binding) || binding.UID != n.uid || binding.GID != n.gid {
			return errors.New("Nginx 容器登记与宿主机专用身份不一致")
		}
		features, err := containerFeatures(binding)
		if err != nil {
			return err
		}
		n.tempModules = features.httpTempModules
	} else {
		features := n.Features(context.Background())
		if !features.Available {
			return fmt.Errorf("无法确认 Nginx 临时目录所需的编译模块：%s", features.Reason)
		}
		n.tempModules = features.httpTempModules
	}
	if err := secure.RootDirectory(n.Journal.Dir, 0700); err != nil {
		return err
	}
	for _, dir := range []string{n.DataDir, filepath.Join(n.DataDir, "nginx"), filepath.Join(n.DataDir, "nginx", "revisions"), filepath.Join(n.DataDir, "run"), filepath.Join(n.DataDir, "logs"), filepath.Join(n.DataDir, "logs", "nginx-global")} {
		if err := secure.RootDirectory(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

// Initialize only writes a no-site baseline. Starting a service is an explicit
// installer action; initialization never stops or takes over a system instance.
func (n *Nginx) Initialize() error {
	if err := n.setup(); err != nil {
		return err
	}
	for _, dir := range []string{n.DataDir, filepath.Join(n.DataDir, "nginx"), filepath.Join(n.DataDir, "nginx", "revisions"), filepath.Join(n.DataDir, "run"), filepath.Join(n.DataDir, "logs"), filepath.Join(n.DataDir, "logs", "nginx-global")} {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		// Correctly initialized parents can be read-only in the worker sandbox.
		if info.Mode() == os.ModeDir|0755 {
			continue
		}
		if err := os.Chmod(dir, 0755); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(n.activePath()); err == nil {
		_, _, err = n.active()
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	parsed, err := nginxconfig.Parse(nginxconfig.InitialFiles(), n.Policy)
	if err != nil || len(parsed.Tree.Diagnostics) != 0 {
		return errors.New("invalid bootstrap configuration")
	}
	if _, err := n.prepare("", "", parsed, map[string]ModuleDependency{}); err != nil {
		return err
	}
	return n.switchTo("bootstrap", "")
}

func (n *Nginx) Open() error {
	if err := n.setup(); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(n.DataDir, "nginx", ".executor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return errors.New("another agent owns Nginx execution")
	}
	n.unlock = lock
	n.http01, err = openHTTP01Store(n.DataDir)
	if err != nil {
		n.Close()
		return err
	}
	n.logs, err = openManagedLogs(n)
	if err != nil {
		n.Close()
		return err
	}
	records, err := n.Journal.List()
	if err != nil {
		n.Close()
		return err
	}
	if _, err := clientDenyCheckpoint(records); err != nil {
		n.Close()
		return err
	}
	for _, record := range records {
		if record.Kind == clientDenyKind && pendingNginxRecord(record) {
			// A failed compensation remains durable and blocks new Nginx writes.
			_ = n.recoverClientDeny(record)
			continue
		}
		if record.DisasterRestoreID != "" {
			i, e := panelrecovery.ReadDisasterIntent(n.DataDir, record.DisasterRestoreID)
			if e == nil {
				e = validDisasterNginxRecord(i, record)
			}
			if e == nil {
				_, e = panelrecovery.ReadDisasterRuntimeApproval(i, false)
			}
			if e != nil {
				n.Close()
				return e
			}
		}
		if record.Kind == "nginx.restore" && (record.State == "running" || record.State == "compensating" || record.State == "recovery_required") {
			if record.Stage == "preparing" || record.Stage == "prepared" || record.Stage == "testing" {
				record.State, record.Stage, record.Error = "failed", "interrupted_before_switch", "恢复准备期间 Agent 重启，原发布指针未改变"
				if err := n.persist(record); err != nil {
					n.Close()
					return err
				}
			} else {
				n.executeRestore(record)
			}
			continue
		}
		if (record.Kind == "nginx.apply" || record.Kind == "nginx.validate") && (record.State == "running" || record.State == "compensating" || record.State == "recovery_required") {
			if record.Stage == "preparing" || record.Stage == "prepared" || record.Stage == "testing" || record.Kind == "nginx.validate" {
				record.State, record.Stage, record.Error = "failed", "interrupted_before_switch", "配置校验期间 Agent 重启，运行修订未改变"
				if err := n.persist(record); err != nil {
					n.Close()
					return err
				}
			} else {
				n.rollback(record)
			}
		}
	}
	return nil
}

func (n *Nginx) Close() {
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	n.workers.Wait()
	if n.logs != nil {
		n.logs.reader.Close()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.unlock != nil {
		unix.Flock(int(n.unlock.Fd()), unix.LOCK_UN)
		n.unlock.Close()
		n.unlock = nil
	}
}

func (n *Nginx) State(ctx context.Context) NginxState {
	s := NginxState{}
	n.mu.Lock()
	available := !n.closed && n.unlock != nil
	n.mu.Unlock()
	if !available {
		s.Reason = ErrRuntimeUnavailable.Error()
		return s
	}
	s.Available = true
	_, m, err := n.active()
	if err != nil {
		s.ExternalChange = errors.Is(err, ErrExternalChange)
		s.Reason = err.Error()
		return s
	}
	s.Integrity, s.RevisionID, s.DeploymentID = true, m.RevisionID, m.DeploymentID
	if err := n.observe(ctx, m); err != nil {
		s.Reason = "专用 Nginx 运行状态尚未确认"
		return s
	}
	s.Running = true
	return s
}

func (n *Nginx) Submit(in ApplyRequest) (Record, error) {
	return n.submit(in, "", "", "")
}

func (n *Nginx) submit(in ApplyRequest, disasterID, epoch, disasterBefore string) (Record, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.unlock == nil {
		return Record{}, ErrRuntimeUnavailable
	}
	if in.Protocol != Protocol || !validID(in.OperationID) || !validID(in.RevisionID) || (in.ExpectedRevision != "" && !validID(in.ExpectedRevision)) {
		return Record{}, errors.New("invalid operation contract")
	}
	if in.RestoreSnapshot != "" {
		if len(in.RestoreSnapshot) != 64 || in.ValidateOnly || len(in.PreviousFiles) == 0 {
			return Record{}, errors.New("invalid restoration contract")
		}
	} else if len(in.PreviousFiles) > 0 {
		return Record{}, errors.New("unexpected previous source tree")
	}
	encoded, err := json.Marshal(in)
	if err != nil {
		return Record{}, err
	}
	digest := secure.Hash(encoded)
	if old, err := n.Journal.Get(in.OperationID); err == nil {
		if old.RequestHash != digest || old.DisasterRestoreID != disasterID {
			return Record{}, errors.New("operation ID conflicts with a different request")
		}
		return old, nil
	} else if !os.IsNotExist(err) {
		return Record{}, err
	}
	// Upgrade admission uses this same lock and is limited to these host data
	// directories. Keep its fence check atomic with publication admission.
	if fail2banManagedData(n.DataDir) {
		unlock, e := (&Journal{Dir: fail2banBindingDir(n.DataDir)}).rootLock("binding.lock")
		if e != nil {
			return Record{}, e
		}
		defer unlock()
	}
	if err = fail2banUpgradeRunIdle(n.DataDir, ""); err != nil {
		return Record{}, err
	}
	if err = fail2banUpgradeRestoreIdle(n.DataDir, ""); err != nil {
		return Record{}, err
	}
	if err = fail2banUpgradeQuiesceIdle(n.DataDir, ""); err != nil {
		return Record{}, err
	}
	if err = fail2banUpgradeActivationIdle(n.DataDir, ""); err != nil {
		return Record{}, err
	}
	if disasterID != "" && n.disasterBusy != "" {
		return Record{}, ErrBusy
	}
	if n.http01 != nil && n.http01.busy() {
		return Record{}, errors.New("HTTP-01 验证进行中，暂不能切换或检查 Nginx 配置")
	}
	records, err := n.Journal.List()
	if err != nil {
		return Record{}, err
	}
	for _, record := range records {
		if strings.HasPrefix(record.Kind, "nginx.") && (record.State == "running" || record.State == "compensating" || record.State == "recovery_required") {
			return Record{}, ErrBusy
		}
	}
	var before string
	var current manifest
	if in.RestoreSnapshot != "" {
		snapshot, inspectErr := n.inspectLocked(InspectRequest{Protocol: Protocol, RevisionID: in.ExpectedRevision, Files: in.PreviousFiles})
		if inspectErr != nil {
			return Record{}, inspectErr
		}
		if !snapshot.Complete || snapshot.Integrity || snapshot.Snapshot != in.RestoreSnapshot {
			return Record{}, ErrExternalChange
		}
		before, current, err = n.activeMetadata()
	} else {
		before, current, err = n.active()
	}
	if err != nil {
		return Record{}, err
	}
	if disasterID != "" && before != disasterBefore {
		return Record{}, ErrExternalChange
	}
	if current.RevisionID != in.ExpectedRevision {
		return Record{}, errors.New("当前运行修订与请求基础不一致")
	}
	parsed, err := nginxconfig.Parse(in.Files, n.Policy)
	if err != nil || len(parsed.Tree.Diagnostics) > 0 {
		return Record{}, errors.New("Agent 安全策略拒绝配置树")
	}
	kind := "nginx.apply"
	if in.ValidateOnly {
		kind = "nginx.validate"
	}
	if in.RestoreSnapshot != "" {
		kind = "nginx.restore"
	}
	record := Record{OperationID: in.OperationID, RequestHash: digest, Kind: kind, BeforeRevision: current.RevisionID, AfterRevision: in.RevisionID, BeforeDir: before, AfterDir: in.OperationID, RestoreSnapshot: in.RestoreSnapshot, State: "running", Stage: "preparing"}
	record.DisasterRestoreID = disasterID
	if disasterID != "" {
		record.MaintenanceEpoch = epoch
	}
	if err := n.persist(record); err != nil {
		return Record{}, err
	}
	if err := n.prepareCertificates(parsed, in.Certificates); err != nil {
		record.State, record.Stage, record.Error = "failed", "certificate_prepare_failed", "证书材料、域名覆盖或不可变版本校验失败；运行修订未改变"
		if putErr := n.persist(record); putErr != nil {
			return Record{}, putErr
		}
		return record, nil
	}
	modules, err := n.prepareModules(parsed)
	if err != nil {
		record.State, record.Stage, record.Error = "failed", "module_prepare_failed", "模块批准、散列、二进制绑定或不可变副本校验失败；运行修订未改变"
		if putErr := n.persist(record); putErr != nil {
			return Record{}, putErr
		}
		return record, nil
	}
	candidate, err := n.prepare(in.RevisionID, record.AfterDir, parsed, modules)
	if err != nil {
		record.State, record.Stage, record.Error = "failed", "prepare_failed", "无法生成不可变候选配置"
		if putErr := n.persist(record); putErr != nil {
			return Record{}, putErr
		}
		return record, nil
	}
	record.Stage, record.CandidateHash = "prepared", manifestHash(candidate)
	if err := n.persist(record); err != nil {
		return Record{}, err
	}
	n.workers.Add(1)
	if disasterID != "" {
		n.disasterBusy = in.OperationID
	}
	go func() {
		defer n.workers.Done()
		if disasterID != "" {
			defer func() { n.mu.Lock(); n.disasterBusy = ""; n.mu.Unlock() }()
		}
		n.execute(record)
	}()
	return record, nil
}

func (n *Nginx) execute(record Record) {
	if record.Kind == "nginx.restore" {
		n.executeRestore(record)
		return
	}
	fail := func(stage, message string) {
		record.State, record.Stage, record.Error = "failed", stage, message
		n.persist(record)
	}
	record.Stage = "testing"
	if n.persist(record) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	err := n.test(ctx, record.AfterDir)
	cancel()
	if err != nil {
		fail("nginx_test_failed", "Nginx 配置校验失败；运行修订未改变")
		return
	}
	if record.Kind == "nginx.validate" {
		record.State, record.Stage = "succeeded", "nginx_tested"
		n.persist(record)
		return
	}
	before, current, err := n.active()
	if err != nil || before != record.BeforeDir || current.RevisionID != record.BeforeRevision {
		fail("external_conflict", ErrExternalChange.Error())
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	err = n.observe(ctx, current)
	cancel()
	if err != nil {
		fail("runtime_unconfirmed", "发布前无法确认旧修订，已停止应用")
		return
	}
	candidate, err := n.readManifest(record.AfterDir)
	if err != nil || manifestHash(candidate) != record.CandidateHash {
		fail("external_conflict", ErrExternalChange.Error())
		return
	}
	if record.BeforeDir == record.AfterDir {
		record.State, record.Stage, record.ObservedRevision = "succeeded", "runtime_confirmed", record.AfterRevision
		_ = n.persist(record)
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	err = n.checkListenerAvailability(ctx, candidate)
	cancel()
	if err != nil {
		fail("listener_unavailable", "发布前监听端口检查未通过，原发布指针未改变："+err.Error())
		return
	}
	// Persist intent before the pointer changes. Recovery treats every later
	// stage as potentially applied, even if a crash occurred before rename.
	record.Stage = "switch_pending"
	if n.persist(record) != nil {
		return
	}
	if err := n.switchTo(record.AfterDir, record.BeforeDir); err != nil {
		n.rollback(record)
		return
	}
	record.Stage = "switched"
	if n.persist(record) != nil {
		n.rollback(record)
		return
	}
	if err := n.reload(); err != nil {
		n.rollback(record)
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	err = n.waitObserved(ctx, candidate)
	cancel()
	if err != nil {
		n.rollback(record)
		return
	}
	active, verified, err := n.active()
	if err != nil || active != record.AfterDir || manifestHash(verified) != record.CandidateHash {
		n.rollback(record)
		return
	}
	record.State, record.Stage, record.ObservedRevision = "succeeded", "runtime_confirmed", record.AfterRevision
	if err := n.persist(record); err != nil {
		n.rollback(record)
	}
}

func (n *Nginx) rollback(record Record) {
	record.State, record.Stage = "compensating", "rollback_pending"
	if n.persist(record) != nil {
		return
	}
	failed := func() {
		record.State, record.Stage, record.Error = "recovery_required", "rollback_unconfirmed", "无法确认 Nginx 回滚结果，需要本机恢复"
		n.persist(record)
	}
	before, err := n.readManifest(record.BeforeDir)
	if err != nil || before.RevisionID != record.BeforeRevision {
		failed()
		return
	}
	active, err := os.Readlink(n.activePath())
	if err != nil {
		failed()
		return
	}
	if active != filepath.Join("revisions", record.BeforeDir) && active != filepath.Join("revisions", record.AfterDir) {
		failed()
		return
	}
	if active != filepath.Join("revisions", record.BeforeDir) {
		if err := n.switchTo(record.BeforeDir, record.AfterDir); err != nil {
			failed()
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = n.observe(ctx, before)
	cancel()
	if err != nil {
		if err := n.reload(); err != nil {
			failed()
			return
		}
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
		err = n.waitObserved(ctx, before)
		cancel()
		if err != nil {
			failed()
			return
		}
	}
	activeDir, verified, err := n.active()
	if err != nil || activeDir != record.BeforeDir || manifestHash(verified) != manifestHash(before) {
		failed()
		return
	}
	record.State, record.Stage, record.Error, record.ObservedRevision = "rolled_back", "rollback_confirmed", "新配置未确认生效，已恢复上一受管修订", record.BeforeRevision
	if record.DisasterRestoreID != "" {
		record.Error = "已按原恢复批准回滚 Nginx，原运行修订已确认"
	}
	n.persist(record)
}

func (n *Nginx) test(ctx context.Context, dir string) error {
	if n.Container != nil {
		if _, err := n.readManifest(dir); err != nil {
			return err
		}
		return n.Container.Test(ctx, dir)
	}
	if _, err := trustedFile(n.Binary, true); err != nil {
		return err
	}
	if _, err := n.readManifest(dir); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, n.Binary, "-t", "-q", "-p", n.DataDir+"/", "-c", n.configPath(dir), "-e", "stderr")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

func (n *Nginx) active() (string, manifest, error) {
	dir, m, err := n.activeMetadata()
	if err != nil {
		return dir, m, err
	}
	m, err = n.readManifest(dir)
	return dir, m, err
}

func (n *Nginx) activeMetadata() (string, manifest, error) {
	target, err := os.Readlink(n.activePath())
	if err != nil {
		return "", manifest{}, ErrRuntimeUnavailable
	}
	dir := strings.TrimPrefix(target, "revisions/")
	if target != "revisions/"+dir || (dir != "bootstrap" && !validID(dir)) {
		return "", manifest{}, ErrExternalChange
	}
	m, err := n.manifestMetadata(dir)
	return dir, m, err
}

func (n *Nginx) manifestMetadata(dir string) (manifest, error) {
	var m manifest
	if dir != "bootstrap" && !validID(dir) {
		return m, ErrExternalChange
	}
	root := filepath.Dir(n.configPath(dir))
	if err := existingRootDirectory(root); err != nil {
		return m, ErrExternalChange
	}
	metadata := filepath.Join(root, ".nginxpanel.json")
	if resolved, err := trustedFile(metadata, false); err != nil || resolved != metadata {
		return m, ErrExternalChange
	}
	info, err := os.Stat(metadata)
	if err != nil || info.Size() > 256<<10 {
		return m, ErrExternalChange
	}
	b, err := os.ReadFile(metadata)
	if err != nil || len(b) > 256<<10 {
		return m, ErrExternalChange
	}
	if err := json.Unmarshal(b, &m); err != nil || revisionDir(m.DeploymentID) != dir || m.RevisionID != "" && !validID(m.RevisionID) || m.Probe == "" {
		return m, ErrExternalChange
	}
	if len(m.Files) == 0 || len(m.Files) > limits.Files || len(m.Dependencies) > limits.CertificateReferences || len(m.Modules) > limits.NginxModules {
		return m, ErrExternalChange
	}
	if !moduleHeader(m.Modules) || !validHTTP01Bindings(m.HTTP01) || !validLogSources(m.Logs) || !validClientDenyBindings(m.ClientDeny) {
		return m, ErrExternalChange
	}
	return m, nil
}

func (n *Nginx) readManifest(dir string) (manifest, error) {
	m, err := n.manifestMetadata(dir)
	if err != nil {
		return m, err
	}
	root := filepath.Dir(n.configPath(dir))
	seen := 0
	entries := 0
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		entries++
		if entries > limits.Files*4 {
			return ErrExternalChange
		}
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return ErrExternalChange
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || stat.Nlink != 1 {
			return ErrExternalChange
		}
		rel, _ := filepath.Rel(root, name)
		if rel == ".nginxpanel.json" {
			return nil
		}
		want, ok := m.Files[rel]
		if !ok || info.Size() > limits.NginxRuntimeFileBytes {
			return ErrExternalChange
		}
		data, err := os.ReadFile(name)
		if err != nil || secure.Hash(data) != want {
			return ErrExternalChange
		}
		seen++
		return nil
	})
	if err != nil || seen != len(m.Files) {
		return m, ErrExternalChange
	}
	for name, want := range m.Dependencies {
		b, err := n.certificateFile(name)
		if err != nil || secure.Hash(b) != want {
			return m, ErrExternalChange
		}
	}
	if err := n.verifyModules(m.Modules); err != nil {
		return m, ErrExternalChange
	}
	if len(m.ClientDeny) > 0 {
		if _, _, err := n.readClientDenySnapshot(); err != nil {
			return m, ErrExternalChange
		}
	}
	return m, nil
}

func manifestHash(m manifest) string { b, _ := json.Marshal(m); return secure.Hash(b) }

func (n *Nginx) sourceHash(p *nginxconfig.Parsed) string {
	policy := n.Policy
	// Adding another approved version must not change the source identity of a
	// publication which does not use it. Revoked paths still fail parsing.
	policy.ModulePaths = p.Tree.ModulePaths
	source, _ := json.Marshal(struct {
		Files         []nginxconfig.File
		Policy        nginxconfig.Policy
		Worker, Group string
		Renderer      int
		Runtime       string
	}{p.Tree.Files, policy, n.WorkerUser, n.workerGroup, 8, n.runtimeIdentity()})
	return secure.Hash(source)
}

func (n *Nginx) prepare(id, deployment string, p *nginxconfig.Parsed, modules map[string]ModuleDependency) (manifest, error) {
	digest := n.sourceHash(p)
	dir := revisionDir(deployment)
	if _, err := os.Lstat(filepath.Dir(n.configPath(dir))); err == nil {
		m, err := n.readManifest(dir)
		if err != nil || m.SourceHash != digest || m.RevisionID != id {
			return m, ErrExternalChange
		}
		return m, nil
	} else if !os.IsNotExist(err) {
		return manifest{}, err
	}
	m := manifest{RevisionID: id, DeploymentID: deployment, SourceHash: digest, Probe: secure.Token(), Files: map[string]string{}, Listeners: []listener{}, TLS: []tlsProbe{}, Modules: modules}
	contents, err := n.render(p, &m, nil)
	if err != nil {
		return m, err
	}
	entries, err := os.ReadDir(filepath.Join(n.DataDir, "nginx", "revisions"))
	if err != nil {
		return m, err
	}
	if len(entries) >= limits.PublishedRevisions {
		return m, errors.New("published revision quota reached")
	}
	tmp := filepath.Join(n.DataDir, "nginx", "revisions", ".tmp-"+secure.ID())
	if err := os.Mkdir(tmp, 0750); err != nil {
		return m, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chown(tmp, 0, n.gid); err != nil {
		return m, err
	}
	if err := os.Chmod(tmp, 0750); err != nil {
		return m, err
	}
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := []byte(contents[name])
		m.Files[name] = secure.Hash(data)
		parent := filepath.Dir(filepath.Join(tmp, name))
		if err := os.MkdirAll(parent, 0750); err != nil {
			return m, err
		}
		for at := parent; at != tmp; at = filepath.Dir(at) {
			if err := os.Chown(at, 0, n.gid); err != nil {
				return m, err
			}
			if err := os.Chmod(at, 0750); err != nil {
				return m, err
			}
		}
		if err := durableFile(filepath.Join(tmp, name), data, 0640, n.gid); err != nil {
			return m, err
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	if len(b) > 256<<10 {
		return m, errors.New("published manifest exceeds limit")
	}
	if err := durableFile(filepath.Join(tmp, ".nginxpanel.json"), b, 0600, 0); err != nil {
		return m, err
	}
	if err := syncTree(tmp); err != nil {
		return m, err
	}
	if err := os.Rename(tmp, filepath.Dir(n.configPath(dir))); err != nil {
		return m, err
	}
	return m, syncDir(filepath.Dir(tmp))
}

func durableFile(name string, b []byte, mode fs.FileMode, gid int) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chown(0, gid); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
func syncDir(name string) error {
	dir, err := os.Open(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func syncTree(root string) error {
	return filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return syncDir(name)
		}
		return nil
	})
}
func (n *Nginx) switchTo(id, expected string) error {
	if id != "bootstrap" && !validID(id) {
		return ErrExternalChange
	}
	if expected != "" {
		target, err := os.Readlink(n.activePath())
		if err != nil || target != filepath.Join("revisions", expected) {
			return ErrExternalChange
		}
	} else if _, err := os.Lstat(n.activePath()); !os.IsNotExist(err) {
		return ErrExternalChange
	}
	tmp := filepath.Join(n.DataDir, "nginx", ".active-"+secure.ID())
	if err := os.Symlink(filepath.Join("revisions", id), tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, n.activePath()); err != nil {
		return err
	}
	return syncDir(filepath.Dir(n.activePath()))
}

func (n *Nginx) reload() error {
	if _, _, err := n.active(); err != nil {
		return err
	}
	pid, err := n.masterPID()
	if err != nil {
		return err
	}
	handle, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	defer unix.Close(handle)
	confirmed, err := n.masterPID()
	if err != nil || confirmed != pid {
		return ErrRuntimeUnavailable
	}
	return unix.PidfdSendSignal(handle, unix.SIGHUP, nil, 0)
}

func (n *Nginx) masterPID() (int, error) {
	if n.Container != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if n.observationOnly {
			return n.Container.ObserveMaster(ctx)
		}
		return n.Container.Master(ctx)
	}
	name := filepath.Join(n.DataDir, "run", "nginx.pid")
	if _, err := trustedFile(name, false); err != nil {
		return 0, ErrRuntimeUnavailable
	}
	info, err := os.Stat(name)
	if err != nil || info.Size() > 64 {
		return 0, ErrRuntimeUnavailable
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return 0, ErrRuntimeUnavailable
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0, ErrRuntimeUnavailable
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || exe != n.Binary {
		return 0, ErrRuntimeUnavailable
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return 0, ErrRuntimeUnavailable
	}
	command := strings.TrimRight(string(cmdline), "\x00")
	fields := strings.Fields(command)
	prefix, config := "", ""
	for i, field := range fields {
		if i+1 < len(fields) {
			if field == "-p" {
				prefix = fields[i+1]
			}
			if field == "-c" {
				config = fields[i+1]
			}
		}
	}
	if !strings.HasPrefix(command, "nginx: master process ") || filepath.Clean(prefix) != n.DataDir || config != filepath.Join(n.activePath(), "nginx.conf") {
		return 0, ErrRuntimeUnavailable
	}
	return pid, nil
}

func (n *Nginx) persist(record Record) error {
	err := n.Journal.Put(record)
	if err != nil {
		slog.Error("persist Nginx operation", "operation_id", record.OperationID, "stage", record.Stage, "error", err)
	}
	return err
}
func existingRootDirectory(name string) error {
	if !filepath.IsAbs(name) {
		return errors.New("trusted directory must be absolute")
	}
	current := "/"
	for _, part := range strings.Split(filepath.Clean(name), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrExternalChange
		}
	}
	return nil
}
