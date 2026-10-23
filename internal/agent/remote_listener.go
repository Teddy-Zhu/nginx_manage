package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/remotelisten"
	"nginxpanel/internal/secure"
)

const remoteListenerKind = "management.listener"

type listenerCheckpoint struct {
	Schema      int                     `json:"schema"`
	Version     int64                   `json:"version"`
	Confirmed   remotelisten.Config     `json:"confirmed"`
	Candidate   *remotelisten.Config    `json:"candidate"`
	Operation   *remotelisten.Operation `json:"operation"`
	RequestHash string                  `json:"request_hash"`
	LastRescue  string                  `json:"last_rescue"`
}
type listenerSocket struct {
	listener *net.TCPListener
	conn     *net.TCPConn
	version  int64
	source   string
}
type remoteListener struct {
	mu                   sync.Mutex
	dir, socket          string
	socketSELinuxContext string
	uid                  uint32
	available            bool
	journal              *Journal
	dns                  *HostDNS
	firewallPending      func() bool
	firewallCheck        func(context.Context, remotelisten.Config) error
	state                listenerCheckpoint
	deadline             time.Time
	problem              string
	fileLock             *os.File
	listener             *net.TCPListener
	listenAddress        string
	broker               *net.UnixListener
	web                  *net.UnixConn
	connections          map[string]listenerSocket
	wg                   sync.WaitGroup
	closed               bool
}

func listenerWrite(path string, value any) error { return rootJSONWrite(path, value, 64<<10) }

func rootJSONWrite(path string, value any, limit int) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > limit {
		return errors.New("独立恢复记录超出限制")
	}
	tmp := path + "." + secure.ID() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func listenerRead(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("监听私有记录权限无效")
	}
	return nginxmodules.ReadTrusted(path, limit)
}
func (m *remoteListener) save() error {
	if err := listenerWrite(filepath.Join(m.dir, "state.json"), m.state); err != nil {
		m.poison()
		return err
	}
	if op := m.state.Operation; op != nil {
		err := m.journal.Put(Record{Kind: remoteListenerKind, OperationID: op.ID, RequestHash: m.state.RequestHash, State: op.State, Stage: op.Stage, Deadline: op.Deadline, Error: op.Error, RemoteListener: op})
		if err != nil {
			m.poison()
			return err
		}
	}
	return nil
}
func (m *remoteListener) pendingLocked() bool { return m.state.Candidate != nil }
func (m *remoteListener) pending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pendingLocked() || m.problem != ""
}
func (m *remoteListener) poison() {
	m.problem = "独立监听恢复记录不可用；须本机检查存储"
	m.stopListening()
	m.closeConnections(0)
}
func (m *remoteListener) stopListening() {
	if m.listener != nil {
		m.listener.Close()
		m.listener = nil
		m.listenAddress = ""
	}
}
func (m *remoteListener) closeConnections(keepVersion int64) {
	for id, c := range m.connections {
		if keepVersion != 0 && c.version == keepVersion {
			continue
		}
		shutdownListenerConn(c.conn)
		delete(m.connections, id)
	}
}
func shutdownListenerConn(c *net.TCPConn) {
	if raw, err := c.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) { _ = unix.Shutdown(int(fd), unix.SHUT_RDWR) })
	}
	c.Close()
}
func (m *remoteListener) effective() remotelisten.Config {
	if m.state.Candidate != nil {
		return *m.state.Candidate
	}
	return m.state.Confirmed
}
func (m *remoteListener) expired() bool {
	return m.pendingLocked() && (time.Now().Unix() >= m.state.Operation.Deadline || !m.deadline.IsZero() && !time.Now().Before(m.deadline))
}

func (m *remoteListener) open() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = listenerCheckpoint{Schema: 1}
	m.connections = map[string]listenerSocket{}
	if !m.available {
		return nil
	}
	if err := secure.RootDirectory(m.dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(m.dir, "lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return err
	}
	m.fileLock = f
	raw, err := listenerRead(filepath.Join(m.dir, "state.json"), 64<<10)
	if err == nil {
		if json.Unmarshal(raw, &m.state) != nil || m.state.Schema != 1 || m.state.Version < 0 || m.state.Confirmed.Validate(false) != nil {
			return errors.New("独立监听恢复记录无效")
		}
		if op := m.state.Operation; op != nil {
			if !validID(op.ID) || op.Version != m.state.Version || m.state.RequestHash == "" || !(op.State == "waiting_confirmation" || op.State == "succeeded" || op.State == "rolled_back" || op.State == "recovery_required") {
				return errors.New("独立监听操作状态无效")
			}
		}
		if m.pendingLocked() && (m.state.Operation == nil || m.state.Candidate.Validate(false) != nil || m.state.Operation.State != "waiting_confirmation") {
			return errors.New("独立监听候选记录无效")
		}
		// An unconfirmed listener never survives an Agent restart, even if the
		// wall clock moved backwards or its former Web process is still alive.
		if m.pendingLocked() {
			m.state.Candidate = nil
			m.state.Operation.State = "rolled_back"
			m.state.Operation.Stage = "agent_restarted"
			m.state.Operation.Error = "Agent 重启，恢复已确认入口"
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = m.rescueLocked(); err != nil {
		return err
	}
	if err = m.reconcile(); err != nil {
		m.problem = "已确认监听无法恢复；请从主入口或本机救援处理"
		if op := m.state.Operation; op != nil && op.State == "rolled_back" {
			op.State = "recovery_required"
			op.Stage = "restore_failed"
			op.Error = m.problem
		}
	} else if op := m.state.Operation; op != nil && op.State == "recovery_required" {
		op.State = "rolled_back"
		op.Stage = "restored_after_restart"
		op.Error = "Agent 重启后已恢复已确认入口"
	}
	if err = m.save(); err != nil {
		return err
	}
	return m.openBroker()
}
func (m *remoteListener) reconcile() error {
	if m.closed {
		return errors.New("监听管理器已停止")
	}
	config := m.effective()
	if !config.Enabled {
		m.stopListening()
		return nil
	}
	if m.listener != nil && m.listenAddress == config.Listen {
		return nil
	}
	addr, err := net.ResolveTCPAddr("tcp", config.Listen)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	m.stopListening()
	m.listener = l
	m.listenAddress = config.Listen
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.acceptTCP(l) }()
	return nil
}
func (m *remoteListener) rollback(reason string) error {
	if !m.pendingLocked() {
		return nil
	}
	m.closeConnections(0)
	m.state.Candidate = nil
	m.state.Operation.State = "rolled_back"
	m.state.Operation.Stage = "restored"
	m.state.Operation.Error = reason
	if err := m.save(); err != nil {
		return err
	}
	if err := m.reconcile(); err != nil {
		m.stopListening()
		m.problem = "原监听地址无法恢复；请使用主入口或本机救援"
		m.state.Operation.State = "recovery_required"
		m.state.Operation.Stage = "restore_failed"
		m.state.Operation.Error = m.problem
		return m.save()
	}
	m.problem = ""
	return nil
}
func (m *remoteListener) view() remotelisten.View {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := remotelisten.View{Available: m.available, Version: m.state.Version, Confirmed: m.state.Confirmed.Public(), Serving: m.listener != nil, Attached: m.web != nil, Reason: m.problem}
	if m.state.Operation != nil {
		op := *m.state.Operation
		out.Operation = &op
	}
	if !m.available {
		out.Reason = "仅支持具有宿主机维护范围的生产 Agent"
	}
	return out
}
func (m *remoteListener) operation(id string) (remotelisten.Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.operationLocked(id)
}
func (m *remoteListener) operationLocked(id string) (remotelisten.Operation, error) {
	if m.state.Operation != nil && m.state.Operation.ID == id {
		return *m.state.Operation, nil
	}
	r, err := m.journal.Get(id)
	if err != nil {
		return remotelisten.Operation{}, err
	}
	if r.Kind != remoteListenerKind || r.RemoteListener == nil {
		return remotelisten.Operation{}, fault.Conflict("操作标识已被其他业务占用")
	}
	return *r.RemoteListener, nil
}
func listenerCertificate(listen string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "NginxPanel management"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	host, _, _ := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		leaf.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), nil
}
func (m *remoteListener) apply(ctx context.Context, id, hash string, in remotelisten.Input, connection string) (remotelisten.Operation, error) {
	// DNS and listener mutations take these locks in the same order. Their
	// recovery workers only need their own lock, so one cannot trap the other.
	m.dns.mu.Lock()
	defer m.dns.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available || m.closed {
		return remotelisten.Operation{}, fault.Unavailable("远程监听不可用")
	}
	if err := m.rescueLocked(); err != nil {
		return remotelisten.Operation{}, err
	}
	if old, err := m.journal.Get(id); err == nil {
		if old.Kind != remoteListenerKind || old.RequestHash != hash || old.RemoteListener == nil {
			return remotelisten.Operation{}, fault.Conflict("幂等键已用于其他请求")
		}
		return *old.RemoteListener, nil
	} else if !os.IsNotExist(err) {
		return remotelisten.Operation{}, err
	}
	if m.problem != "" || m.pendingLocked() || m.firewallPending != nil && m.firewallPending() || m.dns.checkpoint != nil && dnsActive(m.dns.checkpoint.Status.State) {
		return remotelisten.Operation{}, fault.Conflict("存在待恢复或待确认的可达性变更")
	}
	if in.Version != m.state.Version {
		return remotelisten.Operation{}, fault.Conflict("监听版本已变化，请刷新")
	}
	if in.Enabled && m.web == nil {
		return remotelisten.Operation{}, fault.Unavailable("应用尚未连接受控监听通道")
	}
	if !in.Enabled && connection != "" {
		return remotelisten.Operation{}, fault.Conflict("停用远程入口须从主入口执行")
	}
	config := remotelisten.Config{Enabled: in.Enabled, Listen: in.Listen, AllowedSources: in.AllowedSources, CertificatePEM: in.CertificatePEM, KeyPEM: in.KeyPEM}
	if config.Enabled && config.CertificatePEM == "" && config.KeyPEM == "" {
		if !in.RotateCertificate && m.state.Confirmed.CertificatePEM != "" {
			config.CertificatePEM = m.state.Confirmed.CertificatePEM
			config.KeyPEM = m.state.Confirmed.KeyPEM
		} else {
			var err error
			config.CertificatePEM, config.KeyPEM, err = listenerCertificate(in.Listen)
			if err != nil {
				return remotelisten.Operation{}, err
			}
		}
	} else if in.RotateCertificate {
		return remotelisten.Operation{}, fault.Invalid("自动换证不能同时上传证书")
	}
	if err := config.Validate(true); err != nil {
		return remotelisten.Operation{}, err
	}
	if m.firewallCheck != nil {
		if err := m.firewallCheck(ctx, config); err != nil {
			return remotelisten.Operation{}, err
		}
	}
	op := &remotelisten.Operation{ID: id, Version: m.state.Version + 1, State: "waiting_confirmation", Stage: "awaiting_connection", Deadline: time.Now().Unix() + remotelisten.ConfirmationSeconds, Config: config.Public()}
	m.state.Version = op.Version
	m.state.Operation = op
	m.state.RequestHash = hash
	if config.Enabled {
		m.state.Candidate = &config
		m.deadline = time.Now().Add(remotelisten.ConfirmationSeconds * time.Second)
	} else {
		op.State = "succeeded"
		op.Stage = "disabled"
		op.Deadline = 0
		m.state.Confirmed = config
	}
	if err := m.save(); err != nil {
		return *op, err
	}
	if !config.Enabled {
		m.closeConnections(0)
	}
	if err := m.reconcile(); err != nil {
		if e := m.rollback("新监听绑定失败，恢复原入口"); e != nil {
			return *op, e
		}
	}
	// The apply response closes its own HTTP connection. All other old
	// connections are revoked now, so a browser's next request uses new TLS.
	if m.pendingLocked() {
		for socketID, c := range m.connections {
			if socketID != connection {
				shutdownListenerConn(c.conn)
				delete(m.connections, socketID)
			}
		}
	}
	return *m.state.Operation, nil
}
func (m *remoteListener) decide(ctx context.Context, id, action, connection string) (remotelisten.Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return remotelisten.Operation{}, fault.Unavailable("远程监听已停止")
	}
	out, err := m.operationLocked(id)
	if err != nil {
		return out, err
	}
	if action != "confirm" && action != "rollback" {
		return out, fault.Invalid("监听决定无效")
	}
	if !m.pendingLocked() || m.state.Operation.ID != id {
		return out, nil
	}
	if action == "rollback" || m.expired() {
		err = m.rollback("未在期限内确认或已请求恢复")
		return *m.state.Operation, err
	}
	if m.problem != "" {
		return out, fault.Unavailable("独立监听恢复记录不可用，禁止确认")
	}
	c, ok := m.connections[connection]
	if !ok || c.version != m.state.Version || m.web == nil {
		return out, fault.Conflict("须通过新监听建立新的 TCP/TLS 连接后确认")
	}
	var checkErr error
	if m.firewallCheck != nil {
		deadline := time.Unix(m.state.Operation.Deadline, 0)
		if !m.deadline.IsZero() && m.deadline.Before(deadline) {
			deadline = m.deadline
		}
		checkCtx, cancel := context.WithDeadline(ctx, deadline)
		checkErr = m.firewallCheck(checkCtx, *m.state.Candidate)
		cancel()
	}
	if m.expired() {
		err = m.rollback("核对期间确认期限已到，恢复原入口")
		return *m.state.Operation, err
	}
	if checkErr != nil {
		return out, checkErr
	}
	before := m.state
	op := *m.state.Operation
	op.State = "succeeded"
	op.Stage = "confirmed"
	op.ConfirmedSource = c.source
	op.Error = ""
	m.state.Confirmed = *m.state.Candidate
	m.state.Candidate = nil
	m.state.Operation = &op
	if err = m.save(); err != nil {
		m.state = before
		return out, err
	}
	m.closeConnections(m.state.Version)
	return op, nil
}
func (m *remoteListener) run(ctx context.Context) {
	if !m.available {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			if m.pendingLocked() {
				_ = m.rollback("Agent 停止，恢复已确认入口")
			}
			m.mu.Unlock()
			return
		case <-ticker.C:
			m.mu.Lock()
			if err := m.rescueLocked(); err != nil {
				m.poison()
			}
			if m.expired() {
				_ = m.rollback("确认期限已到，恢复已确认入口")
			}
			m.mu.Unlock()
		}
	}
}
func (m *remoteListener) close() {
	m.mu.Lock()
	m.closed = true
	m.stopListening()
	m.closeConnections(0)
	if m.web != nil {
		m.web.Close()
	}
	if m.broker != nil {
		m.broker.Close()
	}
	m.mu.Unlock()
	m.wg.Wait()
	if m.fileLock != nil {
		m.fileLock.Close()
	}
}

// Rescue is a root-only durable request, independent of the Web, DB, TLS,
// authentication and Agent availability. The marker remains as an audit record.
func DisableRemoteListener(dataDir string) error {
	if os.Geteuid() != 0 {
		return errors.New("监听救援需要本机 root")
	}
	dir := filepath.Join(dataDir, "agent", "management-listener")
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	return listenerWrite(filepath.Join(dir, "rescue.json"), struct {
		ID string `json:"id"`
	}{secure.ID()})
}
func (m *remoteListener) rescueLocked() error {
	raw, err := listenerRead(filepath.Join(m.dir, "rescue.json"), 1024)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var rescue struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &rescue) != nil || !validID(rescue.ID) {
		return errors.New("监听救援记录无效")
	}
	if rescue.ID == m.state.LastRescue {
		return nil
	}
	m.closeConnections(0)
	m.stopListening()
	m.state.Candidate = nil
	m.state.Confirmed = remotelisten.Config{}
	m.state.Version++
	m.state.LastRescue = rescue.ID
	if m.state.Operation != nil {
		op := *m.state.Operation
		op.Version = m.state.Version
		op.State = "rolled_back"
		op.Stage = "local_rescue"
		op.Error = "本机救援已停用远程入口"
		m.state.Operation = &op
	}
	if err = m.save(); err != nil {
		return err
	}
	m.problem = ""
	return nil
}
