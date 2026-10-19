package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

const Protocol = protocol.Agent

type CheckRequest struct {
	Protocol    int                `json:"protocol"`
	OperationID string             `json:"operation_id"`
	RevisionID  string             `json:"revision_id"`
	Files       []nginxconfig.File `json:"files"`
}
type CheckResult struct {
	Protocol      int                      `json:"protocol"`
	PolicyVersion string                   `json:"policy_version"`
	Stage         string                   `json:"stage"`
	Diagnostics   []nginxconfig.Diagnostic `json:"diagnostics"`
}
type Server struct {
	Socket           string
	AllowedUID       uint32
	Policy           nginxconfig.Policy
	Journal          *Journal
	Nginx            *Nginx
	Dev              bool
	MaintenanceScope string
	MetricsScope     string
	DataDir          string
	DNSOwner         string
	DNSScope         string
	FirewallScope    string
	FirewallOwner    string
	FirewallSSH      string
	ComponentScope   string
	ReleaseTrust     string
	ReleaseToken     string
	Installation     *nginxruntime.Installation
	historyReads     atomic.Int32
	eventLogs        *eventLogStore
	logReader        *logs.Reader
	fail2banJails    *fail2banJailsExecutor
	fail2banNginx    *fail2banNginxExecutor
	fail2banHostSync *fail2banHostSyncExecutor
}

func (s *Server) Run(ctx context.Context) error {
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if !s.Dev && s.AllowedUID == 0 {
		return errors.New("production Web peer must be a non-root account")
	}
	if !s.Dev && os.Geteuid() != 0 {
		return errors.New("production agent must run as root")
	}
	if !s.Dev {
		if err := secure.RootDirectory(filepath.Dir(s.Socket), 0750); err != nil {
			return err
		}
		if err := secure.RootDirectory(s.Journal.Dir, 0700); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0750); err != nil {
		return err
	}
	if info, err := os.Lstat(s.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("agent socket path is not a socket")
		}
		conn, err := net.DialTimeout("unix", s.Socket, time.Second)
		if err == nil {
			conn.Close()
			return errors.New("agent is already running")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return fmt.Errorf("inspect previous agent socket: %w", err)
		}
		if err := os.Remove(s.Socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer l.Close()
	if err := os.Chmod(s.Socket, 0660); err != nil {
		return err
	}
	rootMaintenance := &maintenanceGate{journal: s.Journal, scope: s.MaintenanceScope, dev: s.Dev, nginx: s.Nginx}
	if err := rootMaintenance.open(); err != nil {
		return err
	}
	if s.Nginx != nil {
		s.Nginx.maintenance = rootMaintenance
	}
	if s.Nginx != nil {
		if s.Dev {
			return errors.New("development agent cannot execute Nginx")
		}
		if err := s.Nginx.Open(); err != nil {
			return err
		}
		defer s.Nginx.Close()
		if s.Nginx.uid == int(s.AllowedUID) {
			return errors.New("Nginx workers and Web must use separate accounts")
		}
		logContext, stopLogs := context.WithCancel(ctx)
		logsDone := make(chan struct{})
		go func() { defer close(logsDone); s.Nginx.RunLogs(logContext) }()
		defer func() { stopLogs(); <-logsDone }()
	}
	var challengeServer *http.Server
	challengeErrors := make(chan error, 1)
	stopFail2banNginx, err := s.startFail2banNginx(ctx, cancelRun, challengeErrors)
	if err != nil {
		return err
	}
	defer stopFail2banNginx()
	stopHostSync, err := s.startFail2banHostSync(ctx, rootMaintenance, cancelRun, challengeErrors)
	if err != nil {
		return err
	}
	defer stopHostSync()
	stopUpgradeRecovery := s.startFail2banUpgradeRecovery(ctx, rootMaintenance)
	defer stopUpgradeRecovery()
	stopJails, err := s.startFail2banJails(ctx, rootMaintenance, cancelRun, challengeErrors)
	if err != nil {
		return err
	}
	defer stopJails()
	if s.Nginx != nil {
		var challengeListener *net.UnixListener
		challengeServer, challengeListener, err = s.Nginx.http01Server()
		if err != nil {
			return err
		}
		defer challengeListener.Close()
		defer challengeServer.Close()
		go func() {
			err := challengeServer.Serve(&credentialListener{UnixListener: challengeListener, uid: uint32(s.Nginx.uid)})
			if !errors.Is(err, http.ErrServerClosed) {
				challengeErrors <- err
				cancelRun()
			}
		}()
	}
	mux := http.NewServeMux()
	componentManager := &components.Manager{DataDir: s.DataDir, Dir: filepath.Join(s.DataDir, "agent", "components"), TrustPath: s.ReleaseTrust, TokenPath: s.ReleaseToken, Scope: s.ComponentScope, Dev: s.Dev}
	defer componentManager.Close()
	if err := componentManager.Open(ctx); err != nil {
		return err
	}
	rootMaintenance.components = componentManager
	s.maintenanceHandlers(mux, rootMaintenance)
	s.runtimeHistoryHandlers(mux)
	s.componentHandlers(mux, componentManager)
	s.installationHandlers(mux)
	s.nginxSwitchHandlers(mux)
	s.panelUpdateHandlers(mux)
	s.agentUpgradeHandlers(mux)
	s.panelImageHandlers(mux)
	cleanupCtx, stopCleanup := context.WithCancel(ctx)
	cleanupDone := make(chan struct{})
	go func() { defer close(cleanupDone); s.runPanelUpdateCleanup(cleanupCtx) }()
	defer func() { stopCleanup(); <-cleanupDone }()
	dns := &HostDNS{Dir: filepath.Join(s.DataDir, "agent", "reachability"), Owner: s.DNSOwner, Scope: s.DNSScope, Dev: s.Dev, Journal: s.Journal}
	defer dns.Close()
	if err := dns.Open(); err != nil {
		return err
	}
	remote := &remoteListener{dir: filepath.Join(s.DataDir, "agent", "management-listener"), socket: s.Socket + ".remote", uid: s.AllowedUID, available: !s.Dev && s.MaintenanceScope == "host", journal: s.Journal, dns: dns}
	defer remote.close()
	if err := remote.open(); err != nil {
		return err
	}
	fw := &hostFirewall{dataDir: s.DataDir, sshMode: s.FirewallSSH, owner: s.FirewallOwner, available: !s.Dev && s.FirewallScope == "host" && (s.FirewallOwner == "direct-nftables" || s.FirewallOwner == "firewalld") && (s.FirewallSSH == "openssh" || s.FirewallSSH == "none") && s.MaintenanceScope == "host", journal: s.Journal, remote: remote, dns: dns}
	defer fw.Close()
	fw.ufwPlanning = !s.Dev && s.FirewallScope == "host" && s.FirewallOwner == "ufw" && (s.FirewallSSH == "openssh" || s.FirewallSSH == "none") && s.MaintenanceScope == "host"
	fw.iptablesPlanning = !s.Dev && s.FirewallScope == "host" && validIPTablesBackend(s.FirewallOwner) && (s.FirewallSSH == "openssh" || s.FirewallSSH == "none") && s.MaintenanceScope == "host"
	if err := fw.Open(); err != nil {
		return err
	}
	remote.firewallPending = fw.pending
	rootMaintenance.mu.Lock()
	rootMaintenance.firewall = fw
	rootMaintenance.mu.Unlock()
	remote.firewallCheck = fw.checkListener
	dns.ReachabilityBlocked = func() bool { return remote.pending() || fw.pending() }
	s.firewallRuntimeHandlers(mux, fw)
	s.listenerHandlers(mux, remote)
	remoteCtx, stopRemote := context.WithCancel(ctx)
	remoteDone := make(chan struct{})
	go func() { defer close(remoteDone); remote.run(remoteCtx) }()
	defer func() { stopRemote(); <-remoteDone }()
	dnsCtx, stopDNS := context.WithCancel(ctx)
	dnsDone := make(chan struct{})
	go func() { defer close(dnsDone); dns.Run(dnsCtx) }()
	defer func() { stopDNS(); <-dnsDone }()
	fwCtx, stopFirewall := context.WithCancel(ctx)
	fwDone := make(chan struct{})
	go func() { defer close(fwDone); fw.Run(fwCtx) }()
	defer func() { stopFirewall(); <-fwDone }()
	s.dnsHandlers(mux, dns, ctx)
	s.http01Handlers(mux)
	if !s.Dev {
		s.eventLogs, err = openEventLogs(s)
		if err != nil {
			slog.Warn("Managed event log initialization failed", "error", err)
		}
	}
	s.logReader = logs.NewReader(s.logSnapshot, s.openCatalogLog)
	defer s.logReader.Close()
	eventCtx, stopEventLogs := context.WithCancel(ctx)
	eventDone := make(chan struct{})
	go func() { defer close(eventDone); s.runEventLogs(eventCtx) }()
	defer func() { stopEventLogs(); <-eventDone }()
	s.logHandlers(mux)
	sampler := &metricSampler{ctx: ctx, capability: platform.MetricsCapability(s.MetricsScope, s.Dev), collector: platform.MetricsCollector{DataDir: s.DataDir}}
	s.monitoringHandlers(mux, sampler)
	firewallObserver := s.firewallHandlers(mux, ctx)
	s.fail2banHostInputHandlers(mux, ctx, firewallObserver)
	s.fail2banHandlers(mux, ctx)
	loginLog := panelLoginLog{server: s}
	if loginLog.available() {
		if err := loginLog.prepare(); err != nil {
			slog.Warn("Panel login log initialization failed", "error", err)
		}
	}
	loginLog.handlers(mux)
	s.fail2banJailsHandlers(mux)
	s.fail2banAddressHandlers(mux)
	lifecycle := &fail2banLifecycle{server: s, gate: rootMaintenance}
	lifecycle.handlers(mux)
	lifecycleCtx, stopLifecycle := context.WithCancel(ctx)
	lifecycleDone := make(chan struct{})
	go func() { defer close(lifecycleDone); lifecycle.run(lifecycleCtx) }()
	defer func() { stopLifecycle(); <-lifecycleDone }()
	pythonTasks := &fail2banPythonTasks{server: s, gate: rootMaintenance}
	pythonTasks.handlers(mux)
	pythonCtx, stopPython := context.WithCancel(ctx)
	pythonDone := make(chan struct{})
	go func() { defer close(pythonDone); pythonTasks.run(pythonCtx) }()
	defer func() { stopPython(); <-pythonDone }()
	upgradeTasks := &fail2banUpgradeTasks{server: s, gate: rootMaintenance}
	upgradeTasks.handlers(mux)
	upgradeCtx, stopUpgrade := context.WithCancel(ctx)
	upgradeDone := make(chan struct{})
	go func() { defer close(upgradeDone); upgradeTasks.run(upgradeCtx) }()
	defer func() { stopUpgrade(); <-upgradeDone }()
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		report := platform.Detect()
		report.Source = "host-agent"
		if s.Dev {
			report.Source = "development-agent"
		}
		report.Monitoring = sampler.capability
		dnsState := dns.Read()
		report.DNS.CandidateOwner = dnsState.Owner
		report.DNS.Writable = dnsState.Writable
		report.DNS.Reason = dnsState.Reason
		report.DNS.LinkTarget = dnsState.LinkTarget
		writeJSON(w, report)
	})
	mux.HandleFunc("GET /v1/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		record, err := s.Journal.Get(r.PathValue("id"))
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "operation not found", 404)
			} else {
				http.Error(w, "operation journal unavailable", 500)
			}
			return
		}
		writeJSON(w, record)
	})
	mux.HandleFunc("POST /v1/nginx/policy-check", s.check)
	mux.HandleFunc("POST /v1/nginx/apply", s.apply)
	mux.HandleFunc("POST /v1/nginx/disaster", s.disasterNginx)
	mux.HandleFunc("POST /v1/nginx/inspect", s.inspect)
	mux.HandleFunc("GET /v1/nginx/features", func(w http.ResponseWriter, r *http.Request) {
		if s.Nginx == nil {
			writeJSON(w, NginxFeatures{Features: map[string]Feature{}, Modules: []NativeModule{}, Reason: "专用 Nginx 执行尚未配置"})
			return
		}
		writeJSON(w, s.Nginx.Features(r.Context()))
	})
	mux.HandleFunc("GET /v1/nginx/state", func(w http.ResponseWriter, r *http.Request) {
		if s.Nginx == nil {
			writeJSON(w, NginxState{Reason: "专用 Nginx 执行尚未配置"})
			return
		}
		writeJSON(w, s.Nginx.State(r.Context()))
	})
	server := &http.Server{Handler: rootMaintenance.handler(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if challengeServer != nil {
			challengeServer.Shutdown(shutdown)
		}
		server.Shutdown(shutdown)
	}()
	err = server.Serve(&credentialListener{UnixListener: l, uid: s.AllowedUID})
	if errors.Is(err, http.ErrServerClosed) {
		select {
		case challengeErr := <-challengeErrors:
			return challengeErr
		default:
		}
		return nil
	}
	return err
}

type credentialListener struct {
	*net.UnixListener
	uid uint32
}

func (l *credentialListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		raw, err := c.SyscallConn()
		if err != nil {
			c.Close()
			continue
		}
		var cred *unix.Ucred
		var credErr error
		err = raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		if err != nil || credErr != nil || cred == nil || cred.Uid != l.uid {
			c.Close()
			continue
		}
		return c, nil
	}
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.RequestBytes)
	defer r.Body.Close()
	var in CheckRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid request", 400)
		return
	}
	if in.Protocol != Protocol || !validID(in.OperationID) || !validID(in.RevisionID) {
		http.Error(w, "protocol or operation mismatch", 400)
		return
	}
	encoded, err := json.Marshal(in)
	if err != nil {
		http.Error(w, "encoding failed", 500)
		return
	}
	digest := secure.Hash(encoded)
	if record, err := s.Journal.Get(in.OperationID); err == nil && record.RequestHash != digest {
		http.Error(w, "operation conflict", 409)
		return
	} else if err != nil && !os.IsNotExist(err) {
		http.Error(w, "journal unavailable", 500)
		return
	}
	parsed, err := nginxconfig.Parse(in.Files, s.Policy)
	if err != nil {
		http.Error(w, "invalid configuration tree", 400)
		return
	}
	record := Record{OperationID: in.OperationID, RequestHash: digest, Kind: "nginx.policy_check", AfterRevision: in.RevisionID, State: "succeeded", Stage: "policy_checked", DiagnosticsCount: len(parsed.Tree.Diagnostics)}
	if len(parsed.Tree.Diagnostics) > 0 {
		record.State = "failed"
		record.Stage = "policy_rejected"
	}
	if err := s.Journal.Put(record); err != nil {
		http.Error(w, "journal unavailable", 500)
		return
	}
	writeJSON(w, CheckResult{Protocol: Protocol, PolicyVersion: s.Policy.Version, Stage: record.Stage, Diagnostics: parsed.Tree.Diagnostics})
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}

type Client struct{ http *http.Client }

var ErrOperationNotFound = errors.New("Agent 操作记录不存在")
var ErrRequestTooLarge = errors.New("Agent 请求包含的配置及证书材料超过 4 MiB")

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("Agent 拒绝操作（HTTP %d）", e.Status) }

func NewClient(socket string) *Client {
	return &Client{http: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, MaxConnsPerHost: limits.TaskWorkers + 1, DisableKeepAlives: true}}}
}
func (c *Client) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if len(b) > limits.RequestBytes {
			return ErrRequestTooLarge
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("无法连接本机 Agent")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		var out struct {
			Protocol int    `json:"protocol"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out) == nil && out.Protocol == Protocol && out.Code != "" {
			return fault.New(resp.StatusCode, out.Code, out.Message)
		}
		return &HTTPError{Status: resp.StatusCode}
	}
	if resp.StatusCode == 404 {
		return ErrOperationNotFound
	}
	if resp.StatusCode != 200 {
		return &HTTPError{Status: resp.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, limits.RequestBytes)).Decode(output)
}
func (c *Client) Capabilities(ctx context.Context) (platform.Report, error) {
	var out platform.Report
	err := c.request(ctx, "GET", "/v1/capabilities", nil, &out)
	return out, err
}
func (c *Client) Check(ctx context.Context, in CheckRequest) (CheckResult, error) {
	var out CheckResult
	err := c.request(ctx, "POST", "/v1/nginx/policy-check", in, &out)
	if err == nil && out.Protocol != Protocol {
		err = errors.New("Agent 协议不兼容")
	}
	return out, err
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	if s.Nginx == nil {
		http.Error(w, "Nginx execution unavailable", 503)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.RequestBytes)
	defer r.Body.Close()
	var in ApplyRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid apply request", 400)
		return
	}
	record, err := s.Nginx.Submit(in)
	if err != nil {
		status := 409
		if errors.Is(err, ErrRuntimeUnavailable) {
			status = 503
		}
		http.Error(w, "Nginx operation rejected", status)
		return
	}
	writeJSON(w, record)
}
func (c *Client) Apply(ctx context.Context, in ApplyRequest) (Record, error) {
	var out Record
	err := c.request(ctx, "POST", "/v1/nginx/apply", in, &out)
	return out, err
}
func (c *Client) Operation(ctx context.Context, id string) (Record, error) {
	if !validID(id) {
		return Record{}, errors.New("invalid operation ID")
	}
	var out Record
	err := c.request(ctx, "GET", "/v1/operations/"+id, nil, &out)
	if err == nil && out.OperationID != id {
		err = errors.New("Agent 操作身份不匹配")
	}
	return out, err
}
func (c *Client) NginxState(ctx context.Context) (NginxState, error) {
	var out NginxState
	err := c.request(ctx, "GET", "/v1/nginx/state", nil, &out)
	return out, err
}
