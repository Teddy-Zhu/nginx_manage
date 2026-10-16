package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func fail2banHostSyncSocket(dataDir string) string {
	return filepath.Join(fail2banHostSyncDir(dataDir), "action.sock")
}

func (s *Server) startFail2banHostSync(ctx context.Context, gate *maintenanceGate, cancelRun context.CancelFunc, failures chan<- error) (func(), error) {
	if s.Dev || os.Geteuid() != 0 || s.MetricsScope != "host" || s.MaintenanceScope != "host" || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return func() {}, nil
	}
	if !filepath.IsAbs(s.DataDir) || filepath.Clean(s.DataDir) != s.DataDir {
		return nil, errors.New("宿主机同步数据目录须为规范绝对路径")
	}
	if err := secure.RootDirectory(fail2banHostSyncDir(s.DataDir), 0700); err != nil {
		return nil, err
	}
	path := fail2banHostSyncSocket(s.DataDir)
	if info, err := os.Lstat(path); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
			return nil, errors.New("宿主机同步 Socket 归属或权限异常")
		}
		conn, e := net.DialTimeout("unix", path, time.Second)
		if e == nil {
			conn.Close()
			return nil, errors.New("宿主机同步执行器已经运行")
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return nil, e
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	f := &fail2banHostSyncExecutor{server: s, gate: gate, wake: make(chan struct{}, 1), value: fail2ban.EmptyHostInputSync("执行器正在启动")}
	s.fail2banHostSync = f
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/fail2ban/host-sync/status", func(w http.ResponseWriter, r *http.Request) { fail2banNginxReply(w, f.status(), nil) })
	mux.HandleFunc("POST /v1/fail2ban/host-sync/refresh", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		defer r.Body.Close()
		var in struct {
			Protocol int `json:"protocol"`
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Protocol != Protocol {
			fail2banNginxReply(w, nil, fault.Invalid("同步通知仅接受当前协议，不接受 IP、jail 或命令"))
			return
		}
		// Reply before sampling: the official server may hold its action lock.
		f.enqueue()
		fail2banNginxReply(w, f.status(), nil)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	runContext, stop := context.WithCancel(ctx)
	workerDone, serverDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(workerDone); f.run(runContext) }()
	f.enqueue()
	go func() {
		defer close(serverDone)
		if err := server.Serve(&credentialListener{UnixListener: l, uid: 0}); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case failures <- err:
			default:
			}
			cancelRun()
		}
	}()
	return func() { stop(); server.Close(); l.Close(); <-serverDone; <-workerDone }, nil
}

func callFail2banHostSync(ctx context.Context, dataDir, action string) (fail2ban.HostInputSyncView, error) {
	out := fail2ban.EmptyHostInputSync("独立持续同步执行器不可读取")
	if event, e := loadFail2banHostSync(dataDir); e == nil {
		out = fail2banHostSyncMetadata(event)
		if out.Enabled {
			out.Reason = "独立执行器不可读取，不能确认保护正在同步"
		}
	}
	path := fail2banHostSyncSocket(dataDir)
	info, err := os.Lstat(path)
	if err != nil {
		return out, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return out, errors.New("持续同步 Socket 无法证明归属")
	}
	method := http.MethodGet
	var in any
	if action == "refresh" {
		method = http.MethodPost
		in = struct {
			Protocol int `json:"protocol"`
		}{Protocol}
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = NewClient(path).envelopeRequest(call, method, "/v1/fail2ban/host-sync/"+action, in, &out)
	if err == nil && !out.Valid() {
		err = errors.New("持续同步状态合同无法核对")
	}
	return out, err
}
