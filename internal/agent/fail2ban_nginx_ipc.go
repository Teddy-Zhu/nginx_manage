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
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func fail2banNginxSocket(data string) string {
	return filepath.Join(fail2banNginxDir(data), "action.sock")
}

func fail2banNginxReply(w http.ResponseWriter, data any, err error) {
	status, code, message := http.StatusOK, "OK", "成功"
	if err != nil {
		data = nil
		status, code, message = http.StatusServiceUnavailable, "FAIL2BAN_NGINX_UNAVAILABLE", err.Error()
		var known *fault.Error
		if errors.As(err, &known) {
			status, code, message = known.Status, known.Code, known.Message
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, struct {
		Protocol int    `json:"protocol"`
		Code     string `json:"code"`
		Message  string `json:"message"`
		Data     any    `json:"data"`
	}{Protocol, code, message, data})
}

func (s *Server) startFail2banNginx(ctx context.Context, cancelRun context.CancelFunc, failures chan<- error) (func(), error) {
	if s.Nginx == nil || s.Dev || (&HostDNS{Scope: s.MetricsScope}).hostScopeReason() != "" {
		return func() {}, nil
	}
	dir := fail2banNginxDir(s.DataDir)
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return nil, err
	}
	socket := fail2banNginxSocket(s.DataDir)
	if info, err := os.Lstat(socket); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
			return nil, errors.New("Nginx 动作 Socket 归属或权限异常")
		}
		conn, dialErr := net.DialTimeout("unix", socket, time.Second)
		if dialErr == nil {
			conn.Close()
			return nil, errors.New("Nginx 动作执行器已经运行")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, dialErr
		}
		if err = os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(socket, 0600); err != nil {
		l.Close()
		return nil, err
	}
	f := &fail2banNginxExecutor{nginx: s.Nginx, wake: make(chan struct{}, 1), value: Fail2banNginxStatus{State: "starting", Registry: fail2banNginxRegistry{Schema: 1, Grants: []fail2banNginxGrant{}}}}
	s.fail2banNginx = f
	registry, registryErr := loadFail2banNginxRegistry(s.DataDir)
	f.value.Registry = registry
	if registryErr != nil {
		f.value.State, f.value.Reason = "failed", registryErr.Error()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/fail2ban/nginx/status", func(w http.ResponseWriter, r *http.Request) { fail2banNginxReply(w, f.status(), nil) })
	mux.HandleFunc("POST /v1/fail2ban/nginx/{action}", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var in Fail2banNginxRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Protocol != Protocol || in.Action != r.PathValue("action") {
			fail2banNginxReply(w, nil, fault.Invalid("Nginx 动作请求格式无效"))
			return
		}
		if in.Action == "refresh" {
			if in.OperationID != "" || in.BaseID != "" || in.Jail != "" || in.ResourceID != "" {
				fail2banNginxReply(w, nil, fault.Invalid("刷新动作不能提交 IP、jail 或其他配置"))
				return
			}
			f.enqueue()
			fail2banNginxReply(w, f.status(), nil)
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		registry, err := f.manage(call, in)
		fail2banNginxReply(w, registry, err)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
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

// Root commands use only the fixed local socket, never a caller-selected API,
// executable, address list, or second Nginx executor.
func ManageFail2banNginx(ctx context.Context, data, scope, action, operation, base, jail, resource string) (any, error) {
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" || !filepath.IsAbs(data) || filepath.Clean(data) != data {
		return nil, errors.New("Nginx 动作须由宿主机 root 指定 --fail2ban-scope=host 及规范数据目录")
	}
	if action != "status" && action != "refresh" && action != "bind" && action != "unbind" {
		return nil, fault.Invalid("未知 Nginx 动作")
	}
	if (action == "status" || action == "refresh") && (operation != "" || base != "" || jail != "" || resource != "") {
		return nil, fault.Invalid("状态或刷新命令不能提交授权参数")
	}
	path := fail2banNginxSocket(data)
	if err := existingRootDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return nil, errors.New("Nginx 动作 Socket 无法证明归属")
	}
	client := NewClient(path)
	method, route := http.MethodPost, "/v1/fail2ban/nginx/"+action
	var in any = Fail2banNginxRequest{Protocol: Protocol, OperationID: operation, BaseID: base, Jail: jail, ResourceID: resource, Action: action}
	if action == "status" {
		method, in = http.MethodGet, nil
	}
	var out json.RawMessage
	err = client.envelopeRequest(ctx, method, route, in, &out)
	if err != nil {
		return nil, err
	}
	if !json.Valid(out) || strings.TrimSpace(string(out)) == "null" {
		return nil, errors.New("Nginx 动作响应数据无效")
	}
	return out, nil
}
