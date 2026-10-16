package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"nginxpanel/internal/secure"
)

func (s *Server) startFail2banJails(ctx context.Context, gate *maintenanceGate, cancelRun context.CancelFunc, failures chan<- error) (func(), error) {
	if s.Dev || os.Geteuid() != 0 || s.MetricsScope != "host" || s.MaintenanceScope != "host" || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return func() {}, nil
	}
	if !filepath.IsAbs(s.DataDir) || filepath.Clean(s.DataDir) != s.DataDir {
		return nil, errors.New("受管 jail 数据目录须为规范绝对路径")
	}
	if err := secure.RootDirectory(filepath.Dir(fail2banJailsSocket(s.DataDir)), 0700); err != nil {
		return nil, err
	}
	path := fail2banJailsSocket(s.DataDir)
	if info, err := os.Lstat(path); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
			return nil, errors.New("受管 jail Socket 归属或权限异常")
		}
		conn, e := net.DialTimeout("unix", path, time.Second)
		if e == nil {
			conn.Close()
			return nil, errors.New("受管 jail 执行器已经运行")
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
	f := &fail2banJailsExecutor{server: s, gate: gate, wake: make(chan struct{}, 1)}
	s.fail2banJails = f
	mux := http.NewServeMux()
	f.jailHandlers(mux)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
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
