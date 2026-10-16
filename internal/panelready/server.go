package panelready

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func credentials(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return nil, err
	}
	return cred, inner
}

type rootListener struct{ *net.UnixListener }

func (l *rootListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		cred, err := credentials(c)
		if err == nil && cred != nil && cred.Uid == 0 {
			return c, nil
		}
		c.Close()
	}
}

// Listen is called after taking the application writer lock. Only a stale
// socket belonging to this dedicated account can be removed.
func Listen(data string) (net.Listener, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("readiness 服务须以面板专用账户运行")
	}
	info, err := os.Lstat(filepath.Dir(Socket(data)))
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid() {
		return nil, errors.New("readiness 目录不属于专用面板账户")
	}
	name := Socket(data)
	if info, err := os.Lstat(name); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || int(st.Uid) != os.Geteuid() {
			return nil, errors.New("已有 readiness Socket 的类型或归属无效")
		}
		c, err := net.DialTimeout("unix", name, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return nil, errors.New("readiness Socket 仍在使用")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		if err = os.Remove(name); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: name})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(name, 0600); err != nil {
		l.Close()
		return nil, err
	}
	return &rootListener{l}, nil
}

func Serve(ctx context.Context, l net.Listener, nodeID string, status func(context.Context) (Status, error)) error {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := secure.ID()
		out := Envelope{Code: "NOT_FOUND", Message: "接口不存在", RequestID: id, NodeID: nodeID}
		code := http.StatusNotFound
		if r.Method == http.MethodGet && r.URL.Path == "/v1/readiness" && r.URL.RawQuery == "" {
			call, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			s, err := status(call)
			if err == nil {
				out.Code, out.Message, out.Data, code = "OK", "操作成功", &s, http.StatusOK
			} else {
				out.Code, out.Message, code = "NOT_READY", "面板尚未就绪", http.StatusServiceUnavailable
				message := err.Error()
				if len(message) > 1024 {
					message = message[:1024]
				}
				out.Message += "：" + strings.ToValidUTF8(message, "")
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Request-ID", id)
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(out)
	})
	s := &http.Server{Handler: h, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	err := s.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
