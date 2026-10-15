package launcher

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

var idValue = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var releaseValue = regexp.MustCompile(`^[0-9a-f]{64}$`)

type rootListener struct{ *net.UnixListener }

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
func (l *rootListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		cred, err := credentials(c)
		if err != nil || cred == nil || cred.Uid != 0 {
			c.Close()
			continue
		}
		return c, nil
	}
}
func listen(data string) (*rootListener, error) {
	name := Socket(data)
	if info, err := os.Lstat(name); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || int(st.Uid) != os.Geteuid() {
			return nil, errors.New("已有 launcher Socket 的类型或归属不匹配")
		}
		conn, err := net.DialTimeout("unix", name, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil, errors.New("launcher Socket 仍在使用")
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
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(name, 0600); err != nil {
		l.Close()
		return nil, err
	}
	return &rootListener{l}, nil
}

type envelope struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
	RequestID string `json:"request_id"`
}

func reply(w http.ResponseWriter, status int, code, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(envelope{Code: code, Message: message, Data: data, RequestID: secure.ID()})
}
func (s *supervisor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, "OK", "", s.view()) })
	mux.HandleFunc("GET /v1/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		op, ok := s.operations[r.PathValue("id")]
		s.mu.Unlock()
		if !ok {
			reply(w, 404, "NOT_FOUND", "本次 launcher 启动中没有该操作记录", nil)
			return
		}
		reply(w, 200, "OK", "", op)
	})
	mux.HandleFunc("POST /v1/restart", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		var req Request
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || req.Protocol != Protocol || !idValue.MatchString(req.BootID) || !idValue.MatchString(req.OperationID) || !releaseValue.MatchString(req.ReleaseID) {
			reply(w, 400, "INVALID_ARGUMENT", "launcher 请求无效", nil)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if req.BootID != s.status.BootID {
			reply(w, 409, "BOOT_CHANGED", "launcher 已重新启动，须核对原结果", nil)
			return
		}
		if op, ok := s.operations[req.OperationID]; ok {
			if op.Request != req {
				reply(w, 409, "CONFLICT", "同一操作标识不能用于不同请求", nil)
				return
			}
			reply(w, 200, "OK", "", op)
			return
		}
		if s.status.State != "running" {
			reply(w, 409, "CONFLICT", "launcher 当前不接收新的重启操作", nil)
			return
		}
		if s.status.Operation != nil && s.status.Operation.State != "started" && s.status.Operation.State != "failed" {
			reply(w, 409, "CONFLICT", "已有 launcher 操作执行中", nil)
			return
		}
		if len(s.operations) >= 64 {
			reply(w, 409, "CONFLICT", "本次 launcher 启动的操作保留数量已达上限", nil)
			return
		}
		op := Operation{Request: req, State: "queued"}
		s.operations[req.OperationID], s.status.Operation = op, &op
		s.queue <- req
		reply(w, 202, "OK", "", op)
	})
	return mux
}
