package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/secure"
)

const Protocol = 3

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
	Socket     string
	AllowedUID uint32
	Policy     nginxconfig.Policy
	Journal    *Journal
	Nginx      *Nginx
	Dev        bool
}

func (s *Server) Run(ctx context.Context) error {
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
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		report := platform.Detect()
		report.Source = "host-agent"
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
	mux.HandleFunc("POST /v1/nginx/inspect", s.inspect)
	mux.HandleFunc("GET /v1/nginx/features", func(w http.ResponseWriter, r *http.Request) {
		if s.Nginx == nil {
			writeJSON(w, NginxFeatures{Features: map[string]Feature{}, Reason: "专用 Nginx 执行尚未配置"})
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
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	err = server.Serve(&credentialListener{UnixListener: l, uid: s.AllowedUID})
	if errors.Is(err, http.ErrServerClosed) {
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
