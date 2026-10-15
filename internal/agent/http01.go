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
	"sort"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/nginxconfig"
)

type HTTP01LeaseRequest struct {
	Epoch            int64    `json:"epoch"`
	Protocol         int      `json:"protocol"`
	OrderID          string   `json:"order_id"`
	ExpectedRevision string   `json:"expected_revision"`
	Domains          []string `json:"domains"`
	ExpiresAt        int64    `json:"expires_at"`
}
type HTTP01PresentRequest struct {
	Epoch            int64  `json:"epoch"`
	Protocol         int    `json:"protocol"`
	OrderID          string `json:"order_id"`
	Domain           string `json:"domain"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"key_authorization"`
}
type HTTP01CleanupRequest struct {
	Epoch    int64  `json:"epoch"`
	Protocol int    `json:"protocol"`
	OrderID  string `json:"order_id"`
}
type HTTP01Result struct {
	Epoch     int64  `json:"epoch"`
	Protocol  int    `json:"protocol"`
	OrderID   string `json:"order_id"`
	Ready     bool   `json:"ready"`
	ExpiresAt int64  `json:"expires_at"`
	Reason    string `json:"reason"`
}

func (n *Nginx) http01Socket() string { return filepath.Join(n.DataDir, "run", "acme-http01.sock") }

func (n *Nginx) http01Server() (*http.Server, *net.UnixListener, error) {
	name := n.http01Socket()
	if info, err := os.Lstat(name); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, errors.New("HTTP-01 responder path is not a socket")
		}
		conn, dialErr := net.DialTimeout("unix", name, time.Second)
		if dialErr == nil {
			conn.Close()
			return nil, nil, errors.New("HTTP-01 responder is already running")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, nil, dialErr
		}
		if err := os.Remove(name); err != nil {
			return nil, nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chown(name, 0, n.gid); err != nil {
		l.Close()
		return nil, nil, err
	}
	if err := os.Chmod(name, 0660); err != nil {
		l.Close()
		return nil, nil, err
	}
	return &http.Server{Handler: n.http01, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}, l, nil
}

func (n *Nginx) http01Runtime(ctx context.Context, revision string, domains []string) (manifest, error) {
	if n.closed || n.unlock == nil || n.http01 == nil {
		return manifest{}, ErrRuntimeUnavailable
	}
	records, err := n.Journal.List()
	if err != nil {
		return manifest{}, err
	}
	for _, record := range records {
		if strings.HasPrefix(record.Kind, "nginx.") && (record.State == "running" || record.State == "compensating" || record.State == "recovery_required") {
			return manifest{}, ErrBusy
		}
	}
	_, m, err := n.active()
	if err != nil {
		return m, err
	}
	if m.RevisionID != revision {
		return m, errors.New("HTTP-01 revision no longer active")
	}
	for _, domain := range domains {
		if len(m.HTTP01[domain]) == 0 {
			return m, errors.New("HTTP-01 domain has no unambiguous port 80 entry")
		}
	}
	if err := n.observe(ctx, m); err != nil {
		return m, err
	}
	return m, nil
}

func (n *Nginx) reserveHTTP01(ctx context.Context, in HTTP01LeaseRequest) HTTP01Result {
	out := HTTP01Result{Protocol: Protocol, OrderID: in.OrderID, Epoch: in.Epoch}
	n.mu.Lock()
	defer n.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	domains := append([]string(nil), in.Domains...)
	sort.Strings(domains)
	lease := http01Lease{Epoch: in.Epoch, OrderID: in.OrderID, Revision: in.ExpectedRevision, Domains: domains, ExpiresAt: in.ExpiresAt, Tokens: map[string]http01Material{}}
	if in.Protocol != Protocol || !validHTTP01Lease(lease) || in.ExpiresAt <= time.Now().Unix() || in.ExpiresAt > time.Now().Add(time.Hour).Unix() {
		out.Reason = "HTTP-01 租约参数无效"
		return out
	}
	if _, err := n.http01Runtime(ctx, in.ExpectedRevision, domains); err != nil {
		out.Reason = "HTTP-01 要求已确认运行的配置、每个域名唯一的 80 端口验证入口，且没有待恢复的 Nginx 任务"
		return out
	}
	if err := n.http01.reserve(lease); err != nil {
		out.Reason = "HTTP-01 租约无法持久保存，或与原订单冲突"
		return out
	}
	out.Ready, out.ExpiresAt = true, lease.ExpiresAt
	return out
}

func (n *Nginx) presentHTTP01(ctx context.Context, in HTTP01PresentRequest) HTTP01Result {
	out := HTTP01Result{Protocol: Protocol, OrderID: in.OrderID, Epoch: in.Epoch}
	n.mu.Lock()
	defer n.mu.Unlock()
	if in.Protocol != Protocol || !validID(in.OrderID) || in.Epoch < 1 || in.Epoch > 1_000_000_000 || n.http01 == nil || n.closed {
		out.Reason = "HTTP-01 执行器不可用"
		return out
	}
	lease, err := n.http01.present(in.OrderID, in.Epoch, in.Domain, in.Token, in.KeyAuthorization)
	if err != nil {
		out.Reason = "HTTP-01 材料无效、租约已过期或无法持久保存"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	m, err := n.http01Runtime(ctx, lease.Revision, lease.Domains)
	if err != nil {
		out.Reason = "HTTP-01 所需的运行修订或域名验证入口已变化"
		return out
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 4096}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, entry := range m.HTTP01[in.Domain] {
		// Addresses come only from the immutable root-owned active manifest.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listenerAddress(entry)+nginxconfig.HTTP01Prefix+in.Token, nil)
		if err != nil {
			out.Reason = "HTTP-01 本机入口无效"
			return out
		}
		req.Host = in.Domain
		response, err := client.Do(req)
		if err != nil {
			out.Reason = "HTTP-01 本机 80 端口验证入口不可达"
			return out
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 513))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || string(body) != in.KeyAuthorization {
			out.Reason = "HTTP-01 本机验证入口未返回本次订单材料，请检查入口与访问控制"
			return out
		}
	}
	out.Ready, out.ExpiresAt = true, lease.ExpiresAt
	return out
}

func (n *Nginx) cleanupHTTP01(in HTTP01CleanupRequest) HTTP01Result {
	out := HTTP01Result{Protocol: Protocol, OrderID: in.OrderID, Epoch: in.Epoch}
	n.mu.Lock()
	defer n.mu.Unlock()
	if in.Protocol != Protocol || !validID(in.OrderID) || in.Epoch < 1 || in.Epoch > 1_000_000_000 || n.http01 == nil || n.closed {
		out.Reason = "HTTP-01 执行器不可用"
		return out
	}
	if err := n.http01.cleanup(in.OrderID, in.Epoch); err != nil {
		out.Reason = "HTTP-01 材料清理未能持久确认"
		return out
	}
	out.Ready = true
	return out
}

func (s *Server) http01Handlers(mux *http.ServeMux) {
	for _, action := range []string{"lease", "present", "cleanup"} {
		mux.HandleFunc("POST /v1/nginx/http01/"+action, func(w http.ResponseWriter, r *http.Request) {
			if s.Nginx == nil {
				http.Error(w, "Nginx execution unavailable", http.StatusServiceUnavailable)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			defer r.Body.Close()
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			var in any
			switch action {
			case "lease":
				in = new(HTTP01LeaseRequest)
			case "present":
				in = new(HTTP01PresentRequest)
			case "cleanup":
				in = new(HTTP01CleanupRequest)
			}
			if err := decoder.Decode(in); err != nil {
				http.Error(w, "invalid HTTP-01 request", 400)
				return
			}
			if decoder.Decode(new(any)) != io.EOF {
				http.Error(w, "invalid HTTP-01 request", 400)
				return
			}
			var out HTTP01Result
			switch value := in.(type) {
			case *HTTP01LeaseRequest:
				out = s.Nginx.reserveHTTP01(r.Context(), *value)
			case *HTTP01PresentRequest:
				out = s.Nginx.presentHTTP01(r.Context(), *value)
			case *HTTP01CleanupRequest:
				out = s.Nginx.cleanupHTTP01(*value)
			}
			writeJSON(w, out)
		})
	}
}

func (c *Client) http01Request(ctx context.Context, action, id string, epoch int64, in any) (HTTP01Result, error) {
	var out HTTP01Result
	if err := c.request(ctx, http.MethodPost, "/v1/nginx/http01/"+action, in, &out); err != nil {
		return out, err
	}
	if out.Protocol != Protocol || out.OrderID != id || out.Epoch != epoch {
		return out, errors.New("HTTP-01 agent response mismatch")
	}
	if !out.Ready {
		return out, errors.New(out.Reason)
	}
	return out, nil
}
func (c *Client) ReserveHTTP01(ctx context.Context, in HTTP01LeaseRequest) (HTTP01Result, error) {
	return c.http01Request(ctx, "lease", in.OrderID, in.Epoch, in)
}
func (c *Client) PresentHTTP01(ctx context.Context, in HTTP01PresentRequest) (HTTP01Result, error) {
	return c.http01Request(ctx, "present", in.OrderID, in.Epoch, in)
}
func (c *Client) CleanupHTTP01(ctx context.Context, id string, epoch int64) (HTTP01Result, error) {
	return c.http01Request(ctx, "cleanup", id, epoch, HTTP01CleanupRequest{Protocol: Protocol, OrderID: id, Epoch: epoch})
}
