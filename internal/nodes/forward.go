package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"nginxpanel/api"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/history"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/secure"
)

type Forward struct {
	Response *http.Response
	NodeID   string
	finish   func(string)
}

func (f *Forward) Close(outcome string) { f.finish(outcome) }

func (s *Service) invalidate(ctx context.Context, c Connection, state, message string) {
	_, err := s.DB.ExecContext(ctx, "UPDATE nodes SET state=?,last_error=?,capabilities=NULL,updated_at=?,version=version+1 WHERE id=? AND version=? AND removed_at IS NULL AND state<>'removing'", state, message, time.Now().Unix(), c.ID, c.Version)
	if err != nil {
		slog.Warn("无法保存远程连接异常", "connection", c.ID, "error", err)
	}
}

// OpenForward only dispatches a current request. No retry or offline queue can
// turn a transport timeout into another business operation.
func (s *Service) OpenForward(ctx context.Context, p auth.Principal, recent bool, trace, id string, route api.RemoteRoute, path string, headers http.Header, body []byte) (*Forward, error) {
	if err := p.Require(append([]string{"nodes.manage", "read"}, route.Scopes...)...); err != nil {
		return nil, err
	}
	c, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	var version struct {
		RemoteProtocol int `json:"remote_protocol"`
	}
	if c.State == "stale" || c.State == "connected" && (json.Unmarshal(c.Capabilities, &version) != nil || version.RemoteProtocol != remoteapi.Protocol) {
		c, err = s.Refresh(ctx, p, trace, id)
		if err != nil {
			return nil, err
		}
	}
	value, _ := s.locks.LoadOrStore(id, &sync.RWMutex{})
	lock := value.(*sync.RWMutex)
	if !lock.TryRLock() {
		return nil, fault.Conflict("节点连接正在检查或删除")
	}
	defer lock.RUnlock()
	c, err = s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.State != "connected" || c.RemovedAt != 0 || c.APIVersion != 1 {
		return nil, fault.New(http.StatusConflict, "REMOTE_CONNECTION_UNAVAILABLE", "目标连接未就绪，请先检查节点连接")
	}
	counter, limit := &s.forwardActive, int32(8)
	if route.Kind == "sse" {
		counter, limit = &s.streamActive, 4
	}
	if counter.Add(1) > limit {
		counter.Add(-1)
		return nil, fault.New(http.StatusTooManyRequests, "REMOTE_BUSY", "远程请求已达并发上限")
	}
	release := func() { counter.Add(-1) }
	token, err := s.Vault.Open(c.token, "node-token:"+id)
	if err != nil {
		release()
		return nil, err
	}
	ep := endpoint(c, token)
	// A version and credential preflight precedes each mutating HTTP method.
	// The target checks its permanent ID again at the mutation boundary.
	if route.Method != http.MethodGet {
		approved, probeErr := call(ctx, ep, c.NodeID, http.MethodGet, "/remote/identity")
		var identity Identity
		if probeErr == nil {
			if json.Unmarshal(approved.Data, &identity) != nil {
				probeErr = errors.New("invalid identity")
			} else {
				probeErr = validateIdentity(identity, c.NodeID)
			}
		}
		if probeErr == nil && (identity.CredentialID != c.CredentialID || identity.APIVersion != 1) {
			probeErr = &probeError{"identity_changed", "目标身份或授权已变化"}
		}
		if probeErr != nil {
			release()
			state, message := probeFailure(probeErr)
			s.invalidate(ctx, c, state, message)
			return nil, fault.New(http.StatusBadGateway, "REMOTE_PREFLIGHT_FAILED", message)
		}
	}
	client, base, err := remoteapi.Client(ep)
	if err != nil {
		release()
		return nil, err
	}
	if route.Method == http.MethodGet && route.Path == "/fail2ban/jails/{name}" {
		// This transport is created above for this one forwarding request.
		client.Transport.(*http.Transport).ResponseHeaderTimeout = fail2ban.JailReadTimeout + time.Second
	}
	if route.Method == http.MethodPost && history.SnapshotRequest(route.Path, body) {
		client.Timeout = history.SnapshotRequestTimeout + 20*time.Second
		client.Transport.(*http.Transport).ResponseHeaderTimeout = history.SnapshotRequestTimeout + 15*time.Second
	}
	if route.Kind == "sse" {
		client.Timeout = 0
	}
	req, err := http.NewRequestWithContext(ctx, route.Method, base+path, bytes.NewReader(body))
	if err != nil {
		release()
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ep.APIKey)
	req.Header.Set(remoteapi.HopHeader, "1")
	req.Header.Set(remoteapi.TargetHeader, c.NodeID)
	req.Header.Set(remoteapi.ProtocolHeader, "1")
	scopes, _ := json.Marshal(p.Scopes)
	req.Header.Set(remoteapi.ScopesHeader, string(scopes))
	req.Header.Set(remoteapi.RecentHeader, strconv.FormatBool(recent))
	for _, name := range []string{"Accept", "Content-Type"} {
		if v := headers.Get(name); v != "" {
			req.Header.Set(name, v)
		}
	}
	if key := headers.Get("Idempotency-Key"); key != "" {
		if err = validKey(key); err != nil {
			release()
			return nil, err
		}
		req.Header.Set("Idempotency-Key", "remote-"+secure.Hash([]byte(s.NodeID+":"+p.ID+":"+key)))
	}
	action := "nodes.forward." + route.Operation
	if err = audit(ctx, s.DB, trace, p.ID, action, id, "started"); err != nil {
		release()
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		release()
		client.CloseIdleConnections()
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if auditErr := audit(finish, s.DB, trace, p.ID, action, id, "unknown"); auditErr != nil {
			slog.Warn("远程请求未知结果审计未完成", "request_id", trace, "error", auditErr)
		}
		return nil, fault.New(http.StatusBadGateway, "REMOTE_RESULT_UNKNOWN", "无法确认目标执行结果，请查询原节点任务；重试写操作须使用原幂等键")
	}
	if response.Header.Get("X-Node-ID") != c.NodeID {
		s.invalidate(ctx, c, "identity_changed", "目标响应永久节点身份无法核验")
	} else if response.Header.Get(remoteapi.ProtocolHeader) != "1" {
		s.invalidate(ctx, c, "incompatible", "目标远程授权协议无法核验")
	} else if response.StatusCode == http.StatusUnauthorized {
		s.invalidate(ctx, c, "authorization_failed", "目标授权不可用，请检查节点连接")
	}
	var once sync.Once
	f := &Forward{Response: response, NodeID: c.NodeID}
	f.finish = func(outcome string) {
		once.Do(func() {
			response.Body.Close()
			client.CloseIdleConnections()
			release()
			finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if err := audit(finish, s.DB, trace, p.ID, action, id, outcome+":"+strconv.Itoa(response.StatusCode)+":"+response.Header.Get("X-Request-ID")); err != nil {
				slog.Warn("远程请求结果审计未完成", "request_id", trace, "error", err)
			}
		})
	}
	return f, nil
}
