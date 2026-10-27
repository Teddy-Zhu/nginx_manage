package nodes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
)

// OpenRealtime uses the same pinned certificate, destination restrictions and
// target-bound machine authorization as ordinary node requests.
func (s *Service) OpenRealtime(ctx context.Context, p auth.Principal, id string, topics []string, resources []string) (*websocket.Conn, string, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return nil, "", err
	}
	c, err := s.get(ctx, id)
	if err != nil {
		return nil, "", err
	}
	if c.State != "connected" || c.RemovedAt != 0 || c.APIVersion != 1 {
		return nil, "", fault.Conflict("目标连接未就绪，请先检查连接")
	}
	token, err := s.Vault.Open(c.token, "node-token:"+id)
	if err != nil {
		return nil, "", err
	}
	client, base, err := remoteapi.Client(endpoint(c, token))
	if err != nil {
		return nil, "", err
	}
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	dialer := websocket.Dialer{NetDialContext: transport.DialContext, TLSClientConfig: transport.TLSClientConfig, HandshakeTimeout: 10 * time.Second, ReadBufferSize: 1024, WriteBufferSize: 1024}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+string(token))
	headers.Set(remoteapi.HopHeader, "1")
	headers.Set(remoteapi.TargetHeader, c.NodeID)
	headers.Set(remoteapi.ProtocolHeader, "1")
	scopes, _ := json.Marshal(p.Scopes)
	headers.Set(remoteapi.ScopesHeader, string(scopes))
	encodedResources, _ := json.Marshal(resources)
	target := "wss" + strings.TrimPrefix(base, "https") + "/events?topics=" + url.QueryEscape(strings.Join(topics, ",")) + "&resources=" + url.QueryEscape(string(encodedResources))
	conn, response, err := dialer.DialContext(ctx, target, headers)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, "", fault.New(502, "REMOTE_STREAM_INTERRUPTED", "无法连接目标实时服务，请检查服务器连接")
	}
	if response.Header.Get("X-Node-ID") != c.NodeID || response.Header.Get(remoteapi.ProtocolHeader) != "1" {
		conn.Close()
		return nil, "", fault.Conflict("目标实时连接身份无法核验")
	}
	return conn, c.NodeID, nil
}
func (s *Service) RealtimeAlive(ctx context.Context, p auth.Principal, id, node string) error {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return err
	}
	c, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	if c.State != "connected" || c.RemovedAt != 0 || c.NodeID != node {
		return fault.Conflict("服务器连接已变化")
	}
	return nil
}
