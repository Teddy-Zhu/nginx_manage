package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/remoteapi"
)

type envelope struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
	RequestID string          `json:"request_id"`
	NodeID    string          `json:"node_id"`
}

type probeError struct{ state, message string }

func (e *probeError) Error() string { return e.message }

// Only fixed local resource paths are used here. Client credentials, cookies,
// request URLs and forwarding headers are never copied from the browser.
func call(ctx context.Context, in remoteapi.Endpoint, expected, method, path string) (envelope, error) {
	var body envelope
	client, base, err := remoteapi.Client(in)
	if err != nil {
		return body, err
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return body, err
	}
	req.Header.Set("Authorization", "Bearer "+in.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set(RemoteHopHeader, "1")
	req.Header.Set(remoteapi.ProtocolHeader, "1")
	req.Header.Set(remoteapi.ScopesHeader, `["read"]`)
	req.Header.Set(remoteapi.RecentHeader, "false")
	if expected != "" {
		req.Header.Set(TargetNodeHeader, expected)
	}
	resp, err := client.Do(req)
	if err != nil {
		return body, &probeError{"unreachable", "无法连接目标 HTTPS API；请检查网络、证书指纹和有效期"}
	}
	defer resp.Body.Close()
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return body, &probeError{"unreachable", "目标未返回约定的 JSON 响应"}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (256<<10)+1))
	if err != nil || len(raw) > 256<<10 || json.Unmarshal(raw, &body) != nil || !uuid.MatchString(body.NodeID) || !uuid.MatchString(body.RequestID) || len(body.Code) == 0 || len(body.Code) > 64 || body.Data == nil {
		return body, &probeError{"unreachable", "目标响应格式无效或超出大小限制"}
	}
	if expected != "" && body.NodeID != expected {
		return body, &probeError{"identity_changed", "目标永久节点身份已变化，连接已停用"}
	}
	if resp.Header.Get(remoteapi.ProtocolHeader) != "1" || resp.Header.Get("X-Node-ID") != body.NodeID {
		return body, &probeError{"incompatible", "目标远程协议或响应身份无法核验"}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return body, &probeError{"authorization_failed", "目标授权不可用；请检查 Token、来源限制及授权范围"}
	}
	if resp.StatusCode != http.StatusOK || body.Code != "OK" {
		return body, &probeError{"unreachable", fmt.Sprintf("目标 API 拒绝请求（HTTP %d，%s）", resp.StatusCode, body.Code)}
	}
	return body, nil
}

func validateIdentity(i Identity, nodeID string) error {
	if i.RemoteProtocol != remoteapi.Protocol {
		return &probeError{"incompatible", "目标不支持当前远程授权协议"}
	}
	if !uuid.MatchString(i.NodeID) || i.NodeID != nodeID || !uuid.MatchString(i.CredentialID) || i.ExpiresAt <= time.Now().Unix() || i.APIVersion < 1 || i.DatabaseSchema < 1 || i.AgentProtocol < 1 || len(i.ParserVersion) == 0 || len(i.ParserVersion) > 128 || len(i.PolicyVersion) == 0 || len(i.PolicyVersion) > 128 || len(i.Scopes) == 0 || len(i.Scopes) > len(auth.AllScopes) {
		return &probeError{"identity_changed", "目标身份或授权信息不完整"}
	}
	seen := map[string]bool{}
	known := map[string]bool{}
	for _, scope := range auth.AllScopes {
		known[scope] = true
	}
	for _, scope := range i.Scopes {
		if !known[scope] || seen[scope] {
			return &probeError{"incompatible", "目标授权范围超出当前 API 合同"}
		}
		seen[scope] = true
	}
	if !seen["read"] {
		return &probeError{"authorization_failed", "目标 Token 未授予 read 权限"}
	}
	return nil
}

func probe(ctx context.Context, in remoteapi.Endpoint, expected, credential string) (Identity, json.RawMessage, error) {
	var identity Identity
	body, err := call(ctx, in, expected, http.MethodGet, "/remote/identity")
	if err != nil {
		return identity, nil, err
	}
	if err = json.Unmarshal(body.Data, &identity); err != nil {
		return identity, nil, &probeError{"identity_changed", "目标身份格式无效"}
	}
	if err = validateIdentity(identity, body.NodeID); err != nil {
		return identity, nil, err
	}
	if credential != "" && identity.CredentialID != credential {
		return identity, nil, &probeError{"identity_changed", "连接授权身份已变化，须重新登记"}
	}
	if identity.APIVersion != 1 {
		return identity, nil, &probeError{"incompatible", "目标 API 主版本不兼容"}
	}
	capabilities, err := call(ctx, in, identity.NodeID, http.MethodGet, "/system/capabilities")
	if err != nil {
		return identity, nil, err
	}
	var version struct {
		APIVersion     int    `json:"api_version"`
		DatabaseSchema int64  `json:"database_schema"`
		RemoteProtocol int    `json:"remote_protocol"`
		AgentProtocol  int    `json:"agent_protocol"`
		ParserVersion  string `json:"parser_version"`
		PolicyVersion  string `json:"policy_version"`
		Mode           string `json:"mode"`
	}
	if json.Unmarshal(capabilities.Data, &version) != nil || version.APIVersion != identity.APIVersion || version.DatabaseSchema != identity.DatabaseSchema || version.RemoteProtocol != identity.RemoteProtocol || version.AgentProtocol != identity.AgentProtocol || version.ParserVersion != identity.ParserVersion || version.PolicyVersion != identity.PolicyVersion || (version.Mode != "connected" && version.Mode != "preview") {
		return identity, nil, &probeError{"incompatible", "目标能力与身份版本信息不一致"}
	}
	return identity, capabilities.Data, nil
}

func probeFailure(err error) (string, string) {
	var remote *probeError
	if errors.As(err, &remote) {
		return remote.state, remote.message
	}
	return "unreachable", "连接检查未完成，未向目标提交业务操作"
}

func endpoint(c Connection, key []byte) remoteapi.Endpoint {
	return remoteapi.Endpoint{URL: c.URL, APIKey: string(key), Fingerprint: strings.ToLower(c.Fingerprint)}
}
