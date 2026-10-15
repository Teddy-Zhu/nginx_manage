package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"nginxpanel/internal/secure"
)

type sendResult struct {
	Success, Retry bool
	Status         int
	RetryAfter     int64
	Message        string
}
type sender struct {
	client    *http.Client
	transport *http.Transport
}

func newSender() *sender {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 6 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 2, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 16 << 10}
	return &sender{transport: transport, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (s *sender) close() { s.transport.CloseIdleConnections() }
func retryAfter(raw string) int64 {
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds > 0 {
		return min(seconds, 24*3600)
	}
	if at, err := http.ParseTime(raw); err == nil {
		return max(int64(0), min(int64(time.Until(at).Seconds())+1, 24*3600))
	}
	return 0
}
func (s *sender) send(ctx context.Context, channel storedChannel, payload []byte) sendResult {
	var body Payload
	if len(payload) > 8192 || json.Unmarshal(payload, &body) != nil || body.Event.ID == "" || body.NodeID == "" {
		return sendResult{Message: "投递材料无效"}
	}
	target, encoded := channel.Config.URL, payload
	if channel.Kind == "telegram" {
		target = "https://api.telegram.org/bot" + channel.Config.BotToken + "/sendMessage"
		text := fmt.Sprintf("NginxPanel · %s\n节点：%s\n事件：%s\n资源：%s / %s\n级别：%s · 状态：%s\n时间：%s\n%s\n事件 ID：%s", body.Event.Kind, body.NodeID, body.Event.Kind, body.Event.ResourceKind, body.Event.ResourceID, body.Event.Severity, body.Event.State, time.Unix(body.Event.CreatedAt, 0).UTC().Format(time.RFC3339), body.Event.Summary, body.Event.ID)
		data := struct {
			ChatID      string `json:"chat_id"`
			ThreadID    int64  `json:"message_thread_id,omitempty"`
			Text        string `json:"text"`
			LinkPreview any    `json:"link_preview_options"`
		}{channel.Config.ChatID, channel.Config.ThreadID, text, map[string]bool{"is_disabled": true}}
		var err error
		encoded, err = json.Marshal(data)
		if err != nil {
			return sendResult{Message: "通知消息无法编码"}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(encoded))
	if err != nil {
		return sendResult{Message: "通知目标地址无效"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NginxPanel-Notifications/1")
	if channel.Kind == "webhook" {
		req.Header.Set("X-NginxPanel-Event-ID", body.Event.ID)
		req.Header.Set("X-NginxPanel-Node-ID", body.NodeID)
		req.Header.Set("Idempotency-Key", secure.Hash([]byte(body.NodeID+":"+body.Event.ID)))
		if channel.Config.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+channel.Config.BearerToken)
		}
		if channel.Config.SigningSecret != "" {
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			signature := hmac.New(sha256.New, []byte(channel.Config.SigningSecret))
			signature.Write([]byte(timestamp + "."))
			signature.Write(encoded)
			req.Header.Set("X-NginxPanel-Timestamp", timestamp)
			req.Header.Set("X-NginxPanel-Signature", "sha256="+hex.EncodeToString(signature.Sum(nil)))
		}
	}
	// Never return/log the transport error: Telegram tokens and webhook
	// credentials can occur in the URL embedded in *url.Error.
	resp, err := s.client.Do(req)
	if err != nil {
		return sendResult{Retry: true, Message: "网络、TLS 或超时错误，请求结果不确定"}
	}
	defer resp.Body.Close()
	result := sendResult{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.Message = "端点返回重定向，请更新渠道地址"
		return result
	}
	if channel.Kind == "telegram" {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
		if err != nil || len(raw) > 16<<10 {
			result.Retry = true
			result.Message = "Telegram 响应无法确认，请求可能已送达"
			return result
		}
		var api struct {
			OK         bool `json:"ok"`
			ErrorCode  int  `json:"error_code"`
			Parameters struct {
				RetryAfter int64 `json:"retry_after"`
			} `json:"parameters"`
		}
		if json.Unmarshal(raw, &api) != nil {
			result.Retry = resp.StatusCode == 429 || resp.StatusCode >= 500 || resp.StatusCode >= 200 && resp.StatusCode < 300
			result.Message = "Telegram 响应格式无效，请求结果不确定"
			return result
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && api.OK {
			result.Success = true
			return result
		}
		result.Retry = resp.StatusCode == 429 || resp.StatusCode >= 500 || api.ErrorCode == 429 || api.ErrorCode >= 500
		if api.Parameters.RetryAfter > 0 {
			result.RetryAfter = max(result.RetryAfter, min(api.Parameters.RetryAfter, 24*3600))
		}
		result.Message = "Telegram 拒绝请求，请检查凭据、目标与发送权限"
		if result.Retry {
			result.Message = "Telegram 暂时不可用或发送受限"
		}
		return result
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Success = true
		return result
	}
	result.Retry = resp.StatusCode == 408 || resp.StatusCode == 425 || resp.StatusCode == 429 || resp.StatusCode >= 500
	result.Message = "Webhook 拒绝请求，请检查地址与认证"
	if result.Retry {
		result.Message = "Webhook 暂时不可用或发送受限"
	}
	return result
}
