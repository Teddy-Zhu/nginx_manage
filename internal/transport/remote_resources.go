package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nginxpanel/api"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
)

const remoteResponseLimit = 32 << 20

func (s *Server) remoteRoutes(mux *http.ServeMux) {
	for _, route := range api.RemoteRoutes() {
		mux.HandleFunc(route.Method+" /api/v1"+route.Pattern, func(w http.ResponseWriter, r *http.Request) { s.forwardNode(w, r, route) })
	}
}

func remotePath(r *http.Request, route api.RemoteRoute) (string, error) {
	segments := strings.Split(route.Path, "/")
	for i, value := range segments {
		if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
			value = r.PathValue(value[1 : len(value)-1])
			if value == "" || value == "." || value == ".." || len(value) > 512 || strings.ContainsAny(value, "/\\\x00\r\n") {
				return "", fault.Invalid("远程资源标识无效")
			}
			segments[i] = url.PathEscape(value)
		}
	}
	if len(r.URL.RawQuery) > 16<<10 {
		return "", fault.Invalid("远程查询参数过长")
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", fault.Invalid("远程查询参数无效")
	}
	allowed := map[string]bool{}
	for _, key := range route.Query {
		allowed[key] = true
	}
	for key := range query {
		if !allowed[key] {
			return "", fault.Invalid("远程查询参数未在合同登记")
		}
	}
	path := strings.Join(segments, "/")
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return path, nil
}

func validRemoteEnvelope(raw []byte, node string, status int) bool {
	var body struct {
		Code      string          `json:"code"`
		Message   *string         `json:"message"`
		Data      json.RawMessage `json:"data"`
		RequestID string          `json:"request_id"`
		NodeID    string          `json:"node_id"`
	}
	return json.Unmarshal(raw, &body) == nil && body.NodeID == node && len(body.RequestID) > 0 && len(body.RequestID) <= 128 && len(body.Code) > 0 && len(body.Code) <= 64 && body.Message != nil && body.Data != nil && status >= 200 && status <= 599 && (status < 300) == (body.Code == "OK")
}

func (s *Server) forwardNode(w http.ResponseWriter, r *http.Request, route api.RemoteRoute) {
	p, ok := s.nodePrincipal(w, r)
	if !ok {
		return
	}
	if err := p.Require(route.Scopes...); err != nil {
		s.fail(w, r, err)
		return
	}
	path, err := remotePath(r, route)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, key := range []string{"Content-Type", "Idempotency-Key"} {
		if len(r.Header.Values(key)) > 1 {
			s.fail(w, r, fault.Invalid("远程请求头重复"))
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, route.BodyLimit))
	if err != nil {
		s.fail(w, r, fault.Invalid("远程请求内容无效或超过大小限制"))
		return
	}
	duration := 30 * time.Second
	if route.Kind == "sse" {
		duration = 10 * time.Minute
	}
	if route.Path == "/firewall/geoip/update" {
		duration = 125 * time.Second
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(130 * time.Second)); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), duration)
	defer cancel()
	r = r.WithContext(ctx)
	forwarded, err := s.Nodes.OpenForward(ctx, p, r.Context().Value(requestIDKey).(string), r.PathValue("connection"), route, path, r.Header, body)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	outcome := "unknown"
	defer func() { forwarded.Close(outcome) }()
	response := forwarded.Response
	if response.Header.Get("X-Node-ID") != forwarded.NodeID || response.Header.Get(remoteapi.ProtocolHeader) != "1" {
		s.fail(w, r, fault.New(http.StatusBadGateway, "REMOTE_IDENTITY_UNCONFIRMED", "目标响应身份或协议无法核验，写操作结果未确认"))
		return
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		s.fail(w, r, fault.New(http.StatusBadGateway, "REMOTE_INVALID_RESPONSE", "目标返回内容类型无效"))
		return
	}
	if route.Kind == "sse" && response.StatusCode == http.StatusOK && media == "text/event-stream" {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Node-ID", forwarded.NodeID)
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		err = s.forwardEvents(w, r, response.Body, forwarded.NodeID, p)
		if err == nil {
			outcome = "stream_closed"
		}
		return
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, remoteResponseLimit+1))
	if err != nil || len(raw) > remoteResponseLimit {
		s.fail(w, r, fault.New(http.StatusBadGateway, "REMOTE_INVALID_RESPONSE", "目标响应未完整接收或超过大小限制，请核对原任务"))
		return
	}
	if media == "application/json" {
		if !validRemoteEnvelope(raw, forwarded.NodeID, response.StatusCode) {
			s.fail(w, r, fault.New(http.StatusBadGateway, "REMOTE_INVALID_RESPONSE", "目标响应格式或身份无效，请核对原任务"))
			return
		}
	} else if response.StatusCode != http.StatusOK || !(route.Kind == "ndjson" && media == "application/x-ndjson" || route.Kind == "text" && media == "text/plain") {
		s.fail(w, r, fault.New(http.StatusBadGateway, "REMOTE_INVALID_RESPONSE", "目标响应不符合资源合同"))
		return
	}
	for _, key := range []string{"Content-Type", "Content-Disposition", "X-Log-Gap", "X-Log-Truncated", "X-Archive-SHA256", "Retry-After"} {
		if value := response.Header.Get(key); value != "" {
			w.Header().Set(key, value)
		}
	}
	w.Header().Set("X-Node-ID", forwarded.NodeID)
	w.Header().Set("X-Request-ID", response.Header.Get("X-Request-ID"))
	w.WriteHeader(response.StatusCode)
	if _, err = w.Write(raw); err == nil {
		outcome = "received"
	}
}

func (s *Server) forwardEvents(w http.ResponseWriter, r *http.Request, reader io.Reader, node string, principal auth.Principal) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), remoteResponseLimit)
	var frame bytes.Buffer
	reported := false
	flush := func() error {
		raw := frame.String()
		frame.Reset()
		if raw == "" {
			return nil
		}
		current, err := s.Auth.Authenticate(r)
		if err == nil {
			err = current.Require(append([]string{"nodes.manage", "read"}, principal.Scopes...)...)
		}
		if err == nil && (current.ID != principal.ID || current.Machine != principal.Machine) {
			err = auth.ErrUnauthorized
		}
		if err == nil && !current.Machine {
			var alive bool
			alive, err = s.Auth.SessionAlive(r.Context())
			if err == nil && !alive {
				err = auth.ErrUnauthorized
			}
		}
		if err != nil {
			code, message := "REMOTE_STREAM_INTERRUPTED", "控制端授权检查失败，请重新查询"
			if errors.Is(err, auth.ErrUnauthorized) {
				code, message = "UNAUTHENTICATED", "控制端会话或授权已失效"
			} else if errors.Is(err, auth.ErrForbidden) {
				code, message = "FORBIDDEN", "控制端权限已变化"
			}
			s.streamFailure(w, r, s.NodeID, code, message)
			reported = true
			return err
		}
		event := ""
		data := []string{}
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(line, ":") || line == "" {
				continue
			}
			switch {
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			case strings.HasPrefix(line, "id:"):
				if strings.ContainsRune(strings.TrimPrefix(line, "id:"), '\x00') {
					return errors.New("invalid SSE event ID")
				}
			default:
				return errors.New("unexpected SSE field")
			}
		}
		if len(data) > 0 {
			payload := []byte(strings.Join(data, "\n"))
			var code struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(payload, &code) != nil {
				return errors.New("invalid SSE payload")
			}
			status := 200
			if code.Code != "OK" {
				status = 400
			}
			if (event != "page" && event != "error" && event != "end") || !validRemoteEnvelope(payload, node, status) {
				return errors.New("SSE identity or event mismatch")
			}
		} else if event != "" {
			return errors.New("SSE event missing payload")
		}
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, raw+"\n"); err != nil {
			return err
		}
		return http.NewResponseController(w).Flush()
	}
	for scanner.Scan() {
		line := scanner.Text()
		if frame.Len()+len(line)+1 > remoteResponseLimit {
			s.remoteStreamError(w, r, node)
			return errors.New("SSE frame exceeds budget")
		}
		if line == "" {
			if err := flush(); err != nil {
				if !reported {
					s.remoteStreamError(w, r, node)
				}
				return err
			}
			continue
		}
		frame.WriteString(line)
		frame.WriteByte('\n')
	}
	err := scanner.Err()
	if err == nil && frame.Len() != 0 {
		err = errors.New("incomplete SSE frame")
	}
	if err != nil {
		s.remoteStreamError(w, r, node)
	}
	return err
}

func (s *Server) remoteStreamError(w http.ResponseWriter, r *http.Request, node string) {
	s.streamFailure(w, r, node, "REMOTE_STREAM_INTERRUPTED", "目标实时连接中断，请重新查询原节点")
}

func (s *Server) streamFailure(w http.ResponseWriter, r *http.Request, node, code, message string) {
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
	raw, _ := json.Marshal(Response{Code: code, Message: message, RequestID: r.Context().Value(requestIDKey).(string), NodeID: node})
	io.WriteString(w, "event: error\ndata: "+string(raw)+"\n\n")
	http.NewResponseController(w).Flush()
}
