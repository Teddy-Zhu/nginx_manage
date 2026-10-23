package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/transport/apigen"
)

func logAgentError(err error) error {
	if err == nil {
		return nil
	}
	var known *fault.Error
	if errors.As(err, &known) {
		return known
	}
	return fault.Unavailable("日志 Agent 不可用，请确认专用实例与本机 Agent 状态")
}
func (s *Server) ListLogSources(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("日志 Agent 未配置"))
		return
	}
	out, err := s.Agent.LogSources(r.Context())
	if err != nil {
		s.fail(w, r, logAgentError(err))
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetLogPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("日志 Agent 未配置"))
		return
	}
	out, err := s.Agent.LogPolicies(r.Context())
	if err != nil {
		s.fail(w, r, logAgentError(err))
		return
	}
	s.ok(w, r, out)
}
func (s *Server) SetLogPolicy(w http.ResponseWriter, r *http.Request, params apigen.SetLogPolicyParams) {
	p, ok := s.authorize(w, r, "system.write")
	if !ok {
		return
	}
	var in logs.PolicyInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.Policy.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	key := params.IdempotencyKey
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		s.fail(w, r, fault.Invalid("幂等标识无效"))
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("日志 Agent 未配置"))
		return
	}
	digest := secure.Hash([]byte("logs.policy\x00" + p.ID + "\x00" + key))
	id := digest[:8] + "-" + digest[8:12] + "-" + digest[12:16] + "-" + digest[16:20] + "-" + digest[20:32]
	if err := s.audit(r, p.ID, "logs.policy", id, "requested"); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Agent.SetLogPolicy(r.Context(), agent.LogPolicyRequest{Protocol: agent.Protocol, OperationID: id, BaseVersion: in.BaseVersion, Policy: in.Policy, Scope: in.Scope})
	outcome := "succeeded"
	if err != nil || out.State != "succeeded" {
		outcome = "failed"
	}
	if auditErr := s.audit(r, p.ID, "logs.policy", id, outcome); auditErr != nil {
		s.fail(w, r, auditErr)
		return
	}
	if err != nil {
		s.fail(w, r, logAgentError(err))
		return
	}
	if out.State != "succeeded" {
		s.fail(w, r, fault.Conflict("原日志策略操作未成功，请重新读取策略后使用新的幂等标识保存"))
		return
	}
	s.ok(w, r, map[string]any{"operation_id": out.OperationID, "version": out.LogPolicyVersion})
}

func (s *Server) logSubject(r *http.Request, p auth.Principal) string {
	if p.Machine {
		return "credential:" + p.ID
	}
	return "session:" + secure.Hash([]byte(s.Auth.Sessions.Token(r.Context())))
}
func (s *Server) logPrincipal(r *http.Request, q logs.Query) (auth.Principal, bool, error) {
	p, err := s.Auth.Authenticate(r)
	if err != nil {
		return p, false, err
	}
	if err := p.Require("read"); err != nil {
		return p, false, err
	}
	if s.Agent == nil {
		return p, false, fault.Unavailable("日志 Agent 未配置")
	}
	sources, err := s.Agent.LogSources(r.Context())
	if err != nil {
		return p, false, logAgentError(err)
	}
	for _, source := range sources {
		if source.ID == q.SourceID {
			allow := p.Has("config.secrets")
			if source.Sensitive && !p.Has("config.secrets") {
				return p, false, auth.ErrForbidden
			}
			return p, allow, nil
		}
	}
	return p, false, fault.NotFound("受管日志来源不存在")
}
func (s *Server) QueryLogs(w http.ResponseWriter, r *http.Request, _ apigen.QueryLogsParams) {
	var q logs.Query
	if err := decode(w, r, &q); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := q.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	p, allow, err := s.logPrincipal(r, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Agent.QueryLogs(r.Context(), agent.LogReadRequest{Subject: s.logSubject(r, p), AllowSensitive: allow, Query: q})
	if err != nil {
		s.fail(w, r, logAgentError(err))
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ReleaseLogCursor(w http.ResponseWriter, r *http.Request, _ apigen.ReleaseLogCursorParams) {
	p, ok := s.authorize(w, r, "read")
	if !ok {
		return
	}
	var in struct {
		Cursor string `json:"cursor"`
	}
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(in.Cursor) > 128 {
		s.fail(w, r, fault.Invalid("日志游标无效"))
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("日志 Agent 未配置"))
		return
	}
	if err := s.Agent.ReleaseLogs(r.Context(), s.logSubject(r, p), in.Cursor); err != nil {
		s.fail(w, r, logAgentError(err))
		return
	}
	s.ok(w, r, nil)
}

func (s *Server) DownloadLogs(w http.ResponseWriter, r *http.Request, _ apigen.DownloadLogsParams) {
	var q logs.Query
	if err := decode(w, r, &q); err != nil {
		s.fail(w, r, err)
		return
	}
	if q.Cursor != "" {
		s.fail(w, r, fault.Invalid("下载须从新的查询开始"))
		return
	}
	if err := q.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	p, allow, err := s.logPrincipal(r, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	subject := s.logSubject(r, p)
	var buffer bytes.Buffer
	scanned, skipped, count := int64(0), 0, 0
	gap, truncated := false, false
	defer func() {
		if q.Cursor != "" {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := s.Agent.ReleaseLogs(cleanup, subject, q.Cursor); err != nil {
				slog.Warn("release download log cursor failed; Agent expiry will reclaim it", "request_id", r.Context().Value(requestIDKey))
			}
		}
	}()
	for {
		page, readErr := s.Agent.QueryLogs(ctx, agent.LogReadRequest{Subject: subject, AllowSensitive: allow, Query: q, Budget: int64(limits.LogScanBytes) - scanned})
		if readErr != nil {
			s.fail(w, r, logAgentError(readErr))
			return
		}
		q.Cursor = page.Cursor
		scanned += page.ScannedBytes
		skipped += page.Skipped
		gap = gap || page.Gap
		for _, row := range page.Rows {
			line, encodeErr := json.Marshal(row)
			if encodeErr != nil {
				s.fail(w, r, encodeErr)
				return
			}
			if buffer.Len()+len(line)+1 > 8<<20 || count >= 10000 {
				truncated = true
				break
			}
			buffer.Write(line)
			buffer.WriteByte('\n')
			count++
		}
		if truncated || !page.More {
			break
		}
		if page.ScannedBytes == 0 {
			truncated = true
			break
		}
		if scanned >= limits.LogScanBytes || count >= 10000 {
			truncated = true
			break
		}
	}
	summary, _ := json.Marshal(map[string]any{"type": "summary", "rows": count, "scanned_bytes": scanned, "skipped": skipped, "gap": gap, "truncated": truncated, "sanitized": true})
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=nginx-logs.jsonl")
	w.Header().Set("X-Log-Truncated", fmt.Sprint(truncated))
	w.Header().Set("X-Log-Gap", fmt.Sprint(gap))
	w.Header().Set("X-Node-ID", s.NodeID)
	w.Write(summary)
	w.Write([]byte("\n"))
	w.Write(buffer.Bytes())
}

type logStreamPage struct {
	page logs.Page
	err  error
}

func (s *Server) StreamLogs(w http.ResponseWriter, r *http.Request, params apigen.StreamLogsParams) {
	if len(params.Query) > 4096 {
		s.fail(w, r, fault.Invalid("日志流查询超出大小限制"))
		return
	}
	var q logs.Query
	decoder := json.NewDecoder(strings.NewReader(params.Query))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&q) != nil || decoder.Decode(new(any)) != io.EOF {
		s.fail(w, r, fault.Invalid("日志流查询无效"))
		return
	}
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		q.Cursor = last
	}
	if err := q.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	if q.Mode != "recent" || q.Until != 0 {
		s.fail(w, r, fault.Invalid("实时跟随须使用最近模式且不指定结束时间"))
		return
	}
	p, _, err := s.logPrincipal(r, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.logStreams.Add(1) > limits.SSEConnections {
		s.logStreams.Add(-1)
		s.fail(w, r, fault.New(429, "LOG_STREAM_LIMIT", "实时日志连接数已达上限"))
		return
	}
	defer s.logStreams.Add(-1)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	subject := s.logSubject(r, p)
	read := func() (logs.Page, error) {
		current, err := s.Auth.Authenticate(r)
		if err != nil {
			return logs.Page{}, err
		}
		if err := current.Require("read"); err != nil {
			return logs.Page{}, err
		}
		if !current.Machine {
			alive, err := s.Auth.SessionAlive(r.Context())
			if err != nil {
				return logs.Page{}, err
			}
			if !alive {
				return logs.Page{}, auth.ErrUnauthorized
			}
		}
		canRead := current.Has("config.secrets")
		page, err := s.Agent.QueryLogs(ctx, agent.LogReadRequest{Subject: subject, AllowSensitive: canRead, Query: q})
		if errors.Is(err, logs.ErrCursor) || isLogCursorExpired(err) {
			q.Cursor = ""
			page, err = s.Agent.QueryLogs(ctx, agent.LogReadRequest{Subject: subject, AllowSensitive: canRead, Query: q})
			page.Gap = true
			page.Notice = "原游标已失效，已重新读取最近日志；中间范围可能存在缺口"
		}
		if err == nil {
			q.Cursor = page.Cursor
		}
		return page, err
	}
	first, err := read()
	if err != nil {
		s.fail(w, r, logAgentError(err))
		return
	}
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Node-ID", s.NodeID)
	emit := func(event string, data any, code, message, cursor string) error {
		if err := controller.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		payload, err := json.Marshal(Response{Code: code, Message: message, Data: data, RequestID: r.Context().Value(requestIDKey).(string), NodeID: s.NodeID})
		if err != nil {
			return err
		}
		if cursor != "" {
			if _, err := fmt.Fprintf(w, "id: %s\n", cursor); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload); err != nil {
			return err
		}
		return controller.Flush()
	}
	if err := emit("page", first, "OK", "操作成功", first.Cursor); err != nil {
		return
	}
	queue := make(chan logStreamPage, 4)
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			page, err := read()
			item := logStreamPage{page: page, err: err}
			select {
			case queue <- item:
			default:
				select {
				case <-queue:
				default:
				}
				item.page.Gap = true
				item.page.Notice = "读取速度低于日志产生速度，部分实时页面已丢弃；可缩小条件后查询历史"
				select {
				case queue <- item:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); <-producerDone }()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			emit("end", nil, "STREAM_ENDED", "实时连接已结束，请重新连接", "")
			return
		case item := <-queue:
			if item.err != nil {
				code, message := "LOG_STREAM_FAILED", "实时日志读取失败，请重新查询"
				var known *fault.Error
				if errors.As(item.err, &known) {
					code, message = known.Code, known.Message
				}
				if errors.Is(item.err, auth.ErrUnauthorized) {
					code, message = "UNAUTHENTICATED", "会话已失效，请重新登录"
				}
				if emit("error", nil, code, message, "") != nil {
					return
				}
				return
			}
			if err := emit("page", item.page, "OK", "操作成功", item.page.Cursor); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := controller.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			if _, err := io.WriteString(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if controller.Flush() != nil {
				return
			}
		}
	}
}
func isLogCursorExpired(err error) bool {
	var known *fault.Error
	return errors.As(err, &known) && known.Code == "LOG_CURSOR_EXPIRED"
}
