package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/logs"
)

type LogReadRequest struct {
	Protocol       int        `json:"protocol"`
	Subject        string     `json:"subject"`
	AllowSensitive bool       `json:"allow_sensitive"`
	Query          logs.Query `json:"query"`
	Budget         int64      `json:"budget"`
}
type logResult[T any] struct {
	Protocol int    `json:"protocol"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Data     T      `json:"data"`
}

func logReply(w http.ResponseWriter, value any, err error) {
	status, code, message := 200, "OK", "成功"
	if err != nil {
		var known *fault.Error
		if errors.As(err, &known) {
			status, code, message = known.Status, known.Code, known.Message
		} else {
			status, code, message = 503, "LOG_AGENT_UNAVAILABLE", "日志 Agent 暂不可用"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, logResult[any]{Protocol: Protocol, Code: code, Message: message, Data: value})
}
func decodeLogRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		logReply(w, nil, fault.Invalid("日志请求格式无效"))
		return false
	}
	return true
}
func (s *Server) logHandlers(mux *http.ServeMux) {
	ready := func(w http.ResponseWriter) bool {
		if s.logReader == nil {
			logReply(w, nil, fault.Unavailable("受管日志尚未配置"))
			return false
		}
		return true
	}
	for _, action := range []string{"sources", "policy", "query", "release"} {
		mux.HandleFunc("POST /v1/logs/"+action, func(w http.ResponseWriter, r *http.Request) {
			if !ready(w) {
				return
			}
			var in LogReadRequest
			if !decodeLogRequest(w, r, &in) {
				return
			}
			if in.Protocol != Protocol {
				logReply(w, nil, fault.Invalid("日志协议版本无效"))
				return
			}
			switch action {
			case "sources":
				logReply(w, s.logSources(), nil)
			case "policy":
				logReply(w, s.logPolicies(), nil)
			case "query":
				page, err := s.logReader.Read(r.Context(), in.Subject, in.Query, in.AllowSensitive, in.Budget)
				logReply(w, page, err)
			case "release":
				s.logReader.Release(in.Subject, in.Query.Cursor)
				logReply(w, nil, nil)
			}
		})
	}
	mux.HandleFunc("POST /v1/logs/set-policy", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var in LogPolicyRequest
		if !decodeLogRequest(w, r, &in) {
			return
		}
		if in.Scope == "system" && s.eventLogs != nil {
			out, err := s.eventLogs.setPolicy(in)
			logReply(w, out, err)
		} else if in.Scope == "nginx" && s.Nginx != nil {
			out, err := s.Nginx.SetLogPolicy(in)
			logReply(w, out, err)
		} else {
			logReply(w, nil, fault.Invalid("日志策略范围不可用"))
		}
	})
	mux.HandleFunc("POST /v1/logs/append-events", func(w http.ResponseWriter, r *http.Request) {
		var in EventLogRequest
		if !decodeLogRequest(w, r, &in) {
			return
		}
		if s.eventLogs == nil {
			logReply(w, nil, fault.Unavailable("系统日志写入尚未就绪"))
			return
		}
		logReply(w, nil, s.eventLogs.append(in))
	})
}
func logRPC[T any](ctx context.Context, c *Client, action string, in any) (T, error) {
	var result logResult[T]
	err := c.request(ctx, "POST", "/v1/logs/"+action, in, &result)
	if err == nil && (result.Protocol != Protocol || result.Code != "OK") {
		err = fault.Unavailable("日志 Agent 协议无效")
	}
	return result.Data, err
}
func (c *Client) LogSources(ctx context.Context) ([]logs.Source, error) {
	return logRPC[[]logs.Source](ctx, c, "sources", LogReadRequest{Protocol: Protocol})
}
func (c *Client) LogPolicies(ctx context.Context) ([]logs.PolicyView, error) {
	return logRPC[[]logs.PolicyView](ctx, c, "policy", LogReadRequest{Protocol: Protocol})
}
func (c *Client) SetLogPolicy(ctx context.Context, in LogPolicyRequest) (Record, error) {
	return logRPC[Record](ctx, c, "set-policy", in)
}
func (c *Client) QueryLogs(ctx context.Context, in LogReadRequest) (logs.Page, error) {
	in.Protocol = Protocol
	return logRPC[logs.Page](ctx, c, "query", in)
}
func (c *Client) ReleaseLogs(ctx context.Context, subject, cursor string) error {
	_, err := logRPC[any](ctx, c, "release", LogReadRequest{Protocol: Protocol, Subject: subject, Query: logs.Query{Cursor: cursor}})
	return err
}

func (s *Server) logSources() []logs.Source {
	out := []logs.Source{}
	if s.eventLogs != nil {
		out = append(out, s.eventLogs.sources()...)
	} else if !s.Dev {
		for _, category := range []string{"application", "security"} {
			source := eventSource(category, "").Source
			source.Active = false
			source.Reason = "系统日志存储未就绪，待投递事件保留在有界队列；请本机核对 Agent"
			out = append(out, source)
		}
	}
	if s.Nginx != nil && s.Nginx.logs != nil {
		out = append(out, s.Nginx.logs.sources()...)
	}
	return out
}
func (s *Server) logPolicies() []logs.PolicyView {
	out := []logs.PolicyView{}
	if s.eventLogs != nil {
		out = append(out, s.eventLogs.policy())
	} else if !s.Dev {
		out = append(out, logs.PolicyView{Scope: "system", Policy: logs.DefaultPolicy(), Owner: "agent", Warning: "系统日志存储未就绪；请本机核对 Agent"})
	}
	if s.Nginx != nil && s.Nginx.logs != nil {
		out = append(out, s.Nginx.logs.policy())
	}
	return out
}
func (s *Server) logSnapshot(id string) (logs.Snapshot, error) {
	if s.eventLogs == nil && (id == eventSource("application", "").Source.ID || id == eventSource("security", "").Source.ID) {
		return logs.Snapshot{}, fault.Unavailable("系统日志存储未就绪")
	}
	if s.eventLogs != nil {
		s.eventLogs.mu.Lock()
		_, ok := s.eventLogs.state.Sources[id]
		s.eventLogs.mu.Unlock()
		if ok {
			return s.eventLogs.snapshot(id)
		}
	}
	if s.Nginx != nil && s.Nginx.logs != nil {
		return s.Nginx.logs.snapshot(id)
	}
	return logs.Snapshot{}, fault.NotFound("日志来源不存在")
}
func (s *Server) openCatalogLog(file logs.File) (*os.File, error) {
	for _, category := range []string{"application", "security", "tasks"} {
		if strings.HasPrefix(file.Name, filepath.Join(s.DataDir, "logs", category)+string(os.PathSeparator)) && s.eventLogs != nil {
			return s.eventLogs.openLog(file)
		}
	}
	if s.Nginx != nil && s.Nginx.logs != nil {
		return s.Nginx.logs.openLog(file)
	}
	return nil, fault.Unavailable("日志文件读取不可用")
}
func (s *Server) runEventLogs(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	defer func() {
		if s.eventLogs != nil {
			s.eventLogs.mu.Lock()
			defer s.eventLogs.mu.Unlock()
			if s.eventLogs.compression != nil {
				s.eventLogs.compression.close()
				s.eventLogs.compression = nil
			}
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		s.logReader.Expire()
		if s.eventLogs != nil {
			s.eventLogs.sweep(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
