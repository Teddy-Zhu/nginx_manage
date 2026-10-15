package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

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
		if s.Nginx == nil || s.Nginx.logs == nil {
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
			m := s.Nginx.logs
			switch action {
			case "sources":
				logReply(w, m.sources(), nil)
			case "policy":
				logReply(w, m.policy(), nil)
			case "query":
				page, err := m.reader.Read(r.Context(), in.Subject, in.Query, in.AllowSensitive, in.Budget)
				logReply(w, page, err)
			case "release":
				m.reader.Release(in.Subject, in.Query.Cursor)
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
		out, err := s.Nginx.SetLogPolicy(in)
		logReply(w, out, err)
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
func (c *Client) LogPolicy(ctx context.Context) (logs.PolicyView, error) {
	return logRPC[logs.PolicyView](ctx, c, "policy", LogReadRequest{Protocol: Protocol})
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
