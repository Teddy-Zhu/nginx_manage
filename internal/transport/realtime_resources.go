package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	contract "nginxpanel/api"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/remoteapi"
)

const realtimeFrameLimit = 8 << 20

type realtimeValue struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
	Status  int             `json:"status,omitempty"`
	Reset   bool            `json:"reset,omitempty"`
}

type realtimeMessage struct {
	realtimeValue
	Resource   string `json:"resource,omitempty"`
	Connection string `json:"connection,omitempty"`
	Revision   uint64 `json:"revision,omitempty"`
}

func validRealtimeValue(value realtimeValue) bool {
	return value.Code != "" && json.Valid(value.Data) &&
		(value.Code == "OK" && value.Status == 0 || value.Code != "OK" && value.Status >= 400 && value.Status <= 599 && value.Message != "")
}

func realtimeUnavailable(message string) realtimeValue {
	err := fault.Unavailable(message).(*fault.Error)
	return realtimeValue{Code: err.Code, Message: err.Message, Data: json.RawMessage("null"), Status: err.Status}
}

func validateRealtimeResources(topics, resources []string) error {
	if len(resources) == 0 || len(resources) > 64 {
		return fault.Invalid("实时资源数量超出限制")
	}
	seen := map[string]bool{}
	for _, resource := range resources {
		topic, ok := contract.RealtimeTopic(resource)
		if !ok || !slices.Contains(topics, topic) || seen[resource] {
			return fault.Invalid("实时资源无效或不属于订阅范围")
		}
		u, _ := url.ParseRequestURI(resource)
		if u.Path == "/firewall/plan" {
			var in firewall.PlanInput
			if json.Unmarshal([]byte(u.Query().Get("input")), &in) != nil || in.PreparationID == "" || in.CancelPreparation || in.DockerTargets != nil {
				return fault.Invalid("实时订阅只允许查询已有准备任务")
			}
		}
		seen[resource] = true
	}
	return nil
}

// Existing read handlers remain the authority for validation, permissions and
// response envelopes. Dispatch happens in process, without a second HTTP request.
type realtimeCapture struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	deadline time.Time
}

func (c *realtimeCapture) Header() http.Header { return c.header }
func (c *realtimeCapture) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}
func (c *realtimeCapture) Write(data []byte) (int, error) {
	if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if c.status == 0 {
		c.status = 200
	}
	if c.body.Len()+len(data) > realtimeFrameLimit {
		return 0, fault.Invalid("实时数据超出大小限制")
	}
	return c.body.Write(data)
}
func (c *realtimeCapture) SetWriteDeadline(deadline time.Time) error {
	c.deadline = deadline
	return nil
}

type realtimeResources struct {
	server   *Server
	request  *http.Request
	subject  string
	cursors  map[string]string
	previous map[string]realtimeValue
}

func (s *Server) realtimeResources(r *http.Request) *realtimeResources {
	return &realtimeResources{server: s, request: r, cursors: map[string]string{}, previous: map[string]realtimeValue{}}
}
func (state *realtimeResources) Close() {
	if state.server.Agent == nil || len(state.cursors) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(state.request.Context()), 3*time.Second)
	defer cancel()
	for _, cursor := range state.cursors {
		if cursor != "" {
			if err := state.server.Agent.ReleaseLogs(ctx, state.subject, cursor); err != nil {
				slog.Warn("realtime log cursor cleanup failed", "error", err)
			}
		}
	}
}
func (state *realtimeResources) Read(ctx context.Context, topics, resources []string) map[string]realtimeValue {
	out := map[string]realtimeValue{}
	total := 0
	for _, resource := range resources {
		topic, _ := contract.RealtimeTopic(resource)
		if !slices.Contains(topics, topic) || ctx.Err() != nil {
			continue
		}
		r := state.request.Clone(ctx)
		u, _ := url.ParseRequestURI("/api/v1" + resource)
		r.URL = u
		r.RequestURI = u.RequestURI()
		r.Method = http.MethodGet
		r.Body = http.NoBody
		r.Header = r.Header.Clone()
		r.Header.Set("Content-Type", "application/json")
		capture := &realtimeCapture{header: http.Header{}}
		if r.Header.Get(remoteapi.HopHeader) != "" && !contract.RealtimeRemoteAllowed(resource) {
			state.server.fail(capture, r, auth.ErrForbidden)
		} else {
			switch u.Path {
			case "/api/v1/logs/live":
				state.logs(capture, r, resource)
			case "/api/v1/firewall/plan":
				r.Method = http.MethodPost
				body := []byte(u.Query().Get("input"))
				r.Body = http.NoBody
				if len(body) > 0 {
					r.Body = io.NopCloser(bytes.NewReader(body))
				}
				r.ContentLength = int64(len(body))
				state.server.realtimeReader.ServeHTTP(capture, r)
			default:
				if u.Path == "/api/v1/monitoring/history" {
					q := u.Query()
					if window := q.Get("window"); window != "" {
						seconds, err := strconv.ParseInt(window, 10, 64)
						if err != nil || seconds < 1 || seconds > 24*3600 {
							state.server.fail(capture, r, fault.Invalid("监控时间范围无效"))
							break
						}
						until := time.Now().Unix()
						q.Del("window")
						q.Set("from", strconv.FormatInt(until-seconds, 10))
						q.Set("until", strconv.FormatInt(until, 10))
						u.RawQuery = q.Encode()
					}
				}
				state.server.realtimeReader.ServeHTTP(capture, r)
			}
		}
		if u.Path == "/api/v1/logs/live" && capture.status == http.StatusNoContent {
			continue
		}
		var value realtimeValue
		if capture.status == 0 || json.Unmarshal(capture.body.Bytes(), &value) != nil || value.Code == "" || !json.Valid(value.Data) || (value.Code == "OK") != (capture.status >= 200 && capture.status < 300) {
			value = realtimeUnavailable("实时状态读取失败")
		}
		if total+capture.body.Len() > 7<<20 {
			value = realtimeUnavailable("实时数据超出限制，请缩小查询范围")
		}
		total += capture.body.Len()
		if value.Code == "OK" {
			value.Message = ""
		} else if value.Status == 0 {
			value.Status = capture.status
		}
		value.Reset = capture.Header().Get("X-Realtime-Reset") == "true"
		previous, exists := state.previous[resource]
		// Live log pages are deltas: identical rows may be separate events.
		if u.Path != "/api/v1/logs/live" && exists && previous.Code == value.Code && previous.Message == value.Message && previous.Status == value.Status && bytes.Equal(previous.Data, value.Data) {
			continue
		}
		state.previous[resource] = value
		out[resource] = value
	}
	return out
}

func (state *realtimeResources) logs(w http.ResponseWriter, r *http.Request, key string) {
	s := state.server
	var query logs.Query
	decoder := json.NewDecoder(strings.NewReader(r.URL.Query().Get("query")))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&query) != nil || decoder.Decode(new(any)) != io.EOF || query.Mode != "recent" || query.Until != 0 || query.Cursor != "" {
		s.fail(w, r, fault.Invalid("实时日志查询无效"))
		return
	}
	if err := query.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	p, allow, err := s.logPrincipal(r, query)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	query.Cursor = state.cursors[key]
	if query.Cursor == "" {
		w.Header().Set("X-Realtime-Reset", "true")
	}
	state.subject = s.logSubject(r, p)
	page, err := s.Agent.QueryLogs(r.Context(), agent.LogReadRequest{Subject: s.logSubject(r, p), AllowSensitive: allow, Query: query})
	if isLogCursorExpired(err) || errors.Is(err, logs.ErrCursor) {
		query.Cursor = ""
		w.Header().Set("X-Realtime-Reset", "true")
		page, err = s.Agent.QueryLogs(r.Context(), agent.LogReadRequest{Subject: s.logSubject(r, p), AllowSensitive: allow, Query: query})
		page.Gap = true
	}
	if err != nil {
		s.fail(w, r, logAgentError(err))
		return
	}
	state.cursors[key] = page.Cursor
	// Cursors belong to the subscription and are released with it.
	page.Cursor = ""
	if len(page.Rows) == 0 && !page.Gap && !page.More && page.ScannedBytes == 0 && page.Skipped == 0 && page.Notice == "" && w.Header().Get("X-Realtime-Reset") != "true" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.ok(w, r, page)
}
