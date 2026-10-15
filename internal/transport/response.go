package transport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

type contextKey uint8

const requestIDKey contextKey = 1

// All API paths, including middleware, malformed requests and unknown routes,
// go through this envelope. HTTP status remains meaningful independently.
type Response struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
	RequestID string `json:"request_id"`
	NodeID    string `json:"node_id"`
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, status int, code, message string, data any) {
	b, err := json.Marshal(Response{code, message, data, r.Context().Value(requestIDKey).(string), s.NodeID})
	if err != nil {
		slog.Error("response encoding failed", "request_id", r.Context().Value(requestIDKey))
		status = 500
		b = []byte(`{"code":"INTERNAL_ERROR","message":"响应编码失败","data":null,"request_id":"` + r.Context().Value(requestIDKey).(string) + `","node_id":"` + s.NodeID + `"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(b)
}
func (s *Server) ok(w http.ResponseWriter, r *http.Request, data any) {
	s.respond(w, r, 200, "OK", "操作成功", data)
}
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var f *fault.Error
	if errors.As(err, &f) {
		s.respond(w, r, f.Status, f.Code, f.Message, f.Data)
		return
	}
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		s.respond(w, r, 401, "UNAUTHENTICATED", "请登录后继续", nil)
	case errors.Is(err, auth.ErrForbidden):
		s.respond(w, r, 403, "FORBIDDEN", "权限不足", nil)
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		s.respond(w, r, 429, "RATE_LIMITED", err.Error(), nil)
	case errors.Is(err, nginxconfig.ErrConflict):
		s.respond(w, r, 409, "REVISION_CONFLICT", err.Error(), nil)
	case errors.Is(err, nginxconfig.ErrInvalid):
		s.respond(w, r, 422, "CONFIG_INVALID", err.Error(), nil)
	case errors.Is(err, nginxconfig.ErrNotFound), errors.Is(err, sql.ErrNoRows):
		s.respond(w, r, 404, "NOT_FOUND", "资源不存在", nil)
	case errors.Is(err, context.DeadlineExceeded):
		s.respond(w, r, 504, "TIMEOUT", "请求超时，请先查询任务状态", nil)
	default:
		slog.Error("API operation failed", "request_id", r.Context().Value(requestIDKey), "error", err)
		s.respond(w, r, 500, "INTERNAL_ERROR", "操作失败，请查看服务日志中的请求标识", nil)
	}
}
func decode(w http.ResponseWriter, r *http.Request, out any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return fault.Invalid("请求须使用 application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.RequestBytes)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fault.Invalid("请求 JSON 无效或超出大小限制")
	}
	if d.Decode(new(any)) != io.EOF {
		return fault.Invalid("请求只能包含一个 JSON 对象")
	}
	return nil
}
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := secure.ID()
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey, id))
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		defer func() {
			if recover() != nil {
				slog.Error("API panic", "request_id", id)
				s.respond(w, r, 500, "INTERNAL_ERROR", "内部错误", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if r.Header.Get("Authorization") == "" {
				origin := r.Header.Get("Origin")
				if origin != "" {
					u, err := url.Parse(origin)
					scheme := "https"
					if s.Dev {
						scheme = "http"
					}
					if err != nil || u.Scheme != scheme || !strings.EqualFold(u.Host, r.Host) {
						s.respond(w, r, 403, "ORIGIN_REJECTED", "请求来源未获授权", nil)
						return
					}
				}
				if !s.Auth.CheckCSRF(r) {
					s.respond(w, r, 403, "CSRF_REJECTED", "页面凭据已失效，请刷新页面", nil)
					return
				}
			} else {
				p, err := s.Auth.Authenticate(r)
				if err != nil {
					s.fail(w, r, err)
					return
				}
				if !p.Machine {
					s.fail(w, r, auth.ErrUnauthorized)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, recent bool, scopes ...string) (auth.Principal, bool) {
	p, err := s.Auth.Authenticate(r)
	if err == nil {
		err = p.Require(scopes...)
	}
	if err != nil {
		s.fail(w, r, err)
		return p, false
	}
	if !p.Machine && recent && !s.Auth.Recent(r.Context()) {
		s.respond(w, r, 403, "REAUTHENTICATION_REQUIRED", "请重新验证密码后继续", nil)
		return p, false
	}
	return p, true
}
