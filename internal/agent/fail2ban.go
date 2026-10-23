package agent

import (
	"context"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

type fail2banObserver struct {
	mu    sync.Mutex
	ctx   context.Context
	scope string
	data  string
	dev   bool
	done  chan struct{}
	last  time.Time
	value fail2ban.Observation
}

func (f *fail2banObserver) read(ctx context.Context) (fail2ban.Observation, error) {
	f.mu.Lock()
	if f.done == nil && (f.last.IsZero() || time.Since(f.last) >= 30*time.Second) {
		f.last, f.done = time.Now(), make(chan struct{})
		done := f.done
		go func() {
			call, cancel := context.WithTimeout(f.ctx, 6*time.Second)
			defer cancel()
			value := f.collect(call)
			f.mu.Lock()
			f.value, f.done = value, nil
			close(done)
			f.mu.Unlock()
		}()
	}
	done := f.done
	if done == nil {
		value := f.value
		f.mu.Unlock()
		return value, nil
	}
	f.mu.Unlock()
	select {
	case <-ctx.Done():
		return fail2ban.Observation{}, fault.Unavailable("Fail2ban 诊断仍在读取，请稍后刷新")
	case <-done:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.value, nil
}

var fail2banClientVersion = regexp.MustCompile(`^Fail2Ban v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:[a-zA-Z0-9.+_-]{0,32}))$`)

func (f *fail2banObserver) collect(ctx context.Context) fail2ban.Observation {
	out := fail2ban.Empty(f.scope, "")
	out.At = time.Now().Unix()
	if f.dev {
		out.Source, out.Scope = "development-agent", "development"
	}
	if (&HostDNS{Dev: f.dev, Scope: f.scope}).hostScopeReason() != "" || os.Geteuid() != 0 {
		out.Reason = "Fail2ban 诊断须由 root Agent 在本机以 --metrics-scope=host 确认宿主机范围"
		return out
	}
	if ctx.Err() != nil {
		out.Reason = "宿主机诊断已停止"
		return out
	}
	out.Available = true
	out.Managed = readFail2banManaged(f.data)
	out.Binding = fail2banBindingView(f.data)
	for _, id := range []string{"fail2ban-client", "fail2ban-server", "fail2ban-regex"} {
		out.Tools = append(out.Tools, fail2banTool(id))
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); out.Python = readFail2banPython(ctx) }()
	go func() { defer wg.Done(); out.Services = readFail2banServices(ctx) }()
	go func() {
		defer wg.Done()
		if out.Tools[0].Trusted {
			if raw, err := fail2banRun(ctx, out.Tools[0], []string{"--version"}, 4096); err == nil {
				if match := fail2banClientVersion.FindStringSubmatch(strings.TrimSpace(string(raw))); match != nil {
					out.ClientVersion = match[1]
				}
			}
		}
	}()
	out.Socket = readFail2banSocket()
	wg.Wait()
	for _, tool := range out.Tools {
		if tool.Present != nil && !*tool.Present {
			out.Missing = append(out.Missing, tool.ID)
		}
		if tool.Present == nil || !tool.Trusted {
			out.Warnings = append(out.Warnings, tool.ID+"："+tool.Reason)
		}
	}
	if out.Python.Executable.Present != nil && !*out.Python.Executable.Present {
		out.Missing = append(out.Missing, "python3")
	}
	if out.Python.StandardLibrary == nil || !*out.Python.StandardLibrary {
		out.Warnings = append(out.Warnings, out.Python.Reason)
	}
	if out.ClientVersion == "" && out.Tools[0].Trusted {
		out.Warnings = append(out.Warnings, "官方客户端版本无法完整读取")
	}
	if out.Binding.State == "bound" {
		out.Warnings = append(out.Warnings, "程序及服务元数据不证明 jail 保护；已接入实例的读取结果须单独核对")
	} else if out.Binding.State == "unbound" {
		out.Warnings = append(out.Warnings, "服务单元状态和默认 Socket 文件不证明引擎健康或 jail 保护；实例尚未授权接入")
	} else {
		out.Warnings = append(out.Warnings, "实例接入授权未知；程序及服务元数据不证明 jail 保护")
	}
	return out
}

func (s *Server) fail2banHandlers(mux *http.ServeMux, ctx context.Context) {
	f := &fail2banObserver{ctx: ctx, data: s.DataDir, scope: s.MetricsScope, dev: s.Dev}
	s.fail2banInstanceHandlers(mux, ctx)
	s.fail2banTemplateHandlers(mux, ctx)
	mux.HandleFunc("GET /v1/fail2ban", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.read(r.Context())
		if err == nil && out.Available {
			// Installation and binding receipts change independently of the
			// cached system-tool inventory. Navigation must see them immediately.
			out.Managed = readFail2banManaged(s.DataDir)
			out.Binding = fail2banBindingView(s.DataDir)
		}
		dnsReply(w, out, err)
	})
}
func (c *Client) ReadFail2ban(ctx context.Context) (fail2ban.Observation, error) {
	var out fail2ban.Observation
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban", nil, &out)
	if err == nil && (out.Source != "host-agent" && out.Source != "development-agent" || out.At <= 0 || out.Writable || len(out.Tools) > 3 || len(out.Services) > 3 || len(out.Python.Modules) > len(fail2banPythonModules) || len(out.Missing) > 4 || len(out.Warnings) > 8 || !fail2ban.ValidManaged(out.Managed) || !fail2ban.ValidBindingView(out.Binding)) {
		err = errors.New("invalid Fail2ban observation")
	}
	return out, err
}
