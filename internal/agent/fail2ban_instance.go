package agent

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

type fail2banReadBudget struct {
	mu              sync.Mutex
	active, started int
	window          time.Time
}

func (b *fail2banReadBudget) reserve() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.window.IsZero() || now.Sub(b.window) >= 30*time.Second {
		b.window, b.started = now, 0
	}
	if b.active >= 2 || b.started >= 16 {
		return false
	}
	b.active++
	b.started++
	return true
}
func (b *fail2banReadBudget) release() { b.mu.Lock(); b.active--; b.mu.Unlock() }

type fail2banReadJob[T any] struct {
	at    time.Time
	done  chan struct{}
	ready bool
	value T
}
type fail2banReadCache[T any] struct {
	mu      sync.Mutex
	entries map[string]*fail2banReadJob[T]
}

func (c *fail2banReadCache[T]) read(ctx, owner context.Context, budget *fail2banReadBudget, key string, collect func(context.Context) T) (T, error) {
	var zero T
	if ctx.Err() != nil {
		return zero, fault.Unavailable("实例读取请求已取消")
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*fail2banReadJob[T]{}
	}
	now := time.Now()
	for k, job := range c.entries {
		if job.ready && now.Sub(job.at) >= 30*time.Second {
			delete(c.entries, k)
		}
	}
	job := c.entries[key]
	if job == nil {
		if len(c.entries) >= 65 || !budget.reserve() {
			c.mu.Unlock()
			return zero, fault.New(429, "FAIL2BAN_READ_BUSY", "实例读取预算已用尽，请稍后刷新")
		}
		job = &fail2banReadJob[T]{at: now, done: make(chan struct{})}
		c.entries[key] = job
		go func() {
			defer budget.release()
			call, cancel := context.WithTimeout(owner, 10*time.Second)
			defer cancel()
			value := collect(call)
			c.mu.Lock()
			job.value, job.ready = value, true
			close(job.done)
			c.mu.Unlock()
		}()
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return zero, fault.Unavailable("实例状态仍在读取，请稍后刷新")
	case <-job.done:
	}
	return job.value, nil
}

type fail2banInstanceReader struct {
	ctx         context.Context
	data, scope string
	dev         bool
	budget      fail2banReadBudget
	instances   fail2banReadCache[fail2ban.Instance]
	jails       fail2banReadCache[fail2ban.Jail]
}

func (f *fail2banInstanceReader) initial() fail2ban.Instance {
	out := fail2ban.EmptyInstance(f.scope, "")
	out.At = time.Now().Unix()
	if f.dev {
		out.Source, out.Scope = "development-agent", "development"
	}
	if os.Geteuid() != 0 || (&HostDNS{Dev: f.dev, Scope: f.scope}).hostScopeReason() != "" {
		out.Reason = "实例读取须由 root Agent 确认宿主机观测范围"
		return out
	}
	out.Binding = fail2banBindingView(f.data)
	if out.Binding.State != "bound" {
		out.Reason = out.Binding.Reason
	}
	return out
}
func (f *fail2banInstanceReader) readInstance(ctx context.Context) (fail2ban.Instance, error) {
	initial := f.initial()
	if initial.Binding.State != "bound" {
		return initial, nil
	}
	b, err := selectFail2banBinding(f.data)
	if err != nil || b == nil || b.ID != initial.Binding.ID || b.State != "bound" {
		return fail2ban.Instance{}, fault.Unavailable("实例接入记录变化，请刷新")
	}
	out, err := f.instances.read(ctx, f.ctx, &f.budget, b.ID, func(call context.Context) fail2ban.Instance {
		value := initial
		value.At = time.Now().Unix()
		version, service, raw, readErr := readFail2banBound(call, f.data, b, true, "")
		if readErr != nil {
			value.Reason = readErr.Error()
			return value
		}
		jails, readErr := parseFail2banJails(raw)
		if readErr != nil {
			value.Reason = readErr.Error()
			return value
		}
		value.Available, value.ServerVersion, value.Service, value.Jails = true, version, service, jails
		value.Reason = "jail 当前只读；引擎封禁记录不证明动作适用于当前流量路径"
		return value
	})
	if err != nil {
		return fail2ban.Instance{}, err
	}
	if err = fail2banCurrentBinding(f.data, b, true); err != nil {
		return fail2ban.Instance{}, fault.Unavailable("实例读取授权已变化，请刷新")
	}
	return out, nil
}
func (f *fail2banInstanceReader) readJail(ctx context.Context, name string) (fail2ban.Jail, error) {
	if !fail2banJailName.MatchString(name) {
		return fail2ban.Jail{}, fault.Invalid("jail 名称无效")
	}
	instance, err := f.readInstance(ctx)
	if err != nil {
		return fail2ban.Jail{}, err
	}
	out := fail2ban.EmptyJail(instance.Scope, name, instance.Reason)
	out.At, out.Source, out.BindingID = time.Now().Unix(), instance.Source, instance.Binding.ID
	if !instance.Available {
		return out, nil
	}
	found := false
	for _, jail := range instance.Jails {
		found = found || jail.Name == name
	}
	if !found {
		return fail2ban.Jail{}, fault.New(404, "FAIL2BAN_JAIL_MISSING", "jail 不在当前完整列表中，请刷新实例")
	}
	b, err := selectFail2banBinding(f.data)
	if err != nil || b == nil || b.ID != out.BindingID || b.State != "bound" {
		return fail2ban.Jail{}, fault.Unavailable("实例接入记录变化，请刷新")
	}
	value, err := f.jails.read(ctx, f.ctx, &f.budget, b.ID+"/"+name, func(call context.Context) fail2ban.Jail {
		value := out
		value.At = time.Now().Unix()
		version, _, raw, readErr := readFail2banBound(call, f.data, b, true, name)
		if readErr == nil {
			readErr = parseFail2banJail(raw, &value)
		}
		if readErr != nil {
			value = fail2ban.EmptyJail(out.Scope, name, readErr.Error())
			value.At, value.Source, value.BindingID = time.Now().Unix(), out.Source, b.ID
			return value
		}
		value.Available, value.ServerVersion = true, version
		value.Reason = "仅显示引擎记录；此 jail 尚未接管，动作的流量路径适用性未核对"
		return value
	})
	if err != nil {
		return fail2ban.Jail{}, err
	}
	if err = fail2banCurrentBinding(f.data, b, true); err != nil {
		return fail2ban.Jail{}, fault.Unavailable("jail 读取授权已变化，请刷新")
	}
	return value, nil
}
func (s *Server) fail2banInstanceHandlers(mux *http.ServeMux, ctx context.Context) {
	f := &fail2banInstanceReader{ctx: ctx, data: s.DataDir, scope: s.MetricsScope, dev: s.Dev}
	mux.HandleFunc("GET /v1/fail2ban/instance", func(w http.ResponseWriter, r *http.Request) {
		value, err := f.readInstance(r.Context())
		dnsReply(w, value, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/jails/{name}", func(w http.ResponseWriter, r *http.Request) {
		value, err := f.readJail(r.Context(), r.PathValue("name"))
		dnsReply(w, value, err)
	})
}
func (c *Client) ReadFail2banInstance(ctx context.Context) (fail2ban.Instance, error) {
	var out fail2ban.Instance
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/instance", nil, &out)
	if err == nil && (out.At <= 0 || out.Writable || !fail2ban.ValidBindingView(out.Binding) || out.Source != "host-agent" && out.Source != "development-agent" || len(out.Jails) > 64 || out.Available && (out.Binding.State != "bound" || !validID(out.Binding.ID) || !fail2banVersion.MatchString(out.ServerVersion))) {
		err = errors.New("invalid Fail2ban instance observation")
	}
	if err == nil {
		for _, jail := range out.Jails {
			if !fail2banJailName.MatchString(jail.Name) || jail.Managed {
				err = errors.New("invalid Fail2ban jail ownership")
				break
			}
		}
	}
	return out, err
}
func (c *Client) ReadFail2banJail(ctx context.Context, name string) (fail2ban.Jail, error) {
	var out fail2ban.Jail
	if !fail2banJailName.MatchString(name) {
		return out, fault.Invalid("jail 名称无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/jails/"+name, nil, &out)
	if err == nil && (out.At <= 0 || out.Name != name || out.Writable || out.Managed || out.Source != "host-agent" && out.Source != "development-agent" || len(out.Banned) > 1024 || out.Available && (!validID(out.BindingID) || !fail2banVersion.MatchString(out.ServerVersion) || out.CurrentFailed == nil || out.TotalFailed == nil || out.CurrentBanned == nil || out.TotalBanned == nil || *out.CurrentBanned != int64(len(out.Banned)))) {
		err = errors.New("invalid Fail2ban jail observation")
	}
	return out, err
}
