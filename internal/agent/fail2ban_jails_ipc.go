package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

type Fail2banJailsStatus = fail2ban.JailsRuntime

func (f *fail2banJailsExecutor) jailsStatus(ctx context.Context) (Fail2banJailsStatus, error) {
	out := Fail2banJailsStatus{Policy: fail2ban.DefaultPolicy(), Resources: []string{}, Pending: []Fail2banJailsOperation{}, HostReason: "尚未核对宿主机动作批准", NginxReason: "尚未核对 Nginx 动作"}
	records, err := f.journal().List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == fail2banJailsKind && pendingNginxRecord(record) {
			if record.Fail2banJails == nil {
				return out, errors.New("受管 jail 记录损坏")
			}
			out.Pending = append(out.Pending, fail2banJailsView(record))
		}
	}
	if len(out.Pending) > 0 {
		out.Reason = "受管 jail 正在应用或等待恢复"
		return out, nil
	}
	leave, err := f.lock(false)
	if err != nil {
		return out, err
	}
	defer leave()
	records, err = f.journal().List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if pendingNginxRecord(record) {
			out.Reason = "共享执行操作尚未完成"
			return out, nil
		}
	}
	binding, err := selectFail2banBinding(f.server.DataDir)
	if err != nil {
		return out, err
	}
	if binding == nil || binding.managed == nil {
		out.Reason = "须先安装并启动独立受管 Fail2ban 实例；已有实例的 jail 保持只读"
		return out, nil
	}
	r := binding.managed
	id, b, err := selectedFail2banJails(r)
	if err != nil {
		return out, err
	}
	out.SelectedID = id
	if b != nil {
		out.Policy = b.Policy
	}
	if err = verifyFail2banManaged(ctx, r, true); err != nil {
		return out, err
	}
	if err = verifyFail2banManagedLive(ctx, r); err != nil {
		out.Reason = err.Error()
		return out, nil
	}
	live, err := readFail2banLiveService(ctx, binding)
	if err != nil {
		return out, err
	}
	basis, m, host, nginxReason := f.basis(ctx, r)
	out.NginxReady, out.NginxReason = basis.NginxDir != "", nginxReason
	out.HostReady, out.HostReason = host.ready, host.reason
	if fail2banJailNeedsNginx(b) && basis.NginxDir == "" {
		out.Reason = nginxReason
		return out, nil
	}
	out.Target = fail2ban.JailTarget(fail2banNginxEngineKey(binding), id, basis.NginxDir, basis.NginxHash, basis.RegistryID, live.invocation, basis.HostHash)
	for resource := range m.ClientDeny {
		out.Resources = append(out.Resources, resource)
	}
	sort.Strings(out.Resources)
	out.Available = true
	return out, ctx.Err()
}

func (s *Server) fail2banJailsHandlers(mux *http.ServeMux) {
	if s.fail2banJails != nil {
		s.fail2banJails.jailHandlers(mux)
		return
	}
	for _, route := range []string{"GET /v1/fail2ban/jails/status", "GET /v1/fail2ban/jails/operations/{id}", "POST /v1/fail2ban/jails/apply"} {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			fail2banNginxReply(w, nil, fault.Unavailable("本机受管 jail 执行器不可用"))
		})
	}
}

func (f *fail2banJailsExecutor) jailHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/fail2ban/jails/status", func(w http.ResponseWriter, r *http.Request) {
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := f.jailsStatus(call)
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/jails/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.jailOperation(r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/fail2ban/jails/apply", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, fail2ban.PolicyBytes+4096)
		defer r.Body.Close()
		var in Fail2banJailsRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			fail2banNginxReply(w, nil, fault.Invalid("受管 jail 应用格式无效"))
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := f.submitJails(call, in)
		var known *fault.Error
		if err != nil && !errors.As(err, &known) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrRuntimeUnavailable) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			err = fault.New(409, "FAIL2BAN_JAIL_REJECTED", err.Error())
		}
		fail2banNginxReply(w, out, err)
	})
}

func ManageFail2banJails(ctx context.Context, data, scope, action, operation, base, policyFile string) (any, error) {
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" || !filepath.IsAbs(data) || filepath.Clean(data) != data {
		return nil, errors.New("受管 jail 操作须由宿主机 root 指定 --fail2ban-scope=host")
	}
	if action != "apply" && action != "status" {
		return nil, fault.Invalid("未知受管 jail 操作")
	}
	if action == "status" && (base != "" || policyFile != "" || operation != "" && !validID(operation)) {
		return nil, fault.Invalid("受管 jail 状态参数无效")
	}
	socket := fail2banJailsSocket(data)
	if err := existingRootDirectory(filepath.Dir(socket)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(socket)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return nil, errors.New("受管 jail 本地 Socket 无法核对")
	}
	client := NewClient(socket)
	var out json.RawMessage
	if action == "status" {
		route := "/v1/fail2ban/jails/status"
		if operation != "" {
			route = "/v1/fail2ban/jails/operations/" + operation
		}
		err = client.envelopeRequest(ctx, http.MethodGet, route, nil, &out)
	} else {
		if policyFile == "" || !validID(operation) || base != "" && !validID(base) {
			return nil, fault.Invalid("须指定策略文件、新操作 UUID 及当前配置 UUID")
		}
		file, err := os.Open(policyFile)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > fail2ban.PolicyBytes {
			return nil, fault.Invalid("受管 jail 策略必须为不超过 64 KiB 的 JSON 普通文件")
		}
		var policy fail2ban.Policy
		d := json.NewDecoder(io.LimitReader(file, fail2ban.PolicyBytes+1))
		d.DisallowUnknownFields()
		if d.Decode(&policy) != nil || d.Decode(new(any)) != io.EOF {
			return nil, fault.Invalid("受管 jail 策略格式无效")
		}
		normalized, err := policy.Normalize()
		if err != nil {
			return nil, err
		}
		old, oldErr := client.Fail2banJailsOperation(ctx, operation)
		if oldErr == nil {
			request := Fail2banJailsRequest{Protocol: Protocol, OperationID: operation, BaseID: base, Target: old.Target, Policy: normalized}
			if old.RequestHash != request.Hash() {
				return nil, fault.Conflict("操作 UUID 已用于其他 jail 请求")
			}
			return old, nil
		}
		var missing *fault.Error
		if !errors.As(oldErr, &missing) || missing.Code != "FAIL2BAN_JAIL_OPERATION_MISSING" {
			return nil, oldErr
		}
		var runtime Fail2banJailsStatus
		if err = client.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/jails/status", nil, &runtime); err != nil {
			return nil, err
		}
		if !runtime.Available || runtime.SelectedID != base {
			return nil, fault.Conflict("受管 jail 目标尚未就绪或配置基准已变化")
		}
		in := Fail2banJailsRequest{Protocol: Protocol, OperationID: operation, BaseID: base, Target: runtime.Target, Policy: normalized}
		err = client.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/jails/apply", in, &out)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}
