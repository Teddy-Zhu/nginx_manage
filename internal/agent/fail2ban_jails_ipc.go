package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

type Fail2banJailsStatus struct {
	SelectedID string                   `json:"selected_id"`
	Policy     fail2ban.Policy          `json:"policy"`
	Pending    []Fail2banJailsOperation `json:"pending"`
}

func (f *fail2banNginxExecutor) jailsStatus() (Fail2banJailsStatus, error) {
	out := Fail2banJailsStatus{Policy: fail2ban.DefaultPolicy(), Pending: []Fail2banJailsOperation{}}
	r, err := loadFail2banManaged(f.nginx.DataDir)
	if err != nil || r == nil || r.State != "installed" {
		return out, errors.New("没有可管理 jail 的独立受管安装")
	}
	id, b, err := selectedFail2banJails(r)
	if err != nil {
		return out, err
	}
	out.SelectedID = id
	if b != nil {
		out.Policy = b.Policy
	}
	records, err := f.nginx.Journal.List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == fail2banJailsKind && pendingNginxRecord(record) {
			if record.Fail2banJails == nil {
				return out, errors.New("受管 jail 执行记录损坏")
			}
			out.Pending = append(out.Pending, fail2banJailsView(record))
		}
	}
	return out, nil
}

func (f *fail2banNginxExecutor) jailHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/fail2ban/nginx/jails/status", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.jailsStatus()
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/nginx/jails/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.jailOperation(r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/fail2ban/nginx/jails/apply", func(w http.ResponseWriter, r *http.Request) {
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
	socket := fail2banNginxSocket(data)
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
		route := "/v1/fail2ban/nginx/jails/status"
		if operation != "" {
			route = "/v1/fail2ban/nginx/jails/operations/" + operation
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
		in := Fail2banJailsRequest{Protocol: Protocol, OperationID: operation, BaseID: base, Policy: normalized}
		err = client.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/nginx/jails/apply", in, &out)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}
