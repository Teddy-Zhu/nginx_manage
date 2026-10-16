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

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxinstall"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/nginxruntime"
)

const nginxInstallTemplate = "nginxpanel-install@.service"

func installUnitName(id string) string { return "nginxpanel-install@" + id + ".service" }

func installationUnitState(ctx context.Context, id string) (bool, bool, error) {
	out, err := installationSystemctl(ctx, "show", "--property=ActiveState", "--value", installUnitName(id))
	if err != nil {
		return false, false, err
	}
	switch strings.TrimSpace(out) {
	case "active", "activating", "deactivating", "reloading":
		return true, false, nil
	case "inactive":
		return false, false, nil
	case "failed":
		return false, true, nil
	default:
		return false, false, errors.New("独立安装服务状态无法核实")
	}
}

func installationTemplate(data string) error {
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil || !strings.HasPrefix(string(intent), "native-install-v8\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") || !strings.Contains(string(intent), "\nwithout_nginx=yes\n") {
		return fault.Conflict("原生未安装登记未确认")
	}
	raw, err := nginxmodules.ReadTrusted("/etc/systemd/system/"+nginxInstallTemplate, 64<<10)
	if err != nil {
		return fault.Unavailable("须由原生安装器登记独立安装服务")
	}
	expected := "ExecStart=/opt/nginxpanel/current/nginxpanel nginx-install-worker --data-dir " + data + " --install-operation %i"
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != expected {
				return fault.Conflict("独立安装服务与本机登记不一致")
			}
		}
	}
	if count != 1 {
		return fault.Conflict("独立安装服务入口无效")
	}
	return nil
}

func installOperation(r Record, active bool) (nginxinstall.Operation, error) {
	if validInstallRecord(r) != nil || r.NginxInstall.Input.API == nil {
		return nginxinstall.Operation{}, fault.Conflict("安装记录不是此 API 的原操作")
	}
	i := r.NginxInstall
	o := nginxinstall.Operation{Protocol: Protocol, ID: r.OperationID, RequestHash: nginxinstall.Hash(r.OperationID, *i.Input.API), Input: *i.Input.API, Sequence: i.Sequence, Command: i.Command, State: r.State, Stage: r.Stage, Error: r.Error, Deadline: r.Deadline, UpdatedAt: r.UpdatedAt, Active: active, Installation: i.Installation, Running: i.Running}
	return o, o.Validate(r.OperationID, *i.Input.API)
}

func (s *Server) readInstallation(ctx context.Context, id string) (nginxinstall.Operation, error) {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return nginxinstall.Operation{}, fault.Unavailable("原生首次安装范围未确认")
	}
	if !validID(id) {
		return nginxinstall.Operation{}, fault.Invalid("安装操作标识无效")
	}
	r, err := s.Journal.Get(id)
	if os.IsNotExist(err) {
		return nginxinstall.Operation{}, fault.NotFound("安装操作不存在")
	}
	if err != nil {
		return nginxinstall.Operation{}, err
	}
	if _, err = installOperation(r, false); err != nil {
		return nginxinstall.Operation{}, err
	}
	active, failed, err := installationUnitState(ctx, id)
	if err != nil {
		return nginxinstall.Operation{}, err
	}
	if !active && (r.State == "queued" || r.State == "running") {
		unlock, e := s.Journal.rootLock(".nginx-install.lock")
		if e == nil {
			defer unlock()
			// Reload under the same lock used by the worker and control requests.
			r, e = s.Journal.Get(id)
			if e != nil {
				return nginxinstall.Operation{}, e
			}
			if _, e = installOperation(r, false); e != nil {
				return nginxinstall.Operation{}, e
			}
			grant, e := s.Journal.Get(r.NginxInstall.Input.MaintenanceID)
			if e != nil {
				return nginxinstall.Operation{}, e
			}
			if (r.State == "queued" || r.State == "running") && (r.State == "running" || failed || r.Deadline <= time.Now().Unix() || grant.MaintenanceEpoch != r.MaintenanceEpoch) {
				r.State, r.Error = "recovery_required", "独立安装未完成且服务已停止，须在原维护会话中显式续办或取消"
				if e = s.Journal.Put(r); e != nil {
					return nginxinstall.Operation{}, e
				}
				r, e = s.Journal.Get(id)
				if e != nil {
					return nginxinstall.Operation{}, e
				}
			}
		} else if !errors.Is(e, unix.EWOULDBLOCK) {
			return nginxinstall.Operation{}, e
		}
	}
	return installOperation(r, active)
}

func (s *Server) queueInstallation(ctx context.Context, req nginxinstall.Request) (nginxinstall.Operation, error) {
	var empty nginxinstall.Operation
	if err := req.Validate(); err != nil {
		return empty, err
	}
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return empty, fault.Conflict("原生首次安装范围未确认")
	}
	if err := installationTemplate(s.DataDir); err != nil {
		return empty, fault.Conflict("须通过当前原生安装器登记独立安装服务")
	}
	unlock, err := s.Journal.rootLock(".nginx-install.lock")
	if err != nil {
		return empty, fault.Conflict("独立安装执行器忙，请先核对原操作")
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	access, err := s.Journal.maintenanceLock()
	if err != nil {
		return empty, err
	}
	held := true
	defer func() {
		if held {
			access()
		}
	}()
	if err = installGrant(s.Journal, req.Input.MaintenanceID, req.Epoch, false); err != nil {
		return empty, fault.Conflict("须重新确认原维护会话已进入 held")
	}
	r, err := s.Journal.Get(req.OperationID)
	if os.IsNotExist(err) {
		if req.Command != "install" {
			return empty, fault.Conflict("原安装记录缺失，不能重建或取消未知操作")
		}
		records, e := (&maintenanceGate{journal: s.Journal}).records()
		if e != nil {
			return empty, e
		}
		for _, prior := range records {
			if prior.Kind == nginxInstallKind {
				if validInstallRecord(prior) != nil {
					return empty, fault.Conflict("已有安装记录无效")
				}
				if !installTerminal(prior.State) {
					return empty, fault.Conflict("已有原安装执行中或待恢复")
				}
			}
		}
		before, info, e := nginxruntime.Selection(ctx, s.DataDir)
		if e != nil {
			return empty, e
		}
		if info != nil || before.Owner != "uninstalled" {
			return empty, fault.Conflict("只能填充明确未安装的 Nginx 槽位")
		}
		catalog, e := nginxmodules.ReadCatalog("/etc/nginxpanel/nginx-modules.json")
		if e != nil {
			return empty, e
		}
		policy := nginxconfig.DefaultPolicy()
		policy.ModulePaths = nginxmodules.Paths(catalog)
		in := NginxInstallInput{API: &req.Input, MaintenanceID: req.Input.MaintenanceID, Source: nginxruntime.Input{DataDir: s.DataDir, PlanID: req.Input.PlanID, AssetID: req.Input.AssetID, TrustPath: s.ReleaseTrust, Prerelease: req.Input.Prerelease}, WorkerUser: "nginxpanel-nginx", Policy: policy, Modules: catalog, Start: req.Input.Start, Enable: req.Input.Enable}
		encoded, e := json.Marshal(in)
		if e != nil {
			return empty, e
		}
		if len(encoded) > 64<<10 {
			return empty, fault.Invalid("安装意图超过 64 KiB")
		}
		r = Record{OperationID: req.OperationID, RequestHash: installHash(req.OperationID, in), Kind: nginxInstallKind, NginxInstall: &NginxInstallIntent{Input: in, Before: &before}}
	} else if err != nil {
		return empty, err
	} else {
		op, e := installOperation(r, false)
		if e != nil {
			return empty, e
		}
		if op.RequestHash != nginxinstall.Hash(req.OperationID, req.Input) {
			return empty, fault.Conflict("原安装意图不能改变")
		}
		if req.Sequence < op.Sequence {
			return op, nil
		}
		if req.Sequence == op.Sequence {
			if req.Command != op.Command {
				return empty, fault.Conflict("同一安装授权序号不能改换操作")
			}
			if r.State != "queued" {
				return op, nil
			}
			if req.Epoch != r.MaintenanceEpoch || req.AuthorizationUntil != r.Deadline || r.Deadline <= time.Now().Unix() {
				return empty, fault.Conflict("原排队授权已失效，须显式续办")
			}
		} else {
			if installTerminal(r.State) {
				return op, nil
			}
			if req.Command == "install" {
				return empty, fault.Conflict("原安装不能重复新建")
			}
			active, _, e := installationUnitState(ctx, req.OperationID)
			if e != nil {
				return empty, e
			}
			if active {
				return empty, fault.Conflict("原安装服务仍未停止，不能重发控制操作")
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	if req.Sequence > r.NginxInstall.Sequence {
		if req.AuthorizationUntil <= time.Now().Unix() || req.AuthorizationUntil > time.Now().Add(10*time.Minute).Unix()+5 {
			return empty, fault.Conflict("安装授权已过期或超过十分钟")
		}
		r.NginxInstall.Sequence, r.NginxInstall.Command = req.Sequence, req.Command
		r.MaintenanceEpoch = req.Epoch
		r.Deadline = req.AuthorizationUntil
		if req.Command == "cancel" {
			current, info, e := nginxruntime.Selection(ctx, s.DataDir)
			if e != nil {
				return empty, e
			}
			if info != nil || r.NginxInstall.Before == nil || nginxruntime.SelectionHash(current) != nginxruntime.SelectionHash(*r.NginxInstall.Before) {
				return empty, fault.Conflict("绑定已发布或状态不明，只能续办原安装确认")
			}
			r.State, r.Stage, r.Error = "cancelled", "cancelled_before_binding", "已取消未发布绑定的安装；已生成的受管基线保留"
		} else {
			r.State, r.Stage, r.Error = "queued", "queued", ""
		}
		if err = s.Journal.Put(r); err != nil {
			return empty, err
		}
	}
	access()
	held = false
	unlock()
	locked = false
	if r.State == "queued" {
		// Starting the deterministic instance is idempotent and never restarts a
		// live worker. Its durable command is read only after it obtains the lock.
		if _, err = installationSystemctl(ctx, "start", "--no-block", installUnitName(req.OperationID)); err != nil {
			return empty, fault.Unavailable("安装意图已保存，独立服务启动结果未确认，请查询原操作")
		}
	}
	return s.readInstallation(ctx, req.OperationID)
}

func RunNginxInstallation(ctx context.Context, data, id string) (Record, error) {
	if os.Geteuid() != 0 || !validID(id) {
		return Record{}, errors.New("独立安装服务身份或标识无效")
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	r, err := j.Get(id)
	if err != nil {
		return r, err
	}
	if validInstallRecord(r) != nil || r.OperationID != id || r.NginxInstall.Input.API == nil || r.NginxInstall.Input.Source.DataDir != data {
		return r, errors.New("独立服务缺少原 API 安装意图")
	}
	return InstallNginx(ctx, NginxInstallOptions{Input: r.NginxInstall.Input, OperationID: id, Epoch: r.MaintenanceEpoch, Resume: true})
}

func (s *Server) installationHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/components/nginx-installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		o, err := s.readInstallation(r.Context(), r.PathValue("id"))
		componentReply(w, o, err)
	})
	mux.HandleFunc("POST /v1/components/nginx-installations", func(w http.ResponseWriter, r *http.Request) {
		var req nginxinstall.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			componentReply(w, nil, fault.Invalid("首次安装请求无效"))
			return
		}
		o, err := s.queueInstallation(r.Context(), req)
		componentReply(w, o, err)
	})
}

func (c *Client) NginxInstallation(ctx context.Context, id string) (nginxinstall.Operation, error) {
	var out nginxinstall.Operation
	if !validID(id) {
		return out, fault.Invalid("安装标识无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/components/nginx-installations/"+id, nil, &out)
	return out, err
}
func (c *Client) SubmitNginxInstallation(ctx context.Context, in nginxinstall.Request) (nginxinstall.Operation, error) {
	var out nginxinstall.Operation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/components/nginx-installations", in, &out)
	return out, err
}
