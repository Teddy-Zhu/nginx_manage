package transport

import (
	"database/sql"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"nginxpanel/internal/acme"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/auditlog"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/backup"
	"nginxpanel/internal/components"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/history"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/migration"
	"nginxpanel/internal/modules"
	"nginxpanel/internal/monitoring"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxinstall"
	"nginxpanel/internal/nginxswitch"
	"nginxpanel/internal/nodes"
	"nginxpanel/internal/notifications"
	"nginxpanel/internal/panelupdates"
	"nginxpanel/internal/realtime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
	"nginxpanel/internal/transport/apigen"
	"nginxpanel/migrations"
)

type Server struct {
	Realtime        *realtime.Hub
	realtimeStreams atomic.Int32
	realtimeReader  http.Handler
	FrontendVersion func() (string, []string, error)
	History         *history.Service
	Audit           *auditlog.Service
	Fail2ban        *fail2ban.PolicyService
	Maintenance     *maintenance.Service
	DB              *sql.DB
	Auth            *auth.Service
	Config          *nginxconfig.Service
	ACME            *acme.Service
	Monitoring      *monitoring.Service
	Notifications   *notifications.Service
	HostDNS         *hostdns.Service
	Firewall        *firewall.Service
	Components      *components.Service
	Installations   *nginxinstall.Service
	Switches        *nginxswitch.Service
	ImageUpgrades   *imageupdates.Service
	Updates         *panelupdates.Service
	Migration       *migration.Service
	Backups         *backup.Service
	Nodes           *nodes.Service
	Agent           *agent.Client
	NodeID          string
	Dev             bool
	Version         string
	PanelRuntime    string
	logStreams      atomic.Int32
	loginLogWarn    atomic.Int64
	metricReads     atomic.Int32
	firewallReads   atomic.Int32
	fail2banReads   atomic.Int32
}

var _ apigen.ServerInterface = (*Server)(nil)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.Realtime == nil {
		s.Realtime = realtime.New(s.realtimeFingerprint)
	}
	apigen.HandlerWithOptions(s, apigen.StdHTTPServerOptions{BaseURL: "/api/v1", BaseRouter: mux, ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
		s.fail(w, r, fault.Invalid("请求参数缺失或无效"))
	}})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, 404, "NOT_FOUND", "接口不存在", nil)
	})
	// SCS continues its original Write after ErrorFunc returns. Unwind to the
	// outer response boundary so a failed session commit cannot append success JSON.
	s.Auth.Sessions.ErrorFunc = func(_ http.ResponseWriter, _ *http.Request, err error) { panic(sessionFailure{err}) }
	s.realtimeReader = s.middleware(s.remoteBoundary(mux))
	s.remoteRoutes(mux)
	sessionHandler := s.Auth.Sessions.LoadAndSave(s.protect(s.operationAdmission(mux)))
	return s.middleware(s.remoteBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/events" {
			// A long-lived socket must not re-save its loaded session after logout.
			token := ""
			if cookie, err := r.Cookie(s.Auth.Sessions.Cookie.Name); err == nil {
				token = cookie.Value
			}
			ctx, err := s.Auth.Sessions.Load(r.Context(), token)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			s.realtime(w, r.WithContext(ctx))
			return
		}
		sessionHandler.ServeHTTP(w, r)
	})))
}

func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {
	s.ok(w, r, map[string]any{"status": "ok", "development": s.Dev})
}
func (s *Server) GetVersion(w http.ResponseWriter, r *http.Request) {
	frontendID, scripts := "", []string{}
	if s.FrontendVersion != nil {
		var err error
		frontendID, scripts, err = s.FrontendVersion()
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.ok(w, r, apigen.SystemVersion{FrontendId: frontendID, FrontendEntries: scripts, Version: s.Version, ApiVersion: 1, AgentProtocol: agent.Protocol, ParserVersion: nginxconfig.ParserVersion, PolicyVersion: nginxconfig.PolicyVersion, LauncherVersion: releases.LauncherVersion, Runtime: apigen.SystemVersionRuntime(s.PanelRuntime)})
}
func (s *Server) GetMe(w http.ResponseWriter, r *http.Request) {
	required, err := s.Auth.BootstrapRequired(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	data := apigen.Me{Authenticated: false, BootstrapRequired: required, Csrf: s.Auth.CSRF(r.Context()), Username: "", Scopes: []string{}}
	p, err := s.Auth.Authenticate(r)
	if err == nil {
		data.Authenticated = true
		data.Username = p.Username
		data.Scopes = p.Scopes
	} else if r.Header.Get("Authorization") != "" || !errors.Is(err, auth.ErrUnauthorized) {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, data)
}
func (s *Server) Bootstrap(w http.ResponseWriter, r *http.Request, _ apigen.BootstrapParams) {
	var in apigen.BootstrapJSONBody
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Auth.Bootstrap(r.Context(), in.Token, in.Username, in.Password); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.audit(r, "bootstrap", "auth.bootstrap", "administrator", "succeeded"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 201, "OK", "管理员已初始化，请登录", nil)
}
func (s *Server) Login(w http.ResponseWriter, r *http.Request, _ apigen.LoginParams) {
	var in apigen.LoginJSONBody
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	err := s.Auth.Login(r.Context(), auth.ClientIP(r), in.Username, in.Password)
	if errors.Is(err, auth.ErrUnauthorized) {
		s.recordPanelLoginFailure(r)
	}
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	if auditErr := s.audit(r, "login", "auth.login", "administrator", outcome); auditErr != nil {
		s.fail(w, r, auditErr)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.GetMe(w, r)
}
func (s *Server) Logout(w http.ResponseWriter, r *http.Request, _ apigen.LogoutParams) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	if p.Machine {
		s.fail(w, r, fault.Invalid("机器凭据请使用撤销操作"))
		return
	}
	if err := s.Auth.Sessions.Destroy(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, nil)
}
func (s *Server) ChangePassword(w http.ResponseWriter, r *http.Request, _ apigen.ChangePasswordParams) {
	p, ok := s.authorize(w, r, "auth.manage")
	if !ok {
		return
	}
	var in apigen.ChangePasswordJSONBody
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Auth.ChangePassword(r.Context(), in.Password); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.audit(r, p.ID, "auth.password", "administrator", "succeeded"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, nil)
}
func (s *Server) RevokeSessions(w http.ResponseWriter, r *http.Request, _ apigen.RevokeSessionsParams) {
	p, ok := s.authorize(w, r, "auth.manage")
	if !ok {
		return
	}
	if err := s.Auth.RevokeSessions(r.Context(), p); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.audit(r, p.ID, "auth.revoke_sessions", "administrator", "succeeded"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, nil)
}
func (s *Server) GetCapabilities(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "read")
	if !ok {
		return
	}
	schema, schemaErr := migrations.LatestVersion()
	if schemaErr != nil {
		s.fail(w, r, schemaErr)
		return
	}
	report, err := s.Agent.Capabilities(r.Context())
	mode := "connected"
	reason := ""
	var host any = report
	if err != nil {
		mode = "preview"
		reason = err.Error()
		host = nil
	}
	operations := []string{"nginx.preview", "nginx.save"}
	var runtime *agent.NginxState
	var features *agent.NginxFeatures
	if mode == "connected" {
		featureReport, featureErr := s.Agent.NginxFeatures(r.Context())
		if featureErr != nil {
			featureReport = agent.NginxFeatures{Features: map[string]agent.Feature{}, Modules: []agent.NativeModule{}, Reason: "无法读取本机 Nginx 模块能力"}
		}
		features = &featureReport
		state, stateErr := s.Agent.NginxState(r.Context())
		if stateErr == nil {
			runtime = &state
			if state.Available && state.ExternalChange {
				operations = append(operations, "nginx.restore")
			}
			if state.Available && state.Integrity {
				operations = append(operations, "nginx.validate")
				if state.Running {
					operations = append(operations, "nginx.apply")
				}
			}
		} else {
			reason = stateErr.Error()
		}
	}
	head, err := dbgen.New(s.DB).GetConfigHead(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var desired, applied any
	if head.DesiredRevision.Valid {
		desired = head.DesiredRevision.String
	}
	if head.AppliedRevision.Valid {
		applied = head.AppliedRevision.String
	}
	s.ok(w, r, map[string]any{"mode": mode, "reason": reason, "host": host, "desired_revision": desired, "applied_revision": applied, "version": head.Version, "api_version": 1, "database_schema": schema, "remote_protocol": remoteapi.Protocol, "authorization": map[string]any{"scopes": p.Scopes, "machine": p.Machine, "delegated": p.Delegated}, "agent_protocol": agent.Protocol, "parser_version": nginxconfig.ParserVersion, "policy_version": s.Config.Policy.Version, "operations": operations, "nginx": runtime, "nginx_features": features})
}
func (s *Server) GetModules(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	data, err := modules.List(r.Context(), s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, data)
}
func (s *Server) SetModule(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.SetModuleParams) {
	p, ok := s.authorize(w, r, "system.write")
	if !ok {
		return
	}
	var in struct {
		Enabled             *bool  `json:"enabled"`
		FirewallRules       string `json:"firewall_rules"`
		FirewallOperationID string `json:"firewall_operation_id"`
	}
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Enabled == nil {
		s.fail(w, r, fault.Invalid("缺少 enabled 字段"))
		return
	}
	if id == "fail2ban" && !*in.Enabled && s.Agent != nil {
		state, err := s.Agent.ReadFail2banContainer(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if state.Installed {
			s.fail(w, r, fault.Conflict("请先在软件商店卸载登录防护，再关闭此功能；配置和防护数据会保留"))
			return
		}
	}
	var err error
	if id == "firewall" {
		if !s.firewallReady(w, r) {
			return
		}
		ctx, done, ok := s.firewallControlContext(w, r)
		if !ok {
			return
		}
		defer done()
		err = s.Firewall.SetManagement(ctx, p, *in.Enabled, in.FirewallRules, in.FirewallOperationID)
	} else {
		if in.FirewallRules != "" || in.FirewallOperationID != "" {
			s.fail(w, r, fault.Invalid("防火墙停用选项不适用于此模块"))
			return
		}
		err = modules.Set(r.Context(), s.DB, p, id, *in.Enabled)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if id == "monitoring" && s.Monitoring != nil {
		s.Monitoring.Wake()
	}
	if id == "notifications" && s.Notifications != nil {
		if *in.Enabled {
			s.Notifications.Wake()
		} else {
			s.Notifications.Pause()
		}
	}
	outcome := "succeeded"
	if id == "firewall" && !*in.Enabled {
		outcome = "disabled_" + in.FirewallRules
	}
	if err := s.audit(r, p.ID, "modules.set", id, outcome); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, nil)
}
func (s *Server) GetConfigTree(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "config.secrets"); !ok {
		return
	}
	data, err := s.Config.Current(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, data)
}
func (s *Server) SaveConfigTree(w http.ResponseWriter, r *http.Request, params apigen.SaveConfigTreeParams) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.SaveRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := s.Config.Save(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if errors.Is(err, nginxconfig.ErrInvalid) {
		s.respond(w, r, 422, "CONFIG_INVALID", err.Error(), data)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := 201
	if data.TaskID != "" {
		status = 202
	}
	s.respond(w, r, status, "OK", "配置已保存", data)
}
func (s *Server) PreviewConfigTree(w http.ResponseWriter, r *http.Request, _ apigen.PreviewConfigTreeParams) {
	if _, ok := s.authorize(w, r, "config.write", "config.secrets"); !ok {
		return
	}
	var in nginxconfig.SaveRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	parsed, err := nginxconfig.Parse(in.Files, s.Config.Policy)
	if err != nil {
		s.fail(w, r, fault.Invalid(err.Error()))
		return
	}
	parsed.Tree.State = "preview"
	parsed.Tree.Version = in.BaseVersion
	s.ok(w, r, parsed.Tree)
}
func (s *Server) PatchResource(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.PatchResourceParams) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.PatchRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := s.Config.Patch(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, in.BaseVersion, in.Changes, in.Metadata)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 201, "OK", "字段已保存至新修订", data)
}
func (s *Server) CreateResource(w http.ResponseWriter, r *http.Request, params apigen.CreateResourceParams) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.CreateRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := s.Config.CreateResource(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 201, "OK", "代理配置已保存", data)
}
func (s *Server) GetRevision(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.authorize(w, r, "config.secrets"); !ok {
		return
	}
	data, err := s.Config.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, data)
}

func pagination(limit, offset *int) (int64, int64, error) {
	l, o := 30, 0
	if limit != nil {
		l = *limit
	}
	if offset != nil {
		o = *offset
	}
	if l < 1 || l > 100 || o < 0 || o > 100000 {
		return 0, 0, fault.Invalid("分页范围无效")
	}
	return int64(l), int64(o), nil
}
func (s *Server) ListRevisions(w http.ResponseWriter, r *http.Request, params apigen.ListRevisionsParams) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	l, o, err := pagination(params.Limit, params.Offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := dbgen.New(s.DB).ListRevisions(r.Context(), dbgen.ListRevisionsParams{Limit: l, Offset: o})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, data)
}
func (s *Server) ListTasks(w http.ResponseWriter, r *http.Request, params apigen.ListTasksParams) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	l, o, err := pagination(params.Limit, params.Offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := dbgen.New(s.DB).ListTasks(r.Context(), dbgen.ListTasksParams{Limit: l, Offset: o})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	data := []apigen.Task{}
	for _, t := range rows {
		data = append(data, taskView(t))
	}
	s.ok(w, r, data)
}
func (s *Server) GetTask(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	data, err := dbgen.New(s.DB).GetTask(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, taskView(data))
}
func taskView(t dbgen.Task) apigen.Task {
	return apigen.Task{Id: t.ID, Kind: t.Kind, State: t.State, Stage: t.Stage, LastError: t.LastError, CreatedAt: t.CreatedAt, RevisionId: t.RevisionID.String, ObservedRevision: t.ObservedRevision}
}
func (s *Server) audit(r *http.Request, principal, action, resource, outcome string) error {
	_, err := s.DB.ExecContext(r.Context(), "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", secure.ID(), r.Context().Value(requestIDKey).(string), principal, action, resource, outcome, time.Now().Unix())
	return err
}

func (s *Server) ApplyConfig(w http.ResponseWriter, r *http.Request, params apigen.ApplyConfigParams) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.ApplySavedRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.ApplySaved(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 202, "OK", "配置已加入应用队列", out)
}
func (s *Server) GetNginxRuntime(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	out, err := s.Agent.NginxState(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) GetResourceTemplate(w http.ResponseWriter, r *http.Request, params apigen.GetResourceTemplateParams) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets")
	if !ok {
		return
	}
	out, err := s.Config.ResourceTemplate(p, string(params.Kind))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 200, "OK", "网站设置已就绪", out)
}

func (s *Server) CopyResource(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.CopyResourceParams) {
	s.resourceAction(w, r, id, "copy", params.IdempotencyKey)
}
func (s *Server) DeleteResource(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteResourceParams) {
	s.resourceAction(w, r, id, "delete", params.IdempotencyKey)
}
func (s *Server) resourceAction(w http.ResponseWriter, r *http.Request, id, action, key string) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.ResourceActionRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.ResourceAction(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, action, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := 201
	message := "副本已保存，尚未应用"
	if action == "delete" {
		status = 200
		message = "代理已从期望修订移除"
	}
	s.respond(w, r, status, "OK", message, out)
}
func (s *Server) CreateAccessList(w http.ResponseWriter, r *http.Request, params apigen.CreateAccessListParams) {
	s.accessList(w, r, "", "create", params.IdempotencyKey)
}
func (s *Server) UpdateAccessList(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.UpdateAccessListParams) {
	s.accessList(w, r, id, "update", params.IdempotencyKey)
}
func (s *Server) DeleteAccessList(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteAccessListParams) {
	s.accessList(w, r, id, "delete", params.IdempotencyKey)
}
func (s *Server) accessList(w http.ResponseWriter, r *http.Request, id, action, key string) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets", "security.write")
	if !ok {
		return
	}
	var in nginxconfig.AccessListRequest
	if action == "delete" {
		var body nginxconfig.ResourceActionRequest
		if err := decode(w, r, &body); err != nil {
			s.fail(w, r, err)
			return
		}
		in.BaseVersion = body.BaseVersion
	} else if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.AccessList(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, action, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := 201
	if action == "delete" {
		status = 200
	}
	s.respond(w, r, status, "OK", "访问列表已保存至新修订", out)
}

func (s *Server) GetNginxFeatures(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	out, err := s.Agent.NginxFeatures(r.Context())
	if err != nil {
		s.fail(w, r, fault.Unavailable("无法连接本机 Nginx 能力探测"))
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateWAFPolicy(w http.ResponseWriter, r *http.Request, params apigen.CreateWAFPolicyParams) {
	s.wafPolicy(w, r, "", "create", params.IdempotencyKey)
}
func (s *Server) UpdateWAFPolicy(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.UpdateWAFPolicyParams) {
	s.wafPolicy(w, r, id, "update", params.IdempotencyKey)
}
func (s *Server) DeleteWAFPolicy(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteWAFPolicyParams) {
	s.wafPolicy(w, r, id, "delete", params.IdempotencyKey)
}
func (s *Server) wafPolicy(w http.ResponseWriter, r *http.Request, id, action, key string) {
	principal, ok := s.authorize(w, r, "config.write", "config.secrets", "security.write")
	if !ok {
		return
	}
	var in nginxconfig.WAFInput
	if action == "delete" {
		var body nginxconfig.ResourceActionRequest
		if err := decode(w, r, &body); err != nil {
			s.fail(w, r, err)
			return
		}
		in.BaseVersion = body.BaseVersion
	} else if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.WAF(r.Context(), principal, r.Context().Value(requestIDKey).(string), key, id, action, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := 201
	if action == "delete" {
		status = 200
	}
	s.respond(w, r, status, "OK", "WAF 策略已保存至新修订", out)
}
