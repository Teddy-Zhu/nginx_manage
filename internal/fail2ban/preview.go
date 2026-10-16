package fail2ban

import (
	"context"
	"strconv"
	"sync"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/logs"
)

type PolicyObserver interface {
	LogSources(context.Context) ([]logs.Source, error)
	ReadFail2banInstance(context.Context) (Instance, error)
	CheckFail2banTemplates(context.Context, TemplateCheckInput) ([]TemplateCheck, error)
}
type PreviewInput struct {
	Version int64 `json:"version"`
}
type PolicyPreview struct {
	HostInput      *HostInputPreview `json:"host_input,omitempty"`
	TemplateChecks []TemplateCheck   `json:"template_checks"`
	Version        int64             `json:"version"`
	PolicyHash     string            `json:"policy_hash"`
	CanApply       bool              `json:"can_apply"`
	Entries        []JailPreview     `json:"entries"`
	Warnings       []string          `json:"warnings"`
	Runtime        JailsRuntime      `json:"runtime"`
	Removed        []string          `json:"removed"`
}
type JailPreview struct {
	TemplateReady bool     `json:"template_ready"`
	ID            string   `json:"id"`
	JailName      string   `json:"jail_name"`
	Enabled       bool     `json:"enabled"`
	SourceID      string   `json:"source_id"`
	SourceReady   bool     `json:"source_ready"`
	Errors        []string `json:"errors"`
}

func (s *PolicyService) Preview(ctx context.Context, version int64) (PolicyPreview, error) {
	out := PolicyPreview{Version: version, Entries: []JailPreview{}, TemplateChecks: []TemplateCheck{}, Warnings: []string{"应用更新本应用的受管 jail；Nginx 拒绝集合和宿主机同步状态分别核对"}, Runtime: JailsRuntime{HostReason: "尚未核对宿主机动作批准", NginxReason: "尚未核对 Nginx 动作", Policy: DefaultPolicy(), Resources: []string{}, Pending: []JailsOperation{}}, Removed: []string{}}
	if version < 1 {
		return out, fault.Invalid("须先保存 jail 配置并提供版本")
	}
	if !s.previewing.CompareAndSwap(false, true) {
		return out, fault.New(429, "FAIL2BAN_PREVIEW_BUSY", "jail 预览正在生成，请稍后重试")
	}
	defer s.previewing.Store(false)
	view, err := s.Policy(ctx)
	if err != nil {
		return out, err
	}
	if view.Version != version {
		return out, fault.Conflict("jail 配置版本已变化，请重新读取")
	}
	out.PolicyHash = view.Policy.Hash()
	ids := []string{}
	seen := map[string]bool{}
	needsHostInput := false
	needsNginxLogs := false
	for _, j := range view.Policy.Jails {
		if !j.Enabled {
			continue
		}
		needsHostInput = needsHostInput || j.Action == "host-input"
		needsNginxLogs = needsNginxLogs || j.Template != PanelLoginTemplate
		if !seen[j.Template] {
			ids = append(ids, j.Template)
			seen[j.Template] = true
		}
	}
	sources := []logs.Source{}
	panelLogin := EmptyPanelLogin("unconfirmed", "未连接面板登录日志来源")
	if needsHostInput {
		value := EmptyHostInput("unconfirmed", "未连接宿主机动作预检")
		out.HostInput = &value
	}
	var instance Instance
	if s.Agent != nil {
		call, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		var logErr, instanceErr, templateErr, runtimeErr, panelLogErr, hostInputErr error
		var wg sync.WaitGroup
		wg.Add(2)
		if needsNginxLogs {
			wg.Add(1)
			go func() { defer wg.Done(); sources, logErr = s.Agent.LogSources(call) }()
		}
		go func() { defer wg.Done(); out.Runtime, runtimeErr = s.Runtime(call) }()
		go func() { defer wg.Done(); instance, instanceErr = s.Agent.ReadFail2banInstance(call) }()
		if needsHostInput {
			wg.Add(1)
			go func() {
				defer wg.Done()
				value, err := s.HostInput(call)
				out.HostInput, hostInputErr = &value, err
			}()
		}
		if seen[PanelLoginTemplate] {
			wg.Add(1)
			go func() { defer wg.Done(); panelLogin, panelLogErr = s.PanelLogin(call) }()
		}
		if len(ids) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out.TemplateChecks, templateErr = s.Agent.CheckFail2banTemplates(call, TemplateCheckInput{Templates: ids})
			}()
		}
		wg.Wait()
		if runtimeErr != nil {
			out.Runtime = JailsRuntime{HostReason: "宿主机动作基准暂不可读取", NginxReason: "Nginx 动作基准暂不可读取", Policy: DefaultPolicy(), Resources: []string{}, Pending: []JailsOperation{}, Reason: "受管 jail 执行基准暂不可读取"}
		}
		if instanceErr != nil {
			instance = Instance{}
		}
		if logErr != nil {
			sources = []logs.Source{}
			out.Warnings = append(out.Warnings, "目标运行日志来源暂不可核对")
		}
		if instanceErr != nil || !instance.Available {
			out.Warnings = append(out.Warnings, "目标 Fail2ban 运行实例尚未确认")
		}
		if templateErr != nil {
			out.TemplateChecks = []TemplateCheck{}
			out.Warnings = append(out.Warnings, "官方模板检查暂不可读取")
		}
		if panelLogErr != nil || !panelLogin.Valid() {
			panelLogin = EmptyPanelLogin("unconfirmed", "面板登录日志来源暂不可核对")
		}
		if needsHostInput && (hostInputErr != nil || !out.HostInput.Valid()) {
			value := EmptyHostInput("unconfirmed", "宿主机动作预检暂不可核对")
			out.HostInput = &value
		}
	} else {
		out.Runtime.Reason = "未连接宿主机 Agent"
		out.Warnings = append(out.Warnings, "未连接宿主机 Agent")
	}
	for _, j := range view.Policy.Jails {
		e := JailPreview{ID: j.ID, JailName: "nginxpanel-" + j.ID, Enabled: j.Enabled, Errors: []string{}}
		if !j.Enabled {
			out.Entries = append(out.Entries, e)
			continue
		}
		if j.Template == PanelLoginTemplate {
			e.SourceID = PanelLoginSource
			e.SourceReady = panelLogin.Available
			if !e.SourceReady {
				e.Errors = append(e.Errors, panelLogin.Reason)
			}
		} else {
			matches := 0
			for _, source := range sources {
				if source.Active && source.ResourceID == j.ResourceID && source.Category == "http_access" && source.Format == "nginxpanel_http" && source.AuthPresence {
					matches++
					e.SourceID = source.ID
				}
			}
			e.SourceReady = matches == 1
			if !e.SourceReady {
				e.SourceID = ""
				e.Errors = append(e.Errors, "须存在唯一且包含认证头存在标记的站点结构化日志；请先发布当前 Nginx 配置。匹配数量："+strconv.Itoa(matches))
			}
		}
		for _, check := range out.TemplateChecks {
			if check.Template == j.Template {
				e.TemplateReady = check.Available && check.Passed && instance.Available && instance.ServerVersion == RegexVersion && check.Engine == instance.Binding.Engine
			}
		}
		if !e.TemplateReady {
			e.Errors = append(e.Errors, "过滤器检查须通过，且须与已确认实例使用相同组件及版本")
		}
		if j.Action == "host-input" && out.HostInput != nil && !out.HostInput.CanPrepare {
			e.Errors = append(e.Errors, out.HostInput.Reason)
		}
		if j.Template == PanelLoginTemplate {
			if !out.Runtime.HostReady {
				e.Errors = append(e.Errors, out.Runtime.HostReason)
			}
		} else if j.Action != "nginx-client" {
			e.Errors = append(e.Errors, "该日志来源当前只支持 Nginx 客户端动作")
		}
		bound := false
		for _, resource := range out.Runtime.Resources {
			if resource == j.ResourceID {
				bound = true
			}
		}
		if j.Template != PanelLoginTemplate && !out.Runtime.NginxReady {
			e.Errors = append(e.Errors, out.Runtime.NginxReason)
		}
		if j.Template != PanelLoginTemplate && out.Runtime.NginxReady && !bound {
			e.Errors = append(e.Errors, "站点须先发布明确的客户端拒绝入口及可信代理配置")
		}
		out.Entries = append(out.Entries, e)
	}
	out.CanApply = out.Runtime.Available
	if !out.Runtime.Available {
		out.Warnings = append(out.Warnings, out.Runtime.Reason)
		out.CanApply = false
	}
	if err = s.moduleEnabled(ctx, s.DB); err != nil {
		out.Warnings = append(out.Warnings, err.Error())
		out.CanApply = false
	}
	if err = s.migrationIdle(ctx, s.DB); err != nil {
		out.Warnings = append(out.Warnings, err.Error())
		out.CanApply = false
	}
	if err = s.applyIdle(ctx, s.DB); err != nil {
		out.Warnings = append(out.Warnings, err.Error())
		out.CanApply = false
	}
	wanted := map[string]bool{}
	for _, j := range view.Policy.Jails {
		if j.Enabled {
			wanted[j.ID] = true
		}
	}
	for _, j := range out.Runtime.Policy.Jails {
		if j.Enabled && !wanted[j.ID] {
			out.Removed = append(out.Removed, "nginxpanel-"+j.ID)
		}
	}
	for _, e := range out.Entries {
		if len(e.Errors) > 0 {
			out.CanApply = false
		}
	}
	current, err := s.Policy(ctx)
	if err != nil {
		return out, err
	}
	if current.Version != version {
		return out, fault.Conflict("预览期间 jail 配置已变化，请重新读取")
	}
	return out, nil
}
