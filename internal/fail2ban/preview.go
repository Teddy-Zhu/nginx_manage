package fail2ban

import (
	"context"
	"strconv"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/logs"
)

type PolicyObserver interface {
	LogSources(context.Context) ([]logs.Source, error)
	ReadFail2banInstance(context.Context) (Instance, error)
}
type PreviewInput struct {
	Version int64 `json:"version"`
}
type PolicyPreview struct {
	Version    int64         `json:"version"`
	PolicyHash string        `json:"policy_hash"`
	CanApply   bool          `json:"can_apply"`
	Entries    []JailPreview `json:"entries"`
	Warnings   []string      `json:"warnings"`
}
type JailPreview struct {
	ID          string   `json:"id"`
	JailName    string   `json:"jail_name"`
	Enabled     bool     `json:"enabled"`
	SourceID    string   `json:"source_id"`
	SourceReady bool     `json:"source_ready"`
	Errors      []string `json:"errors"`
}

func (s *PolicyService) Preview(ctx context.Context, version int64) (PolicyPreview, error) {
	out := PolicyPreview{Version: version, Entries: []JailPreview{}, Warnings: []string{"保存的 jail 配置尚未安装到 Fail2ban 实例；实例授权、动作后端和执行能力须在应用前核对"}}
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
	sources := []logs.Source{}
	if s.Agent != nil {
		call, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		var readErr error
		sources, readErr = s.Agent.LogSources(call)
		if readErr != nil {
			sources = []logs.Source{}
			out.Warnings = append(out.Warnings, "目标运行日志来源暂不可核对")
		}
		instance, readErr := s.Agent.ReadFail2banInstance(call)
		if readErr != nil || !instance.Available {
			out.Warnings = append(out.Warnings, "目标 Fail2ban 运行实例尚未确认")
		}
	} else {
		out.Warnings = append(out.Warnings, "未连接宿主机 Agent")
	}
	for _, j := range view.Policy.Jails {
		e := JailPreview{ID: j.ID, JailName: "nginxpanel-" + j.ID, Enabled: j.Enabled, Errors: []string{}}
		matches := 0
		for _, source := range sources {
			if source.Active && source.ResourceID == j.ResourceID && source.Category == "http_access" && source.Format == "nginxpanel_http" {
				matches++
				e.SourceID = source.ID
			}
		}
		e.SourceReady = matches == 1
		if !e.SourceReady {
			e.SourceID = ""
			e.Errors = append(e.Errors, "须存在唯一的站点结构化 HTTP 访问日志；当前匹配数量："+strconv.Itoa(matches))
		}
		e.Errors = append(e.Errors, "当前尚无可应用的受管 jail 动作执行器")
		out.Entries = append(out.Entries, e)
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
