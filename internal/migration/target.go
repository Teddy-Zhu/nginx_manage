package migration

import (
	"nginxpanel/internal/agent"
	"nginxpanel/internal/nginxconfig"
)

// InspectNginxTarget is shared by logical imports and offline restore planning.
// Observations come from the target Agent; archive claims grant no capability.
func InspectNginxTarget(parsed *nginxconfig.Parsed, features agent.NginxFeatures, runtime agent.NginxState) []Step {
	out := []Step{}
	if !features.Available {
		out = append(out, Step{"component", "nginx", "unavailable", "无法确认目标 Nginx 能力；请先安装或接入受管实例"})
	} else {
		for _, name := range parsed.MigrationFeatures() {
			f, ok := features.Features[name]
			if !ok || !f.Available {
				out = append(out, Step{"image", name, "unavailable", "目标 Nginx 缺少已确认能力；Docker 须换用预置对应模块的镜像"})
			} else {
				out = append(out, Step{"capability", name, "ready", "目标已具备所需能力"})
			}
		}
	}
	if !runtime.Available || !runtime.Running || !runtime.Integrity || runtime.ExternalChange {
		out = append(out, Step{"runtime", "nginx", "unavailable", "专用实例未就绪或存在外部修改，须先恢复目标接入状态"})
	}
	return out
}
