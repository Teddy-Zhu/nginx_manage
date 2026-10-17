package migration

import (
	"nginxpanel/internal/agent"
	"nginxpanel/internal/nginxconfig"
)

// InspectNginxTarget is shared by logical imports and offline restore planning.
// Observations come from the target Agent; archive claims grant no capability.
func InspectNginxTarget(parsed *nginxconfig.Parsed, features agent.NginxFeatures, runtime agent.NginxState) []Step {
	out := inspectNginxDependencies(parsed, features)
	if !runtime.Available || !runtime.Running || !runtime.Integrity || runtime.ExternalChange {
		out = append(out, Step{"runtime", "nginx", "unavailable", "专用实例未就绪或存在外部修改，须先恢复目标接入状态"})
	}
	return out
}

// Preparation and import preflight must agree on capabilities. A readable
// binary alone does not satisfy the mapped configuration's dependencies.
func inspectNginxDependencies(parsed *nginxconfig.Parsed, features agent.NginxFeatures) []Step {
	out := []Step{}
	selectedFeatures := map[string]bool{}
	seenModules := map[string]bool{}
	for _, path := range parsed.Tree.ModulePaths {
		if seenModules[path] {
			continue
		}
		seenModules[path] = true
		available := false
		for _, module := range features.Modules {
			if module.Path == path && module.Available {
				available = true
				for _, feature := range module.Features {
					selectedFeatures[feature] = true
				}
				break
			}
		}
		if available {
			out = append(out, Step{"module", path, "review", "目标已有匹配的受信模块；应用前须通过配置与 ABI 校验"})
		} else {
			out = append(out, Step{"module", path, "unavailable", "目标未确认此受信模块；须映射目标批准路径，或在已静态预置该能力时显式移除 load_module。迁移不复制动态库，Docker 不增装模块"})
		}
	}
	if !features.Available {
		out = append(out, Step{"component", "nginx", "unavailable", "无法确认目标 Nginx 能力；请先安装或接入受管实例"})
	} else {
		for _, name := range parsed.MigrationFeatures() {
			f, ok := features.Features[name]
			if !ok || !f.Available {
				if selectedFeatures[name] {
					out = append(out, Step{"capability", name, "review", "由已选择的目标受信模块提供，等待应用时验证加载"})
				} else {
					out = append(out, Step{"image", name, "unavailable", "目标 Nginx 缺少已确认能力；Docker 须换用预置对应模块的镜像"})
				}
			} else {
				out = append(out, Step{"capability", name, "ready", "目标已具备所需能力"})
			}
		}
	}
	return out
}
