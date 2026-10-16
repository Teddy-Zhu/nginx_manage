package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/migration"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

type RestorePreviewInput struct {
	PlanID          string            `json:"plan_id"`
	Preparation     Preparation       `json:"preparation"`
	ExpectedApplied string            `json:"expected_applied"`
	Mappings        map[string]string `json:"mappings"`
}

type RestorePreview struct {
	Verification       MaterialVerification `json:"verification"`
	CandidateSHA256    string               `json:"candidate_sha256"`
	MaterialsSHA256    string               `json:"materials_sha256"`
	CapabilitiesSHA256 string               `json:"capabilities_sha256"`
	PolicySHA256       string               `json:"policy_sha256"`
	Policy             nginxconfig.Policy   `json:"policy"`
	Publication        *RestorePublication  `json:"publication,omitempty"`
	Runtime            agent.NginxState     `json:"runtime"`
	RequiredFeatures   []string             `json:"required_features"`
	Steps              []migration.Step     `json:"steps"`
	StepCount          int                  `json:"step_count"`
	FileCount          int                  `json:"file_count"`
	CertificateCount   int                  `json:"certificate_count"`
	CanInstall         bool                 `json:"can_install"`
	PendingChecks      []string             `json:"pending_checks"`
}

// PreviewRestorationDescriptors reads only the verified root projection. It
// does not open live business data, launch workers, or submit an Agent operation.
func PreviewRestorationDescriptors(ctx context.Context, data, id string, in RestorePreviewInput, files []*os.File) (out RestorePreview, err error) {
	if !validID.MatchString(in.PlanID) || in.PlanID == id {
		return out, errors.New("恢复计划须使用独立标识")
	}
	if in.ExpectedApplied != "" && !validID.MatchString(in.ExpectedApplied) {
		return out, errors.New("目标运行修订依据无效")
	}
	if in.Preparation.Source.Database.DesiredRevision == "" && in.Preparation.Source.Database.AppliedRevision != "" {
		return out, errors.New("源期望修订缺失，不能用初始配置替代已应用配置")
	}
	out.Verification, err = verifyAdoptionDescriptors(ctx, data, id, in.Preparation, files, func(call context.Context, db *sql.DB, vault *secure.Vault) error {
		client := agent.NewClient(filepath.Join(data, "run", "agent", "agent.sock"))
		features, e := client.NginxFeatures(call)
		if e != nil {
			features.Available = false
		}
		runtime, e := client.NginxState(call)
		if e != nil {
			runtime.Available = false
		}
		policy := nginxconfig.DefaultPolicy()
		for _, module := range features.Modules {
			if module.Available && nginxmodules.Reference(module.Path) {
				policy.ModulePaths = append(policy.ModulePaths, module.Path)
			}
		}
		sort.Strings(policy.ModulePaths)
		sort.Slice(features.Modules, func(i, j int) bool { return features.Modules[i].Path < features.Modules[j].Path })
		out.Runtime = runtime
		var ehash error
		out.CapabilitiesSHA256, ehash = adoptionValueHash(features)
		if ehash != nil {
			return ehash
		}
		out.PolicySHA256, ehash = adoptionValueHash(policy)
		if ehash != nil {
			return ehash
		}
		out.Policy = policy
		source, e := restoreRevisionFiles(call, db, vault, in.Preparation.Database.DesiredRevision)
		if e != nil {
			return e
		}
		mapped, e := nginxconfig.RestorationFiles(source, policy, in.Mappings)
		if e != nil {
			return e
		}
		for index := range mapped {
			mapped[index].SHA256 = secure.Hash([]byte(mapped[index].Content))
		}
		out.CandidateSHA256, ehash = adoptionValueHash(mapped)
		if ehash != nil {
			return ehash
		}
		out.FileCount = len(mapped)
		parsed, e := nginxconfig.Parse(mapped, policy)
		if e != nil {
			return e
		}
		out.RequiredFeatures = parsed.MigrationFeatures()
		out.CanInstall = true
		out.Steps = []migration.Step{}
		add := func(kind, resource, state, message string) {
			out.StepCount++
			if state == "blocked" || state == "unavailable" {
				out.CanInstall = false
			}
			if len(out.Steps) < 64 {
				out.Steps = append(out.Steps, migration.Step{Kind: kind, Resource: previewText(resource, 96), State: state, Message: previewText(message, 128)})
			}
		}
		for _, d := range parsed.Tree.Diagnostics {
			add("configuration", d.FileID, "blocked", fmt.Sprintf("第 %d 行：%s", d.Line, d.Message))
		}
		for _, name := range parsed.MigrationLocalDependencies() {
			add("mapping", name, "blocked", "主机信任证书须映射为恢复数据库中的受管证书，或重新确认目标信任")
		}
		uses, e := parsed.CertificateUses()
		if e != nil {
			return e
		}
		paths := []string{}
		for _, use := range uses {
			paths = append(paths, use.Path)
		}
		materials, e := (&certificates.Service{Vault: vault}).Materials(call, db, paths)
		if e != nil {
			add("certificate", "materials", "blocked", "恢复数据库缺少可解密的受管证书材料")
		} else {
			out.CertificateCount = len(materials)
			out.MaterialsSHA256, ehash = adoptionValueHash(materials)
			if ehash != nil {
				return ehash
			}
			if e = parsed.ValidateTLS(materials); e != nil {
				add("certificate", "tls", "blocked", e.Error())
			} else {
				add("certificate", "tls", "ready", "引用材料与 TLS 配置匹配")
			}
		}
		for _, step := range migration.InspectNginxTarget(parsed, features, runtime) {
			add(step.Kind, step.Resource, step.State, step.Message)
		}
		if runtime.Available && runtime.RevisionID != in.ExpectedApplied {
			add("runtime", "basis", "blocked", "目标 Nginx 运行修订与原回退数据库不一致，须先核对目标接入")
		}
		for _, resource := range parsed.Tree.Resources {
			for _, name := range []string{"listeners", "upstream", "upstream_servers", "domains"} {
				if field, ok := resource.Fields[name]; ok {
					for _, value := range field.Values {
						add("review", resource.ID+":"+name, "review", value)
					}
				}
			}
		}
		out.PendingChecks = []string{"configuration_apply", "external_authorizations_review", "host_access_review", "automation_disabled"}
		if in.Preparation.Isolation.Tasks > 0 {
			out.PendingChecks = append(out.PendingChecks, "quarantined_tasks_review")
			add("tasks", "quarantined", "pending", fmt.Sprintf("%d 项旧任务保持隔离，须核对实际结果后再协调", in.Preparation.Isolation.Tasks))
		} else {
			add("tasks", "quarantined", "ready", "没有源在途任务需要协调")
		}
		add("authorization", "remote", "pending", "源远程授权、配对和 CA/DNS 订单须核对外部结果，禁止自动重放")
		add("host", "network", "preserved", "保留目标 DNS、网络与防火墙状态，变更须重新计划和确认")
		add("automation", "modules", "disabled", "通知、定期备份、ACME 自动化及其他模块保持停用")
		if out.CanInstall {
			publication, e := publishRestorationDatabase(call, data, in.PlanID, in.Preparation, files[0], vault, policy, mapped, out.PendingChecks)
			if e != nil {
				return e
			}
			out.Publication = &publication
			add("configuration", "revision", "prepared", "映射配置已生成隔离修订，须固定材料并完成运行确认")
		} else {
			add("configuration", "revision", "pending", "阻塞项解除前不生成安装数据库")
		}
		if out.StepCount > len(out.Steps) {
			out.Steps = append(out.Steps, migration.Step{Kind: "preview", Resource: "remaining", State: "review", Message: fmt.Sprintf("共 %d 项，展示前 64 项；全部项目参与准入判断", out.StepCount)})
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if len(raw) > 64<<10 {
		return out, errors.New("恢复计划预览超过 64 KiB")
	}
	return out, nil
}

func previewText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return value
}

func restoreRevisionFiles(ctx context.Context, db *sql.DB, vault *secure.Vault, revision string) ([]nginxconfig.File, error) {
	if revision == "" {
		return nginxconfig.InitialFiles(), nil
	}
	rows, err := db.QueryContext(ctx, "SELECT substr(id,1,129),substr(path,1,1025),CASE WHEN length(content)<=262208 THEN content ELSE NULL END,substr(sha256,1,65) FROM nginx_config_files WHERE revision_id=? ORDER BY path,id LIMIT 129", revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []nginxconfig.File{}
	total := 0
	for rows.Next() {
		var file nginxconfig.File
		var cipher []byte
		if err = rows.Scan(&file.ID, &file.Path, &cipher, &file.SHA256); err != nil {
			return nil, err
		}
		if len(out) >= 128 || len(file.ID) > 128 || len(file.Path) > 1024 || len(cipher) > (256<<10)+64 {
			return nil, errors.New("恢复修订文件超过容量限制")
		}
		plain, err := vault.Open(cipher, "nginx:"+revision+":"+file.ID)
		if err != nil {
			return nil, err
		}
		total += len(plain)
		if total > 2<<20 || secure.Hash(plain) != file.SHA256 {
			return nil, errors.New("恢复修订内容散列无效或总大小超限")
		}
		file.Content = string(plain)
		out = append(out, file)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("恢复修订缺少完整文件树")
	}
	return out, nil
}
