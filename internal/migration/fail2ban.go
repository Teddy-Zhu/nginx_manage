package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type Fail2banInput struct {
	Mode        string `json:"mode"`
	BaseVersion *int64 `json:"base_version,omitempty"`
}
type Fail2banPlan struct {
	Mode           string   `json:"mode"`
	State          string   `json:"state"`
	BaseVersion    int64    `json:"base_version"`
	SavedVersion   int64    `json:"saved_version"`
	SourceJails    int      `json:"source_jails"`
	PreservedJails int      `json:"preserved_jails"`
	ReplacedJails  int      `json:"replaced_jails"`
	TotalJails     int      `json:"total_jails"`
	PolicyHash     string   `json:"policy_hash"`
	Warnings       []string `json:"warnings"`
}
type fail2banImportState struct {
	Input           Fail2banInput       `json:"input"`
	Before          fail2ban.PolicyView `json:"before"`
	Candidate       fail2ban.Policy     `json:"candidate"`
	ImportedVersion int64               `json:"imported_version"`
}

func (in Fail2banInput) validate() error {
	if in.Mode == "" || in.Mode == "preserve" {
		if in.BaseVersion != nil {
			return fault.Invalid("保留目标 jail 配置时不能指定替换版本")
		}
		return nil
	}
	if in.Mode != "merge" && in.Mode != "replace" {
		return fault.Invalid("jail 迁入模式须为 preserve、merge 或 replace")
	}
	if in.BaseVersion != nil && (*in.BaseVersion < 0 || *in.BaseVersion == math.MaxInt64) {
		return fault.Invalid("jail 基础版本无效")
	}
	return nil
}
func (s *Service) prepareFail2ban(ctx context.Context, st *storedPlan, in Fail2banInput) error {
	if err := in.validate(); err != nil {
		return err
	}
	if err := fail2ban.ValidateTransfer(st.Payload.Fail2ban); err != nil {
		return err
	}
	if in.Mode == "" || in.Mode == "preserve" {
		return nil
	}
	if st.Payload.Fail2ban == nil {
		return fault.Invalid("配置包未包含 jail 配置")
	}
	if s.Fail2ban == nil {
		return fault.Unavailable("jail 配置服务未配置")
	}
	before, err := s.Fail2ban.Policy(ctx)
	if err != nil {
		return err
	}
	if before.Version == math.MaxInt64 || in.BaseVersion != nil && *in.BaseVersion != before.Version {
		return fault.Conflict("目标 jail 版本已变化或达到上限，请重新准备迁移")
	}
	base := before.Version
	in.BaseVersion = &base
	candidate := fail2ban.DefaultPolicy()
	if in.Mode == "merge" {
		candidate.Jails = append(candidate.Jails, before.Policy.Jails...)
	}
	for index, jail := range st.Payload.Fail2ban.Jails {
		hash := secure.Hash([]byte(st.Plan.ID + "\x00fail2ban"))
		jail.ID = fmt.Sprintf("%s-%04x-%s-%s-%s", hash[:8], index, hash[12:16], hash[16:20], hash[20:32])
		candidate.Jails = append(candidate.Jails, jail)
	}
	candidate, err = candidate.Normalize()
	if err != nil {
		return err
	}
	st.Fail2ban = &fail2banImportState{Input: in, Before: before, Candidate: candidate}
	return nil
}
func (s *Service) checkFail2banBase(ctx context.Context, q fail2ban.PolicyReader, st *storedPlan) error {
	if st.Fail2ban == nil {
		return nil
	}
	view, err := s.Fail2ban.ReadPolicy(ctx, q)
	if err != nil {
		return err
	}
	if view.Version != st.Fail2ban.Before.Version || view.Policy.Hash() != st.Fail2ban.Before.Policy.Hash() {
		return fault.Conflict("目标 jail 期望配置已变化，请重新准备迁移")
	}
	return nil
}
func (s *Service) inspectFail2ban(ctx context.Context, st *storedPlan, add func(string, string, string, string)) error {
	if st.Payload.Fail2ban == nil {
		st.Plan.Fail2ban = nil
		return nil
	}
	f := &Fail2banPlan{Mode: "preserve", State: "preserved", SourceJails: len(st.Payload.Fail2ban.Jails), Warnings: []string{}}
	st.Plan.Fail2ban = f
	state := st.Fail2ban
	if state == nil {
		add("fail2ban", "policy", "review", "配置包含 jail 期望配置；当前选择保留目标配置")
		return nil
	}
	f.Mode, f.State, f.BaseVersion, f.SavedVersion = state.Input.Mode, "pending_import", state.Before.Version, state.ImportedVersion
	f.TotalJails = len(state.Candidate.Jails)
	f.PolicyHash = state.Candidate.Hash()
	if f.Mode == "merge" {
		f.PreservedJails = len(state.Before.Policy.Jails)
	} else {
		f.ReplacedJails = len(state.Before.Policy.Jails)
	}
	if err := s.checkFail2banBase(ctx, s.DB, st); err != nil {
		var known *fault.Error
		if !errors.As(err, &known) || known.Code != "CONFLICT" {
			return err
		}
		add("fail2ban", "policy", "blocked", "目标 jail 版本已变化，须重新准备迁移")
	}
	f.Warnings = append(f.Warnings, "仅保存期望配置；不安装、启动或变更 Fail2ban 实例，不导入 Socket、所有权或封禁状态", "须在目标核对日志来源、白名单、实际流量路径与动作后端；保留的 jail 可能引用已替换站点")
	add("fail2ban", "policy", "review", fmt.Sprintf("%s：导入 %d 个 jail，保留 %d 个，替换 %d 个；须在目标单独配置运行接入", f.Mode, f.SourceJails, f.PreservedJails, f.ReplacedJails))
	return s.inspectFail2banDependencies(ctx, state.Candidate, add)
}
func (s *Service) importFail2ban(ctx context.Context, tx *sql.Tx, st *storedPlan, principal, requestID string) error {
	if st.Fail2ban == nil {
		return nil
	}
	if err := s.checkFail2banBase(ctx, tx, st); err != nil {
		return err
	}
	view, err := s.Fail2ban.StorePolicy(ctx, tx, st.Fail2ban.Before.Version, st.Fail2ban.Candidate)
	if err != nil {
		return err
	}
	st.Fail2ban.ImportedVersion = view.Version
	st.Plan.Fail2ban.SavedVersion, st.Plan.Fail2ban.State = view.Version, "saved_unapplied"
	return pushAudit(ctx, tx, principal, requestID, st.Plan.ID, "migration.fail2ban.import", "saved_unapplied")
}
func (s *Service) compensateFail2ban(ctx context.Context, tx *sql.Tx, st *storedPlan, principal, requestID string) error {
	if st.Fail2ban == nil {
		return nil
	}
	if st.Fail2ban.ImportedVersion < 1 {
		return fault.Conflict("jail 迁入版本缺失，不能补偿")
	}
	view, err := s.Fail2ban.ReadPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if view.Version != st.Fail2ban.ImportedVersion || view.Policy.Hash() != st.Fail2ban.Candidate.Hash() {
		return fault.Conflict("jail 期望配置已有其他变更，禁止覆盖")
	}
	if _, err = s.Fail2ban.StorePolicy(ctx, tx, view.Version, st.Fail2ban.Before.Policy); err != nil {
		return err
	}
	return pushAudit(ctx, tx, principal, requestID, st.Plan.ID, "migration.fail2ban.compensate", "restored")
}
func validateFail2banPreview(f *Fail2banPlan) error {
	if f.Mode != "preserve" && f.Mode != "merge" && f.Mode != "replace" || f.BaseVersion < 0 || f.SavedVersion < 0 || f.SourceJails < 0 || f.SourceJails > fail2ban.MaxJails || f.PreservedJails < 0 || f.PreservedJails > fail2ban.MaxJails || f.ReplacedJails < 0 || f.ReplacedJails > fail2ban.MaxJails || f.TotalJails < 0 || f.TotalJails > fail2ban.MaxJails || f.Warnings == nil || len(f.Warnings) > 4 {
		return errors.New("invalid jail migration preview")
	}
	if f.Mode == "preserve" {
		if f.State != "preserved" || f.BaseVersion != 0 || f.SavedVersion != 0 || f.PolicyHash != "" || f.TotalJails != 0 || f.PreservedJails != 0 || f.ReplacedJails != 0 {
			return errors.New("invalid preserved jail preview")
		}
	} else {
		if f.BaseVersion == math.MaxInt64 || len(f.PolicyHash) != 64 || strings.Trim(f.PolicyHash, "0123456789abcdef") != "" {
			return errors.New("invalid jail migration digest")
		}
		if f.State != "pending_import" && f.State != "saved_unapplied" && f.State != "restored" && f.State != "recovery_required" {
			return errors.New("invalid jail migration state")
		}
		if f.Mode == "merge" && (f.TotalJails != f.SourceJails+f.PreservedJails || f.ReplacedJails != 0) || f.Mode == "replace" && (f.TotalJails != f.SourceJails || f.PreservedJails != 0) {
			return errors.New("invalid jail migration counts")
		}
	}
	for _, warning := range f.Warnings {
		if len(warning) > 1024 {
			return errors.New("invalid jail migration warning")
		}
	}
	return nil
}
func acceptPushFail2ban(plan Plan, in PushInput, prior *Plan) error {
	f := plan.Fail2ban
	if in.Remote.Selection.Fail2ban != (f != nil) {
		return errors.New("target jail selection mismatch")
	}
	if f == nil {
		return nil
	}
	mode := in.Fail2ban.Mode
	if mode == "" {
		mode = "preserve"
	}
	if f.Mode != mode {
		return errors.New("target jail mode mismatch")
	}
	if mode == "preserve" {
		return nil
	}
	if in.Fail2ban.BaseVersion != nil && f.BaseVersion != *in.Fail2ban.BaseVersion {
		return errors.New("target jail base mismatch")
	}
	if prior != nil && (prior.Fail2ban == nil || f.BaseVersion != prior.Fail2ban.BaseVersion || f.PolicyHash != prior.Fail2ban.PolicyHash || f.SourceJails != prior.Fail2ban.SourceJails || f.TotalJails != prior.Fail2ban.TotalJails || f.PreservedJails != prior.Fail2ban.PreservedJails || f.ReplacedJails != prior.Fail2ban.ReplacedJails) {
		return errors.New("target jail plan changed")
	}
	expected := "saved_unapplied"
	switch plan.State {
	case "planned", "failed":
		expected = "pending_import"
	case "rolled_back":
		expected = "restored"
	case "recovery_required":
		expected = "recovery_required"
	}
	if f.State != expected || expected == "pending_import" && f.SavedVersion != 0 || expected != "pending_import" && f.SavedVersion != f.BaseVersion+1 {
		return errors.New("target jail result mismatch")
	}
	return nil
}
