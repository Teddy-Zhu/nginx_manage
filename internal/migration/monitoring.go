package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/monitoring"
	"nginxpanel/internal/secure"
)

type MonitoringInput struct {
	Mode        string `json:"mode"`
	BaseVersion *int64 `json:"base_version,omitempty"`
}

type MonitoringPlan struct {
	Mode         string              `json:"mode"`
	State        string              `json:"state"`
	BaseVersion  int64               `json:"base_version"`
	SavedVersion int64               `json:"saved_version"`
	Settings     monitoring.Settings `json:"settings"`
	SettingsHash string              `json:"settings_hash"`
}

type monitoringImportState struct {
	Before          monitoring.SettingsView `json:"before"`
	ImportedVersion int64                   `json:"imported_version"`
}

func (in MonitoringInput) validate() error {
	if in.Mode == "" || in.Mode == "preserve" {
		if in.BaseVersion != nil {
			return fault.Invalid("保留目标监控配置时不能指定替换版本")
		}
		return nil
	}
	if in.Mode != "replace" {
		return fault.Invalid("监控迁入模式须为 preserve 或 replace")
	}
	if in.BaseVersion != nil && (*in.BaseVersion < 1 || *in.BaseVersion > math.MaxInt64-2) {
		return fault.Invalid("监控基础版本无效或无法保留补偿版本")
	}
	return nil
}

func validateMonitoringSelection(in MonitoringInput, selected bool) error {
	if err := in.validate(); err != nil {
		return err
	}
	if in.Mode == "replace" && !selected {
		return fault.Invalid("替换监控配置须选择导出源监控配置")
	}
	return nil
}

func monitoringHash(settings monitoring.Settings) (string, error) {
	raw, err := json.Marshal(settings)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}

func (s *Service) prepareMonitoring(ctx context.Context, st *storedPlan, in MonitoringInput) error {
	if err := in.validate(); err != nil {
		return err
	}
	if st.Payload.Monitoring != nil {
		if err := st.Payload.Monitoring.Validate(); err != nil {
			return err
		}
	}
	if in.Mode != "replace" {
		return nil
	}
	if st.Payload.Monitoring == nil {
		return fault.Invalid("配置包未包含监控配置")
	}
	if s.Monitoring == nil {
		return fault.Unavailable("监控配置服务未配置")
	}
	before, err := s.Monitoring.Settings(ctx)
	if err != nil {
		return err
	}
	if before.Version > math.MaxInt64-2 || in.BaseVersion != nil && *in.BaseVersion != before.Version {
		return fault.Conflict("目标监控版本已变化或达到上限，请重新准备迁移")
	}
	st.Monitoring = &monitoringImportState{Before: before}
	return nil
}

func (s *Service) checkMonitoringBase(ctx context.Context, q monitoring.SettingsReader, st *storedPlan) error {
	if st.Monitoring == nil {
		return nil
	}
	current, err := s.Monitoring.ReadSettings(ctx, q)
	if err != nil {
		return err
	}
	if current != st.Monitoring.Before {
		return fault.Conflict("目标监控配置已变化，请重新准备迁移")
	}
	return nil
}

func (s *Service) inspectMonitoring(ctx context.Context, st *storedPlan, add func(string, string, string, string)) error {
	if st.Payload.Monitoring == nil {
		st.Plan.Monitoring = nil
		return nil
	}
	hash, err := monitoringHash(*st.Payload.Monitoring)
	if err != nil {
		return err
	}
	view := &MonitoringPlan{Mode: "preserve", State: "preserved", Settings: *st.Payload.Monitoring, SettingsHash: hash}
	st.Plan.Monitoring = view
	if st.Monitoring == nil {
		add("monitoring", "settings", "review", "包内包含监控配置，当前保留目标配置")
		return nil
	}
	view.Mode, view.State, view.BaseVersion = "replace", "pending_import", st.Monitoring.Before.Version
	if err := s.checkMonitoringBase(ctx, s.DB, st); err != nil {
		var known *fault.Error
		if !errors.As(err, &known) || known.Code != "CONFLICT" {
			return err
		}
		add("monitoring", "settings", "blocked", "目标监控配置已变化，须重新准备迁移")
	}
	add("monitoring", "settings", "review", "保存或应用时替换采样、保留时间和阈值；草稿不替换监控配置。目标模块开关、指标历史及告警状态保留")
	return nil
}

func (s *Service) importMonitoring(ctx context.Context, tx *sql.Tx, st *storedPlan, principal, requestID string, draft bool) error {
	if st.Monitoring == nil {
		return nil
	}
	if err := s.checkMonitoringBase(ctx, tx, st); err != nil {
		return err
	}
	if draft {
		st.Plan.Monitoring.State = "not_imported"
		return nil
	}
	view, err := s.Monitoring.StoreSettings(ctx, tx, st.Monitoring.Before.Version, *st.Payload.Monitoring)
	if err != nil {
		return err
	}
	st.Monitoring.ImportedVersion = view.Version
	st.Plan.Monitoring.State, st.Plan.Monitoring.SavedVersion = "saved", view.Version
	return pushAudit(ctx, tx, principal, requestID, st.Plan.ID, "migration.monitoring.import", "saved")
}

func (s *Service) compensateMonitoring(ctx context.Context, tx *sql.Tx, st *storedPlan, principal, requestID string) error {
	if st.Monitoring == nil {
		return nil
	}
	if st.Monitoring.ImportedVersion < 2 {
		return fault.Conflict("监控迁入版本缺失，不能补偿")
	}
	current, err := s.Monitoring.ReadSettings(ctx, tx)
	if err != nil {
		return err
	}
	if current.Version != st.Monitoring.ImportedVersion || current.Settings != *st.Payload.Monitoring {
		return fault.Conflict("监控配置已有其他变更，禁止覆盖")
	}
	if _, err = s.Monitoring.StoreSettings(ctx, tx, current.Version, st.Monitoring.Before.Settings); err != nil {
		return err
	}
	return pushAudit(ctx, tx, principal, requestID, st.Plan.ID, "migration.monitoring.compensate", "restored")
}

func validateMonitoringPreview(m *MonitoringPlan) error {
	hash, err := monitoringHash(m.Settings)
	if m.Settings.Validate() != nil || err != nil || m.SettingsHash != hash {
		return errors.New("invalid monitoring settings preview")
	}
	if m.Mode == "preserve" {
		if m.State != "preserved" || m.BaseVersion != 0 || m.SavedVersion != 0 {
			return errors.New("invalid preserved monitoring preview")
		}
		return nil
	}
	if m.Mode != "replace" || m.BaseVersion < 1 || m.BaseVersion > math.MaxInt64-2 {
		return errors.New("invalid monitoring migration version")
	}
	switch m.State {
	case "pending_import", "not_imported":
		if m.SavedVersion == 0 {
			return nil
		}
	case "saved", "restored", "recovery_required":
		if m.SavedVersion == m.BaseVersion+1 {
			return nil
		}
	}
	return errors.New("invalid monitoring migration state")
}

func acceptPushMonitoring(plan Plan, in PushInput, prior *Plan) error {
	m := plan.Monitoring
	if in.Remote.Selection.Monitoring != (m != nil) {
		return errors.New("target monitoring selection mismatch")
	}
	if m == nil {
		return nil
	}
	mode := in.Monitoring.Mode
	if mode == "" {
		mode = "preserve"
	}
	if m.Mode != mode || in.Monitoring.BaseVersion != nil && *in.Monitoring.BaseVersion != m.BaseVersion {
		return errors.New("target monitoring mode or version mismatch")
	}
	if prior != nil && (prior.Monitoring == nil || m.BaseVersion != prior.Monitoring.BaseVersion || m.SettingsHash != prior.Monitoring.SettingsHash) {
		return errors.New("target monitoring plan changed")
	}
	if mode == "preserve" {
		return nil
	}
	expected := "saved"
	switch plan.State {
	case "planned", "failed":
		expected = "pending_import"
	case "draft":
		expected = "not_imported"
	case "rolled_back":
		expected = "restored"
	case "recovery_required":
		expected = "recovery_required"
	}
	if m.State != expected {
		return errors.New("target monitoring result mismatch")
	}
	return nil
}
