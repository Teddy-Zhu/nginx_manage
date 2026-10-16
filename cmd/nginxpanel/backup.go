package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/backup"
)

type backupCLIOptions struct {
	DataDir, File, OperationID string
	InputFD                    int
}

func isBackupRecoveryCommand(command string) bool {
	switch command {
	case "backup-restore-reconcile", "backup-restore-reconcile-data", "backup-restore-reconcile-verify-data", "backup-restore-activate", "backup-restore-activate-data", "backup-restore-activate-verify-data":
		return true
	case "backup-prepare", "backup-prepare-data", "backup-preparation", "backup-preparation-data", "backup-preparation-cleanup", "backup-preparation-cleanup-data", "backup-adopt", "backup-adoption", "backup-adoption-cleanup", "backup-adoption-verify-data", "backup-restore", "backup-restore-rollback", "backup-restore-status", "backup-restore-plan", "backup-restore-plan-status", "backup-restore-plan-data", "backup-restore-plan-verify-data", "backup-restore-plan-cleanup", "backup-restore-plan-cleanup-data", "backup-restore-apply", "backup-restore-runtime-status", "backup-restore-runtime-data":
		return true
	default:
		return false
	}
}

func readBackupInput(out any) error { return readBackupJSON(out, 8192) }
func readBackupJSON(out any, limit int64) error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, limit+1))
	if err != nil {
		return err
	}
	defer clear(raw)
	if int64(len(raw)) > limit {
		return errors.New("备份恢复命令输入超过限制")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("备份恢复命令输入须为单个 JSON 对象")
	}
	return nil
}

func runBackupCommand(ctx context.Context, command string, options backupCLIOptions) (bool, error) {
	if command != "backup-inspect" && !isBackupRecoveryCommand(command) {
		return false, nil
	}
	if command == "backup-inspect" {
		if os.Geteuid() == 0 || options.File == "" {
			return true, errors.New("backup-inspect 须由非 root 账户执行并指定 --backup-file；解密材料通过标准输入提供")
		}
		var credentials backup.InspectCredentials
		if err := readBackupInput(&credentials); err != nil {
			return true, err
		}
		out, err := backup.InspectFile(ctx, options.File, credentials)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	}
	if options.OperationID == "" {
		return true, errors.New("恢复命令须指定 --restore-operation")
	}
	data, err := filepath.Abs(options.DataDir)
	if err != nil {
		return true, err
	}
	switch command {
	case "backup-restore-activate":
		var input backup.RestoreActivateInput
		if err = readBackupInput(&input); err != nil {
			return true, err
		}
		out, err := backup.ActivateRestoration(ctx, data, options.OperationID, input)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-restore-reconcile":
		var input backup.RestoreReconcileInput
		if err = readBackupInput(&input); err != nil {
			return true, err
		}
		out, err := backup.ReconcileRestoration(ctx, data, options.OperationID, input)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-restore-apply":
		var input backup.RestoreInput
		if err = readBackupInput(&input); err != nil {
			return true, err
		}
		out, err := backup.ApplyRestoration(ctx, data, options.OperationID, input)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-restore-runtime-status":
		out, err := agent.DisasterRuntime(data, options.OperationID)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-restore-runtime-data":
		var input agent.DisasterRuntimeRequest
		if err = readBackupInput(&input); err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(backup.AdvanceRestorationAsPanel(ctx, data, options.OperationID, input))
	case "backup-restore-plan":
		if os.Geteuid() != 0 {
			return true, errors.New("恢复目标计划须由 root 调用")
		}
		var input backup.RestorePlanInput
		if err = readBackupJSON(&input, 32<<10); err != nil {
			return true, err
		}
		out, err := backup.CreateRestorePlan(ctx, data, options.OperationID, input)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-restore-plan-status":
		out, err := backup.QueryRestorePlan(data, options.OperationID)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-restore", "backup-restore-rollback":
		if os.Geteuid() != 0 {
			return true, errors.New("独立灾备恢复须由 root 调用")
		}
		var input backup.RestoreInput
		if err = readBackupInput(&input); err != nil {
			return true, err
		}
		out, err := backup.RestoreAdoption(ctx, data, options.OperationID, input, command == "backup-restore-rollback")
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-restore-status":
		out, err := agent.DisasterRestoreStatus(data, options.OperationID)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-adopt":
		if os.Geteuid() != 0 {
			return true, errors.New("恢复材料接入须由 root 调用")
		}
		var input backup.AdoptInput
		if err = readBackupInput(&input); err != nil {
			return true, err
		}
		out, err := backup.AdoptPreparation(ctx, data, options.OperationID, input)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-adoption":
		out, err := backup.QueryAdoption(ctx, data, options.OperationID)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-adoption-cleanup":
		if err = backup.CleanupAdoption(ctx, data, options.OperationID); err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(struct {
			OperationID string `json:"operation_id"`
			Cleaned     bool   `json:"cleaned"`
		}{options.OperationID, true})
	case "backup-restore-plan-cleanup", "backup-restore-plan-cleanup-data":
		if command == "backup-restore-plan-cleanup" {
			err = backup.CleanupRestorePlan(ctx, data, options.OperationID)
		} else {
			err = backup.CleanupRestorationWork(data, options.OperationID)
		}
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(struct {
			OperationID string `json:"operation_id"`
			Cleaned     bool   `json:"cleaned"`
		}{options.OperationID, true})
	case "backup-adoption-verify-data", "backup-restore-plan-data", "backup-restore-plan-verify-data", "backup-restore-reconcile-data", "backup-restore-reconcile-verify-data", "backup-restore-activate-data", "backup-restore-activate-verify-data":
		if os.Geteuid() == 0 {
			return true, errors.New("恢复材料核对助手须使用非 root 身份")
		}
		var files []*os.File
		lastFD := 6
		if command == "backup-restore-plan-verify-data" {
			lastFD = 7
		}
		for fd := 3; fd <= lastFD; fd++ {
			f := os.NewFile(uintptr(fd), "root-recovery-material")
			if f == nil {
				return true, errors.New("恢复材料核对缺少固定描述符")
			}
			defer f.Close()
			files = append(files, f)
		}
		if command == "backup-restore-activate-data" || command == "backup-restore-activate-verify-data" {
			var input backup.RestoreActivateMaterialInput
			if err = readBackupJSON(&input, 512<<10); err != nil {
				return true, err
			}
			if command == "backup-restore-activate-data" {
				out, err := backup.PrepareActivatedRestorationDescriptors(ctx, data, options.OperationID, input, files)
				if err != nil {
					return true, err
				}
				return true, json.NewEncoder(os.Stdout).Encode(out)
			}
			out, err := backup.VerifyActivatedRestorationDescriptors(ctx, data, options.OperationID, input, files)
			if err != nil {
				return true, err
			}
			return true, json.NewEncoder(os.Stdout).Encode(out)
		}
		if command == "backup-restore-reconcile-data" || command == "backup-restore-reconcile-verify-data" {
			var input backup.RestoreReconcileMaterialInput
			if err = readBackupJSON(&input, 512<<10); err != nil {
				return true, err
			}
			if command == "backup-restore-reconcile-data" {
				out, err := backup.ReconcileRestorationDescriptors(ctx, data, options.OperationID, input, files)
				if err != nil {
					return true, err
				}
				return true, json.NewEncoder(os.Stdout).Encode(out)
			}
			out, err := backup.VerifyReconciledRestorationDescriptors(ctx, data, options.OperationID, input, files)
			if err != nil {
				return true, err
			}
			return true, json.NewEncoder(os.Stdout).Encode(out)
		}
		if command == "backup-restore-plan-verify-data" {
			var input backup.RestorePublicationInput
			if err = readBackupJSON(&input, 256<<10); err != nil {
				return true, err
			}
			out, err := backup.VerifyRestorationPublication(ctx, data, options.OperationID, input, files)
			if err != nil {
				return true, err
			}
			return true, json.NewEncoder(os.Stdout).Encode(out)
		}
		if command == "backup-restore-plan-data" {
			var input backup.RestorePreviewInput
			if err = readBackupJSON(&input, 128<<10); err != nil {
				return true, err
			}
			out, err := backup.PreviewRestorationDescriptors(ctx, data, options.OperationID, input, files)
			if err != nil {
				return true, err
			}
			return true, json.NewEncoder(os.Stdout).Encode(out)
		}
		var input backup.Preparation
		if err = readBackupJSON(&input, 128<<10); err != nil {
			return true, err
		}
		out, err := backup.VerifyAdoptionDescriptors(ctx, data, options.OperationID, input, files)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-prepare", "backup-prepare-data":
		if command == "backup-prepare" && (os.Geteuid() != 0 || options.File == "") {
			return true, errors.New("backup-prepare 须由 root 调用并指定 --backup-file")
		}
		if command == "backup-prepare-data" && (os.Geteuid() == 0 || options.InputFD != 3) {
			return true, errors.New("恢复准备数据助手须使用非 root 身份及固定描述符 3")
		}
		var input backup.PrepareInput
		if err = readBackupInput(&input); err != nil {
			return true, err
		}
		var out backup.Preparation
		if command == "backup-prepare" {
			out, err = backup.PrepareStopped(ctx, data, options.OperationID, options.File, input)
		} else {
			f := os.NewFile(uintptr(options.InputFD), "encrypted-backup")
			if f == nil {
				return true, errors.New("恢复准备缺少加密输入描述符")
			}
			defer f.Close()
			out, err = backup.PrepareWithFile(ctx, data, options.OperationID, f, input)
		}
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-preparation", "backup-preparation-data":
		var out backup.PreparationStatus
		if command == "backup-preparation" {
			out, err = backup.QueryPreparation(ctx, data, options.OperationID)
		} else {
			out, err = backup.GetPreparation(ctx, data, options.OperationID)
		}
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(out)
	case "backup-preparation-cleanup", "backup-preparation-cleanup-data":
		if command == "backup-preparation-cleanup" {
			err = backup.CleanupStoppedPreparation(ctx, data, options.OperationID)
		} else {
			err = backup.CleanupPreparation(data, options.OperationID)
		}
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(struct {
			OperationID string `json:"operation_id"`
			Cleaned     bool   `json:"cleaned"`
		}{options.OperationID, true})
	}
	return true, errors.New("未知恢复准备命令")
}
