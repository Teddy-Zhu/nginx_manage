package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"nginxpanel/internal/backup"
)

type backupCLIOptions struct {
	DataDir, File, OperationID string
	InputFD                    int
}

func isBackupPreparationCommand(command string) bool {
	switch command {
	case "backup-prepare", "backup-prepare-data", "backup-preparation", "backup-preparation-data", "backup-preparation-cleanup", "backup-preparation-cleanup-data":
		return true
	default:
		return false
	}
}

func readBackupInput(out any) error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) > 8192 {
		return errors.New("备份解密输入超过限制")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("备份解密输入须为单个 JSON 对象")
	}
	return nil
}

func runBackupCommand(ctx context.Context, command string, options backupCLIOptions) (bool, error) {
	if command != "backup-inspect" && !isBackupPreparationCommand(command) {
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
		return true, errors.New("恢复准备命令须指定 --restore-operation")
	}
	data, err := filepath.Abs(options.DataDir)
	if err != nil {
		return true, err
	}
	switch command {
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
