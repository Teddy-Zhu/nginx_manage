package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
	"nginxpanel/migrations"
)

// PrepareStopped passes only a ciphertext descriptor and temporary stdin to
// the selected immutable binary after dropping all root credentials. Root never
// opens an archive-supplied SQLite database or installs preparation output.
func PrepareStopped(ctx context.Context, data, id, path string, in PrepareInput) (out Preparation, err error) {
	if err = in.validate(); err != nil {
		return out, err
	}
	if os.Geteuid() != 0 {
		return out, errors.New("离线恢复准备入口须由 root 调用")
	}
	running, err := panelruntime.Read(data)
	if err != nil {
		return out, err
	}
	hold, err := storage.ReadServiceHold(data)
	if err != nil {
		return out, err
	}
	binding, err := json.Marshal(running.Deployment)
	if err != nil {
		return out, err
	}
	if hold.MaintenanceID != in.MaintenanceID || hold.ReleaseID != running.Release.ID || hold.BindingSHA256 != secure.Hash(binding) {
		return out, errors.New("恢复准备与目标原持久停机事务不一致")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return out, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !stat.Mode().IsRegular() || stat.Size() < 1 || stat.Size() > ArchiveMax {
		return out, errors.New("恢复输入须为受限普通加密文件")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	if err = runPreparationHelper(ctx, data, "backup-prepare-data", id, raw, []*os.File{f}, &out); err != nil {
		return out, err
	}
	if err = out.Validate(); err != nil {
		return out, err
	}
	if out.OperationID != id || out.MaintenanceID != in.MaintenanceID || out.Mode != in.Mode || out.ArchiveSHA256 != in.ArchiveSHA256 || out.Source.Database.NodeID != in.SourceNodeID || out.Target.Database.NodeID != in.TargetNodeID || out.Target.ReleaseID != running.Release.ID || out.Target.Runtime != running.Deployment.Mode || out.PreserveNodeIdentity != in.PreserveNodeIdentity || out.SourceOfflineConfirmed != in.SourceOfflineConfirmed {
		return out, errors.New("恢复准备助手返回了不同事务或目标身份")
	}
	after, err := storage.ReadServiceHold(data)
	if err != nil {
		return out, err
	}
	if after != hold {
		return out, errors.New("恢复准备期间原持久停机边界发生变化，禁止采用结果")
	}
	return out, nil
}

func QueryPreparation(ctx context.Context, data, id string) (out PreparationStatus, err error) {
	err = runPreparationHelper(ctx, data, "backup-preparation-data", id, nil, nil, &out)
	if err != nil {
		return out, err
	}
	if err = out.Preparation.Validate(); err != nil {
		return out, err
	}
	if out.Preparation.OperationID != id {
		return out, errors.New("恢复准备查询返回了不同操作身份")
	}
	hash, err := preparationHash(out.Preparation)
	if err != nil {
		return out, err
	}
	if out.SHA256 != hash {
		return out, errors.New("恢复准备查询返回无效摘要")
	}
	return out, nil
}

func CleanupStoppedPreparation(ctx context.Context, data, id string) error {
	if os.Geteuid() != 0 {
		return errors.New("离线恢复准备清理入口须由 root 调用")
	}
	running, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	hold, err := storage.ReadServiceHold(data)
	if err != nil {
		return err
	}
	binding, err := json.Marshal(running.Deployment)
	if err != nil {
		return err
	}
	if hold.ReleaseID != running.Release.ID || hold.BindingSHA256 != secure.Hash(binding) {
		return errors.New("恢复准备清理与当前持久停机版本不一致")
	}
	var result struct {
		OperationID string `json:"operation_id"`
		Cleaned     bool   `json:"cleaned"`
	}
	if err = runPreparationHelper(ctx, data, "backup-preparation-cleanup-data", id, nil, nil, &result); err != nil {
		return err
	}
	if result.OperationID != id || !result.Cleaned {
		return errors.New("恢复准备清理助手未确认原操作")
	}
	after, err := storage.ReadServiceHold(data)
	if err != nil {
		return err
	}
	if after != hold {
		return errors.New("恢复准备清理期间持久停机边界变化")
	}
	return nil
}

func runPreparationHelper(ctx context.Context, data, command, id string, input []byte, files []*os.File, out any) error {
	if os.Geteuid() != 0 || !validID.MatchString(id) {
		return errors.New("恢复准备助手须由 root 调用并使用有界固定身份")
	}
	switch command {
	case "backup-prepare-data":
		if len(files) != 1 || len(input) > 8192 {
			return errors.New("恢复准备缺少加密文件描述符")
		}
	case "backup-adoption-verify-data", "backup-restore-plan-data":
		if len(files) != len(resources) || len(input) > 128<<10 {
			return errors.New("恢复接入助手缺少固定资源描述符或输入超过限制")
		}
	case "backup-restore-plan-verify-data":
		if len(files) != len(resources) || len(input) > 256<<10 {
			return errors.New("恢复发布核对缺少固定描述符或输入超过限制")
		}
	case "backup-preparation-data", "backup-preparation-cleanup-data", "backup-restore-plan-cleanup-data":
		if len(files) != 0 || len(input) != 0 {
			return errors.New("恢复准备查询或清理不接受解密材料")
		}
	default:
		return errors.New("未知恢复准备助手")
	}
	running, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	for _, id := range []int{running.Deployment.UID, running.Deployment.GID, running.Deployment.IPCGID} {
		if id <= 0 || uint64(id) >= uint64(^uint32(0)) {
			return errors.New("恢复准备助手的非 root 用户或组范围无效")
		}
	}
	latest, err := migrations.LatestVersion()
	if err != nil {
		return err
	}
	if running.Release.DatabaseSchema != latest {
		return errors.New("恢复准备程序与当前已批准数据库版本不同")
	}
	before, err := json.Marshal(running)
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	args := []string{command, "--data-dir", data, "--restore-operation", id}
	if command == "backup-prepare-data" {
		args = append(args, "--backup-input-fd", "3")
	}
	cmd := exec.CommandContext(call, filepath.Join(running.Directory, "nginxpanel"), args...)
	cmd.Dir = running.Directory
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(running.Deployment.UID), Gid: uint32(running.Deployment.GID), Groups: []uint32{uint32(running.Deployment.IPCGID)}}, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = io.Discard
	cmd.ExtraFiles = files
	var output bytes.Buffer
	cmd.Stdout = &boundedWriter{w: &output, max: 128 << 10}
	if err = cmd.Run(); err != nil {
		return errors.Join(fmt.Errorf("非 root 恢复准备助手 %s 失败，材料保留且原停机边界未解除：%w", command, err), call.Err())
	}
	if err = decodeStrict(output.Bytes(), out); err != nil {
		return errors.New("恢复准备助手返回无效记录")
	}
	after, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	afterRaw, err := json.Marshal(after)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, afterRaw) {
		return errors.New("恢复准备助手执行期间已批准运行版本变化，禁止采用结果")
	}
	return nil
}
