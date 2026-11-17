package software

import (
	"bytes"
	"context"
	"fmt"
	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/secure"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type limitedLog struct {
	bytes.Buffer
	progress Progress
	last     time.Time
}

func (b *limitedLog) Write(p []byte) (int, error) {
	n := len(p)
	_, _ = b.Buffer.Write(p)
	if b.progress != nil && time.Since(b.last) >= time.Second {
		b.last = time.Now()
		lines := strings.FieldsFunc(strings.ToValidUTF8(string(p), ""), func(r rune) bool { return r == '\n' || r == '\r' })
		if len(lines) > 0 {
			last := lines[len(lines)-1]
			if len(last) > 500 {
				last = last[:500]
			}
			b.progress(last)
		}
	}
	if b.Len() > 16000 {
		tail := append([]byte(nil), b.Bytes()[b.Len()-16000:]...)
		b.Reset()
		_, _ = b.Buffer.Write(tail)
	}
	return n, nil
}
func Docker(ctx context.Context, progress Progress, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "/usr/bin/docker", args...)
	log := limitedLog{progress: progress}
	command.Stdout = &log
	command.Stderr = &log
	err := command.Run()
	text := strings.TrimSpace(log.String())
	if err != nil {
		if text == "" {
			return text, fmt.Errorf("无法执行 Docker 操作：%w", err)
		}
		return text, fmt.Errorf("Docker 操作失败：%s", text)
	}
	return text, nil
}

func applicationDirectory(data, source, app string) string {
	return filepath.Join(data, "agent", "software", "work", source, app)
}
func operationCommand(ctx context.Context, data, source string, app Application, action string, progress Progress) (string, error) {
	return versionCommand(ctx, data, source, app, action, nil, nil, progress)
}
func versionCommand(ctx context.Context, data, source string, app Application, action string, target, previous *componentversions.Version, progress Progress) (string, error) {
	operation, ok := app.Actions[action]
	if !ok {
		return "", fmt.Errorf("软件未提供此操作：%s", action)
	}
	dir := applicationDirectory(data, source, app.ID)
	if action == "status" {
		if _, err := os.Lstat(dir); err != nil {
			return "", fmt.Errorf("软件工作目录不可用：%w", err)
		}
	}
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, operation.Command[0], operation.Command[1:]...)
	command.Dir = dir
	command.Env = append(os.Environ(), "NGINXPANEL_SOFTWARE_DIR="+dir, "NGINXPANEL_SOFTWARE_ID="+secure.Hash([]byte(source + "/" + app.ID))[:16], "NGINXPANEL_SOURCE_ID="+source, "NGINXPANEL_APP_ID="+app.ID)
	version, id, oldVersion, oldID := "", "", "", ""
	if target != nil {
		version, id = target.Version, target.ID
	}
	if previous != nil {
		oldVersion, oldID = previous.Version, previous.ID
	}
	command.Env = append(command.Env, "NGINXPANEL_TARGET_VERSION="+version, "NGINXPANEL_TARGET_VERSION_ID="+id, "NGINXPANEL_PREVIOUS_VERSION="+oldVersion, "NGINXPANEL_PREVIOUS_VERSION_ID="+oldID)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	log := limitedLog{progress: progress}
	diagnostics := limitedLog{}
	command.Stdout = &log
	command.Stderr = &log
	if action == "status" {
		command.Stderr = &diagnostics
	}
	err := command.Run()
	output := strings.TrimSpace(log.String())
	if err != nil {
		if ctx.Err() != nil {
			return output, fmt.Errorf("软件操作已中止：%w", ctx.Err())
		}
		if action == "status" && diagnostics.Len() > 0 {
			return output, fmt.Errorf("状态检查失败：%s", strings.TrimSpace(diagnostics.String()))
		}
		return output, fmt.Errorf("软件操作未完成：%w", err)
	}
	return output, nil
}
