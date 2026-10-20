package nginxcontainer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type diagnostic struct {
	ExecID                string `json:"exec_id"`
	ContainerID           string `json:"container_id"`
	MasterPID             int    `json:"master_pid"`
	BootID                string `json:"boot_id"`
	MasterStart           uint64 `json:"master_start"`
	CommandSHA256         string `json:"command_sha256"`
	LauncherCommandSHA256 string `json:"launcher_command_sha256,omitempty"`
}

func diagnosticPath(data string) string {
	return filepath.Join(data, "agent", "nginx-container-exec.json")
}
func bootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if !revisionValue.MatchString(id) || id == "bootstrap" {
		return "", errors.New("无法确认宿主机启动标识")
	}
	return id, nil
}
func startTicks(pid int) (uint64, error) {
	raw, err := readProc(pid, "stat", 8192)
	if err != nil {
		return 0, err
	}
	end := strings.LastIndex(string(raw), ") ")
	if end < 0 {
		return 0, errors.New("进程启动标识格式无效")
	}
	fields := strings.Fields(string(raw)[end+2:])
	if len(fields) < 20 {
		return 0, errors.New("进程启动标识缺失")
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("进程启动标识无效")
	}
	return value, nil
}
func (r *Runtime) lock(ctx context.Context) error {
	r.once.Do(func() { r.gate = make(chan struct{}, 1) })
	select {
	case r.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *Runtime) unlock() { <-r.gate }
func (r *Runtime) readDiagnostic() (diagnostic, error) {
	var p diagnostic
	raw, err := secure.ReadRootFile(diagnosticPath(r.Binding.DataDir), 4096)
	if err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !bytes.Equal(canonical(p), raw) || !hashValue.MatchString(p.ExecID) || !hashValue.MatchString(p.ContainerID) || !hashValue.MatchString(p.CommandSHA256) || p.MasterPID <= 1 || p.MasterStart == 0 || !revisionValue.MatchString(p.BootID) || p.BootID == "bootstrap" {
		return p, errors.New("Nginx 原诊断回执无效，须本机恢复")
	}
	if p.LauncherCommandSHA256 != "" && !hashValue.MatchString(p.LauncherCommandSHA256) {
		return p, errors.New("Nginx 原诊断启动器身份无效，须本机恢复")
	}
	return p, nil
}
func (r *Runtime) saveDiagnostic(p diagnostic) error {
	path := diagnosticPath(r.Binding.DataDir)
	if err := secure.RootDirectory(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".nginx-exec-")
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(f.Name())
	if _, err = f.Write(canonical(p)); err != nil {
		return err
	}
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
func (r *Runtime) clearDiagnostic(p diagnostic) error {
	prior, err := r.readDiagnostic()
	if err != nil {
		return err
	}
	if prior != p {
		return errors.New("Nginx 原诊断回执已变化")
	}
	path := diagnosticPath(r.Binding.DataDir)
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// PID 1 exiting destroys the original PID namespace and its descendants. The
// host boot ID and start ticks prevent PID reuse from being treated as that
// original master, including after Agent or Docker restarts.
func (p diagnostic) masterGone() (bool, error) {
	boot, err := bootID()
	if err != nil {
		return false, err
	}
	if boot != p.BootID {
		return true, nil
	}
	start, err := startTicks(p.MasterPID)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return start != p.MasterStart, nil
}
func (r *Runtime) reconcileDiagnostic(ctx context.Context, d *dockerClient) error {
	p, err := r.readDiagnostic()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	gone, err := p.masterGone()
	if err != nil {
		return err
	}
	if !gone {
		var original containerInfo
		original.ID, original.State.Pid = p.ContainerID, p.MasterPID
		if err = r.finishExec(call, d, p.ExecID, original, p.CommandSHA256, p.LauncherCommandSHA256); err != nil {
			return err
		}
	}
	return r.clearDiagnostic(p)
}
