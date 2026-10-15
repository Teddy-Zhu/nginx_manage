package nginxcontainer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

var revisionValue = regexp.MustCompile(`^(bootstrap|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

type execInfo struct {
	ID          string `json:"ID"`
	ContainerID string
	Running     bool
	ExitCode    *int
	Pid         int
}

func streamOutput(body io.Reader) ([]byte, error) {
	var out []byte
	for frames := 0; ; frames++ {
		var header [8]byte
		n, err := io.ReadFull(body, header[:])
		if err == io.EOF && n == 0 {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint32(header[4:]))
		if frames >= 1024 || (header[0] != 1 && header[0] != 2) || header[1] != 0 || header[2] != 0 || header[3] != 0 || size > 64<<10 || len(out)+size > 64<<10 {
			return nil, errors.New("Nginx 容器诊断输出格式或大小无效")
		}
		start := len(out)
		out = append(out, make([]byte, size)...)
		if _, err = io.ReadFull(body, out[start:]); err != nil {
			return nil, err
		}
	}
}
func (r *Runtime) finishExec(ctx context.Context, d *dockerClient, id string, c containerInfo, commandSHA string) error {
	var state execInfo
	path := "/exec/" + id + "/json"
	if err := d.json(ctx, "GET", path, nil, &state); err != nil {
		return err
	}
	if state.ID != id || state.ContainerID != c.ID {
		return errors.New("Nginx 校验进程回执不匹配")
	}
	if !state.Running && state.ExitCode != nil {
		return nil
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for !state.Running || state.Pid == 0 {
		select {
		case <-ctx.Done():
			return errors.New("原 Nginx 诊断尚未确认开始或结束，保留回执且不重新提交")
		case <-tick.C:
		}
		if err := d.json(ctx, "GET", path, nil, &state); err != nil {
			return err
		}
		if state.ID != id || state.ContainerID != c.ID {
			return errors.New("Nginx 校验进程回执已变化")
		}
		if !state.Running && state.ExitCode != nil {
			return nil
		}
	}
	if state.Pid <= 1 || state.Pid == c.State.Pid {
		return errors.New("Nginx 校验进程 PID 未确认")
	}
	fd, err := unix.PidfdOpen(state.Pid, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = r.processIdentity(state.Pid, c.State.Pid, false, false); err != nil {
		return err
	}
	command, err := readProc(state.Pid, "cmdline", 16<<10)
	if err != nil {
		return err
	}
	if secure.Hash(command) != commandSHA {
		return errors.New("原诊断 PID 的命令身份不匹配，拒绝发送信号")
	}
	var confirmed execInfo
	if err = d.json(ctx, "GET", path, nil, &confirmed); err != nil {
		return err
	}
	if confirmed.ID != id || confirmed.ContainerID != c.ID || confirmed.Pid != state.Pid {
		return errors.New("Nginx 校验进程身份已变化")
	}
	if !confirmed.Running && confirmed.ExitCode != nil {
		return nil
	}
	if err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return err
	}
	for {
		if err = d.json(ctx, "GET", path, nil, &confirmed); err != nil {
			return err
		}
		if confirmed.ID != id || confirmed.ContainerID != c.ID {
			return errors.New("Nginx 校验进程回执已变化")
		}
		if !confirmed.Running && confirmed.ExitCode != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func (r *Runtime) command(ctx context.Context, args []string) (out []byte, runErr error) {
	if err := r.lock(ctx); err != nil {
		return nil, err
	}
	defer r.unlock()
	d, err := newDocker()
	if err != nil {
		return nil, err
	}
	defer d.close()
	if err = r.reconcileDiagnostic(ctx, d); err != nil {
		return nil, err
	}
	c, err := r.inspect(ctx, d)
	if err != nil {
		return nil, err
	}
	boot, err := bootID()
	if err != nil {
		return nil, err
	}
	start, err := startTicks(c.State.Pid)
	if err != nil {
		return nil, err
	}
	var created struct {
		ID string `json:"Id"`
	}
	b := r.Binding
	input := map[string]any{"AttachStdout": true, "AttachStderr": true, "AttachStdin": false, "Tty": false, "Privileged": false, "User": strconv.Itoa(b.UID) + ":" + strconv.Itoa(b.GID), "WorkingDir": b.DataDir, "Env": []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}, "Cmd": append([]string{Binary}, args...)}
	if err = d.json(ctx, "POST", "/containers/"+c.ID+"/exec", input, &created); err != nil {
		return nil, err
	}
	if !hashValue.MatchString(created.ID) {
		return nil, errors.New("Docker 校验进程 ID 无效")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	pending := diagnostic{ExecID: created.ID, ContainerID: c.ID, MasterPID: c.State.Pid, BootID: boot, MasterStart: start, CommandSHA256: secure.Hash([]byte(strings.Join(append([]string{Binary}, args...), "\x00") + "\x00"))}
	if err = r.saveDiagnostic(pending); err != nil {
		return nil, err
	}
	submitted := false
	defer func() {
		if !submitted {
			runErr = errors.Join(runErr, r.clearDiagnostic(pending))
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := r.reconcileDiagnostic(cleanup, d); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("未能确认诊断进程结束: %w", err))
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	submitted = true
	resp, err := d.request(ctx, "POST", "/exec/"+created.ID+"/start", map[string]bool{"Detach": false, "Tty": false})
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(ctx, func() { resp.Body.Close() })
	value, err := streamOutput(resp.Body)
	stopClose()
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var state execInfo
	if err = d.json(ctx, "GET", "/exec/"+created.ID+"/json", nil, &state); err != nil {
		return nil, err
	}
	if state.ID != created.ID || state.ContainerID != c.ID || state.Running || state.ExitCode == nil || *state.ExitCode != 0 {
		return nil, errors.New("Nginx 容器诊断未确认成功")
	}
	after, err := r.inspect(ctx, d)
	if err != nil {
		return nil, err
	}
	if after.ID != c.ID || after.State.Pid != c.State.Pid {
		return nil, errors.New("Nginx 容器在诊断期间发生重启")
	}
	afterStart, err := startTicks(after.State.Pid)
	if err != nil {
		return nil, err
	}
	if afterStart != start {
		return nil, errors.New("Nginx 容器在诊断期间更换了 master")
	}
	return value, nil
}
func (r *Runtime) Version(ctx context.Context) (string, error) {
	value, err := r.command(ctx, []string{"-V"})
	if err != nil {
		return "", err
	}
	if string(value) != r.Binding.Build {
		return "", errors.New("运行镜像的编译信息与批准清单不一致")
	}
	return string(value), nil
}
func (r *Runtime) Test(ctx context.Context, revision string) error {
	if !revisionValue.MatchString(revision) {
		return errors.New("Nginx 校验仅接受受管发布 ID")
	}
	_, err := r.command(ctx, []string{"-t", "-q", "-p", r.Binding.DataDir + "/", "-c", filepath.Join(r.Binding.DataDir, "nginx", "revisions", revision, "nginx.conf"), "-e", "stderr"})
	return err
}
