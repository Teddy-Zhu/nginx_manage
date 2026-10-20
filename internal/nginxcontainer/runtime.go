package nginxcontainer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type Runtime struct {
	Binding Binding
	once    sync.Once
	gate    chan struct{}
}
type containerInfo struct {
	ID           string `json:"Id"`
	Name, Image  string
	RestartCount int
	State        struct {
		Running, Paused, Restarting, Dead bool
		Status, StartedAt, FinishedAt     string
		OOMKilled                         bool
		ExitCode                          int
		Pid                               int
	}
	Config struct {
		Image, User          string
		Labels               map[string]string
		StopSignal           string
		StopTimeout          *int
		Entrypoint, Cmd, Env []string
		Volumes              map[string]any
		WorkingDir           string
	}
	HostConfig struct {
		Privileged, ReadonlyRootfs, AutoRemove bool
		PublishAllPorts                        bool
		UTSMode, CgroupnsMode                  string
		PidsLimit                              *int64
		DeviceCgroupRules                      []string
		Sysctls                                map[string]string
		PortBindings                           map[string]any
		RestartPolicy                          struct {
			Name              string
			MaximumRetryCount int
		}
		NetworkMode, PidMode, IpcMode, UsernsMode                  string
		CapAdd, CapDrop, SecurityOpt, VolumesFrom, Links, GroupAdd []string
		Devices, DeviceRequests                                    []jsonObject
		Tmpfs                                                      map[string]string
		Init                                                       *bool
	}
	Mounts []struct {
		Type, Source, Destination, Propagation string
		RW                                     bool
	}
}
type jsonObject map[string]any

func sorted(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
func capabilities(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.TrimPrefix(v, "CAP_"))
	}
	return sorted(out)
}
func (r *Runtime) inspect(ctx context.Context, d *dockerClient) (containerInfo, error) {
	var c containerInfo
	b := r.Binding
	if err := b.validate(b.DataDir); err != nil {
		return c, err
	}
	current, err := Read(b.DataDir)
	if err != nil {
		return c, err
	}
	if !reflect.DeepEqual(current, b) {
		return c, errors.New("Nginx 容器绑定已被外部修改")
	}
	if err := d.JSON(ctx, "GET", "/containers/"+Name+"/json", nil, &c); err != nil {
		return c, err
	}
	if err := checkConfiguration(c, b); err != nil {
		return c, err
	}
	if !c.State.Running || c.State.Paused || c.State.Restarting || c.State.Dead || c.State.OOMKilled || c.State.Pid <= 1 {
		return c, errors.New("Nginx 容器未稳定运行")
	}
	if err := r.process(c.State.Pid, c.State.Pid, true); err != nil {
		return c, err
	}
	return c, nil
}
func readProc(pid int, part string, limit int64) ([]byte, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/%s", pid, part))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("容器进程信息超过预算")
	}
	return raw, nil
}
func (r *Runtime) process(pid, master int, init bool) error {
	return r.processIdentity(pid, master, init, !init)
}
func (r *Runtime) processIdentity(pid, master int, init, directChild bool) error {
	return r.processProgram(pid, master, init, directChild, false)
}

func (r *Runtime) processProgram(pid, master int, init, directChild, bootstrap bool) error {
	if pid <= 1 || master <= 1 {
		return errors.New("容器宿主机 PID 无效")
	}
	b := r.Binding
	uidWant, gidWant, binaryWant := b.UID, b.GID, b.BinarySHA256
	if bootstrap {
		uidWant, gidWant, binaryWant = 0, 0, b.BootstrapSHA256
	}
	raw, err := readProc(pid, "status", 32<<10)
	if err != nil {
		return err
	}
	uid, gid, nspid, parent, nnp := false, false, false, false, false
	capCount := 0
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "Uid:":
			uid = len(f) == 5
			for _, v := range f[1:] {
				uid = uid && v == strconv.Itoa(uidWant)
			}
		case "Gid:":
			gid = len(f) == 5
			for _, v := range f[1:] {
				gid = gid && v == strconv.Itoa(gidWant)
			}
		case "NSpid:":
			nspid = len(f) == 3 && f[1] == strconv.Itoa(pid) && (!init || f[2] == "1")
		case "PPid:":
			parent = f[1] == strconv.Itoa(master)
		case "NoNewPrivs:":
			nnp = f[1] == "1"
		case "Groups:":
			for _, value := range f[1:] {
				if value != strconv.Itoa(gidWant) {
					return errors.New("Nginx 进程持有额外的宿主机组")
				}
			}
		case "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:":
			allowed := uint64(1 << 10)
			// Docker exec keeps the original OCI bounding set. Only the verified
			// bootstrap may hold transition capabilities in other sets; Nginx
			// itself must have discarded them before executing diagnostics.
			if bootstrap || !init && !directChild && f[0] == "CapBnd:" {
				allowed |= 1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID | 1<<unix.CAP_SETPCAP
			}
			value, parse := strconv.ParseUint(f[1], 16, 64)
			if parse != nil || value & ^allowed != 0 {
				return errors.New("Nginx 进程持有超出允许范围的权限")
			}
			capCount++
		}
	}
	if !uid || !gid || !nspid || !nnp || capCount != 5 || directChild && !parent {
		return errors.New("Nginx 容器进程的身份、父进程或权限无法确认")
	}
	for _, part := range []string{"uid_map", "gid_map"} {
		raw, err := readProc(pid, part, 4096)
		if err != nil {
			return err
		}
		fields := strings.Fields(string(raw))
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "0" || fields[2] != "4294967295" {
			return errors.New("Nginx 容器不支持 rootless 或 UID/GID 重映射")
		}
	}
	for _, ns := range []string{"pid", "mnt"} {
		own, err := os.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, ns))
		if err != nil {
			return err
		}
		original, err := os.Stat(fmt.Sprintf("/proc/%d/ns/%s", master, ns))
		if err != nil {
			return err
		}
		if !os.SameFile(own, original) {
			return errors.New("Nginx 子进程不属于固定容器命名空间")
		}
	}
	hostNet, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	containerNet, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil || !os.SameFile(hostNet, containerNet) {
		return errors.New("Nginx 容器未使用当前宿主机网络")
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > binaryLimit {
		return errors.New("Nginx 进程程序身份无效")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, binaryLimit+1))
	if err != nil {
		return err
	}
	if n != info.Size() || !secure.RootFileUnchanged(f, info) || hex.EncodeToString(hash.Sum(nil)) != binaryWant {
		return errors.New("Nginx 容器实际程序散列不匹配")
	}
	if init {
		raw, err := readProc(pid, "cmdline", 16<<10)
		if err != nil {
			return err
		}
		command := strings.TrimRight(string(raw), "\x00")
		fields := strings.Fields(command)
		prefix, config := "", ""
		for i, word := range fields {
			if i+1 < len(fields) {
				if word == "-p" {
					prefix = fields[i+1]
				}
				if word == "-c" {
					config = fields[i+1]
				}
			}
		}
		if !strings.HasPrefix(command, "nginx: master process ") || filepath.Clean(prefix) != b.DataDir || config != filepath.Join(b.DataDir, "nginx", "active", "nginx.conf") {
			return errors.New("容器 PID 1 未运行固定受管 Nginx 主配置")
		}
	}
	return nil
}
func (r *Runtime) Master(ctx context.Context) (int, error) {
	if err := r.lock(ctx); err != nil {
		return 0, err
	}
	defer r.unlock()
	d, err := newDocker()
	if err != nil {
		return 0, err
	}
	defer d.Close()
	if err = r.reconcileDiagnostic(ctx, d); err != nil {
		return 0, err
	}
	c, err := r.inspect(ctx, d)
	if err != nil {
		return 0, err
	}
	return c.State.Pid, nil
}

// ObserveMaster performs no diagnostic reconciliation. A reader cannot finish
// an old exec or remove its recovery evidence merely to obtain a live PID.
func (r *Runtime) ObserveMaster(ctx context.Context) (int, error) {
	if err := r.lock(ctx); err != nil {
		return 0, err
	}
	defer r.unlock()
	if _, err := r.readDiagnostic(); !errors.Is(err, os.ErrNotExist) {
		return 0, errors.Join(errors.New("Nginx 容器仍有诊断恢复材料，仅读取不得清理或续办"), err)
	}
	d, err := newDocker()
	if err != nil {
		return 0, err
	}
	defer d.Close()
	c, err := r.inspect(ctx, d)
	if err != nil {
		return 0, err
	}
	if _, err = r.readDiagnostic(); !errors.Is(err, os.ErrNotExist) {
		return 0, errors.Join(errors.New("Nginx 容器观测期间出现诊断恢复材料"), err)
	}
	return c.State.Pid, ctx.Err()
}

// CheckProcess extends the verified master's identity to its direct workers.
func (r *Runtime) CheckProcess(ctx context.Context, pid, master int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.process(pid, master, pid == master)
}

func checkConfiguration(c containerInfo, b Binding) error { return checkPolicy(c, b, Name, nil) }

func checkPolicy(c containerInfo, b Binding, name string, revision *string) error {
	user := "0:0"
	entry := []string{Bootstrap, "nginx-container-launch"}
	args := []string{"--data-dir", b.DataDir}
	signal, timeout, pids, restart := "SIGQUIT", 65, int64(2048), "unless-stopped"
	caps := []string{"NET_BIND_SERVICE", "SETGID", "SETPCAP", "SETUID"}
	if revision != nil {
		launch := testLaunchArgs(b.DataDir, *revision)
		entry, args = launch[:2], launch[2:]
		signal, timeout, pids, restart = "SIGTERM", 5, 128, "no"
	}
	h := c.HostConfig
	if !hashValue.MatchString(c.ID) || c.Name != "/"+name || c.Image != b.ImageID || c.Config.Image != b.Image || c.Config.User != user || c.Config.WorkingDir != b.DataDir || !reflect.DeepEqual(c.Config.Entrypoint, entry) || !reflect.DeepEqual(c.Config.Cmd, args) || !reflect.DeepEqual(c.Config.Env, b.Environment) || len(c.Config.Volumes) != 0 || c.Config.StopSignal != signal || c.Config.StopTimeout == nil || *c.Config.StopTimeout != timeout {
		return errors.New("固定 Nginx 容器、镜像或启动定义不匹配")
	}
	if h.PidsLimit == nil || *h.PidsLimit != pids || h.RestartPolicy.Name != restart || h.RestartPolicy.MaximumRetryCount != 0 || h.PublishAllPorts || h.UTSMode != "" || (h.CgroupnsMode != "" && h.CgroupnsMode != "private") || len(h.DeviceCgroupRules) != 0 || len(h.Sysctls) != 0 || len(h.PortBindings) != 0 || h.Privileged || !h.ReadonlyRootfs || h.AutoRemove || h.NetworkMode != "host" || h.PidMode != "" || (h.IpcMode != "private" && h.IpcMode != "") || h.UsernsMode != "" || h.Init != nil && *h.Init || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.VolumesFrom) != 0 || len(h.Links) != 0 || len(h.GroupAdd) != 0 || !reflect.DeepEqual(capabilities(h.CapDrop), []string{"ALL"}) || !reflect.DeepEqual(capabilities(h.CapAdd), caps) || !reflect.DeepEqual(sorted(h.SecurityOpt), []string{"no-new-privileges:true"}) || len(h.Tmpfs) != 1 || h.Tmpfs["/tmp"] != "rw,noexec,nosuid,nodev,size=64m,mode=1777" {
		return errors.New("Nginx 容器的权限或命名空间不符合固定策略")
	}
	expected := b.Mounts()
	if len(c.Mounts) != len(expected) {
		return errors.New("Nginx 容器挂载数量不匹配")
	}
	seen := map[string]bool{}
	for _, m := range c.Mounts {
		match := false
		for _, want := range expected {
			if m.Type == "bind" && m.Source == want.Source && m.Destination == want.Target && m.RW != want.ReadOnly && m.Propagation == "rprivate" && !seen[m.Destination] {
				match = true
				seen[m.Destination] = true
				break
			}
		}
		if !match {
			return errors.New("Nginx 容器存在非预期或可写配置挂载")
		}
	}
	return nil
}
