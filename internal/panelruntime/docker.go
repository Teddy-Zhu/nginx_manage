package panelruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/dockerapi"
)

const DockerName = "nginxpanel"
const DockerLauncher = "/usr/local/bin/nginxpanel-launcher"

// DockerInstance identifies one live container generation. It is obtained from
// the host daemon, never from the launcher's response or a Web request.
type DockerInstance struct {
	ID           string `json:"id"`
	ImageID      string `json:"image_id"`
	PID          int    `json:"pid"`
	StartedAt    string `json:"started_at"`
	RestartCount int    `json:"restart_count"`
}

type dockerContainer struct {
	ID           string `json:"Id"`
	Name         string
	Image        string
	RestartCount int
	State        struct {
		Status                                       string
		Running, Paused, Restarting, Dead, OOMKilled bool
		Pid                                          int
		StartedAt                                    string
	}
	Config struct {
		Image, User, WorkingDir, StopSignal string
		Entrypoint, Cmd                     []string
		Volumes                             map[string]any
		Healthcheck                         map[string]any
		Tty, OpenStdin, StdinOnce           bool
		StopTimeout                         *int
	}
	HostConfig struct {
		Privileged, ReadonlyRootfs, AutoRemove, PublishAllPorts                       bool
		NetworkMode, PidMode, IpcMode, UTSMode, UsernsMode, CgroupnsMode              string
		CapAdd, CapDrop, SecurityOpt, VolumesFrom, Links, GroupAdd, DeviceCgroupRules []string
		Devices, DeviceRequests                                                       []map[string]any
		Sysctls                                                                       map[string]string
		PortBindings                                                                  map[string]any
		Tmpfs                                                                         map[string]string
		Init                                                                          *bool
		PidsLimit                                                                     *int64
		RestartPolicy                                                                 struct {
			Name              string
			MaximumRetryCount int
		}
	}
	Mounts []struct {
		Type, Source, Destination, Propagation string
		RW                                     bool
	}
}

// InspectDocker checks the actual container against the root deployment and
// the kernel-authenticated Unix peer. It only reads the fixed Docker endpoint;
// no container, exec, image pull or host mutation is issued here.
func InspectDocker(ctx context.Context, d Deployment, peerPID int) (DockerInstance, error) {
	var zero DockerInstance
	if os.Geteuid() != 0 || peerPID <= 1 || d.Mode != "docker" {
		return zero, errors.New("面板容器核对需要宿主机 root 和实际 launcher 对端")
	}
	if err := d.validate(d.DataDir); err != nil {
		return zero, err
	}
	current, err := ReadDeployment(d.DataDir)
	if err != nil {
		return zero, err
	}
	if current != d {
		return zero, errors.New("面板容器绑定在连接期间变化")
	}
	client, err := dockerapi.New()
	if err != nil {
		return zero, err
	}
	defer client.Close()
	var c dockerContainer
	if err = client.JSON(ctx, "GET", "/containers/"+DockerName+"/json", nil, &c); err != nil {
		return zero, err
	}
	if err = checkDockerDefinition(c, d, peerPID); err != nil {
		return zero, err
	}
	after, err := ReadDeployment(d.DataDir)
	if err != nil {
		return zero, err
	}
	if after != d {
		return zero, errors.New("面板容器绑定在运行核对期间变化")
	}
	return DockerInstance{ID: c.ID, ImageID: c.Image, PID: c.State.Pid, StartedAt: c.State.StartedAt, RestartCount: c.RestartCount}, nil
}

func checkDockerDefinition(c dockerContainer, d Deployment, peerPID int) error {
	s, h := c.State, c.HostConfig
	started, err := time.Parse(time.RFC3339Nano, s.StartedAt)
	if !digest.MatchString(c.ID) || c.Name != "/"+DockerName || c.Image != d.ImageID || c.RestartCount < 0 || !s.Running || s.Status != "running" || s.Paused || s.Restarting || s.Dead || s.OOMKilled || s.Pid != peerPID || err != nil || started.IsZero() {
		return errors.New("实际面板容器、镜像或运行代次与 launcher 对端不一致")
	}
	config := c.Config
	if config.Image != d.Image || config.User != fmt.Sprintf("%d:%d", d.UID, d.GID) || config.WorkingDir != d.DataDir || !slices.Equal(config.Entrypoint, []string{DockerLauncher, "launcher"}) || !slices.Equal(config.Cmd, []string{"--data-dir", d.DataDir}) || len(config.Volumes) != 0 || len(config.Healthcheck) != 0 || config.Tty || config.OpenStdin || config.StdinOnce || config.StopSignal != "SIGTERM" || config.StopTimeout == nil || *config.StopTimeout != 60 {
		return errors.New("面板容器启动定义不属于固定部署")
	}
	if h.Privileged || !h.ReadonlyRootfs || h.AutoRemove || h.PublishAllPorts || h.NetworkMode != "host" || h.PidMode != "" || h.UTSMode != "" || h.IpcMode != "" && h.IpcMode != "private" || h.UsernsMode != "" || h.CgroupnsMode != "" && h.CgroupnsMode != "private" || h.Init != nil && *h.Init || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.DeviceCgroupRules) != 0 || len(h.Sysctls) != 0 || len(h.PortBindings) != 0 || len(h.VolumesFrom) != 0 || len(h.Links) != 0 || len(h.CapAdd) != 0 || len(h.CapDrop) != 1 || strings.TrimPrefix(h.CapDrop[0], "CAP_") != "ALL" || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) || !slices.Equal(h.GroupAdd, []string{strconv.Itoa(d.IPCGID)}) || h.PidsLimit == nil || *h.PidsLimit != 128 || h.RestartPolicy.Name != "unless-stopped" || h.RestartPolicy.MaximumRetryCount != 0 || len(h.Tmpfs) != 1 || h.Tmpfs["/tmp"] != "rw,noexec,nosuid,nodev,size=64m,mode=1777" {
		return errors.New("面板容器的权限、命名空间或持久运行配置不符合固定策略")
	}
	if len(c.Mounts) != 2 {
		return errors.New("面板容器挂载数量不匹配")
	}
	seen := map[string]bool{}
	for _, m := range c.Mounts {
		if m.Type != "bind" || m.Propagation != "rprivate" || m.Source != m.Destination || seen[m.Destination] || !(m.Source == d.DataDir && m.RW || m.Source == "/etc/nginxpanel" && !m.RW) {
			return errors.New("面板容器包含非预期的挂载或配置写权限")
		}
		seen[m.Destination] = true
	}
	return nil
}
