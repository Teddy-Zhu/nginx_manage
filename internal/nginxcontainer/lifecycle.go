package nginxcontainer

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"nginxpanel/internal/dockerapi"
)

type Instance struct {
	ID           string `json:"id"`
	ImageID      string `json:"image_id"`
	PID          int    `json:"pid"`
	StartedAt    string `json:"started_at"`
	RestartCount int    `json:"restart_count"`
}
type Container struct {
	Instance Instance          `json:"instance"`
	State    string            `json:"state"`
	Labels   map[string]string `json:"labels"`
}

func ImageLabels(ctx context.Context, b Binding) (map[string]string, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("Nginx 镜像读取需要宿主机 root")
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	d, err := newDocker()
	if err != nil {
		return nil, err
	}
	defer d.Close()
	image, err := localImage(ctx, d, b.Image, b.ImageID)
	if err != nil {
		return nil, err
	}
	if err = dockerapi.ValidateLabels(image.Config.Labels); err != nil {
		return nil, err
	}
	return image.Config.Labels, nil
}

// ReadContainer observes only the fixed Nginx name and frozen configuration.
// It also accepts stopped instances, without weakening running process checks.
func ReadContainer(ctx context.Context, b Binding) (Container, error) {
	var zero Container
	if os.Geteuid() != 0 {
		return zero, errors.New("Nginx 生命周期操作需要宿主机 root")
	}
	if err := b.Validate(); err != nil {
		return zero, err
	}
	d, err := newDocker()
	if err != nil {
		return zero, err
	}
	defer d.Close()
	var c containerInfo
	if err = d.JSON(ctx, "GET", "/containers/"+Name+"/json", nil, &c); err != nil {
		var status *dockerapi.StatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
			return zero, os.ErrNotExist
		}
		return zero, err
	}
	if err = checkConfiguration(c, b); err != nil {
		return zero, err
	}
	if err = dockerapi.ValidateLabels(c.Config.Labels); err != nil {
		return zero, err
	}
	state := c.State
	switch {
	case state.Status == "running" && state.Running && !state.Paused && !state.Restarting && !state.Dead && !state.OOMKilled && state.Pid > 1:
	case (state.Status == "created" || state.Status == "exited") && !state.Running && !state.Paused && !state.Restarting && !state.Dead && state.Pid == 0:
	default:
		return zero, errors.New("Nginx 容器状态正在转换或未知")
	}
	if c.RestartCount < 0 {
		return zero, errors.New("Nginx 容器重启计数无效")
	}
	if c.State.Status == "running" {
		started, e := time.Parse(time.RFC3339Nano, c.State.StartedAt)
		if e != nil || started.IsZero() {
			return zero, errors.New("Nginx 容器启动代次无效")
		}
	}
	return Container{Instance: Instance{ID: c.ID, ImageID: c.Image, PID: c.State.Pid, StartedAt: c.State.StartedAt, RestartCount: c.RestartCount}, State: c.State.Status, Labels: c.Config.Labels}, nil
}

func ContainerAction(ctx context.Context, b Binding, id, action string) error {
	if !hashValue.MatchString(id) {
		return errors.New("Nginx 容器实例标识无效")
	}
	c, err := ReadContainer(ctx, b)
	if err != nil {
		return err
	}
	if c.Instance.ID != id {
		return errors.New("Nginx 固定容器已被替换")
	}
	method, path := "POST", "/containers/"+id
	switch action {
	case "stop":
		if c.State != "running" {
			return nil
		}
		path += "/stop?t=65"
	case "start":
		if c.State == "running" {
			return nil
		}
		path += "/start"
	case "remove":
		if c.State == "running" {
			return errors.New("禁止删除运行中的 Nginx 容器")
		}
		method = "DELETE"
	default:
		return errors.New("不允许的 Nginx 容器动作")
	}
	d, err := newDocker()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.JSON(ctx, method, path, nil, nil)
}

func runtimeInput(b Binding, labels map[string]string) map[string]any {
	var mounts []map[string]any
	for _, m := range b.Mounts() {
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": m.Source, "Target": m.Target, "ReadOnly": m.ReadOnly, "BindOptions": map[string]any{"Propagation": "rprivate", "CreateMountpoint": false}})
	}
	return map[string]any{"Image": b.Image, "User": "0:0", "WorkingDir": b.DataDir, "Entrypoint": []string{Bootstrap, "nginx-container-launch"}, "Cmd": []string{"--data-dir", b.DataDir}, "Env": b.Environment, "Labels": labels, "StopSignal": "SIGQUIT", "StopTimeout": 65,
		"HostConfig": map[string]any{"NetworkMode": "host", "IpcMode": "private", "CgroupnsMode": "private", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "CapAdd": []string{"SETUID", "SETGID", "SETPCAP", "NET_BIND_SERVICE"}, "SecurityOpt": []string{"no-new-privileges:true"}, "PidsLimit": 2048, "RestartPolicy": map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0}, "Tmpfs": map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777"}, "Mounts": mounts}}
}

// A lost create response must be reconciled by name, full fixed configuration
// and the transaction's labels. It is never permission to create another name.
func CreateContainer(ctx context.Context, b Binding, labels map[string]string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("Nginx 容器创建需要宿主机 root")
	}
	if err := b.Validate(); err != nil {
		return "", err
	}
	if err := dockerapi.ValidateLabels(labels); err != nil {
		return "", err
	}
	d, err := newDocker()
	if err != nil {
		return "", err
	}
	defer d.Close()
	var out struct {
		ID       string `json:"Id"`
		Warnings []string
	}
	if err = d.JSON(ctx, "POST", "/containers/create?name="+Name, runtimeInput(b, labels), &out); err != nil {
		return "", err
	}
	if !hashValue.MatchString(out.ID) {
		return "", errors.New("Docker 未返回有效 Nginx 容器标识")
	}
	if len(out.Warnings) != 0 {
		return out.ID, errors.New("Docker 创建 Nginx 容器时返回警告，须核对原操作")
	}
	return out.ID, nil
}
