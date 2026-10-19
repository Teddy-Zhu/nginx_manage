package panelruntime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"nginxpanel/internal/dockerapi"
)

const DockerOperationLabel = "io.nginxpanel.image-operation"
const DockerDirectionLabel = "io.nginxpanel.image-direction"
const DockerBindingLabel = "io.nginxpanel.image-binding"

type DockerContainer struct {
	Instance DockerInstance    `json:"instance"`
	State    string            `json:"state"`
	Labels   map[string]string `json:"labels"`
}

// ValidateDockerLabels bounds the metadata retained across replacement.
func ValidateDockerLabels(labels map[string]string) error {
	return dockerapi.ValidateLabels(labels)
}

// DockerImageLabels freezes inherited metadata before any running container is
// removed. Docker merges image defaults into Labels at creation time.
func DockerImageLabels(ctx context.Context, d Deployment) (map[string]string, error) {
	if os.Geteuid() != 0 || d.Mode != "docker" {
		return nil, errors.New("镜像元数据读取需要宿主机 root")
	}
	if err := d.validate(d.DataDir); err != nil {
		return nil, err
	}
	client, err := dockerapi.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	var image struct {
		ID     string `json:"Id"`
		Config struct{ Labels map[string]string }
	}
	if err = client.JSON(ctx, "GET", "/images/"+d.ImageID+"/json", nil, &image); err != nil {
		return nil, err
	}
	if image.ID != d.ImageID {
		return nil, errors.New("实际镜像元数据不属于签名配置摘要")
	}
	if err = ValidateDockerLabels(image.Config.Labels); err != nil {
		return nil, err
	}
	return image.Config.Labels, nil
}

// ReadDockerContainer only accepts the fixed panel name and the supplied frozen
// root binding. Stopped instances are observable for crash recovery, too.
func ReadDockerContainer(ctx context.Context, d Deployment) (DockerContainer, error) {
	var out DockerContainer
	if os.Geteuid() != 0 || d.Mode != "docker" {
		return out, errors.New("容器生命周期操作需要宿主机 root 和容器绑定")
	}
	if err := d.validate(d.DataDir); err != nil {
		return out, err
	}
	client, err := dockerapi.New()
	if err != nil {
		return out, err
	}
	defer client.Close()
	var c dockerContainer
	if err = client.JSON(ctx, "GET", "/containers/"+DockerName+"/json", nil, &c); err != nil {
		var status *dockerapi.StatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
			return out, os.ErrNotExist
		}
		return out, err
	}
	if err = checkDockerConfiguration(c, d); err != nil {
		return out, err
	}
	if err = ValidateDockerLabels(c.Config.Labels); err != nil {
		return out, err
	}
	s := c.State
	switch {
	case s.Status == "running" && s.Running && !s.Paused && !s.Restarting && !s.Dead && !s.OOMKilled && s.Pid > 1:
	case (s.Status == "created" || s.Status == "exited") && !s.Running && !s.Paused && !s.Restarting && !s.Dead && s.Pid == 0:
	default:
		return out, errors.New("面板容器仍在转换或状态不明")
	}
	out = DockerContainer{Instance: DockerInstance{ID: c.ID, ImageID: c.Image, PID: s.Pid, StartedAt: s.StartedAt, RestartCount: c.RestartCount}, State: s.Status, Labels: c.Config.Labels}
	return out, nil
}

// DockerAction rechecks the exact instance immediately before a fixed action.
// No force deletion, image removal, exec or caller-selected Docker path exists.
func DockerAction(ctx context.Context, d Deployment, id, action string) error {
	if !digest.MatchString(id) {
		return errors.New("容器实例标识无效")
	}
	c, err := ReadDockerContainer(ctx, d)
	if err != nil {
		return err
	}
	if c.Instance.ID != id {
		return errors.New("面板容器实例已被替换")
	}
	method, path := "POST", "/containers/"+id
	switch action {
	case "stop":
		if c.State != "running" {
			return nil
		}
		path += "/stop?t=60"
	case "start":
		if c.State == "running" {
			return nil
		}
		path += "/start"
	case "remove":
		if c.State == "running" {
			return errors.New("禁止删除运行中的面板容器")
		}
		method = "DELETE"
	default:
		return errors.New("不允许的面板容器动作")
	}
	client, err := dockerapi.New()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.JSON(ctx, method, path, nil, nil)
}

// CreateDockerContainer submits only the fixed least-privilege deployment. A
// lost create response must be reconciled by name and operation labels, never
// treated as evidence that no container was created.
func CreateDockerContainer(ctx context.Context, d Deployment, labels map[string]string) (string, error) {
	if os.Geteuid() != 0 || d.Mode != "docker" {
		return "", errors.New("创建面板容器需要宿主机 root")
	}
	if err := d.validate(d.DataDir); err != nil {
		return "", err
	}
	if err := ValidateDockerLabels(labels); err != nil {
		return "", err
	}
	input := map[string]any{
		"Image": d.Image, "User": fmt.Sprintf("%d:%d", d.UID, d.GID), "WorkingDir": d.DataDir,
		"Entrypoint": []string{DockerLauncher, "launcher"}, "Cmd": []string{"--data-dir", d.DataDir},
		"Labels": labels, "StopSignal": "SIGTERM", "StopTimeout": 60,
		"HostConfig": map[string]any{
			"NetworkMode": "host", "IpcMode": "private", "CgroupnsMode": "private",
			"ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
			"GroupAdd": []string{strconv.Itoa(d.IPCGID)}, "PidsLimit": 128,
			"RestartPolicy": map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0},
			"Tmpfs":         map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777"},
			"Mounts": []map[string]any{
				{"Type": "bind", "Source": d.DataDir, "Target": d.DataDir, "ReadOnly": false, "BindOptions": map[string]any{"Propagation": "rprivate", "CreateMountpoint": false}},
				{"Type": "bind", "Source": "/etc/nginxpanel", "Target": "/etc/nginxpanel", "ReadOnly": true, "BindOptions": map[string]any{"Propagation": "rprivate", "CreateMountpoint": false}},
			},
		},
	}
	client, err := dockerapi.New()
	if err != nil {
		return "", err
	}
	defer client.Close()
	var result struct {
		ID       string `json:"Id"`
		Warnings []string
	}
	err = client.JSON(ctx, "POST", "/containers/create?name="+DockerName, input, &result)
	if err != nil {
		return "", err
	}
	if !digest.MatchString(result.ID) {
		return "", errors.New("Docker 未返回有效的新容器实例")
	}
	if len(result.Warnings) != 0 {
		return result.ID, errors.New("Docker 创建面板容器时返回警告，须核对原操作")
	}
	return result.ID, nil
}
