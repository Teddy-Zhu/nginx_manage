package nginxcontainer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"nginxpanel/internal/dockerapi"
)

type CandidateCheck struct {
	Container  Container `json:"container"`
	ExitCode   int       `json:"exit_code"`
	FinishedAt string    `json:"finished_at"`
}

func checkName(operation string) (string, error) {
	if !revisionValue.MatchString(operation) || operation == "bootstrap" {
		return "", errors.New("Nginx 候选校验必须关联独立操作 UUID")
	}
	return Name + "-check-" + operation, nil
}
func checkRevision(revision string) error {
	if !revisionValue.MatchString(revision) {
		return errors.New("候选校验须使用固定发布目录")
	}
	return nil
}

// Candidate checks use the signed bootstrap to give the dedicated Nginx user
// only NET_BIND_SERVICE, as in production. The fixed test command has the same
// data mounts, temporary storage and host DNS/network as the serving instance.
func ReadCandidateCheck(ctx context.Context, b Binding, revision, operation string) (CandidateCheck, error) {
	var zero CandidateCheck
	if os.Geteuid() != 0 {
		return zero, errors.New("候选配置校验仅允许宿主机 root")
	}
	if err := b.Validate(); err != nil {
		return zero, err
	}
	if err := checkRevision(revision); err != nil {
		return zero, err
	}
	name, err := checkName(operation)
	if err != nil {
		return zero, err
	}
	d, err := newDocker()
	if err != nil {
		return zero, err
	}
	defer d.Close()
	var c containerInfo
	if err = d.JSON(ctx, "GET", "/containers/"+name+"/json", nil, &c); err != nil {
		var status *dockerapi.StatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
			return zero, os.ErrNotExist
		}
		return zero, err
	}
	if err = checkPolicy(c, b, name, &revision); err != nil {
		return zero, err
	}
	mount, err := candidateBindingMount(b, operation)
	if err != nil {
		return zero, err
	}
	if err = verifyCandidateBinding(b, mount); err != nil {
		// ENOENT is reserved for Docker-confirmed container absence. A missing
		// approval must retain the existing container for explicit recovery.
		return zero, fmt.Errorf("候选校验绑定无法核对：%v", err)
	}
	if err = dockerapi.ValidateLabels(c.Config.Labels); err != nil {
		return zero, err
	}
	if c.RestartCount != 0 {
		return zero, errors.New("候选校验进程不能重启")
	}
	s := c.State
	switch {
	case s.Status == "running" && s.Running && !s.Paused && !s.Restarting && !s.Dead && !s.OOMKilled && s.Pid > 1:
	case (s.Status == "created" || s.Status == "exited") && !s.Running && !s.Paused && !s.Restarting && !s.Dead && !s.OOMKilled && s.Pid == 0:
	default:
		return zero, errors.New("候选校验容器状态未知")
	}
	if s.Status == "exited" {
		finished, e := time.Parse(time.RFC3339Nano, s.FinishedAt)
		if e != nil || finished.IsZero() {
			return zero, errors.New("候选校验结束时间未确认")
		}
	}
	return CandidateCheck{Container: Container{Instance: Instance{ID: c.ID, ImageID: c.Image, PID: s.Pid, StartedAt: s.StartedAt, RestartCount: c.RestartCount}, State: s.Status, Labels: c.Config.Labels}, ExitCode: s.ExitCode, FinishedAt: s.FinishedAt}, nil
}
func CreateCandidateCheck(ctx context.Context, b Binding, revision, operation string, labels map[string]string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("候选配置校验仅允许宿主机 root")
	}
	if err := b.Validate(); err != nil {
		return "", err
	}
	if err := checkRevision(revision); err != nil {
		return "", err
	}
	if err := dockerapi.ValidateLabels(labels); err != nil {
		return "", err
	}
	name, err := checkName(operation)
	if err != nil {
		return "", err
	}
	mount, err := publishCandidateBinding(ctx, b, operation)
	if err != nil {
		return "", err
	}
	input := runtimeInput(b, labels)
	launch := testLaunchArgs(b.DataDir, revision)
	input["Entrypoint"], input["Cmd"] = launch[:2], launch[2:]
	input["StopSignal"], input["StopTimeout"] = "SIGTERM", 5
	h := input["HostConfig"].(map[string]any)
	h["Mounts"] = append(h["Mounts"].([]map[string]any), map[string]any{"Type": "bind", "Source": mount.Source, "Target": mount.Target, "ReadOnly": true, "BindOptions": map[string]any{"Propagation": "rprivate", "CreateMountpoint": false}})
	h["PidsLimit"] = 128
	h["RestartPolicy"] = map[string]any{"Name": "no", "MaximumRetryCount": 0}
	d, err := newDocker()
	if err != nil {
		return "", err
	}
	defer d.Close()
	var out struct {
		ID       string `json:"Id"`
		Warnings []string
	}
	if err = d.JSON(ctx, "POST", "/containers/create?name="+name, input, &out); err != nil {
		return "", err
	}
	if !hashValue.MatchString(out.ID) {
		return "", errors.New("Docker 未返回有效候选校验标识")
	}
	if len(out.Warnings) != 0 {
		return out.ID, errors.New("Docker 创建候选校验时返回警告，须核对原操作")
	}
	return out.ID, nil
}
func CandidateCheckAction(ctx context.Context, b Binding, revision, operation, id, action string) error {
	if !hashValue.MatchString(id) {
		return errors.New("候选校验实例标识无效")
	}
	c, err := ReadCandidateCheck(ctx, b, revision, operation)
	if err != nil {
		return err
	}
	if c.Container.Instance.ID != id {
		return errors.New("候选校验容器已被替换")
	}
	method, path := "POST", "/containers/"+id
	switch action {
	case "start":
		if c.Container.State != "created" {
			return errors.New("候选配置校验只能首次启动")
		}
		path += "/start"
	case "stop":
		if c.Container.State != "running" {
			return nil
		}
		path += "/stop?t=5"
	case "remove":
		if c.Container.State == "running" {
			return errors.New("不能移除运行中的候选校验")
		}
		method = "DELETE"
	default:
		return errors.New("不允许的候选校验动作")
	}
	d, err := newDocker()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.JSON(ctx, method, path, nil, nil)
}
