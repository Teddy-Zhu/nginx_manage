package containers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/dockerapi"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/frps"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelruntime"
)

const logLimit = 256 << 10

func dockerError(err error) error {
	var status *dockerapi.StatusError
	if errors.As(err, &status) {
		if status.StatusCode == 404 {
			return fault.NotFound("容器不存在或已被移除")
		}
		if status.StatusCode == 409 || status.StatusCode == 304 {
			return fault.Conflict("容器状态已变化，请刷新后重试")
		}
		if status.StatusCode == 400 {
			return fault.Invalid("Docker 无法执行此请求，请检查容器状态")
		}
		if status.StatusCode == 501 {
			return fault.Unavailable("当前 Docker 服务不支持此操作")
		}
	}
	return fault.Unavailable("Docker 请求未完成，请检查服务状态并刷新容器列表确认结果")
}
func protected(name string) bool {
	// Reserve the managed panel container name even if deployment metadata is unavailable.
	return strings.TrimPrefix(name, "/") == panelruntime.DockerName
}
func component(name string) string {
	name = strings.TrimPrefix(name, "/")
	switch name {
	case panelruntime.DockerName:
		return "panel"
	case nginxcontainer.Name:
		return "nginx"
	case fail2ban.ContainerName:
		return "fail2ban"
	case frps.ContainerName:
		return "frps"
	}
	if strings.HasPrefix(name, nginxcontainer.Name+"-check-") {
		return "nginx"
	}
	return ""
}
func List(ctx context.Context) (Overview, error) {
	out := Overview{Containers: []Container{}}
	d, err := dockerapi.New()
	if err != nil {
		out.Reason = "Docker 尚未安装或服务未运行"
		return out, nil
	}
	defer d.Close()
	resp, err := d.Request(ctx, http.MethodGet, "/containers/json?all=true&size=false", nil)
	if err != nil {
		return out, dockerError(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil {
		return out, dockerError(err)
	}
	if len(raw) > 2<<20 {
		return out, fault.Unavailable("容器列表过大，暂时无法读取")
	}
	var rows []struct {
		ID           string
		Names        []string
		Image, State string
		Created      int64
		Labels       map[string]string
		Ports        []struct {
			IP                      string
			PrivatePort, PublicPort int
			Type                    string
		}
	}
	if json.Unmarshal(raw, &rows) != nil {
		return out, fault.Unavailable("无法解析 Docker 容器信息")
	}
	for _, r := range rows {
		if !ValidID(r.ID) || len(r.Names) == 0 {
			return out, fault.Unavailable("Docker 返回了无效的容器信息")
		}
		c := Container{ID: r.ID, Name: strings.TrimPrefix(r.Names[0], "/"), Image: r.Image, State: r.State, Created: r.Created, Ports: []Port{}, Project: r.Labels["com.docker.compose.project"], Service: r.Labels["com.docker.compose.service"], Protected: protected(r.Names[0])}
		c.Component = component(c.Name)
		for _, p := range r.Ports {
			c.Ports = append(c.Ports, Port{Address: p.IP, Public: p.PublicPort, Private: p.PrivatePort, Protocol: p.Type})
		}
		sort.Slice(c.Ports, func(i, j int) bool {
			a, b := c.Ports[i], c.Ports[j]
			if a.Private != b.Private {
				return a.Private < b.Private
			}
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
			if a.Public != b.Public {
				return a.Public < b.Public
			}
			return a.Address < b.Address
		})
		out.Containers = append(out.Containers, c)
	}
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Name < out.Containers[j].Name })
	out.Available = true
	return out, nil
}

type inspection struct {
	ID, Name, Image, Created string
	RestartCount             int
	Config                   struct {
		Image  string
		Tty    bool
		Labels map[string]string
	}
	State struct {
		Status, StartedAt, FinishedAt string
		ExitCode                      int
		Health                        *struct{ Status string }
	}
	HostConfig struct {
		NetworkMode   string
		RestartPolicy struct{ Name string }
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress, GlobalIPv6Address, Gateway string }
		Ports    map[string][]struct{ HostIP, HostPort string }
	}
	Mounts []struct {
		Source, Destination string
		RW                  bool
	}
}

func inspect(ctx context.Context, d *dockerapi.Client, id string) (inspection, error) {
	var out inspection
	if !ValidID(id) {
		return out, fault.Invalid("容器标识无效")
	}
	if err := d.JSON(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &out); err != nil {
		return out, dockerError(err)
	}
	if out.ID != id {
		return out, fault.Conflict("容器已变化，请刷新后重试")
	}
	return out, nil
}
func Inspect(ctx context.Context, id string) (Detail, error) {
	var out Detail
	d, err := dockerapi.New()
	if err != nil {
		return out, dockerError(err)
	}
	defer d.Close()
	r, err := inspect(ctx, d, id)
	if err != nil {
		return out, err
	}
	created, err := time.Parse(time.RFC3339Nano, r.Created)
	if err != nil {
		return out, fault.Unavailable("容器创建时间无效")
	}
	out = Detail{Container: Container{ID: r.ID, Name: strings.TrimPrefix(r.Name, "/"), Image: r.Config.Image, State: r.State.Status, Created: created.Unix(), Ports: []Port{}, Project: r.Config.Labels["com.docker.compose.project"], Service: r.Config.Labels["com.docker.compose.service"], Protected: protected(r.Name)}, ImageID: r.Image, Started: r.State.StartedAt, Finished: r.State.FinishedAt, Restarts: r.RestartCount, RestartPolicy: r.HostConfig.RestartPolicy.Name, ExitCode: r.State.ExitCode, NetworkMode: r.HostConfig.NetworkMode, Networks: []Network{}, Mounts: []Mount{}}
	out.Component = component(out.Name)
	if r.State.Health != nil {
		out.Health = r.State.Health.Status
	}
	for key, bindings := range r.NetworkSettings.Ports {
		parts := strings.Split(key, "/")
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		if len(bindings) == 0 {
			out.Ports = append(out.Ports, Port{Private: port, Protocol: parts[1]})
		}
		for _, b := range bindings {
			public, err := strconv.Atoi(b.HostPort)
			if err != nil {
				return out, fault.Unavailable("容器端口信息无效")
			}
			out.Ports = append(out.Ports, Port{Address: b.HostIP, Public: public, Private: port, Protocol: parts[1]})
		}
	}
	for name, n := range r.NetworkSettings.Networks {
		address := n.IPAddress
		if n.GlobalIPv6Address != "" {
			if address != "" {
				address += "、"
			}
			address += n.GlobalIPv6Address
		}
		out.Networks = append(out.Networks, Network{Name: name, Address: address, Gateway: n.Gateway})
	}
	sort.Slice(out.Networks, func(i, j int) bool { return out.Networks[i].Name < out.Networks[j].Name })
	sort.Slice(out.Ports, func(i, j int) bool {
		a, b := out.Ports[i], out.Ports[j]
		if a.Private != b.Private {
			return a.Private < b.Private
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Public != b.Public {
			return a.Public < b.Public
		}
		return a.Address < b.Address
	})
	for _, m := range r.Mounts {
		out.Mounts = append(out.Mounts, Mount{Source: m.Source, Target: m.Destination, ReadOnly: !m.RW})
	}
	return out, nil
}
func ReadLogs(ctx context.Context, id string, tail int) (Logs, error) {
	var out Logs
	if tail < 1 || tail > 500 {
		return out, fault.Invalid("日志行数须为 1–500")
	}
	d, err := dockerapi.New()
	if err != nil {
		return out, dockerError(err)
	}
	defer d.Close()
	r, err := inspect(ctx, d, id)
	if err != nil {
		return out, err
	}
	query := url.Values{"stdout": {"true"}, "stderr": {"true"}, "timestamps": {"true"}, "tail": {strconv.Itoa(tail)}, "follow": {"false"}}
	resp, err := d.Request(ctx, http.MethodGet, "/containers/"+id+"/logs?"+query.Encode(), nil)
	if err != nil {
		var status *dockerapi.StatusError
		if errors.As(err, &status) && (status.StatusCode == 400 || status.StatusCode == 501) {
			return out, fault.Unavailable("此容器的日志驱动不支持读取日志")
		}
		return out, dockerError(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, logLimit+1))
	if err != nil {
		return out, dockerError(err)
	}
	if len(raw) > logLimit {
		out.Truncated = true
		raw = raw[:logLimit]
	}
	if r.Config.Tty {
		out.Text = string(raw)
		return out, nil
	}
	var text strings.Builder
	for len(raw) > 0 {
		if len(raw) < 8 {
			if out.Truncated {
				break
			}
			return out, fault.Unavailable("容器日志数据不完整")
		}
		if raw[0] > 2 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
			return out, fault.Unavailable("容器日志格式不受支持")
		}
		size := int64(binary.BigEndian.Uint32(raw[4:8]))
		raw = raw[8:]
		if size > int64(len(raw)) {
			if !out.Truncated {
				return out, fault.Unavailable("容器日志数据不完整")
			}
			size = int64(len(raw))
		}
		text.Write(raw[:size])
		raw = raw[size:]
	}
	out.Text = text.String()
	return out, nil
}
func Run(ctx context.Context, in Control, progress func(string)) (string, error) {
	if err := in.Validate(); err != nil {
		return "", err
	}
	d, err := dockerapi.New()
	if err != nil {
		return "", dockerError(err)
	}
	defer d.Close()
	r, err := inspect(ctx, d, in.ID)
	if err != nil {
		return "", err
	}
	if protected(r.Name) {
		return "", fault.Conflict("这是当前面板使用的系统容器，无法在容器管理中启停")
	}
	if r.State.Status == "paused" {
		return "", fault.Conflict("容器已暂停，请先通过 Docker 解除暂停")
	}
	labels := map[string]string{"start": "启动", "stop": "停止", "restart": "重启"}
	label := labels[in.Action]
	name := strings.TrimPrefix(r.Name, "/")
	progress("正在" + label + "容器 " + name)
	if in.Action == "start" && r.State.Status == "running" || in.Action == "stop" && (r.State.Status == "exited" || r.State.Status == "created") {
		return "容器已处于目标状态", nil
	}
	path := "/containers/" + in.ID + "/" + in.Action
	if in.Action != "start" {
		path += "?t=10"
	}
	if err = d.JSON(ctx, http.MethodPost, path, nil, nil); err != nil {
		return "", dockerError(err)
	}
	after, err := inspect(ctx, d, in.ID)
	if err != nil {
		return "", err
	}
	if in.Action == "stop" && after.State.Status != "exited" && after.State.Status != "created" {
		return "", fault.Conflict("停止请求已发送，但容器仍未停止，请查看日志确认")
	}
	if in.Action != "stop" && after.State.Status != "running" {
		return "", fault.Conflict("容器未持续运行，请查看容器日志")
	}
	return "容器 " + name + " 已" + label, nil
}
