package frpscontainer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"nginxpanel/internal/frps"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
	"strconv"
	"strings"
	"time"
)

type instance struct {
	ID     string            `json:"id"`
	State  string            `json:"state"`
	Labels map[string]string `json:"labels"`
}

func inspect(ctx context.Context, data, name string) (*instance, error) {
	raw, err := software.Docker(ctx, nil, "container", "ls", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	raw, err = software.Docker(ctx, nil, "inspect", "--format", `{"id":{{json .Id}},"state":{{json .State.Status}},"labels":{{json .Config.Labels}}}`, name)
	if err != nil {
		return nil, err
	}
	var out instance
	if err = json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	if out.ID == "" || out.Labels[ownerLabel] != "frps" || out.Labels[dataLabel] != secure.Hash([]byte(data)) {
		return nil, errors.New("同名 FRP 服务不属于当前面板，已停止操作")
	}
	return &out, nil
}
func statistics(ctx context.Context, r record) (*frps.Stats, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.DashboardPort))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/serverinfo", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("nginxpanel", r.DashboardPassword)
	transport := &http.Transport{DisableKeepAlives: true, Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("FRP 状态服务返回 %d", response.StatusCode)
	}
	var body struct {
		Version     string           `json:"version"`
		Clients     int64            `json:"clientCounts"`
		Connections int64            `json:"curConns"`
		TrafficIn   int64            `json:"totalTrafficIn"`
		TrafficOut  int64            `json:"totalTrafficOut"`
		Proxies     map[string]int64 `json:"proxyTypeCount"`
	}
	if err = decodeJSON(response.Body, &body); err != nil {
		return nil, err
	}
	if body.Version == "" || body.Clients < 0 || body.Connections < 0 || body.TrafficIn < 0 || body.TrafficOut < 0 {
		return nil, errors.New("FRP 状态信息不完整")
	}
	total := int64(0)
	for _, count := range body.Proxies {
		if count < 0 {
			return nil, errors.New("FRP 映射数量无效")
		}
		total += count
	}
	return &frps.Stats{Version: body.Version, Clients: body.Clients, Connections: body.Connections, TrafficIn: body.TrafficIn, TrafficOut: body.TrafficOut, Proxies: total}, nil
}
func Status(ctx context.Context, data string) frps.Status {
	r, err := read(data)
	out := frps.Status{Installed: r.Installed, State: "unknown", Config: r.Config, TokenSet: r.Config.Token != ""}
	out.Config.Token = ""
	if err != nil {
		out.Error = "无法读取 FRP 配置，请检查服务日志"
		return out
	}
	current, err := inspect(ctx, data, Name)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if current == nil {
		out.State = "missing"
		if out.Installed {
			out.Error = "FRP 服务不存在，请更新或重新安装"
		}
		return out
	}
	out.Installed = true
	switch current.State {
	case "created", "exited":
		out.State = "stopped"
	case "restarting", "dead":
		out.State = "unhealthy"
		out.Error = "FRP 服务启动异常，请查看服务日志"
	case "running":
		out.Stats, err = statistics(ctx, r)
		if err != nil {
			out.State = "starting"
			out.Error = "FRP 服务尚未就绪，请查看服务日志"
		} else {
			out.State = "running"
		}
	default:
		out.State = "unknown"
		out.Error = "FRP 服务状态暂时不可用"
	}
	return out
}
func waitReady(ctx context.Context, data string, r record) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, err := inspect(ctx, data, Name)
		if err != nil {
			return err
		}
		if current == nil || current.State == "exited" || current.State == "dead" || current.State == "restarting" {
			return errors.New("FRP 服务启动失败，请查看操作日志")
		}
		if _, err = statistics(ctx, r); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("FRP 服务未能按时启动，请查看操作日志")
		case <-ticker.C:
		}
	}
}
func availablePorts(c frps.Config, dashboard int) error {
	listeners := []net.Listener{}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, item := range []struct {
		address string
		port    int
	}{{c.BindAddress, c.BindPort}, {c.BindAddress, c.HTTPPort}, {c.BindAddress, c.HTTPSPort}, {"127.0.0.1", dashboard}} {
		if item.port == 0 {
			continue
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(item.address, strconv.Itoa(item.port)))
		if err != nil {
			return fmt.Errorf("端口 %d 无法使用，请检查端口占用或监听地址", item.port)
		}
		listeners = append(listeners, listener)
	}
	return nil
}
func addLog(previous, text string) string {
	out := strings.TrimSpace(previous + "\n" + text)
	if len(out) > 16000 {
		out = out[len(out)-16000:]
	}
	return out
}
