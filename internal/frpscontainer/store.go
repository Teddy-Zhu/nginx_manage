// Package frpscontainer manages only the panel-owned FRP server container.
package frpscontainer

import (
	"encoding/json"
	"errors"
	"io"
	"nginxpanel/internal/frps"
	"nginxpanel/internal/secure"
	"os"
	"path/filepath"
)

const Name = frps.ContainerName
const ownerLabel = "io.nginxpanel.component"
const dataLabel = "io.nginxpanel.data"

type record struct {
	Installed         bool        `json:"installed"`
	Config            frps.Config `json:"config"`
	DashboardPort     int         `json:"dashboard_port"`
	DashboardPassword string      `json:"dashboard_password"`
}

func directory(data string) string { return filepath.Join(data, "agent", "frps") }
func read(data string) (record, error) {
	out := record{Config: frps.Default()}
	raw, err := secure.ReadRootFile(filepath.Join(directory(data), "state.json"), 16<<10)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return out, errors.New("FRP 安装记录损坏")
	}
	if err = out.Config.Validate(); err != nil {
		return out, err
	}
	if out.DashboardPort < 1 || out.DashboardPort > 65535 || len(out.DashboardPassword) < 20 || len(out.DashboardPassword) > 128 || out.Config.Token == "" {
		return out, errors.New("FRP 安装记录不完整")
	}
	return out, nil
}
func atomicFile(name string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".frps-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = os.Rename(f.Name(), name)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func save(data string, r record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return atomicFile(filepath.Join(directory(data), "state.json"), raw)
}

// Native JSON belongs to this built-in adapter; third-party catalogs never describe Docker.
func render(r record) ([]byte, error) {
	ports := make([]map[string]int, 0, len(r.Config.AllowPorts))
	for _, p := range r.Config.AllowPorts {
		if p.From == p.To {
			ports = append(ports, map[string]int{"single": p.From})
		} else {
			ports = append(ports, map[string]int{"start": p.From, "end": p.To})
		}
	}
	return json.Marshal(map[string]any{
		"bindAddr": r.Config.BindAddress, "bindPort": r.Config.BindPort, "proxyBindAddr": r.Config.BindAddress,
		"auth":       map[string]any{"method": "token", "token": r.Config.Token},
		"transport":  map[string]any{"tls": map[string]any{"force": r.Config.TLSOnly}},
		"allowPorts": ports, "vhostHTTPPort": r.Config.HTTPPort, "vhostHTTPSPort": r.Config.HTTPSPort, "subDomainHost": r.Config.SubdomainHost,
		"webServer": map[string]any{"addr": "127.0.0.1", "port": r.DashboardPort, "user": "nginxpanel", "password": r.DashboardPassword},
		"log":       map[string]any{"to": "console", "level": "info", "disablePrintColor": true},
	})
}
func writeRuntime(data string, r record) error {
	raw, err := render(r)
	if err != nil {
		return err
	}
	return atomicFile(filepath.Join(directory(data), "runtime", "frps.json"), raw)
}
func candidate(data string, r record) (string, func(), error) {
	raw, err := render(r)
	if err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(directory(data), ".verify-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return f.Name(), cleanup, nil
}
func decodeJSON(raw io.Reader, out any) error {
	decoder := json.NewDecoder(io.LimitReader(raw, 1<<20))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("服务返回了多余内容")
	}
	return nil
}
