// Package fail2bancontainer manages the built-in Fail2ban Docker installation.
package fail2bancontainer

import (
	"encoding/json"
	"errors"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
	"os"
	"path/filepath"
)

const Name = fail2ban.ContainerName

func directory(data string) string { return filepath.Join(data, "agent", "fail2ban-container") }
func Configuration(data string) (fail2ban.ContainerConfig, bool, error) {
	c := fail2ban.ContainerConfig{Image: fail2ban.ContainerImage, AutoStart: true, Whitelist: []string{"127.0.0.1/8", "::1"}, Rules: []fail2ban.ContainerRule{}}
	raw, err := secure.ReadRootFile(filepath.Join(directory(data), "config.json"), 32<<10)
	if os.IsNotExist(err) {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	var state struct {
		Installed bool                     `json:"installed"`
		Config    fail2ban.ContainerConfig `json:"config"`
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return c, false, err
	}
	return state.Config, state.Installed, state.Config.Validate()
}
func atomicFile(name string, raw []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".fail2ban-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(mode); err == nil {
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
	dir, err := os.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func save(data string, c fail2ban.ContainerConfig) error { return saveState(data, c, true) }
func saveState(data string, c fail2ban.ContainerConfig, installed bool) error {
	raw, err := json.Marshal(struct {
		Installed bool                     `json:"installed"`
		Config    fail2ban.ContainerConfig `json:"config"`
	}{installed, c})
	if err != nil {
		return err
	}
	return atomicFile(filepath.Join(directory(data), "config.json"), raw, 0600)
}
func setup(data string) error {
	for _, dir := range []string{directory(data), filepath.Join(directory(data), "data"), filepath.Join(directory(data), "data", "jail.d"), filepath.Join(directory(data), "data", "filter.d"), filepath.Join(directory(data), "data", "action.d"), filepath.Join(data, "agent", "security")} {
		if err := secure.RootDirectory(dir, 0700); err != nil {
			return err
		}
	}
	path := filepath.Join(data, "agent", "security", "login.jsonl")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err = atomicFile(path, nil, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Join(data, "logs"), filepath.Join(data, "logs", "nginx")} {
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			return errors.New("网站日志目录尚未准备好，请检查系统安装")
		} else if err != nil {
			return err
		}
	}
	return nil
}
