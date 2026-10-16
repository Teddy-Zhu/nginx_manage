package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"nginxpanel/internal/fail2ban"
)

var fail2banServiceWord = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var fail2banServiceIDs = []string{"fail2ban.service", "nginxpanel-fail2ban.service", "fail2ban.socket"}

func readFail2banServices(ctx context.Context) []fail2ban.Service {
	out := make([]fail2ban.Service, 0, len(fail2banServiceIDs))
	for _, id := range fail2banServiceIDs {
		out = append(out, fail2ban.Service{ID: id, Reason: "systemd 状态无法完整读取"})
	}
	args := append([]string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID"}, fail2banServiceIDs...)
	raw, err := fail2banRun(ctx, fail2banTool("systemctl"), args, 16<<10)
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || ctx.Err() != nil {
			return out
		}
	}
	parsed := map[string]fail2ban.Service{}
	for _, block := range strings.Split(strings.TrimSpace(string(raw)), "\n\n") {
		values := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || len(value) > 128 {
				return out
			}
			switch key {
			case "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID":
			default:
				return out
			}
			if _, duplicate := values[key]; duplicate {
				return out
			}
			values[key] = value
		}
		id := values["Id"]
		known := false
		for _, allowed := range fail2banServiceIDs {
			known = known || id == allowed
		}
		if !known {
			return out
		}
		if _, duplicate := parsed[id]; duplicate {
			return out
		}
		if !fail2banServiceWord.MatchString(values["LoadState"]) || !fail2banServiceWord.MatchString(values["ActiveState"]) || !fail2banServiceWord.MatchString(values["SubState"]) || values["UnitFileState"] != "" && !fail2banServiceWord.MatchString(values["UnitFileState"]) {
			return out
		}
		state := fail2ban.Service{ID: id, Available: true, Load: values["LoadState"], Active: values["ActiveState"], Sub: values["SubState"], UnitFile: values["UnitFileState"]}
		if rawPID, exists := values["MainPID"]; exists {
			pid, err := strconv.ParseInt(rawPID, 10, 32)
			if err != nil || pid < 0 {
				return out
			}
			state.MainPID = &pid
		}
		parsed[id] = state
	}
	if len(parsed) != len(out) {
		return out
	}
	for i := range out {
		out[i] = parsed[out[i].ID]
	}
	return out
}

func readFail2banSocket() fail2ban.Socket {
	out := fail2ban.Socket{Path: "/run/fail2ban/fail2ban.sock", Reason: "默认 Socket 不可核对；不据此判断实例健康"}
	if err := existingRootDirectory(filepath.Dir(out.Path)); err != nil {
		if _, statErr := os.Lstat(filepath.Dir(out.Path)); os.IsNotExist(statErr) {
			present := false
			out.Present, out.Reason = &present, "未发现默认 Socket 目录；已有实例可能使用其他路径"
		}
		return out
	}
	info, err := os.Lstat(out.Path)
	if os.IsNotExist(err) {
		present := false
		out.Present, out.Reason = &present, "未发现默认 Socket；已有实例可能使用其他路径"
		return out
	}
	if err != nil {
		return out
	}
	present := true
	out.Present = &present
	stat, ok := info.Sys().(*syscall.Stat_t)
	out.RootProtected = ok && stat.Uid == 0 && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm()&0022 == 0
	if out.RootProtected {
		out.Reason = "仅核对默认 Socket 文件；未连接实例或核对 jail 状态"
	}
	return out
}
