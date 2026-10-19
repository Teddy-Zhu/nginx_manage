package launcher

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"nginxpanel/internal/panelruntime"
)

func peerFile(base, name string, limit int64) ([]byte, error) {
	f, err := os.Open(base + "/" + name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("launcher 进程信息超过预算")
	}
	return raw, nil
}

func verifyPeerProcess(base string, pid int, d panelruntime.Deployment) error {
	raw, err := peerFile(base, "status", 16<<10)
	if err != nil {
		return err
	}
	values := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return errors.New("launcher 进程状态字段重复")
		}
		values[key] = strings.Fields(value)
	}
	for _, item := range []struct {
		key string
		id  int
	}{{"Uid", d.UID}, {"Gid", d.GID}} {
		fields := values[item.key]
		if len(fields) != 4 {
			return errors.New("launcher 进程身份不完整")
		}
		for _, value := range fields {
			if value != strconv.Itoa(item.id) {
				return errors.New("launcher 进程实际身份与绑定不一致")
			}
		}
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		f := values[key]
		if len(f) != 1 {
			return errors.New("launcher capabilities 信息不完整")
		}
		bits, err := strconv.ParseUint(f[0], 16, 64)
		if err != nil || bits != 0 {
			return errors.New("launcher 进程持有未授权的 capabilities")
		}
	}
	if f := values["NoNewPrivs"]; len(f) != 1 || f[0] != "1" {
		return errors.New("launcher 进程未启用禁止提权")
	}
	if f := values["NSpid"]; len(f) != 2 || f[0] != strconv.Itoa(pid) || f[1] != "1" {
		return errors.New("launcher 必须是独立容器 PID 1")
	}
	hasIPC := d.IPCGID == d.GID
	if _, ok := values["Groups"]; !ok {
		return errors.New("launcher 进程组信息不完整")
	}
	seen := map[string]bool{}
	for _, value := range values["Groups"] {
		if seen[value] || value != strconv.Itoa(d.GID) && value != strconv.Itoa(d.IPCGID) {
			return errors.New("launcher 进程持有额外的宿主机组授权")
		}
		seen[value] = true
		hasIPC = hasIPC || value == strconv.Itoa(d.IPCGID)
	}
	if !hasIPC {
		return errors.New("launcher 进程缺少固定 IPC 组")
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		raw, err := peerFile(base, name, 4096)
		if err != nil {
			return err
		}
		if strings.Join(strings.Fields(string(raw)), " ") != "0 0 4294967295" {
			return errors.New("面板容器不支持 rootless 或 UID/GID 重映射")
		}
	}
	for _, name := range []string{"pid", "mnt", "net"} {
		peer, err := os.Stat(base + "/ns/" + name)
		if err != nil {
			return err
		}
		host, err := os.Stat("/proc/self/ns/" + name)
		if err != nil {
			return err
		}
		if os.SameFile(peer, host) != (name == "net") {
			return errors.New("面板容器实际命名空间不符合固定策略")
		}
	}
	raw, err = peerFile(base, "cmdline", 4096)
	if err != nil {
		return err
	}
	expected := []byte(strings.Join([]string{panelruntime.DockerLauncher, "launcher", "--data-dir", d.DataDir}, "\x00") + "\x00")
	if !bytes.Equal(raw, expected) {
		return errors.New("launcher 进程实际参数不属于固定入口")
	}
	return nil
}
