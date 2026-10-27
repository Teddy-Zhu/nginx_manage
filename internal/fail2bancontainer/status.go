package fail2bancontainer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/software"
	"strings"
)

func command(ctx context.Context, args ...string) (string, error) {
	return software.Docker(ctx, nil, args...)
}
func client(ctx context.Context, args ...string) (string, error) {
	return command(ctx, append([]string{"exec", Name, "fail2ban-client"}, args...)...)
}
func exists(ctx context.Context) (bool, error) { return containerNamed(ctx, Name) }
func containerNamed(ctx context.Context, name string) (bool, error) {
	s, err := command(ctx, "container", "ls", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	return s != "", err
}
func owned(ctx context.Context) error { return ownedNamed(ctx, Name) }
func ownedNamed(ctx context.Context, name string) error {
	raw, err := command(ctx, "inspect", "--format", "{{json .Config.Labels}}", name)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	if json.Unmarshal([]byte(raw), &labels) != nil || labels["org.nginxpanel.builtin"] != "fail2ban" {
		return errors.New("同名容器不属于面板，未修改")
	}
	return nil
}
func running(ctx context.Context) (bool, error) {
	raw, err := command(ctx, "inspect", "--format", "{{.State.Running}}", Name)
	return raw == "true", err
}
func jailName(id string) string {
	raw, _ := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return "np" + base64.RawURLEncoding.EncodeToString(raw)
}

// Read through Fail2ban's client protocol in one container invocation. Limiting
// the returned address list keeps both IPC responses and live updates bounded.
const statusScript = `import json, base64, uuid
from fail2ban.client.csocket import CSocket
s = CSocket('/var/run/fail2ban/fail2ban.sock')
r = s.send(['status', '--all'])
s.close()
if r[0] != 0:
    raise RuntimeError(str(r[1]))
jails = r[1][-1]
if not isinstance(jails, dict):
    raise RuntimeError('Unexpected Fail2ban response')
result = []
remaining = 128
for name, groups in jails.items():
    if not name.startswith('np') or len(name) != 24:
        continue
    values = {key: value for section, fields in groups for key, value in fields}
    addresses = [str(value) for value in values.get('Banned IP list', [])][:remaining]
    remaining -= len(addresses)
    result.append(dict(id=str(uuid.UUID(bytes=base64.urlsafe_b64decode(name[2:] + '=='))), running=True, banned=addresses,
        current_failed=values['Currently failed'], total_failed=values['Total failed'],
        current_banned=values['Currently banned'], total_banned=values['Total banned'], error=''))
print(json.dumps(result))
`

func Status(ctx context.Context, data string) (fail2ban.ContainerStatus, error) {
	c, installed, err := Configuration(data)
	out := fail2ban.ContainerStatus{State: "unknown", Installed: installed, Config: c, Jails: []fail2ban.ContainerJail{}}
	if err != nil {
		return out, err
	}
	if !installed {
		out.State = "missing"
		return out, nil
	}
	present, err := exists(ctx)
	if err != nil {
		return out, err
	}
	if !present {
		out.State = "missing"
		out.Error = "软件容器不存在，请重新安装"
		return out, nil
	}
	if err = owned(ctx); err != nil {
		return out, err
	}
	out.Running, err = running(ctx)
	if err != nil {
		return out, err
	}
	logs, err := command(ctx, "logs", "--tail", "100", Name)
	if err != nil {
		out.Error = "暂时无法读取服务日志"
	} else {
		out.Logs = logs
	}
	if !out.Running {
		out.State = "stopped"
		return out, nil
	}
	out.State = "starting"
	raw, err := command(ctx, "exec", Name, "python3", "-c", statusScript)
	if err != nil {
		out.Error = "登录防护尚未就绪，请查看服务日志"
		return out, nil
	}
	var jails []fail2ban.ContainerJail
	if err = json.Unmarshal([]byte(raw), &jails); err != nil {
		return out, errors.New("登录防护返回的状态不完整")
	}
	if len(jails) > 32 {
		return out, errors.New("登录防护返回的规则过多")
	}
	out.Ready = true
	out.State = "running"
	for _, rule := range c.Rules {
		if !rule.Enabled {
			continue
		}
		jail := fail2ban.ContainerJail{ID: rule.ID, Banned: []string{}, Error: "规则尚未运行"}
		for _, value := range jails {
			if value.ID == rule.ID {
				jail = value
				for _, address := range value.Banned {
					if _, err := netip.ParseAddr(address); err != nil {
						return out, errors.New("登录防护返回的地址无效")
					}
				}
				break
			}
		}
		out.Jails = append(out.Jails, jail)
	}
	return out, nil
}
