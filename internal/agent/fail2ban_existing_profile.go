package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

const fail2banExistingConfig = "/etc/fail2ban"

// Audited 1.1.1 data assets are read from the existing root installation. The
// preview never downloads programs or trusts an arbitrary action supplied by UI.
var fail2banExistingProfileAssets = map[string]string{
	"filter.d/sshd.conf":               "d88b5e62a8afe537eab00cfc55c42db0140529c1d655ba2843f4c5603225a3ec",
	"filter.d/common.conf":             "ebf00cecd2c4227189ca8e8d55049fe21cf2379e7d388cb160bc6c4caa63e4fa",
	"action.d/nftables.conf":           "6487b2e9cdcd98515d4fecf7cc2f5e40da7c3409c36b6c675f94f76c2c6c3472",
	"action.d/nftables-multiport.conf": "9c552cb2fb83e42081486f898a5a3104736547c1c8432ad32cd754c6612b4c64",
}

type fail2banExistingConfigSnapshot struct {
	Files map[string][]byte `json:"files"`
}

func (s fail2banExistingConfigSnapshot) hash() string {
	raw, _ := json.Marshal(s)
	return secure.Hash(raw)
}
func readFail2banExistingConfig() (fail2banExistingConfigSnapshot, error) {
	out := fail2banExistingConfigSnapshot{Files: map[string][]byte{}}
	if err := existingRootDirectory(fail2banExistingConfig); err != nil {
		return out, err
	}
	entries, total := 0, 0
	err := filepath.WalkDir(fail2banExistingConfig, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 1024 {
			return errors.New("已有 Fail2ban 配置目录超过 1024 项")
		}
		if entry.IsDir() {
			return existingRootDirectory(name)
		}
		if !entry.Type().IsRegular() {
			return errors.New("已有 Fail2ban 配置包含链接或特殊文件")
		}
		rel, err := filepath.Rel(fail2banExistingConfig, name)
		if err != nil || strings.HasPrefix(rel, "../") || strings.ContainsAny(rel, "\x00\r\n\\") {
			return errors.New("已有 Fail2ban 配置路径无效")
		}
		raw, err := secure.ReadRootFile(name, 256<<10)
		if err != nil {
			return err
		}
		total += len(raw)
		if total > 8<<20 {
			return errors.New("已有 Fail2ban 配置超过 8 MiB")
		}
		out.Files[rel] = raw
		return nil
	})
	if err != nil {
		return out, err
	}
	if len(out.Files["jail.conf"]) == 0 || len(out.Files["fail2ban.conf"]) == 0 {
		return out, errors.New("已有 Fail2ban 主配置不完整")
	}
	return out, nil
}

func fail2banExistingOverlay(profile fail2ban.ExistingJailProfile, policy fail2ban.ExistingJailPolicy) string {
	return "[" + profile.Name + "]\nenabled = " + strconv.FormatBool(policy.Enabled) + "\nbantime = " + strconv.FormatInt(policy.BanTime, 10) + "\nfindtime = " + strconv.FormatInt(policy.FindTime, 10) + "\nmaxretry = " + strconv.Itoa(policy.MaxRetry) + "\nignoreip = " + strings.Join(policy.IgnoreIPs, " ") + "\n"
}

func fail2banExistingReference(profile fail2ban.ExistingJailProfile, policy fail2ban.ExistingJailPolicy, backend string, files map[string][]byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	for name, hash := range fail2banExistingProfileAssets {
		raw, ok := files[name]
		if !ok || secure.Hash(raw) != hash {
			return nil, errors.New("SSH 接管配置要求未修改的官方 Fail2ban 1.1.1 filter/action 数据：" + name)
		}
		out[name] = raw
	}
	ports := make([]string, len(profile.Ports))
	for i, port := range profile.Ports {
		ports[i] = strconv.Itoa(port)
	}
	logpath := "/var/log/auth.log"
	if profile.LogSource == "secure-log" {
		logpath = "/var/log/secure"
	}
	source := "logpath = " + logpath + "\n"
	if profile.LogSource == "systemd" {
		if backend != "systemd" {
			return nil, errors.New("journal 来源必须使用实际 systemd 后端")
		}
		source = ""
	} else if backend != "auto" && backend != "polling" {
		return nil, errors.New("SSH 文件来源仅支持 auto/polling 后端")
	}
	out["fail2ban.conf"] = []byte("[Definition]\nlogtarget = STDERR\nsyslogsocket = /dev/null\n")
	out["jail.conf"] = []byte("[DEFAULT]\nenabled = false\nbackend = " + backend + "\nusedns = no\nlogencoding = auto\nfindtime = 600\nbantime = 600\nmaxretry = 5\n\n" + fail2banExistingOverlay(profile, policy) + "filter = sshd[mode=normal]\naction = nftables-multiport[name=" + profile.Name + ", port=\"" + strings.Join(ports, ",") + "\", protocol=tcp]\n" + source)
	return out, nil
}

func writeFail2banExistingCandidate(dir string, files map[string][]byte) error {
	for name, raw := range files {
		path := filepath.Join(dir, name)
		if filepath.Clean(name) != name || filepath.IsAbs(name) || strings.HasPrefix(name, "../") {
			return errors.New("候选配置路径无效")
		}
		if err := secure.RootDirectory(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := writeFail2banJailImmutable(path, raw, 256<<10); err != nil {
			return err
		}
	}
	return nil
}

func dumpFail2banExisting(ctx context.Context, program fail2banProgram, b *fail2banBinding, dir, name string) ([][]any, error) {
	args := append([]string{"-c", dir}, fail2banReadArgs(b.Socket, "-d")...)
	raw, err := program.run(ctx, args, 2<<20)
	if err != nil {
		return nil, errors.New("官方客户端未能完整编译已有 jail 配置")
	}
	return parseFail2banDump(raw, name)
}

func fail2banExistingBackend(commands [][]any, name string) (string, error) {
	backend := ""
	for _, command := range commands {
		if command[0] != "add" {
			continue
		}
		if backend != "" || len(command) != 3 || command[1] != name {
			return "", errors.New("目标 jail 的创建配置不唯一")
		}
		backend, _ = command[2].(string)
	}
	if backend == "" {
		return "", errors.New("目标 jail 未在完整配置中启用")
	}
	return backend, nil
}

// Only known tuning fields can differ from the reviewed profile. Preserve all
// other commands when comparing the original and proposed configuration.
func fail2banExistingStableDump(commands [][]any, profile bool) ([][]any, error) {
	out := [][]any{}
	var maxretry int64
	for _, command := range commands {
		if len(command) == 4 && command[0] == "set" && command[2] == "maxretry" {
			maxretry, _ = command[3].(int64)
		}
	}
	for _, command := range commands {
		verb, _ := command[0].(string)
		if verb == "start" {
			continue
		}
		if verb == "set" || verb == "multi-set" {
			if len(command) < 4 {
				return nil, errors.New("目标 jail 参数配置不完整")
			}
			field, ok := command[2].(string)
			if !ok {
				return nil, errors.New("目标 jail 参数标识未知")
			}
			switch field {
			case "findtime", "bantime", "maxretry", "addignoreip":
				continue
			case "maxmatches":
				if len(command) != 4 {
					return nil, errors.New("目标 jail maxmatches 格式未知")
				}
				matches, ok := command[3].(int64)
				if !ok || matches < 1 || matches > 1000 {
					return nil, errors.New("目标 jail maxmatches 超出接管预算")
				}
				if profile || matches == maxretry {
					continue
				}
			case "ignorecommand":
				if len(command) != 4 || command[3] != "" {
					return nil, errors.New("接管不支持可执行 ignorecommand")
				}
				continue
			case "ignoreself":
				if len(command) != 4 || command[3] != true {
					return nil, errors.New("接管要求保持本机地址忽略保护")
				}
				if profile {
					continue
				}
			case "bantime.increment":
				if len(command) != 4 || command[3] != false {
					return nil, errors.New("接管暂不支持递增封禁时长")
				}
				if profile {
					continue
				}
			case "bantime.rndtime":
				if len(command) != 4 || command[3] != int64(0) {
					return nil, errors.New("接管暂不支持随机封禁时长")
				}
				if profile {
					continue
				}
			case "addlogpath", "addjournalmatch", "logencoding", "usedns", "prefregex", "addfailregex", "addignoreregex", "datepattern", "maxlines", "addaction", "action":
			default:
				return nil, errors.New("目标 jail 包含尚未接纳的配置参数：" + field)
			}
		}
		out = append(out, command)
	}
	return out, nil
}

func checkFail2banExistingTuningDump(actual, expected [][]any) error {
	selectTuning := func(commands [][]any) [][]any {
		out := [][]any{}
		for _, command := range commands {
			if len(command) < 4 || command[0] != "set" {
				continue
			}
			switch command[2] {
			case "findtime", "bantime", "maxretry", "addignoreip":
				out = append(out, command)
			}
		}
		return out
	}
	if fail2banDumpHash(selectTuning(actual)) != fail2banDumpHash(selectTuning(expected)) {
		return errors.New("候选 jail 的启用或参数期望被其他配置覆盖；未接管")
	}
	return nil
}
