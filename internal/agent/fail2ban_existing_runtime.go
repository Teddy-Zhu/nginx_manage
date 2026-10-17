package agent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

type Fail2banExistingRuntime struct {
	At           int64                       `json:"at"`
	AdoptionID   string                      `json:"adoption_id"`
	BindingID    string                      `json:"binding_id"`
	Name         string                      `json:"name"`
	Target       string                      `json:"target"`
	ProfileProof string                      `json:"profile_proof"`
	Timezone     fail2banExistingTimezone    `json:"timezone"`
	ClockProof   string                      `json:"clock_proof"`
	Policy       fail2ban.ExistingJailPolicy `json:"policy"`
	Jails        []string                    `json:"jails"`
	Bans         map[string]fail2banBanTime  `json:"bans"`
}

// These are observations from the official running filter, including expanded
// expressions. Compare native observations with native observations, rather
// than treating a source <HOST> token as the engine's expanded expression.
func readFail2banExistingNativeProfile(ctx context.Context, program fail2banProgram, b *fail2banBinding, profile fail2ban.ExistingJailProfile, policy fail2ban.ExistingJailPolicy, commands [][]any) (string, error) {
	observed := map[string]string{}
	total := 0
	get := func(key string, args ...string) (string, error) {
		raw, err := program.run(ctx, append(fail2banReadArgs(b.Socket, "get"), append([]string{profile.Name}, args...)...), 128<<10)
		if err != nil {
			return "", err
		}
		total += len(raw)
		if total > 2<<20 {
			return "", errors.New("已有 jail 的实际过滤器/动作输出超过总预算")
		}
		if !utf8.Valid(raw) || strings.IndexByte(string(raw), 0) >= 0 {
			return "", errors.New("已有 jail 的实际过滤器输出编码未知")
		}
		value := strings.TrimSpace(string(raw))
		observed[key] = value
		return value, nil
	}
	for _, field := range []string{"prefregex", "failregex", "ignoreregex", "usedns", "logencoding", "logtimezone", "maxlines", "maxmatches", "ignoreself", "ignorecommand"} {
		value, err := get(field, field)
		if err != nil {
			return "", err
		}
		switch field {
		case "usedns":
			if value != "no" {
				return "", errors.New("已有 SSH jail 的实际 DNS 解析方式不符合固定配置")
			}
		case "ignoreself":
			if value != "True" {
				return "", errors.New("已有 SSH jail 没有实际启用本机地址忽略")
			}
		case "ignorecommand":
			if value != "" && value != "None" {
				return "", errors.New("已有 SSH jail 的实际 ignorecommand 不为空")
			}
			observed[field] = ""
		case "logtimezone":
			if value != "None" {
				return "", errors.New("已有 SSH jail 的实际日志时区被单独改写")
			}
		case "maxlines", "maxmatches":
			n, err := strconv.ParseInt(value, 10, 32)
			if err != nil || n < 1 || n > 1000 {
				return "", errors.New("已有 SSH jail 的实际行数/匹配预算未知")
			}
			if field == "maxmatches" && n == int64(policy.MaxRetry) {
				observed[field] = "derived-from-maxretry"
			}
		}
	}
	if profile.LogSource == "systemd" {
		value, err := get("source", "journalmatch")
		if err != nil {
			return "", err
		}
		tokens := []string{}
		matches := 0
		for _, command := range commands {
			if len(command) < 4 || command[0] != "set" || command[2] != "addjournalmatch" {
				continue
			}
			matches++
			for _, arg := range command[3:] {
				token, ok := arg.(string)
				if !ok {
					return "", errors.New("固定 SSH journal 匹配格式未知")
				}
				tokens = append(tokens, token)
			}
		}
		if matches != 1 || value != "Current match filter:\n"+strings.Join(tokens, " ") {
			return "", errors.New("已有 SSH jail 的实际 journal 匹配来源变化")
		}
	} else {
		value, err := get("source", "logpath")
		if err != nil {
			return "", err
		}
		path := "/var/log/auth.log"
		if profile.LogSource == "secure-log" {
			path = "/var/log/secure"
		}
		if value != "Current monitored log file(s):\n`- "+path {
			return "", errors.New("已有 SSH jail 的实际日志来源与固定路径不一致")
		}
	}
	properties, err := fail2banExistingActionProperties(commands)
	if err != nil {
		return "", err
	}
	if len(properties) == 0 || len(properties) > 64 {
		return "", errors.New("已有 jail 的 action 属性超出核对预算")
	}
	for _, key := range []string{"actionstart", "actionstop", "actioncheck", "actionban", "actionunban"} {
		if _, ok := properties[key].(string); !ok {
			return "", errors.New("已有 jail 缺少必要的官方动作命令")
		}
	}
	const action = "nftables-multiport"
	value, err := get("actions", "actions")
	if err != nil || value != "The jail "+profile.Name+" has the following actions:\n"+action {
		return "", errors.New("已有 jail 的实际动作名单变化")
	}
	keys := make([]string, 0, len(properties))
	for key := range properties {
		if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n\t ") {
			return "", errors.New("已有 jail 的 action 属性标识未知")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, err := get("action:"+key, "action", action, key)
		if err != nil {
			return "", err
		}
		switch key {
		case "actionstart", "actionstop", "actioncheck", "actionban", "actionunban":
			expected, ok := properties[key].(string)
			if !ok || value != strings.TrimSpace(expected) {
				return "", errors.New("已有 jail 的实际动作命令与固定配置不一致")
			}
		}
	}
	raw, _ := json.Marshal(observed)
	return secure.Hash(raw), ctx.Err()
}

func ReadFail2banExistingRuntime(ctx context.Context, data, scope, adoption string) (Fail2banExistingRuntime, error) {
	out := Fail2banExistingRuntime{At: time.Now().Unix(), AdoptionID: adoption, Jails: []string{}, Bans: map[string]fail2banBanTime{}}
	if err := fail2banManagedRoot(data, scope); err != nil {
		return out, err
	}
	if !validID(adoption) {
		return out, errors.New("须指定原接管 UUID")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	unlock, err := fail2banHostSyncLocks(data)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banManagedIdle(data, ""); err != nil {
		return out, err
	}
	leave, err := fail2banHostSyncAdmission(data, true)
	if err != nil {
		return out, err
	}
	defer leave()
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	r, err := j.Get(adoption)
	if err != nil {
		return out, err
	}
	c, err := validFail2banExistingRecord(data, r)
	if err != nil {
		return out, err
	}
	g, err := loadFail2banExistingGrant(data, c.Plan.Profile.Name)
	if err != nil {
		return out, err
	}
	if r.State != "succeeded" || r.Fail2banExisting.Action != "adopt" || g == nil || g.ID != adoption || g.Action != "adopt" {
		return out, errors.New("目标 jail 尚未由当前接管授权发布")
	}
	b := &c.Binding
	if err = fail2banCurrentBinding(data, b, true); err != nil {
		return out, err
	}
	unit, err := fail2banExistingUnitHash(ctx, b.Service)
	if err != nil || unit != c.Unit {
		return out, errors.New("接管后的服务单元变化")
	}
	live, err := readFail2banLiveService(ctx, b)
	if err != nil {
		return out, err
	}
	if _, err = fail2banExistingServerConfig(live); err != nil {
		return out, err
	}
	program, err := selectFail2banClient(b)
	if err != nil {
		return out, err
	}
	program, err = program.authenticate(ctx)
	if err != nil {
		return out, err
	}
	_, _, status, err := readFail2banBound(ctx, data, b, true, "")
	if err != nil {
		return out, err
	}
	jails, err := parseFail2banJails(status)
	if err != nil {
		return out, err
	}
	for _, jail := range jails {
		out.Jails = append(out.Jails, jail.Name)
	}
	sort.Strings(out.Jails)
	config, err := readFail2banExistingConfig()
	if err != nil {
		return out, err
	}
	if err = verifyFail2banExistingConfigSource(live, config); err != nil {
		return out, err
	}
	commands, err := dumpFail2banExisting(ctx, program, b, fail2banExistingConfig, c.Plan.Profile.Name)
	if err != nil || fail2banDumpHash(commands) != c.DumpHash {
		return out, errors.New("接管后的目标 jail 配置变化")
	}
	out.Policy, err = readFail2banExistingTuning(ctx, program, b, c.Plan.Profile.Name)
	if err != nil || !equalFail2banExistingPolicy(out.Policy, c.Plan.Before) {
		return out, errors.New("接管后的 jail 实际参数变化")
	}
	out.ProfileProof, err = readFail2banExistingNativeProfile(ctx, program, b, c.Plan.Profile, out.Policy, commands)
	if err != nil {
		return out, err
	}
	if out.ProfileProof != c.Plan.NativeProof {
		return out, errors.New("接管后的实际过滤器或动作属性变化")
	}
	out.Timezone, err = readFail2banExistingTimezone(ctx, b, live)
	if err != nil {
		return out, err
	}
	labels, err := readFail2banHostJail(ctx, program, b.Socket, c.Plan.Profile.Name)
	if err != nil {
		return out, err
	}
	out.Bans, err = fail2banExistingBanProof(labels, out.Timezone)
	if err != nil {
		return out, err
	}
	out.ClockProof, err = verifyFail2banExistingNativeClock(ctx, live, out.Timezone, labels, out.Bans)
	if err != nil {
		return out, err
	}
	currentPolicy, err := readFail2banExistingTuning(ctx, program, b, c.Plan.Profile.Name)
	if err != nil || !equalFail2banExistingPolicy(currentPolicy, out.Policy) {
		return out, errors.New("读取运行证明期间实际参数变化")
	}
	currentProfile, err := readFail2banExistingNativeProfile(ctx, program, b, c.Plan.Profile, currentPolicy, commands)
	if err != nil || currentProfile != out.ProfileProof {
		return out, errors.New("读取运行证明期间实际过滤器或动作变化")
	}
	status, err = program.run(ctx, fail2banReadArgs(b.Socket, "status"), 128<<10)
	if err != nil {
		return out, err
	}
	jails, err = parseFail2banJails(status)
	if err != nil {
		return out, err
	}
	names := make([]string, 0, len(jails))
	for _, jail := range jails {
		names = append(names, jail.Name)
	}
	sort.Strings(names)
	if strings.Join(names, "\x00") != strings.Join(out.Jails, "\x00") {
		return out, errors.New("读取运行证明期间完整 jail 名单变化")
	}
	currentUnit, err := fail2banExistingUnitHash(ctx, b.Service)
	if err != nil || currentUnit != unit {
		return out, errors.New("读取运行证明期间服务单元变化")
	}
	after, err := readFail2banExistingConfig()
	if err != nil || after.hash() != config.hash() {
		return out, errors.New("读取运行证明期间配置变化")
	}
	if err = verifyFail2banExistingConfigSource(live, after); err != nil {
		return out, err
	}
	afterZone, err := readFail2banExistingTimezone(ctx, b, live)
	if err != nil || afterZone.SHA256 != out.Timezone.SHA256 || afterZone.StartedAt != out.Timezone.StartedAt {
		return out, errors.New("读取封禁证明期间时区材料变化")
	}
	currentLive, err := readFail2banLiveService(ctx, b)
	if err != nil || !sameFail2banLive(live, currentLive) {
		return out, errors.New("读取运行证明期间服务变化")
	}
	if err = program.unchanged(ctx, data); err != nil {
		return out, err
	}
	if err = fail2banCurrentBinding(data, b, true); err != nil {
		return out, err
	}
	out.Name, out.BindingID = c.Plan.Profile.Name, b.ID
	raw, _ := json.Marshal([]string{adoption, b.ID, unit, config.hash(), out.ProfileProof, live.invocation, live.inode, out.Timezone.SHA256, out.ClockProof})
	out.Target = secure.Hash(raw)
	return out, ctx.Err()
}
