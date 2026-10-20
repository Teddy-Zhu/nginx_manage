package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

const fail2banBanProofLimit = 4 << 20

type fail2banBanTime struct {
	Expires  int64 `json:"expires"`
	Duration int64 `json:"duration"`
}
type fail2banBanProof map[string]map[string]fail2banBanTime

// Reuse the official CLI in one interpreter so fixed jail reads do not pay
// Python startup for every property. Commands and formatting remain official.
const fail2banManagedClientBatch = `import contextlib,io,json,sys
sys.path.insert(0,sys.argv[1])
from fail2ban.client.fail2banclient import Fail2banClient
results=[]
for args in json.loads(sys.argv[2]):
 output=io.StringIO()
 with contextlib.redirect_stdout(output):
  if not Fail2banClient().start(["fail2ban-client"]+args):
   raise RuntimeError("official read command failed")
 results.append(output.getvalue())
print(json.dumps(results))
`

func managedFail2banRead(ctx context.Context, r *fail2banManagedRecord, args ...string) ([]byte, error) {
	argv := fail2banReadArgs(fail2banManagedSocket, args[0])
	argv = append(argv, args[1:]...)
	return fail2banManagedExec(ctx, r.python(), r.args(true, argv...), 2*time.Second, 256<<10)
}

func parseFail2banBanTimes(raw []byte) (map[string]fail2banBanTime, error) {
	out := map[string]fail2banBanTime{}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return out, nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 1024 {
		return nil, errors.New("官方封禁时间记录超过 1024 项")
	}
	for _, line := range lines {
		address, times, ok := strings.Cut(line, "\t")
		ip, err := netip.ParseAddr(strings.TrimSpace(address))
		if !ok || err != nil || ip.Zone() != "" {
			return nil, errors.New("官方封禁地址或时间格式未知")
		}
		address = ip.Unmap().String()
		start, rest, ok := strings.Cut(strings.TrimSpace(times), " + ")
		durationText, end, complete := strings.Cut(rest, " = ")
		duration, err := strconv.ParseInt(durationText, 10, 64)
		if !ok || !complete || err != nil || duration < -1 {
			return nil, errors.New("官方封禁时长格式未知")
		}
		if _, exists := out[address]; exists {
			return nil, errors.New("官方封禁时间记录重复")
		}
		value := fail2banBanTime{Duration: duration}
		if duration != -1 {
			began, e1 := time.Parse("2006-01-02 15:04:05", start)
			expires, e2 := time.Parse("2006-01-02 15:04:05", end)
			if e1 != nil || e2 != nil || expires.Unix()-began.Unix() < duration-1 || expires.Unix()-began.Unix() > duration+1 {
				return nil, errors.New("官方封禁起止时间无法核对")
			}
			value.Expires = expires.Unix()
		}
		out[address] = value
	}
	return out, nil
}

func fail2banIgnoreSet(j fail2ban.DesiredJail, b *fail2banJailBundle) ([]string, error) {
	values := append([]string{"127.0.0.0/8", "::1"}, j.IgnoreIPs...)
	if j.Action == "host-input" {
		values = append(values, b.HostProtected...)
	} else {
		values = append(values, b.Proxies[j.ResourceID]...)
	}
	return canonicalFail2banIgnore(values)
}

func canonicalFail2banIgnore(values []string) ([]string, error) {
	set := map[string]bool{}
	for _, value := range values {
		if ip, err := netip.ParseAddr(value); err == nil {
			value = ip.Unmap().String()
		} else if p, err := netip.ParsePrefix(value); err == nil {
			p = p.Masked()
			value = p.String()
			if p.Bits() == p.Addr().BitLen() {
				value = p.Addr().String()
			}
		} else {
			return nil, errors.New("实际忽略列表包含未知地址")
		}
		set[value] = true
	}
	out := []string{}
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func readFail2banJailRuntime(ctx context.Context, r *fail2banManagedRecord, b *fail2banJailBundle) (fail2banBanProof, error) {
	out := fail2banBanProof{}
	if err := verifyFail2banManagedLive(ctx, r); err != nil {
		return nil, err
	}
	before, err := readFail2banLiveService(ctx, r.binding())
	if err != nil {
		return nil, err
	}
	raw, err := managedFail2banRead(ctx, r, "get", "dbfile")
	if err != nil || strings.TrimSpace(string(raw)) != "Current database file is:\n`- "+r.work()+"/state/fail2ban.sqlite3" {
		return nil, errors.New("受管引擎的实际状态库无法核对")
	}
	raw, err = managedFail2banRead(ctx, r, "status")
	if err != nil {
		return nil, err
	}
	if err = checkFail2banJailNames(raw, b); err != nil {
		return nil, err
	}
	jails := []fail2ban.DesiredJail{}
	if b != nil {
		for _, j := range b.Policy.Jails {
			if j.Enabled {
				jails = append(jails, j)
			}
		}
	}
	proofs := make([]map[string]fail2banBanTime, len(jails))
	failures := make([]error, len(jails))
	for start := 0; start < len(jails); start += 4 {
		var wg sync.WaitGroup
		for i := start; i < min(start+4, len(jails)); i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); proofs[i], failures[i] = readFail2banJailDetails(ctx, r, b, jails[i]) }(i)
		}
		wg.Wait()
		for i := start; i < min(start+4, len(jails)); i++ {
			if failures[i] != nil {
				return nil, errors.New(fail2banJailNameFor(jails[i].ID) + "：" + failures[i].Error())
			}
		}
	}
	for i, j := range jails {
		out[fail2banJailNameFor(j.ID)] = proofs[i]
	}
	after, err := readFail2banLiveService(ctx, r.binding())
	if err != nil || !sameFail2banLive(before, after) {
		return nil, errors.New("受管 jail 核对期间实例变化")
	}
	if err = verifyFail2banManaged(ctx, r, true); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

func readFail2banJailDetails(ctx context.Context, r *fail2banManagedRecord, b *fail2banJailBundle, j fail2ban.DesiredJail) (map[string]fail2banBanTime, error) {
	name := fail2banJailNameFor(j.ID)
	filter, _ := fail2ban.FilterConfig(j.Template)
	_, regex, _ := strings.Cut(filter, "failregex = ")
	regex, _, _ = strings.Cut(regex, "\n")
	if regex == "" || len(regex) > 16384 {
		return nil, errors.New("受管固定过滤器表达式不完整")
	}
	compiled, err := fail2banManagedExec(ctx, r.python(), []string{"-I", "-S", "-B", "-c", fail2banManagedRegexValue, r.PackageRoot, regex}, 2*time.Second, 128<<10)
	if err != nil {
		return nil, err
	}
	regex = strings.TrimSpace(string(compiled))
	if regex == "" || strings.ContainsAny(regex, "\x00\r\n") {
		return nil, errors.New("官方固定过滤器展开结果不完整")
	}
	action, command, err := fail2banJailAction(r, j)
	if err != nil {
		return nil, err
	}
	checks := []struct {
		args     []string
		expected string
	}{
		{[]string{"bantime"}, strconv.FormatInt(j.BanTime, 10)},
		{[]string{"findtime"}, strconv.FormatInt(j.FindTime, 10)},
		{[]string{"maxretry"}, strconv.Itoa(j.MaxRetry)},
		{[]string{"logpath"}, "Current monitored log file(s):\n`- " + r.DataDir + "/" + b.Sources[j.ID]},
		{[]string{"failregex"}, "The following regular expression are defined:\n`- [0]: " + regex},
		{[]string{"actions"}, "The jail " + name + " has the following actions:\n" + action},
		{[]string{"action", action, "actionstart"}, command},
		{[]string{"action", action, "actionstop"}, command},
		{[]string{"action", action, "actionban"}, command},
		{[]string{"action", action, "actionunban"}, command},
	}
	queries := make([][]string, 0, len(checks)+2)
	for _, check := range checks {
		args := append(fail2banReadArgs(fail2banManagedSocket, "get"), name)
		queries = append(queries, append(args, check.args...))
	}
	queries = append(queries,
		append(fail2banReadArgs(fail2banManagedSocket, "get"), name, "ignoreip"),
		append(fail2banReadArgs(fail2banManagedSocket, "get"), name, "banip", "--with-time"),
	)
	input, err := json.Marshal(queries)
	if err != nil {
		return nil, err
	}
	raw, err := fail2banManagedExec(ctx, r.python(), []string{"-I", "-S", "-B", "-c", fail2banManagedClientBatch, r.PackageRoot, string(input)}, 5*time.Second, 256<<10)
	if err != nil {
		return nil, err
	}
	var values []string
	if err = json.Unmarshal(raw, &values); err != nil || len(values) != len(queries) {
		return nil, errors.New("官方 jail 只读查询结果不完整")
	}
	for i, check := range checks {
		if strings.TrimSpace(values[i]) != check.expected {
			return nil, errors.New("实际 jail 参数无法核对：" + check.args[0])
		}
	}
	lines := strings.Split(strings.TrimSpace(values[len(checks)]), "\n")
	if len(lines) < 2 || lines[0] != "These IP addresses/networks are ignored:" {
		return nil, errors.New("实际忽略列表格式未知")
	}
	actual := []string{}
	for i, line := range lines[1:] {
		prefix := "|- "
		if i == len(lines)-2 {
			prefix = "`- "
		}
		value, ok := strings.CutPrefix(line, prefix)
		if !ok {
			return nil, errors.New("实际忽略列表不完整")
		}
		actual = append(actual, value)
	}
	actualSet, err := canonicalFail2banIgnore(actual)
	if err != nil {
		return nil, err
	}
	expectedSet, err := fail2banIgnoreSet(j, b)
	if err != nil || strings.Join(actualSet, " ") != strings.Join(expectedSet, " ") {
		return nil, errors.New("实际忽略列表与配置不一致")
	}
	return parseFail2banBanTimes([]byte(values[len(checks)+1]))
}

func checkFail2banJailNames(raw []byte, b *fail2banJailBundle) error {
	actual, err := parseFail2banJails(raw)
	if err != nil {
		return err
	}
	names := []string{}
	for _, jail := range actual {
		names = append(names, jail.Name)
	}
	sort.Strings(names)
	if !sameFail2banHostJails(names, fail2banJailNames(b)) {
		return errors.New("受管实例实际完整 jail 名单与所选配置不一致")
	}
	return nil
}

func checkFail2banBanPreservation(before, after fail2banBanProof) error {
	return checkFail2banBanPreservationAt(before, after, time.Now().Unix())
}

func checkFail2banBanPreservationAt(before, after fail2banBanProof, now int64) error {
	for jail, current := range after {
		for ip, old := range before[jail] {
			if old.Expires > 0 && old.Expires <= now {
				continue
			}
			got, exists := current[ip]
			if !exists || (old.Expires == 0) != (got.Expires == 0) || got.Expires > old.Expires+1 || got.Expires < old.Expires-1 {
				return errors.New("未能确认原有未过期封禁及其到期时间：" + jail)
			}
		}
	}
	return nil
}

func saveFail2banBanProof(r *fail2banManagedRecord, id string, proof fail2banBanProof) (string, error) {
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", err
	}
	if err = writeFail2banJailImmutable(fail2banJailBansPath(r, id), raw, fail2banBanProofLimit); err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}
