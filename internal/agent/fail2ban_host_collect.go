package agent

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// Official calendar labels are server-local. Preserve them as evidence rather
// than inventing UTC expiry for an existing server with an unknown timezone.
type fail2banHostBanTime struct {
	Started  string `json:"started"`
	Duration int64  `json:"duration"`
	End      string `json:"end"`
}

type fail2banHostSample struct {
	view      fail2ban.HostInputSourcesView
	addresses []string
	binding   *fail2banBinding
	live      fail2banLiveService
	program   fail2banProgram
}

func parseFail2banHostBanTimes(raw []byte) (map[string]fail2banHostBanTime, error) {
	out := map[string]fail2banHostBanTime{}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return out, nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > firewall.NFTBanLimit {
		return nil, errors.New("官方封禁时间记录超过限制")
	}
	for _, line := range lines {
		address, rest, ok := strings.Cut(line, "\t")
		ip, err := netip.ParseAddr(strings.TrimSpace(address))
		if !ok || len(line) > 256 || err != nil || ip.Zone() != "" {
			return nil, errors.New("宿主机动作仅支持官方数值单 IP 封禁")
		}
		started, rest, ok := strings.Cut(strings.TrimSpace(rest), " + ")
		durationText, end, complete := strings.Cut(rest, " = ")
		duration, err := strconv.ParseInt(durationText, 10, 64)
		_, startErr := time.Parse("2006-01-02 15:04:05", started)
		if !ok || !complete || err != nil || duration < -1 || startErr != nil || len(end) == 0 || len(end) > 64 || strings.ContainsAny(end, "\x00\r\t") {
			return nil, errors.New("官方封禁时间格式未知")
		}
		if duration != -1 {
			if _, err = time.Parse("2006-01-02 15:04:05", end); err != nil {
				return nil, errors.New("官方封禁结束时间格式未知")
			}
		}
		address = ip.Unmap().String()
		if _, exists := out[address]; exists {
			return nil, errors.New("官方封禁时间地址重复")
		}
		out[address] = fail2banHostBanTime{Started: started, Duration: duration, End: end}
	}
	return out, nil
}

func readFail2banHostJail(ctx context.Context, program fail2banProgram, socket, name string) (map[string]fail2banHostBanTime, error) {
	readTimes := func() (map[string]fail2banHostBanTime, error) {
		raw, err := program.run(ctx, append(fail2banReadArgs(socket, "get"), name, "banip", "--with-time"), 128<<10)
		if err != nil {
			return nil, err
		}
		return parseFail2banHostBanTimes(raw)
	}
	before, err := readTimes()
	if err != nil {
		return nil, err
	}
	raw, err := program.run(ctx, append(fail2banReadArgs(socket, "status"), name), 128<<10)
	if err != nil {
		return nil, err
	}
	status := fail2ban.Jail{Name: name, Banned: []string{}}
	if err = parseFail2banJail(raw, &status); err != nil {
		return nil, err
	}
	after, err := readTimes()
	if err != nil {
		return nil, err
	}
	if !maps.Equal(before, after) || len(after) != len(status.Banned) {
		return nil, errors.New("jail 封禁在采集期间变化，未返回部分集合")
	}
	for _, ip := range status.Banned {
		if _, exists := after[ip]; !exists {
			return nil, errors.New("官方封禁状态与时间记录不一致")
		}
	}
	return after, nil
}

func (s fail2banHostSample) unchanged(ctx context.Context, dataDir string) error {
	if err := s.program.unchanged(ctx, dataDir); err != nil {
		return err
	}
	if err := fail2banCurrentBinding(dataDir, s.binding, true); err != nil {
		return err
	}
	live, err := readFail2banLiveService(ctx, s.binding)
	if err != nil || !sameFail2banLive(s.live, live) {
		return errors.New("宿主机封禁采集期间实例或 Socket 代次变化")
	}
	return ctx.Err()
}

// This collector has no Nginx manifest, resource or execution dependency. A
// missing/stopped engine is unavailable, never an authoritative empty ban set.
func collectFail2banHost(ctx context.Context, dataDir string, event *fail2banHostSourcesEvent, protected []string) (fail2banHostSample, error) {
	out := fail2banHostSample{view: fail2ban.EmptyHostInputSources("官方宿主机封禁来源未完整采集"), addresses: []string{}}
	if event == nil || event.Action != "approve" || !event.valid() {
		return out, errors.New("宿主机封禁来源未获 root 批准")
	}
	out.view.ID, out.view.ApprovedAt, out.view.Jails = event.ID, event.ApprovedAt, append([]string{}, event.Policy.Jails...)
	set, err := (firewall.NFTBanSet{Addresses: []string{}, Protected: protected}).Normalize()
	if err != nil {
		return out, err
	}
	b, err := selectFail2banBinding(dataDir)
	if err != nil || b == nil || b.State != "bound" || fail2banNginxEngineKey(b) != event.EngineKey {
		return out, errors.New("官方实例身份或读取授权变化，须本机重新批准封禁来源")
	}
	program, err := selectFail2banClient(b)
	if err == nil {
		program, err = program.authenticate(ctx)
	}
	if err != nil {
		return out, err
	}
	if err = fail2banCurrentBinding(dataDir, b, true); err != nil {
		return out, err
	}
	before, err := readFail2banLiveService(ctx, b)
	if err != nil {
		return out, err
	}
	client, err := program.run(ctx, []string{"--version"}, 4096)
	if err != nil || b.ClientVersion != "1.1.1" || strings.TrimSpace(string(client)) != "Fail2Ban v1.1.1" {
		return out, errors.New("宿主机动作客户端须为已核对的 1.1.1")
	}
	server, err := program.run(ctx, fail2banReadArgs(b.Socket, "version"), 4096)
	if err != nil || strings.TrimSpace(string(server)) != "1.1.1" {
		return out, errors.New("宿主机动作服务端版本无法核对")
	}
	proofs := make([]map[string]fail2banHostBanTime, len(event.Policy.Jails))
	failures := make([]error, len(proofs))
	for start := 0; start < len(proofs); start += 4 {
		var wg sync.WaitGroup
		for i := start; i < min(start+4, len(proofs)); i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				proofs[i], failures[i] = readFail2banHostJail(ctx, program, b.Socket, event.Policy.Jails[i])
			}(i)
		}
		wg.Wait()
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		for i := start; i < min(start+4, len(proofs)); i++ {
			if failures[i] != nil {
				return out, errors.New("宿主机来源 jail 未完整采集：" + event.Policy.Jails[i] + "：" + failures[i].Error())
			}
		}
	}
	union := map[string]bool{}
	for _, proof := range proofs {
		for address := range proof {
			union[address] = true
		}
		if len(union) > firewall.NFTBanLimit {
			return out, errors.New("多个 jail 合并的唯一封禁超过 1024 项")
		}
	}
	for address := range union {
		ip, _ := netip.ParseAddr(address)
		excluded := !ip.IsGlobalUnicast()
		for _, raw := range set.Protected {
			prefix, _ := netip.ParsePrefix(raw)
			excluded = excluded || prefix.Contains(ip)
		}
		if excluded {
			out.view.ProtectedCount++
		} else {
			out.addresses = append(out.addresses, address)
		}
	}
	sort.Strings(out.addresses)
	out.binding, out.live, out.program = b, before, program
	if err = out.unchanged(ctx, dataDir); err != nil {
		return out, err
	}
	out.view.CollectedAt = time.Now().Unix()
	raw, err := json.Marshal(struct {
		Registry, Engine, Invocation, Socket string
		CollectedAt                          int64
		Proofs                               []map[string]fail2banHostBanTime
	}{event.ID, event.EngineKey, before.invocation, before.inode, out.view.CollectedAt, proofs})
	if err != nil {
		return out, err
	}
	if len(raw) > fail2banBanProofLimit {
		return out, errors.New("官方来源证明超过预算")
	}
	out.view.SourceHash, out.view.BannedCount = secure.Hash(raw), len(out.addresses)
	out.view.State, out.view.Reason = "ready", ""
	return out, nil
}
