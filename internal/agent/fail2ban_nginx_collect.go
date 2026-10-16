package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

type fail2banNginxSample struct {
	snapshot     clientDenySnapshot
	binding      *fail2banBinding
	live         fail2banLiveService
	protected    int
	inactive     int
	stoppedEvent string
}

func sameFail2banLive(a, b fail2banLiveService) bool {
	return a.view.MainPID != nil && b.view.MainPID != nil && a.invocation == b.invocation && *a.view.MainPID == *b.view.MainPID && a.inode == b.inode && os.SameFile(a.file, b.file)
}

func collectFail2banNginx(ctx context.Context, data string, registry fail2banNginxRegistry, bindings map[string][]string) (fail2banNginxSample, error) {
	out := fail2banNginxSample{snapshot: clientDenySnapshot{Schema: 1, Entries: map[string][]string{}}}
	active := []fail2banNginxGrant{}
	for _, grant := range registry.Grants {
		if len(bindings[grant.ResourceID]) == 0 {
			out.inactive++
			continue
		}
		active = append(active, grant)
	}
	var program fail2banProgram
	if len(active) > 0 {
		stoppedEvent, err := stoppedFail2banNginxSource(ctx, data, active)
		if err != nil {
			return out, err
		}
		if stoppedEvent != "" {
			identity, _ := json.Marshal(struct{ Registry, StoppedEvent string }{registry.ID, stoppedEvent})
			out.stoppedEvent = stoppedEvent
			out.snapshot.SourceKey, out.snapshot.ObservedAt = secure.Hash(identity), time.Now().Unix()
			return out, ctx.Err()
		}
		b, err := selectFail2banBinding(data)
		if err != nil || b == nil || b.State != "bound" {
			return out, errors.New("Nginx 动作的 Fail2ban 实例授权不可用")
		}
		for _, grant := range active {
			if grant.EngineKey != fail2banNginxEngineKey(b) {
				return out, errors.New("实例身份已变化，须由 root 重新授权 Nginx 动作")
			}
		}
		program, err = selectFail2banClient(b)
		if err == nil {
			program, err = program.authenticate(ctx)
		}
		if err != nil {
			return out, err
		}
		if err = fail2banCurrentBinding(data, b, true); err != nil {
			return out, err
		}
		before, err := readFail2banLiveService(ctx, b)
		if err != nil {
			return out, err
		}
		client, err := program.run(ctx, []string{"--version"}, 4096)
		if err != nil || strings.TrimSpace(string(client)) != "Fail2Ban v1.1.1" || b.ClientVersion != "1.1.1" {
			return out, errors.New("Nginx 动作客户端版本须为 1.1.1")
		}
		server, err := program.run(ctx, fail2banReadArgs(b.Socket, "version"), 4096)
		if err != nil || strings.TrimSpace(string(server)) != "1.1.1" {
			return out, errors.New("Nginx 动作服务端版本无法核对")
		}
		statuses := make([]fail2ban.Jail, len(active))
		errorsByJail := make([]error, len(active))
		// Fixed-size batches bound official client processes and aggregate memory.
		for start := 0; start < len(active); start += 4 {
			var wg sync.WaitGroup
			for i := start; i < min(start+4, len(active)); i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					statuses[i] = fail2ban.Jail{Name: active[i].Jail, Banned: []string{}}
					raw, err := program.run(ctx, append(fail2banReadArgs(b.Socket, "status"), active[i].Jail), 128<<10)
					if err == nil {
						err = parseFail2banJail(raw, &statuses[i])
					}
					errorsByJail[i] = err
				}(i)
			}
			wg.Wait()
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
		}
		sets := map[string]map[string]bool{}
		for i, jail := range statuses {
			if errorsByJail[i] != nil {
				return out, errors.New("授权 jail 状态读取不完整：" + active[i].Jail)
			}
			resource := active[i].ResourceID
			if sets[resource] == nil {
				sets[resource] = map[string]bool{}
			}
			for _, address := range jail.Banned {
				ip, err := netip.ParseAddr(address)
				if err != nil || ip.Zone() != "" {
					return out, errors.New("Nginx 客户端动作仅支持单个 IP，jail 含不支持的网络封禁")
				}
				ip = ip.Unmap()
				protected := ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast()
				for _, value := range bindings[resource] {
					prefix, _ := netip.ParsePrefix(value)
					protected = protected || prefix.Contains(ip)
				}
				if protected {
					out.protected++
					continue
				}
				sets[resource][ip.String()] = true
			}
		}
		for resource, set := range sets {
			out.snapshot.Entries[resource] = []string{}
			for address := range set {
				out.snapshot.Entries[resource] = append(out.snapshot.Entries[resource], address)
			}
			sort.Strings(out.snapshot.Entries[resource])
		}
		after, err := readFail2banLiveService(ctx, b)
		if err != nil || !sameFail2banLive(before, after) {
			return out, errors.New("Nginx 动作采集期间实例或 Socket 变化")
		}
		if err = program.unchanged(ctx, data); err != nil {
			return out, err
		}
		if err = fail2banCurrentBinding(data, b, true); err != nil {
			return out, err
		}
		out.binding, out.live = b, after
	}
	identity, _ := json.Marshal(struct{ Registry, Invocation, Socket string }{registry.ID, out.live.invocation, out.live.inode})
	out.snapshot.SourceKey, out.snapshot.ObservedAt = secure.Hash(identity), time.Now().Unix()
	if _, _, err := renderClientDenySnapshot(out.snapshot); err != nil {
		return out, err
	}
	return out, ctx.Err()
}
