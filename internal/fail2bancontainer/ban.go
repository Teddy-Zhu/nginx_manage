package fail2bancontainer

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
)

// The client acknowledgement precedes asynchronous firewall actions. Report a
// completed operation only after both the set and its rule reflect the request.
func waitBan(ctx context.Context, rule fail2ban.ContainerRule, address string, banned bool) error {
	ip, _ := netip.ParseAddr(address)
	prefix, tool := "f2b-", "iptables-legacy"
	if ip.Is6() {
		prefix, tool = "f2b6-", "ip6tables-legacy"
	}
	set := prefix + jailName(rule.ID)
	ports := make([]string, len(rule.Ports))
	for i, port := range rule.Ports {
		ports[i] = strconv.Itoa(port)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var last error
	for {
		out, err := command(ctx, "exec", Name, "ipset", "test", set, address)
		if !banned && err != nil && (strings.Contains(out, "is NOT in set") || strings.Contains(out, "set with the given name does not exist")) {
			return nil
		}
		if banned && err == nil {
			_, err = command(ctx, "exec", Name, tool, "-w", "-C", "INPUT", "-j", "NGINXPANEL_F2B")
			if err == nil {
				_, err = command(ctx, "exec", Name, tool, "-w", "-C", "NGINXPANEL_F2B", "-p", "tcp", "-m", "multiport", "--dports", strings.Join(ports, ","), "-m", "set", "--match-set", set, "src", "-j", "REJECT")
			}
			if err == nil {
				return nil
			}
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("封禁名单操作未生效：%v；%w", last, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
