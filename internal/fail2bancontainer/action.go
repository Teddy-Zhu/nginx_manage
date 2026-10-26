package fail2bancontainer

// Keep bans in IPSet and one private chain per address family. In particular,
// do not let a container's newer nft userspace write set metadata that an older
// host nft cannot read. A shared lock serializes chain creation and removal.
const ipsetAction = `[Definition]
actionstart = flock -x /run/nginxpanel-fail2ban.lock sh -ec 'ipset create <setname> hash:ip family <family> -exist; <iptables> -N <chain> 2>/dev/null || <iptables> -S <chain> >/dev/null; <iptables> -C INPUT -j <chain> 2>/dev/null || <iptables> -I INPUT -j <chain>; <iptables> -C <chain> -p tcp -m multiport --dports <port> -m set --match-set <setname> src -j REJECT 2>/dev/null || <iptables> -A <chain> -p tcp -m multiport --dports <port> -m set --match-set <setname> src -j REJECT'
actioncheck = <iptables> -C INPUT -j <chain> && <iptables> -C <chain> -p tcp -m multiport --dports <port> -m set --match-set <setname> src -j REJECT
actionban = ipset add <setname> <ip> -exist
actionunban = ipset del <setname> <ip> -exist
actionstop = flock -x /run/nginxpanel-fail2ban.lock sh -ec '<iptables> -D <chain> -p tcp -m multiport --dports <port> -m set --match-set <setname> src -j REJECT; ipset destroy <setname>; if [ "$(<iptables> -S <chain> | wc -l)" -eq 1 ]; then <iptables> -D INPUT -j <chain>; <iptables> -X <chain>; fi'

[Init]
name = default
chain = NGINXPANEL_F2B
setname = f2b-<name>
family = inet
iptables = /usr/sbin/iptables-legacy -w

[Init?family=inet6]
setname = f2b6-<name>
family = inet6
iptables = /usr/sbin/ip6tables-legacy -w
`
