package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
)

// Missing tools alone cannot prove an empty backend. Use independent kernel
// evidence only when both applets are absent; existing but broken or untrusted
// tools retain their original failure. This does not authorize an executor.
func completeAbsentXtables(ctx context.Context, sets []firewall.Ruleset) {
	if ctx.Err() != nil || len(sets) != 5 || sets[0].ID != "nftables" {
		return
	}
	for i := 1; i < len(sets); i++ {
		set := &sets[i]
		variant, name := "nft", "iptables"
		if i >= 3 {
			variant = "legacy"
		}
		if i%2 == 0 {
			name = "ip6tables"
		}
		name += "-" + variant
		if set.Available || !xtablesToolsAbsentAt(name, "/usr/sbin", "/usr/bin", "/sbin", "/bin") {
			continue
		}
		switch {
		case variant == "nft" && nftFamilyAbsent(sets[0], set.Family):
			set.Available = true
			set.Reason = "未安装该族 xtables 工具；完整 nftables 视图已确认无对应地址族表"
		case variant == "legacy" && legacyTablesAbsentAt("/proc/self/net", set.Family):
			set.Available = true
			set.Reason = "未安装该族 legacy 工具；内核已确认无已登记的 legacy 表"
		}
	}
}

func xtablesToolsAbsentAt(name string, directories ...string) bool {
	for _, applet := range []string{name, name + "-save"} {
		for _, dir := range directories {
			if _, err := os.Lstat(filepath.Join(dir, applet)); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
	}
	return true
}

// iptables-nft uses the ip/ip6 families. An inet firewalld table is independent;
// even an empty ip/ip6 table prevents this absence proof.
func nftFamilyAbsent(nft firewall.Ruleset, family string) bool {
	if nft.ID != "nftables" || !nft.Available || nft.Backend != "nftables" || nft.Family != "all" {
		return false
	}
	want := map[string]string{"ipv4": "ip", "ipv6": "ip6"}[family]
	if want == "" {
		return false
	}
	for _, table := range nft.Tables {
		if table.Family == want {
			return false
		}
	}
	return true
}

// x_tables exposes each network namespace's registered tables through these
// proc files. Open relative to a verified procfs directory, and never accept a
// substituted regular file, a symlink, a read error or a truncated inventory.
func legacyTablesAbsentAt(directory, family string) bool {
	name := map[string]string{"ipv4": "ip_tables_names", "ipv6": "ip6_tables_names"}[family]
	if name == "" {
		return false
	}
	dir, err := os.Open(directory)
	if err != nil {
		return false
	}
	defer dir.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(dir.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return false
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.Is(err, unix.ENOENT)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	return err == nil && len(raw) <= 4096 && len(bytes.TrimSpace(raw)) == 0
}
