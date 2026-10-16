package agent

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"nginxpanel/internal/fail2ban"
)

var fail2banJailName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func fail2banStatusField(line, prefix, label string) (string, bool) {
	value, ok := strings.CutPrefix(line, prefix+label+":\t")
	return strings.TrimSpace(value), ok
}
func parseFail2banJails(raw []byte) ([]fail2ban.JailSummary, error) {
	invalid := errors.New("jail 列表格式未知、不完整或超过 64 项")
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 || lines[0] != "Status" {
		return nil, invalid
	}
	countRaw, ok := fail2banStatusField(lines[1], "|- ", "Number of jail")
	if !ok {
		return nil, invalid
	}
	count, err := strconv.ParseInt(countRaw, 10, 32)
	if err != nil || count < 0 || count > 64 {
		return nil, invalid
	}
	list, ok := fail2banStatusField(lines[2], "`- ", "Jail list")
	if !ok {
		return nil, invalid
	}
	out := []fail2ban.JailSummary{}
	if list == "" {
		if count != 0 {
			return nil, invalid
		}
		return out, nil
	}
	names, seen := strings.Split(list, ","), map[string]bool{}
	if len(names) != int(count) {
		return nil, invalid
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if !fail2banJailName.MatchString(name) || seen[name] {
			return nil, invalid
		}
		seen[name] = true
		out = append(out, fail2ban.JailSummary{Name: name})
	}
	return out, nil
}
func parseFail2banJail(raw []byte, out *fail2ban.Jail) error {
	invalid := errors.New("jail 状态格式未知、不完整或封禁记录超过 1024 项")
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 9 || lines[0] != "Status for the jail: "+out.Name || lines[1] != "|- Filter" || lines[5] != "`- Actions" {
		return invalid
	}
	targets := []struct {
		line          int
		prefix, label string
		dest          **int64
	}{
		{2, "|  |- ", "Currently failed", &out.CurrentFailed}, {3, "|  |- ", "Total failed", &out.TotalFailed},
		{6, "   |- ", "Currently banned", &out.CurrentBanned}, {7, "   |- ", "Total banned", &out.TotalBanned},
	}
	for _, target := range targets {
		text, ok := fail2banStatusField(lines[target.line], target.prefix, target.label)
		if !ok {
			return invalid
		}
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil || value < 0 {
			return invalid
		}
		*target.dest = &value
	}
	if _, files := fail2banStatusField(lines[4], "|  `- ", "File list"); !files {
		if _, journal := fail2banStatusField(lines[4], "|  `- ", "Journal matches"); !journal {
			return invalid
		}
	}
	ips, ok := fail2banStatusField(lines[8], "   `- ", "Banned IP list")
	if !ok {
		return invalid
	}
	entries, seen := strings.Fields(ips), map[string]bool{}
	if len(entries) > 1024 || int64(len(entries)) != *out.CurrentBanned {
		return invalid
	}
	for _, entry := range entries {
		if ip, err := netip.ParseAddr(entry); err == nil && ip.Zone() == "" {
			entry = ip.Unmap().String()
		} else if prefix, err := netip.ParsePrefix(entry); err == nil {
			entry = prefix.Masked().String()
		} else {
			return invalid
		}
		if seen[entry] {
			return invalid
		}
		seen[entry] = true
		out.Banned = append(out.Banned, entry)
	}
	return nil
}
