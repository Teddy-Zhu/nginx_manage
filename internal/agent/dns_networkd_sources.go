package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

var networkDirs = []string{"/usr/lib/systemd/network", "/usr/local/lib/systemd/network", "/run/systemd/network", "/etc/systemd/network"}

type networkSource struct {
	Path   string
	File   dnsFile
	Masked bool
}
type networkDirectory struct {
	Path    string
	Device  uint64
	Inode   uint64
	Changed int64
}

func networkDirectoryState(path string) (networkDirectory, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return networkDirectory{}, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return networkDirectory{}, errors.New("unsafe network source directory")
	}
	return networkDirectory{path, uint64(st.Dev), st.Ino, st.Ctim.Nano()}, nil
}
func networkSourcePath(path, base string, dropin bool) bool {
	if !utf8.ValidString(path) || len(path) > 512 || strings.ContainsRune(path, 0) || filepath.Clean(path) != path || filepath.Base(path) == "." {
		return false
	}
	for _, root := range networkDirs {
		if !dropin && filepath.Dir(path) == root && filepath.Base(path) == base && strings.HasSuffix(base, ".network") {
			return true
		}
		if dropin && filepath.Dir(path) == filepath.Join(root, base+".d") && strings.HasSuffix(filepath.Base(path), ".conf") {
			return true
		}
	}
	return false
}
func readNetworkSource(path string) (networkSource, error) {
	out := networkSource{Path: path}
	if link, e := os.Readlink(path); e == nil {
		info, e := os.Lstat(path)
		if e != nil {
			return out, e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || link != "/dev/null" {
			return out, errors.New("untrusted network source link")
		}
		out.Masked = true
		out.File = dnsFile{UID: st.Uid, GID: st.Gid, Dev: uint64(st.Dev), Ino: st.Ino, Mtime: info.ModTime().UnixNano()}
		return out, nil
	}
	var e error
	out.File, e = readDNSFile(path)
	return out, e
}

// Resolve current on-disk precedence independently of networkd's loaded list.
// New, masked and removed drop-ins must not be mistaken for loaded state.
func networkSources(loaded string) ([]networkSource, error) {
	base := filepath.Base(loaded)
	if !networkSourcePath(loaded, base, false) {
		return nil, errors.New("network source is outside known roots")
	}
	var chosen *networkSource
	candidates := map[string]networkSource{}
	dirs := []networkDirectory{}
	budget := 0
	for _, root := range networkDirs {
		state, e := networkDirectoryState(root)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		dirs = append(dirs, state)
		path := filepath.Join(root, base)
		if _, e = os.Lstat(path); e == nil {
			source, err := readNetworkSource(path)
			if err != nil {
				return nil, err
			}
			budget += len(source.File.Data)
			if budget > 128<<10 {
				return nil, errors.New("network source set exceeds budget")
			}
			chosen = &source
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		dir := filepath.Join(root, base+".d")
		state, e = networkDirectoryState(dir)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		dirs = append(dirs, state)
		entries, e := networkDirectoryEntries(dir)
		if e != nil {
			return nil, e
		}
		if len(entries) > 64 {
			return nil, errors.New("network drop-in inventory exceeds budget")
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			source, e := readNetworkSource(path)
			if e != nil {
				return nil, e
			}
			budget += len(source.File.Data)
			if budget > 128<<10 {
				return nil, errors.New("network source set exceeds budget")
			}
			candidates[entry.Name()] = source
			if len(candidates) > 32 {
				return nil, errors.New("network drop-in set exceeds budget")
			}
		}
	}
	if chosen == nil || chosen.Masked || len(chosen.File.Data) == 0 {
		return nil, errors.New("loaded network source is removed or masked")
	}
	if len(candidates) > 32 || budget > 128<<10 {
		return nil, errors.New("network source set exceeds budget")
	}
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []networkSource{*chosen}
	for _, name := range names {
		out = append(out, candidates[name])
	}
	for _, dir := range dirs {
		after, e := networkDirectoryState(dir.Path)
		if e != nil || after != dir {
			return nil, errors.New("network source directory changed while reading")
		}
	}
	for _, source := range out {
		after, e := readNetworkSource(source.Path)
		if e != nil || after.Masked != source.Masked || after.File.hash() != source.File.hash() {
			return nil, errors.New("network source changed while reading")
		}
	}
	return out, nil
}
func networkSourceHash(sources []networkSource, b *dnsBus, index int32, name string) string {
	raw, _ := json.Marshal([]any{b.busID, b.owner, index, name, sources})
	return secure.Hash(raw)
}

// This projection recognizes only unambiguous DNS syntax. Unsupported escapes
// and legacy policy sections produce unknown state, never guessed defaults.
func networkDNSProjection(sources []networkSource) (*hostdns.NetworkDNS, error) {
	out := &hostdns.NetworkDNS{Servers: []string{}, Search: []string{}, RoutingDomains: []string{}}
	var common *string
	domainPolicies := map[string]*string{}
	for _, source := range sources {
		if source.Masked {
			continue
		}
		section, pending := "", ""
		for _, physical := range strings.Split(string(source.File.Data), "\n") {
			line := strings.TrimSpace(physical)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			line = pending + line
			pending = ""
			if strings.HasSuffix(line, "\\") {
				pending = strings.TrimSuffix(line, "\\") + " "
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.TrimSpace(line[1 : len(line)-1])
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, errors.New("unsupported network source syntax")
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if section == "Network" && (key == "DNS" || key == "Domains") {
				words, e := networkDNSWords(value)
				if e != nil {
					return nil, e
				}
				if key == "DNS" {
					for _, word := range words {
						if !networkDNSServer(word) {
							return nil, errors.New("unsupported network DNS server syntax")
						}
					}
					if value == "" {
						out.Servers = []string{}
					} else {
						out.Servers = append(out.Servers, words...)
					}
				} else {
					if value == "" {
						out.Search = []string{}
						out.RoutingDomains = []string{}
					}
					for _, word := range words {
						domain := strings.TrimPrefix(word, "~")
						if !(word == "~." || hostdns.Hostname(domain)) {
							return nil, errors.New("unsupported network DNS domain")
						}
						if strings.HasPrefix(word, "~") {
							out.RoutingDomains = append(out.RoutingDomains, word)
						} else {
							out.Search = append(out.Search, word)
						}
					}
				}
			}
			if key == "UseDNS" || key == "UseDomains" {
				if section == "DHCP" {
					return nil, errors.New("legacy DHCP DNS policy needs a version-specific adapter")
				}
				if section == "Network" && key == "UseDomains" {
					v, e := networkDomainPolicy(value)
					if e != nil {
						return nil, e
					}
					common = v
					continue
				}
				if !slices.Contains([]string{"DHCPv4", "DHCPv6", "IPv6AcceptRA"}, section) {
					continue
				}
				if key == "UseDNS" {
					v, e := networkBool(value)
					if e != nil {
						return nil, e
					}
					switch section {
					case "DHCPv4":
						out.DHCP4 = v
					case "DHCPv6":
						out.DHCP6 = v
					case "IPv6AcceptRA":
						out.IPv6RA = v
					}
				} else {
					v, e := networkDomainPolicy(value)
					if e != nil {
						return nil, e
					}
					domainPolicies[section] = v
				}
			}
		}
		if pending != "" {
			return nil, errors.New("incomplete network source continuation")
		}
	}
	for section, ptr := range map[string]**string{"DHCPv4": &out.Domains4, "DHCPv6": &out.Domains6, "IPv6AcceptRA": &out.DomainsRA} {
		v := domainPolicies[section]
		if v == nil {
			v = common
		}
		*ptr = v
	}
	if len(out.Servers) > 64 || len(out.Search)+len(out.RoutingDomains) > 128 {
		return nil, errors.New("network DNS fields exceed budget")
	}
	return out, nil
}
func networkDNSWords(value string) ([]string, error) {
	words := []string{}
	var word strings.Builder
	var quote rune
	flush := func() {
		if word.Len() > 0 {
			words = append(words, word.String())
			word.Reset()
		}
	}
	for _, c := range value {
		if c == '\\' || c == '%' || c < 32 && c != '\t' || c > 126 {
			return nil, errors.New("network DNS syntax cannot be projected safely")
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == ' ' || c == '\t' {
			flush()
			continue
		}
		word.WriteRune(c)
	}
	if quote != 0 {
		return nil, errors.New("unclosed network DNS quote")
	}
	flush()
	for _, s := range words {
		if len(s) > 512 {
			return nil, errors.New("network DNS value exceeds budget")
		}
	}
	return words, nil
}
func networkBool(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	var v bool
	switch strings.ToLower(value) {
	case "yes", "true", "on", "1":
		v = true
	case "no", "false", "off", "0":
		v = false
	default:
		return nil, errors.New("invalid network DNS boolean")
	}
	return &v, nil
}
func networkDomainPolicy(value string) (*string, error) {
	if value == "" {
		return nil, nil
	}
	if value == "route" {
		return &value, nil
	}
	v, e := networkBool(value)
	if e != nil {
		return nil, e
	}
	value = "no"
	if *v {
		value = "yes"
	}
	return &value, nil
}

func networkDNSServer(value string) bool {
	address, name, hasName := strings.Cut(value, "#")
	if hasName && !hostdns.Hostname(name) {
		return false
	}
	if ip, e := netip.ParseAddr(address); e == nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Is4In6()
	}
	if addr, e := netip.ParseAddrPort(address); e == nil {
		return addr.Port() != 0 && !addr.Addr().IsUnspecified() && !addr.Addr().IsMulticast() && !addr.Addr().Is4In6()
	}
	return false
}

func networkDirectoryEntries(path string) ([]os.DirEntry, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	entries, e := f.ReadDir(65)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(entries) > 64 {
		return nil, errors.New("network drop-in inventory exceeds budget")
	}
	return entries, nil
}
