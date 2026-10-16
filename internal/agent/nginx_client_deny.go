package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

const clientDenyArtifactLimit = 1 << 20
const clientDenyHeader = "# nginxpanel-client-deny-v1\n"
const clientDenyHeaderEnd = "# nginxpanel-client-deny-end\n"

type clientDenySnapshot struct {
	Schema     int                 `json:"schema"`
	SourceKey  string              `json:"source_key"`
	ObservedAt int64               `json:"observed_at"`
	Entries    map[string][]string `json:"entries"`
}

func (n *Nginx) clientDenyPath() string {
	return filepath.Join(n.DataDir, "nginx", "client-deny", "sets.conf")
}

func validClientDenyBindings(bindings map[string][]string) bool {
	if len(bindings) > 32 {
		return false
	}
	for id, prefixes := range bindings {
		if !validID(id) || len(prefixes) == 0 || len(prefixes) > 64 {
			return false
		}
		last := ""
		for _, value := range prefixes {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Masked().String() != value || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || value <= last {
				return false
			}
			last = value
		}
	}
	return true
}

func renderClientDenySnapshot(snapshot clientDenySnapshot) ([]byte, string, error) {
	invalid := errors.New("客户端拒绝集合格式、来源或容量无效")
	if snapshot.Schema != 1 || snapshot.Entries == nil || len(snapshot.Entries) > 32 || snapshot.ObservedAt < 0 {
		return nil, "", invalid
	}
	if snapshot.SourceKey != "" && (len(snapshot.SourceKey) != 64 || strings.Trim(snapshot.SourceKey, "0123456789abcdef") != "" || snapshot.ObservedAt == 0) {
		return nil, "", invalid
	}
	ids := []string{}
	count := 0
	for id, addresses := range snapshot.Entries {
		if !validID(id) || len(addresses) > 1024 || snapshot.SourceKey == "" {
			return nil, "", invalid
		}
		last := ""
		for _, address := range addresses {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.Zone() != "" || ip.Unmap().String() != address || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || address <= last {
				return nil, "", invalid
			}
			last = address
		}
		count += len(addresses)
		ids = append(ids, id)
	}
	if count > 4096 {
		return nil, "", invalid
	}
	sort.Strings(ids)
	entries, err := json.Marshal(snapshot.Entries)
	if err != nil {
		return nil, "", err
	}
	generation := secure.Hash(entries)
	metadata, err := json.Marshal(snapshot)
	if err != nil {
		return nil, "", err
	}
	prefix := nginxconfig.ClientDenyVariablePrefix
	var out strings.Builder
	out.WriteString(clientDenyHeader)
	encoded := base64.RawStdEncoding.EncodeToString(metadata)
	for len(encoded) > 0 {
		size := min(len(encoded), 2048)
		out.WriteString("# " + encoded[:size] + "\n")
		encoded = encoded[size:]
	}
	out.WriteString(clientDenyHeaderEnd)
	out.WriteString("map \"\" $" + prefix + "_scope { default \"\"; }\n")
	out.WriteString("map \"$" + prefix + "_scope:$remote_addr\" $" + prefix + "_blocked {\n    volatile;\n    default 0;\n")
	for _, id := range ids {
		for _, address := range snapshot.Entries[id] {
			out.WriteString("    " + nginxQuote(id+":"+address) + " 1;\n")
			if ip, _ := netip.ParseAddr(address); ip.Is4() {
				out.WriteString("    " + nginxQuote(id+":::ffff:"+address) + " 1;\n")
			}
		}
	}
	out.WriteString("}\nmap \"\" $" + prefix + "_generation { default " + nginxQuote(generation) + "; }\n")
	if out.Len() > clientDenyArtifactLimit {
		return nil, "", invalid
	}
	return []byte(out.String()), generation, nil
}

func decodeClientDenySnapshot(raw []byte) (clientDenySnapshot, string, error) {
	var snapshot clientDenySnapshot
	if len(raw) > clientDenyArtifactLimit || !bytes.HasPrefix(raw, []byte(clientDenyHeader)) {
		return snapshot, "", ErrExternalChange
	}
	header, _, ok := bytes.Cut(raw[len(clientDenyHeader):], []byte(clientDenyHeaderEnd))
	if !ok {
		return snapshot, "", ErrExternalChange
	}
	var encoded strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(string(header), "\n"), "\n") {
		if !strings.HasPrefix(line, "# ") || len(line) > 2050 {
			return snapshot, "", ErrExternalChange
		}
		encoded.WriteString(line[2:])
	}
	metadata, err := base64.RawStdEncoding.DecodeString(encoded.String())
	if err != nil {
		return snapshot, "", ErrExternalChange
	}
	decoder := json.NewDecoder(bytes.NewReader(metadata))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || decoder.Decode(new(any)) != io.EOF {
		return snapshot, "", ErrExternalChange
	}
	expected, generation, err := renderClientDenySnapshot(snapshot)
	if err != nil || !bytes.Equal(expected, raw) {
		return snapshot, "", ErrExternalChange
	}
	return snapshot, generation, nil
}

func (n *Nginx) readClientDenySnapshot() (clientDenySnapshot, string, error) {
	var empty clientDenySnapshot
	name := n.clientDenyPath()
	if existingRootDirectory(filepath.Dir(name)) != nil {
		return empty, "", ErrExternalChange
	}
	directory, err := os.Lstat(filepath.Dir(name))
	if err != nil {
		return empty, "", err
	}
	directoryStat, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || directory.Mode().Perm() != 0750 || int(directoryStat.Gid) != n.gid {
		return empty, "", ErrExternalChange
	}
	info, err := os.Lstat(name)
	if err != nil {
		return empty, "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0440 || stat.Uid != 0 || int(stat.Gid) != n.gid || stat.Nlink != 1 || info.Size() > clientDenyArtifactLimit {
		return empty, "", ErrExternalChange
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return empty, "", err
	}
	return decodeClientDenySnapshot(raw)
}

func (n *Nginx) initializeClientDeny() error {
	dir := filepath.Dir(n.clientDenyPath())
	if info, err := os.Lstat(dir); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != 0750 || stat.Uid != 0 || int(stat.Gid) != n.gid {
			return ErrExternalChange
		}
		_, _, err = n.readClientDenySnapshot()
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := existingRootDirectory(filepath.Dir(dir)); err != nil {
		return err
	}
	raw, _, err := renderClientDenySnapshot(clientDenySnapshot{Schema: 1, Entries: map[string][]string{}})
	if err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(dir), ".client-deny-"+secure.ID())
	if err = os.Mkdir(temporary, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err = os.Chown(temporary, 0, n.gid); err != nil {
		return err
	}
	if err = os.Chmod(temporary, 0750); err != nil {
		return err
	}
	if err = durableFile(filepath.Join(temporary, "sets.conf"), raw, 0440, n.gid); err != nil {
		return err
	}
	if err = syncDir(temporary); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, dir, unix.RENAME_NOREPLACE); err != nil && !os.IsExist(err) {
		return err
	}
	if err = syncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	_, _, err = n.readClientDenySnapshot()
	return err
}

func (n *Nginx) revisionProbe(m manifest) (string, error) {
	if len(m.ClientDeny) == 0 {
		return m.Probe, nil
	}
	_, generation, err := n.readClientDenySnapshot()
	return m.Probe + ":" + generation, err
}

// Keep proxy protection in the immutable revision. Publishing a new trust
// list cannot turn an earlier client ban into a proxy ban.
func runtimeClientDenyControls(bindings map[string][]string) string {
	ids := []string{}
	for id := range bindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	prefix := nginxconfig.ClientDenyVariablePrefix
	var out strings.Builder
	for _, id := range ids {
		suffix := strings.ReplaceAll(id, "-", "")
		protected := prefix + "_protected_" + suffix
		effective := prefix + "_effective_" + suffix
		out.WriteString("    geo $remote_addr $" + protected + " {\n        default 0;\n")
		for _, subnet := range bindings[id] {
			out.WriteString("        " + subnet + " 1;\n")
		}
		out.WriteString("    }\n    map \"$" + prefix + "_blocked:$" + protected + "\" $" + effective + " {\n        volatile;\n        default 0;\n        \"1:0\" 1;\n    }\n")
	}
	return out.String()
}
