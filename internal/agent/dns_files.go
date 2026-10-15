package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

const dnsSource = "/etc/resolv.conf"

type dnsFile struct {
	Data   []byte            `json:"data"`
	Mode   uint32            `json:"mode"`
	UID    uint32            `json:"uid"`
	GID    uint32            `json:"gid"`
	Xattrs map[string][]byte `json:"xattrs"`
	Dev    uint64            `json:"dev"`
	Ino    uint64            `json:"ino"`
	Mtime  int64             `json:"mtime"`
}

func (f dnsFile) hash() string { b, _ := json.Marshal(f); return secure.Hash(b) }
func sameDNSFile(a, b dnsFile) bool {
	a.Dev, a.Ino, a.Mtime = 0, 0, 0
	b.Dev, b.Ino, b.Mtime = 0, 0, 0
	return a.hash() == b.hash()
}
func readDNSFile(path string) (dnsFile, error) {
	var out dnsFile
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return out, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() > hostdns.SourceLimit {
		return out, errors.New("DNS source has unsafe attributes or exceeds budget")
	}
	out = dnsFile{Mode: uint32(info.Mode().Perm()), UID: st.Uid, GID: st.Gid, Dev: uint64(st.Dev), Ino: st.Ino, Mtime: info.ModTime().UnixNano(), Xattrs: map[string][]byte{}}
	out.Data, err = io.ReadAll(io.LimitReader(f, hostdns.SourceLimit+1))
	if err != nil || len(out.Data) > hostdns.SourceLimit {
		return out, errors.New("DNS source cannot be read within budget")
	}
	if !utf8.Valid(out.Data) || bytes.IndexByte(out.Data, 0) >= 0 {
		return out, errors.New("DNS source is not valid text")
	}
	buf := make([]byte, 8192)
	n, err := unix.Flistxattr(fd, buf)
	if errors.Is(err, unix.ENOTSUP) {
		err = nil
		n = 0
	}
	if err != nil {
		return out, err
	}
	total := 0
	for _, name := range strings.Split(string(buf[:n]), "\x00") {
		if name == "" {
			continue
		}
		if !utf8.ValidString(name) {
			return out, errors.New("DNS attribute names cannot be preserved safely")
		}
		value := make([]byte, 8192)
		n, err := unix.Fgetxattr(fd, name, value)
		if err != nil {
			return out, err
		}
		total += len(name) + n
		if total > 8192 {
			return out, errors.New("DNS attributes exceed budget")
		}
		out.Xattrs[name] = value[:n]
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != int64(len(out.Data)) || after.ModTime() != info.ModTime() {
		return out, errors.New("DNS source changed while reading")
	}
	return out, nil
}
func parseDNS(data []byte) hostdns.Config {
	out := hostdns.Config{Servers: []string{}, Search: []string{}}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0])
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			out.Servers = append(out.Servers, fields[1])
		case "search":
			out.Search = append([]string{}, fields[1:]...)
		case "domain":
			out.Search = []string{fields[1]}
		}
	}
	return out
}
func renderDNS(before []byte, config hostdns.Config) ([]byte, error) {
	var out strings.Builder
	for _, line := range strings.SplitAfter(string(before), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && slices.Contains([]string{"nameserver", "search", "domain"}, fields[0]) {
			if i := strings.IndexAny(line, "#;"); i >= 0 {
				out.WriteString(line[i:])
				if !strings.HasSuffix(line, "\n") {
					out.WriteByte('\n')
				}
			}
			continue
		}
		out.WriteString(line)
	}
	if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
		out.WriteByte('\n')
	}
	for _, server := range config.Servers {
		out.WriteString("nameserver " + server + "\n")
	}
	if len(config.Search) > 0 {
		out.WriteString("search " + strings.Join(config.Search, " ") + "\n")
	}
	if out.Len() > hostdns.SourceLimit {
		return nil, errors.New("DNS candidate exceeds budget")
	}
	return []byte(out.String()), nil
}
func writeDNSFile(expected, desired dnsFile, operationID string) error {
	if !validID(operationID) {
		return errors.New("invalid DNS operation")
	}
	if err := secure.RootDirectory("/etc", 0755); err != nil {
		return err
	}
	current, err := readDNSFile(dnsSource)
	if err != nil {
		return err
	}
	if current.hash() != expected.hash() {
		return errors.New("DNS source changed before replacement")
	}
	tmp := filepath.Join("/etc", ".nginxpanel-dns-"+operationID)
	// A previous crash may leave only this operation's exclusive temporary file.
	if info, e := os.Lstat(tmp); e == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 {
			return errors.New("unsafe DNS temporary file")
		}
		if e = os.Remove(tmp); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	defer f.Close()
	if _, err = f.Write(desired.Data); err != nil {
		return err
	}
	if err = f.Chown(int(desired.UID), int(desired.GID)); err != nil {
		return err
	}
	if err = f.Chmod(os.FileMode(desired.Mode)); err != nil {
		return err
	}
	for name, value := range desired.Xattrs {
		if err = unix.Fsetxattr(int(f.Fd()), name, value, 0); err != nil {
			return err
		}
	}
	// Remove inherited attributes absent from the snapshot, preserving ACL and
	// SELinux labels exactly rather than inheriting the temporary file's labels.
	attrs := make([]byte, 8192)
	n, e := unix.Flistxattr(int(f.Fd()), attrs)
	if errors.Is(e, unix.ENOTSUP) {
		e = nil
		n = 0
	}
	if e != nil {
		return e
	}
	for _, name := range strings.Split(string(attrs[:n]), "\x00") {
		if name != "" {
			if _, ok := desired.Xattrs[name]; !ok {
				if err = unix.Fremovexattr(int(f.Fd()), name); err != nil {
					return err
				}
			}
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	current, err = readDNSFile(dnsSource)
	if err != nil {
		return err
	}
	if current.hash() != expected.hash() {
		return errors.New("DNS source changed before rename")
	}
	if err = os.Rename(tmp, dnsSource); err != nil {
		return err
	}
	dir, err := os.Open("/etc")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func cleanDNSTemp(operationID string) error {
	if !validID(operationID) {
		return errors.New("invalid DNS operation")
	}
	tmp := filepath.Join("/etc", ".nginxpanel-dns-"+operationID)
	info, err := os.Lstat(tmp)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 {
		return errors.New("unsafe DNS temporary file")
	}
	if err = os.Remove(tmp); err != nil {
		return err
	}
	dir, err := os.Open("/etc")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
