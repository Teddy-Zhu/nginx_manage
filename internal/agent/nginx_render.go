package agent

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

type listener struct {
	Network   string `json:"network"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	DualStack bool   `json:"dual_stack"`
}
type tlsProbe struct {
	Address     string `json:"address"`
	ServerName  string `json:"server_name"`
	Fingerprint string `json:"fingerprint"`
}

func nginxQuote(s string) string {
	s = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$", "\n", "\\n", "\r", "\\r").Replace(s)
	return "\"" + s + "\""
}

func (n *Nginx) expand(p *nginxconfig.Parsed, nodes []*nginxconfig.Node, depth int) ([]*nginxconfig.Node, error) {
	if depth > limits.Depth {
		return nil, errors.New("include nesting limit")
	}
	out := []*nginxconfig.Node{}
	for _, node := range nodes {
		if node.Name != "include" {
			out = append(out, node)
			continue
		}
		if len(node.Args) != 1 {
			return nil, errors.New("invalid include")
		}
		paths := []string{}
		for _, doc := range p.Documents {
			if match, _ := path.Match(node.Args[0].Value, doc.File.Path); match {
				paths = append(paths, doc.File.Path)
			}
		}
		sort.Strings(paths)
		for _, name := range paths {
			for _, doc := range p.Documents {
				if doc.File.Path == name {
					children, err := n.expand(p, doc.Nodes, depth+1)
					if err != nil {
						return nil, err
					}
					out = append(out, children...)
				}
			}
		}
		if len(out) > limits.Directives {
			return nil, errors.New("expanded directive limit")
		}
	}
	return out, nil
}

func (n *Nginx) render(p *nginxconfig.Parsed, m *manifest) (map[string]string, error) {
	contents := map[string]string{}
	var main *nginxconfig.Document
	for _, doc := range p.Documents {
		if strings.HasPrefix(doc.File.Path, ".nginxpanel") || strings.Contains(doc.File.Path, "/.nginxpanel") {
			return nil, errors.New("reserved generated path")
		}
		contents[doc.File.Path] = doc.File.Content
		if doc.File.Path == "nginx.conf" {
			main = doc
		}
	}
	if main == nil {
		return nil, errors.New("main configuration is required")
	}
	count := 0
	if err := n.expandedBudget(p, main.Nodes, 0, &count); err != nil {
		return nil, err
	}
	var httpBlock *nginxconfig.Node
	pidCount := 0
	for _, node := range main.Nodes {
		if node.Name == "http" {
			if httpBlock != nil {
				return nil, errors.New("exactly one http block is required")
			}
			httpBlock = node
		}
		if node.Name == "pid" {
			pidCount++
		}
	}
	if httpBlock == nil || pidCount != 1 {
		return nil, errors.New("the managed http and pid entry points are required")
	}
	m.Dependencies = map[string]string{}
	for _, doc := range p.Documents {
		edits := []nginxconfig.Edit{}
		var walk func([]*nginxconfig.Node) error
		walk = func(nodes []*nginxconfig.Node) error {
			for _, node := range nodes {
				switch node.Name {
				case "include":
					if len(node.Args) != 1 {
						return errors.New("invalid include")
					}
					arg := node.Args[0]
					edits = append(edits, nginxconfig.Edit{Start: arg.Start, End: arg.End, Text: nginxQuote(filepath.Join(filepath.Dir(n.configPath(revisionDir(m.RevisionID))), arg.Value))})
				case "access_log", "error_log":
					if len(node.Args) > 0 && node.Args[0].Value != "off" {
						if err := secure.RootDirectory(filepath.Dir(filepath.Join(n.DataDir, node.Args[0].Value)), 0755); err != nil {
							return err
						}
					}
				case "ssl_certificate", "ssl_certificate_key", "ssl_trusted_certificate", "proxy_ssl_trusted_certificate":
					if len(node.Args) != 1 {
						return errors.New("invalid certificate reference")
					}
					name := node.Args[0].Value
					if _, ok := m.Dependencies[name]; ok {
						break
					}
					if len(m.Dependencies) >= limits.CertificateReferences {
						return errors.New("certificate reference limit reached")
					}
					b, err := n.certificateFile(name)
					if err != nil {
						return err
					}
					m.Dependencies[name] = secure.Hash(b)
				}
				if err := walk(node.Children); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(doc.Nodes); err != nil {
			return nil, err
		}
		if doc == main {
			probe := "\n    # Reserved local revision probe.\n    server {\n        listen " + nginxQuote("unix:"+filepath.Join(n.DataDir, "run", "nginx-probe.sock")) + ";\n        server_name localhost;\n        access_log off;\n        location = /__nginxpanel_revision { return 200 " + nginxQuote(m.Probe) + "; }\n    }\n"
			probe += "    client_body_temp_path " + nginxQuote(filepath.Join(n.DataDir, "nginx", "tmp", "client")) + ";\n    proxy_temp_path " + nginxQuote(filepath.Join(n.DataDir, "nginx", "tmp", "proxy")) + ";\n"
			edits = append(edits, nginxconfig.Edit{Start: httpBlock.Close, End: httpBlock.Close, Text: probe})
			edits = append(edits, nginxconfig.Edit{Start: 0, End: 0, Text: "# Generated runtime controls; original revision is retained in the database.\nuser " + n.WorkerUser + " " + n.workerGroup + ";\n"})
		}
		sort.SliceStable(edits, func(i, j int) bool { return edits[i].Start > edits[j].Start })
		text := doc.File.Content
		for _, edit := range edits {
			text = text[:edit.Start] + edit.Text + text[edit.End:]
		}
		contents[doc.File.Path] = text
	}
	if err := n.runtimeDirectories(); err != nil {
		return nil, err
	}
	root, err := n.expand(p, main.Nodes, 0)
	if err != nil {
		return nil, err
	}
	seen := map[string]string{}
	for _, block := range root {
		if block.Name != "http" && block.Name != "stream" {
			continue
		}
		children, err := n.expand(p, block.Children, 0)
		if err != nil {
			return nil, err
		}
		for _, server := range children {
			if server.Name != "server" {
				continue
			}
			directives, err := n.expand(p, server.Children, 0)
			if err != nil {
				return nil, err
			}
			listens := 0
			for _, node := range directives {
				if node.Name != "listen" {
					continue
				}
				listens++
				l, ssl, err := parseListener(node.Args, block.Name)
				if err != nil {
					return nil, err
				}
				key := fmt.Sprintf("%s/%s/%d", l.Network, l.IP, l.Port)
				if kind, ok := seen[key]; ok {
					if kind != "http" || block.Name != "http" {
						return nil, errors.New("conflicting HTTP/Stream listeners")
					}
				} else {
					m.Listeners = append(m.Listeners, l)
					seen[key] = block.Name
				}
				if len(m.Listeners) > limits.NginxListeners || len(m.TLS) >= limits.NginxListeners {
					return nil, errors.New("listener verification limit reached")
				}
				if ssl {
					probe, err := n.tlsExpectation(l, directives, children)
					if err != nil {
						return nil, err
					}
					m.TLS = append(m.TLS, probe)
				}
			}
			if listens == 0 {
				return nil, errors.New("every server requires an explicit supported listener")
			}
		}
	}
	return contents, nil
}

func (n *Nginx) expandedBudget(p *nginxconfig.Parsed, nodes []*nginxconfig.Node, depth int, count *int) error {
	if depth > limits.Depth {
		return errors.New("expanded configuration depth limit")
	}
	expanded, err := n.expand(p, nodes, 0)
	if err != nil {
		return err
	}
	for _, node := range expanded {
		*count += 1
		if *count > limits.Directives {
			return errors.New("expanded configuration directive limit")
		}
		if err := n.expandedBudget(p, node.Children, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func (n *Nginx) runtimeDirectories() error {
	if err := secure.RootDirectory(filepath.Join(n.DataDir, "nginx", "tmp"), 0755); err != nil {
		return err
	}
	for _, name := range []string{"client", "proxy"} {
		dir := filepath.Join(n.DataDir, "nginx", "tmp", name)
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			if err := os.Mkdir(dir, 0700); err != nil {
				return err
			}
			if err := os.Chown(dir, n.uid, n.gid); err != nil {
				return err
			}
		} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid Nginx temporary directory")
		} else {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(stat.Uid) != n.uid || int(stat.Gid) != n.gid || info.Mode().Perm() != 0700 {
				return errors.New("Nginx temporary directory ownership changed")
			}
		}
	}
	return nil
}

func parseListener(args []nginxconfig.Token, kind string) (listener, bool, error) {
	if len(args) == 0 {
		return listener{}, false, errors.New("empty listener")
	}
	address := args[0].Value
	if strings.Contains(address, "$") || strings.HasPrefix(address, "unix:") {
		return listener{}, false, errors.New("only literal IP/port listeners are supported")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		if strings.Contains(address, ":") {
			return listener{}, false, errors.New("invalid listener address")
		}
		host, port = "0.0.0.0", address
	}
	if host == "" || host == "*" {
		host = "0.0.0.0"
	}
	ip := net.ParseIP(host)
	number, err := strconv.Atoi(port)
	if ip == nil || err != nil || number < 1 || number > 65535 {
		return listener{}, false, errors.New("invalid listener address or port")
	}
	l := listener{Network: "tcp4", IP: ip.String(), Port: number}
	if strings.Contains(host, ":") {
		l.Network = "tcp6"
	}
	ssl := false
	for _, arg := range args[1:] {
		switch arg.Value {
		case "udp":
			if kind != "stream" {
				return l, false, errors.New("HTTP UDP listener is unsupported")
			}
			l.Network = strings.Replace(l.Network, "tcp", "udp", 1)
		case "ssl":
			if kind != "http" {
				return l, false, errors.New("Stream TLS termination is unsupported")
			}
			ssl = true
		case "quic":
			return l, false, errors.New("QUIC listeners are unsupported")
		case "ipv6only=off":
			l.DualStack = true
		}
	}
	return l, ssl, nil
}
func listenerAddress(l listener) string {
	ip := net.ParseIP(l.IP)
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			ip = net.ParseIP("127.0.0.1")
		} else {
			ip = net.ParseIP("::1")
		}
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(l.Port))
}

func (n *Nginx) certificateFile(name string) ([]byte, error) {
	if !strings.HasPrefix(name, "certificates/") || path.Clean(name) != name || strings.Contains(name, "$") {
		return nil, errors.New("invalid managed certificate path")
	}
	full := filepath.Join(n.DataDir, name)
	resolved, err := trustedFile(full, false)
	if err != nil || resolved != full {
		return nil, errors.New("certificate is missing or externally modified")
	}
	info, err := os.Stat(full)
	if err != nil || info.Size() > 1<<20 {
		return nil, errors.New("certificate exceeds size limit")
	}
	return os.ReadFile(full)
}
func (n *Nginx) tlsExpectation(l listener, server, parent []*nginxconfig.Node) (tlsProbe, error) {
	certs := []string{}
	names := []string{}
	for _, node := range server {
		if node.Name == "ssl_certificate" && len(node.Args) == 1 {
			certs = append(certs, node.Args[0].Value)
		}
		if node.Name == "server_name" {
			for _, a := range node.Args {
				names = append(names, a.Value)
			}
		}
	}
	if len(certs) == 0 {
		for _, node := range parent {
			if node.Name == "ssl_certificate" && len(node.Args) == 1 {
				certs = append(certs, node.Args[0].Value)
			}
		}
	}
	if len(certs) != 1 {
		return tlsProbe{}, errors.New("a TLS listener requires one unambiguous certificate")
	}
	b, err := n.certificateFile(certs[0])
	if err != nil {
		return tlsProbe{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return tlsProbe{}, errors.New("invalid TLS certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tlsProbe{}, err
	}
	sni := ""
	for _, name := range names {
		if name != "_" && !strings.HasPrefix(name, "~") && !strings.Contains(name, "$") {
			sni = name
			break
		}
	}
	if strings.HasPrefix(sni, "*.") {
		sni = "nginxpanel-probe." + sni[2:]
	}
	if strings.HasPrefix(sni, ".") {
		sni = "nginxpanel-probe" + sni
	}
	return tlsProbe{Address: listenerAddress(l), ServerName: sni, Fingerprint: secure.Hash(cert.Raw)}, nil
}
