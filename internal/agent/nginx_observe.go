package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/secure"
)

func (n *Nginx) waitObserved(ctx context.Context, m manifest) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := n.observe(attempt, m)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (n *Nginx) observe(ctx context.Context, m manifest) error {
	pid, err := n.masterPID()
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", n.runPath("nginx-probe.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("unexpected probe redirect") }}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/__nginxpanel_revision", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	b, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
	resp.Body.Close()
	if readErr != nil || resp.StatusCode != 200 || string(b) != m.Probe {
		return errors.New("running revision probe mismatch")
	}
	owned, err := processSockets(pid)
	if err != nil {
		return err
	}
	sockets, err := networkSockets()
	if err != nil {
		return err
	}
	for _, want := range m.Listeners {
		found := false
		for _, socket := range sockets {
			if socket.listener.Network == want.Network && socket.listener.IP == want.IP && socket.listener.Port == want.Port && owned[socket.inode] {
				found = true
				break
			}
		}
		if !found {
			return errors.New("Nginx listener ownership is unconfirmed")
		}
	}
	for _, socket := range sockets {
		if !owned[socket.inode] {
			continue
		}
		found := false
		for _, want := range m.Listeners {
			if socket.listener.Network == want.Network && socket.listener.IP == want.IP && socket.listener.Port == want.Port {
				found = true
				break
			}
		}
		if !found {
			return errors.New("unexpected Nginx listener remains active")
		}
	}
	for _, probe := range m.TLS {
		// The certificate is pinned to the immutable revision. Public-CA trust
		// is deliberately not used for local deployment confirmation.
		dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: probe.ServerName, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || secure.Hash(state.PeerCertificates[0].Raw) != probe.Fingerprint {
				return errors.New("deployed TLS certificate mismatch")
			}
			return nil
		}}}
		conn, err := dialer.DialContext(ctx, "tcp", probe.Address)
		if err != nil {
			return err
		}
		conn.Close()
	}
	return nil
}
func processSockets(pid int) (map[string]bool, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, entry := range entries {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			out[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	return out, nil
}

type networkSocket struct {
	listener listener
	inode    string
}

func networkSockets() ([]networkSocket, error) {
	out := []networkSocket{}
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		name := strings.TrimSuffix(network, "4")
		f, err := os.Open("/proc/net/" + name)
		if os.IsNotExist(err) && strings.HasSuffix(network, "6") {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				f.Close()
				return nil, errors.New("invalid kernel socket table")
			}
			if strings.HasPrefix(network, "tcp") && fields[3] != "0A" {
				continue
			}
			if strings.HasPrefix(network, "udp") && fields[3] != "07" {
				continue
			}
			ipHex, portHex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			bytes, err := hex.DecodeString(ipHex)
			if err != nil {
				continue
			}
			for start := 0; start+4 <= len(bytes); start += 4 {
				bytes[start], bytes[start+3] = bytes[start+3], bytes[start]
				bytes[start+1], bytes[start+2] = bytes[start+2], bytes[start+1]
			}
			port, err := strconv.ParseInt(portHex, 16, 32)
			if err != nil {
				continue
			}
			out = append(out, networkSocket{listener: listener{Network: network, IP: net.IP(bytes).String(), Port: int(port)}, inode: fields[9]})
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
