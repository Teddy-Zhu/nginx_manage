package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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
	expectedProbe, err := n.revisionProbe(m)
	if err != nil {
		return err
	}
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
	if readErr != nil || resp.StatusCode != 200 || string(b) != expectedProbe {
		return errors.New("running revision probe mismatch")
	}
	owned, err := processSockets(pid)
	if err != nil {
		return err
	}
	sockets, err := networkSockets(ctx)
	if err != nil {
		return err
	}
	if err := confirmNginxListeners(m.Listeners, owned, sockets); err != nil {
		return err
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
