// Package remoteapi provides the shared HTTPS boundary for registered nodes and migration.
package remoteapi

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type Endpoint struct {
	URL         string
	APIKey      string
	Fingerprint string
}

// Client fixes the API origin, checks resolved addresses on every dial, and
// refuses proxy settings and redirects. A supplied pin replaces public CA trust.
func Client(remote Endpoint) (*http.Client, string, error) {
	u, err := url.Parse(remote.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(remote.URL) > 2048 || (u.Path != "" && u.Path != "/" && u.Path != "/api/v1") || strings.ContainsAny(remote.APIKey, "\x00\r\n") || len(remote.APIKey) < 20 || len(remote.APIKey) > 512 {
		return nil, "", fault.Invalid("远程 API 须为 HTTPS 根地址或 /api/v1，并提供有效 Key")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if remote.Fingerprint != "" {
		pin, err := hex.DecodeString(remote.Fingerprint)
		if err != nil || len(pin) != 32 {
			return nil, "", fault.Invalid("TLS 指纹须为 64 位十六进制 SHA-256")
		}
		config.InsecureSkipVerify = true // A locally supplied exact certificate pin replaces public CA trust.
		config.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing certificate")
			}
			leaf := cs.PeerCertificates[0]
			now := time.Now()
			if secure.Hash(leaf.Raw) != strings.ToLower(remote.Fingerprint) || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errors.New("certificate pin or validity mismatch")
			}
			return nil
		}
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 || len(ips) > 16 {
			return nil, errors.New("unresolved destination")
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip == netip.MustParseAddr("100.100.100.200") {
				return nil, errors.New("reserved destination")
			}
		}
		d := net.Dialer{Timeout: 8 * time.Second}
		var last error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: config, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	return client, "https://" + u.Host + "/api/v1", nil
}
