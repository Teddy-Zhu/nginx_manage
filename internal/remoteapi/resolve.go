package remoteapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// Resolve establishes initial certificate trust without sending credentials.
// Public certificates retain normal CA/name verification, including renewals.
// Private certificates use first-contact trust; callers persist the returned
// pin before exchanging secrets so retries cannot silently accept another key.
func Resolve(ctx context.Context, remote Endpoint) (Endpoint, error) {
	client, base, err := Client(remote)
	if err != nil {
		return remote, err
	}
	defer client.CloseIdleConnections()
	if remote.Fingerprint != "" {
		remote.Fingerprint = strings.ToLower(remote.Fingerprint)
		return remote, nil
	}
	target, _ := url.Parse(base)
	port := target.Port()
	if port == "" {
		port = "443"
	}
	work, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := client.Transport.(*http.Transport)
	raw, err := transport.DialContext(work, "tcp", net.JoinHostPort(target.Hostname(), port))
	if err != nil {
		return remote, connectionError()
	}
	defer raw.Close()
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.Hostname(), InsecureSkipVerify: true} // Verification below selects CA trust or a first-contact pin.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("missing certificate")
		}
		leaf := state.PeerCertificates[0]
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return errors.New("certificate expired or not yet valid")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: target.Hostname(), Intermediates: intermediates, CurrentTime: now})
		if verifyErr == nil {
			return nil
		}
		var unknown x509.UnknownAuthorityError
		selfSigned := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
		if !errors.As(verifyErr, &unknown) && !selfSigned {
			return verifyErr
		}
		remote.Fingerprint = secure.Hash(leaf.Raw)
		return nil
	}
	conn := tls.Client(raw, config)
	defer conn.Close()
	if err = conn.HandshakeContext(work); err != nil {
		return remote, connectionError()
	}
	return remote, nil
}
func connectionError() error {
	return fault.New(http.StatusBadGateway, "REMOTE_TLS_FAILED", "无法建立安全连接，请检查服务器地址、证书有效期及网络")
}
