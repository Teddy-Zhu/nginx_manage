// Package remotelisten defines the optional management ingress. The permanent
// loopback listener and its TLS material are deliberately outside this policy.
package remotelisten

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"time"

	"nginxpanel/internal/fault"
)

const ConfirmationSeconds = 120

type PublicConfig struct {
	Enabled              bool     `json:"enabled"`
	Listen               string   `json:"listen"`
	AllowedSources       []string `json:"allowed_sources"`
	Fingerprint          string   `json:"tls_fingerprint"`
	CertificateExpiresAt int64    `json:"certificate_expires_at"`
}

type Config struct {
	Enabled        bool     `json:"enabled"`
	Listen         string   `json:"listen"`
	AllowedSources []string `json:"allowed_sources"`
	CertificatePEM string   `json:"certificate_pem"`
	KeyPEM         string   `json:"key_pem"`
}

type Input struct {
	Version           int64    `json:"version"`
	Enabled           bool     `json:"enabled"`
	Listen            string   `json:"listen"`
	AllowedSources    []string `json:"allowed_sources"`
	CertificatePEM    string   `json:"certificate_pem"`
	KeyPEM            string   `json:"key_pem"`
	RotateCertificate bool     `json:"rotate_certificate"`
}

func (in *Input) UnmarshalJSON(raw []byte) error {
	type wireInput Input
	var wire wireInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, key := range []string{"version", "enabled", "listen", "allowed_sources", "certificate_pem", "key_pem", "rotate_certificate"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fault.Invalid("监听请求缺少必填字段")
		}
	}
	*in = Input(wire)
	return nil
}

type Operation struct {
	ID              string       `json:"id"`
	Version         int64        `json:"version"`
	State           string       `json:"state"`
	Stage           string       `json:"stage"`
	Deadline        int64        `json:"deadline"`
	Config          PublicConfig `json:"config"`
	ConfirmedSource string       `json:"confirmed_source"`
	Error           string       `json:"error"`
}

type View struct {
	Available bool         `json:"available"`
	Version   int64        `json:"version"`
	Confirmed PublicConfig `json:"confirmed"`
	Operation *Operation   `json:"operation"`
	Serving   bool         `json:"serving"`
	Attached  bool         `json:"attached"`
	Reason    string       `json:"reason"`
}

func (c Config) Public() PublicConfig {
	p := PublicConfig{Enabled: c.Enabled, Listen: c.Listen, AllowedSources: append([]string{}, c.AllowedSources...)}
	if cert, err := tls.X509KeyPair([]byte(c.CertificatePEM), []byte(c.KeyPEM)); err == nil && len(cert.Certificate) > 0 {
		hash := sha256.Sum256(cert.Certificate[0])
		p.Fingerprint = hex.EncodeToString(hash[:])
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			p.CertificateExpiresAt = leaf.NotAfter.Unix()
		}
	}
	return p
}

func (c Config) Validate(checkTime bool) error {
	if !c.Enabled {
		if c.Listen != "" || len(c.AllowedSources) != 0 || c.CertificatePEM != "" || c.KeyPEM != "" {
			return fault.Invalid("停用监听不能包含地址或证书")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(c.Listen)
	ip, e := netip.ParseAddr(host)
	n, pErr := strconv.Atoi(port)
	if err != nil || e != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || pErr != nil || n < 1024 || n > 65535 || net.JoinHostPort(ip.String(), strconv.Itoa(n)) != c.Listen {
		return fault.Invalid("监听须使用规范 IP 地址及 1024–65535 端口，不能占用回环入口")
	}
	if len(c.AllowedSources) == 0 || len(c.AllowedSources) > 32 {
		return fault.Invalid("须配置 1–32 个允许来源 CIDR")
	}
	seen := map[string]bool{}
	for _, source := range c.AllowedSources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.String() != source || seen[source] {
			return fault.Invalid("允许来源须为不重复的规范 CIDR")
		}
		seen[source] = true
	}
	if len(c.CertificatePEM) > 16<<10 || len(c.KeyPEM) > 8<<10 {
		return fault.Invalid("监听证书或私钥超出限制")
	}
	cert, err := tls.X509KeyPair([]byte(c.CertificatePEM), []byte(c.KeyPEM))
	if err != nil || len(cert.Certificate) == 0 || len(cert.Certificate) > 4 {
		return fault.Invalid("监听证书与私钥无效或不匹配")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.IsCA || (checkTime && (time.Now().Before(leaf.NotBefore) || !time.Now().Add(5*time.Minute).Before(leaf.NotAfter))) {
		return fault.Invalid("监听证书用途或有效期无效")
	}
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
			return fault.Invalid("监听 RSA 密钥须为 2048–8192 位")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return fault.Invalid("监听 ECDSA 密钥至少为 256 位")
		}
	case ed25519.PublicKey:
	default:
		return fault.Invalid("监听证书密钥类型不支持")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		server := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				server = true
			}
		}
		if !server {
			return fault.Invalid("监听证书不允许服务器认证")
		}
	}
	return nil
}

func (c Config) Allows(remote net.Addr) bool {
	address, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return false
	}
	ip := address.Addr().Unmap()
	for _, source := range c.AllowedSources {
		prefix, err := netip.ParsePrefix(source)
		if err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
