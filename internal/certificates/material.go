package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
var dnsName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
var systemCA = regexp.MustCompile(`^certificates/ca/system/[a-f0-9]{64}\.pem$`)

type Material struct {
	CertificateID string `json:"certificate_id"`
	VersionID     string `json:"version_id"`
	FullchainPEM  string `json:"fullchain_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
}
type Summary struct {
	DNSNames       []string `json:"dns_names"`
	IPAddresses    []string `json:"ip_addresses"`
	Issuer         string   `json:"issuer"`
	Subject        string   `json:"subject"`
	NotBefore      int64    `json:"not_before"`
	NotAfter       int64    `json:"not_after"`
	ChainNotBefore int64    `json:"chain_not_before"`
	ChainNotAfter  int64    `json:"chain_not_after"`
	Fingerprint    string   `json:"fingerprint"`
	KeyAlgorithm   string   `json:"key_algorithm"`
	ChainLength    int      `json:"chain_length"`
	Trust          string   `json:"trust"`
}
type Pair struct {
	Summary          Summary
	Chain            []*x509.Certificate
	ChainPEM, KeyPEM string
}

func Path(id, version, kind string) string {
	return "certificates/" + id + "/" + version + "/" + kind + ".pem"
}
func Reference(name string) (id, version, kind string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != "certificates" || !uuid.MatchString(parts[1]) || !uuid.MatchString(parts[2]) || (parts[3] != "fullchain.pem" && parts[3] != "privatekey.pem") {
		return
	}
	return parts[1], parts[2], strings.TrimSuffix(parts[3], ".pem"), true
}
func IsSystemCA(name string) bool { return systemCA.MatchString(name) }
func (m Material) ValidIdentity() bool {
	return uuid.MatchString(m.CertificateID) && uuid.MatchString(m.VersionID)
}

// Parse accepts only an ordered, connected PEM chain and one unencrypted key.
// Retained versions remain readable after expiry or trust-store changes.
// Import and active bindings separately require Validate(now).
func Parse(chainText, keyText string) (*Pair, error) {
	if len(chainText)+len(keyText) > limits.CertificateMaterialBytes || len(chainText) == 0 || len(keyText) == 0 {
		return nil, errors.New("证书材料为空或超过 128 KiB")
	}
	chain := []*x509.Certificate{}
	var normalized bytes.Buffer
	rest := bytes.TrimSpace([]byte(chainText))
	seen := map[string]bool{}
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("证书链只能包含 PEM CERTIFICATE 块")
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, errors.New("证书 PEM 格式无效")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("证书无法解析")
		}
		fingerprint := secure.Hash(cert.Raw)
		if seen[fingerprint] {
			return nil, errors.New("证书链含重复证书")
		}
		seen[fingerprint] = true
		chain = append(chain, cert)
		if len(chain) > limits.CertificateChain {
			return nil, errors.New("证书链超过 16 张")
		}
		normalized.Write(pem.EncodeToMemory(block))
		rest = bytes.TrimSpace(next)
	}
	keyData := bytes.TrimSpace([]byte(keyText))
	if len(keyData) > 16<<10 {
		return nil, errors.New("私钥 PEM 超过 16 KiB")
	}
	keyBlock, keyRest := pem.Decode(keyData)
	if keyBlock == nil || !bytes.HasPrefix(keyData, []byte("-----BEGIN "+keyBlock.Type+"-----")) || len(bytes.TrimSpace(keyRest)) > 0 || len(keyBlock.Headers) > 0 || (keyBlock.Type != "PRIVATE KEY" && keyBlock.Type != "RSA PRIVATE KEY" && keyBlock.Type != "EC PRIVATE KEY") {
		return nil, errors.New("私钥须为一个未加密的 PKCS#8、RSA 或 EC PEM 块")
	}
	pair, err := tls.X509KeyPair(normalized.Bytes(), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, errors.New("证书与私钥不匹配或私钥无效")
	}
	algorithm := ""
	switch key := pair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
			return nil, errors.New("RSA 私钥须为 2048–8192 位")
		}
		algorithm = "RSA"
	case *ecdsa.PrivateKey:
		if key.Curve.Params().BitSize < 256 {
			return nil, errors.New("EC 私钥至少需要 256 位")
		}
		algorithm = "ECDSA"
	case ed25519.PrivateKey:
		algorithm = "Ed25519"
	default:
		return nil, errors.New("当前仅支持 RSA、ECDSA 与 Ed25519 私钥")
	}
	leaf := chain[0]
	if leaf.IsCA || len(leaf.DNSNames)+len(leaf.IPAddresses) == 0 {
		return nil, errors.New("需要含 DNS 或 IP SAN 的服务器终端证书")
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses) > 64 || len(leaf.Subject.String()) > 2048 || len(leaf.Issuer.String()) > 2048 {
		return nil, errors.New("证书 SAN 或主体信息超过限制")
	}
	for _, name := range leaf.DNSNames {
		if len(name) > 253 {
			return nil, errors.New("证书 DNS SAN 超过 253 字节")
		}
	}
	from, until := leaf.NotBefore, leaf.NotAfter
	for i, cert := range chain {
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
				return nil, errors.New("证书链 RSA 公钥须为 2048–8192 位")
			}
		case *ecdsa.PublicKey:
			if key.Curve.Params().BitSize < 256 {
				return nil, errors.New("证书链 EC 公钥至少需要 256 位")
			}
		case ed25519.PublicKey:
		default:
			return nil, errors.New("证书链公钥算法不受支持")
		}
		if cert.NotBefore.After(from) {
			from = cert.NotBefore
		}
		if cert.NotAfter.Before(until) {
			until = cert.NotAfter
		}
		if i+1 < len(chain) {
			issuer := chain[i+1]
			if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || cert.CheckSignatureFrom(issuer) != nil {
				return nil, errors.New("证书链顺序错误、签名无效或签发者不是 CA")
			}
		}
	}
	if !from.Before(until) {
		return nil, errors.New("证书链不存在共同有效期")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return nil, errors.New("私钥无法规范化")
	}
	names := append([]string{}, leaf.DNSNames...)
	ips := []string{}
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if normalized.Len()+len(keyPEM) > limits.CertificateMaterialBytes {
		return nil, errors.New("规范化证书材料超过 128 KiB")
	}
	return &Pair{Summary: Summary{DNSNames: names, IPAddresses: ips, Issuer: leaf.Issuer.String(), Subject: leaf.Subject.String(), NotBefore: leaf.NotBefore.Unix(), NotAfter: leaf.NotAfter.Unix(), ChainNotBefore: from.Unix(), ChainNotAfter: until.Unix(), Fingerprint: secure.Hash(leaf.Raw), KeyAlgorithm: algorithm, ChainLength: len(chain)}, Chain: chain, ChainPEM: normalized.String(), KeyPEM: keyPEM}, nil
}
func (p *Pair) ValidAt(now time.Time) error {
	for _, cert := range p.Chain {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return errors.New("证书链尚未生效或已过期")
		}
	}
	return nil
}
func (p *Pair) Validate(now time.Time) error {
	if err := p.ValidAt(now); err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for _, cert := range p.Chain[1:] {
		intermediates.AddCert(cert)
	}
	leaf := p.Chain[0]
	options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	p.Summary.Trust = "system"
	if _, err := leaf.Verify(options); err == nil {
		return nil
	}
	last := p.Chain[len(p.Chain)-1]
	if !bytes.Equal(last.RawIssuer, last.RawSubject) || last.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature) != nil {
		return errors.New("证书链无法到达已知根；私有 CA 须包含自签根证书")
	}
	privateRoots := x509.NewCertPool()
	privateRoots.AddCert(last)
	options.Roots = privateRoots
	if _, err := leaf.Verify(options); err != nil {
		return errors.New("证书链不适用于 TLS 服务器或包含无效约束")
	}
	p.Summary.Trust = "private"
	if len(p.Chain) == 1 {
		p.Summary.Trust = "self_signed"
	}
	return nil
}
func (p *Pair) Covers(names []string) error {
	if len(names) == 0 {
		return errors.New("HTTPS 站点须明确指定证书覆盖的域名或 IP")
	}
	for _, name := range names {
		value := strings.TrimSuffix(strings.ToLower(name), ".")
		if strings.HasPrefix(value, "*.") {
			found := false
			for _, san := range p.Chain[0].DNSNames {
				if strings.ToLower(san) == value {
					found = true
				}
			}
			if !found {
				return errors.New("证书 SAN 未覆盖站点通配域名")
			}
			continue
		}
		if strings.HasPrefix(value, ".") {
			wildcard := false
			for _, san := range p.Chain[0].DNSNames {
				if strings.ToLower(san) == "*"+value {
					wildcard = true
				}
			}
			if p.Chain[0].VerifyHostname(value[1:]) != nil || !wildcard {
				return errors.New("证书 SAN 未同时覆盖根域名及其子域名")
			}
			continue
		}
		if net.ParseIP(strings.Trim(value, "[]")) == nil && !dnsName.MatchString(value) {
			return errors.New("站点域名包含正则、变量或不能可靠核对的模式")
		}
		if p.Chain[0].VerifyHostname(value) != nil {
			return errors.New("证书 SAN 未覆盖站点域名或 IP：" + name)
		}
	}
	return nil
}
