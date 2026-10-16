package migration

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

var archiveNames = map[string]bool{"config/host-dns.json": true, "config/monitoring.json": true, "config/fail2ban.json": true, "config/firewall.json": true, "manifest.json": true, "config/nginx-tree.json": true, "certificates/materials.json": true, "secrets/dns-credentials.json": true, "config/acme.json": true, "secrets/notification-channels.json": true}

func validPassphrase(value string) bool {
	return len(value) >= 16 && len(value) <= 256 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validateExport(in ExportInput) error {
	switch in.Mode {
	case "portable":
		if in.Passphrase != "" || in.Selection != (Selection{}) {
			return fault.Invalid("可移植配置不使用口令，也不携带完整原文或可选材料")
		}
	case "encrypted":
		if !validPassphrase(in.Passphrase) {
			return fault.Invalid("迁移口令须为 16–256 字节")
		}
		if in.Selection.Automation && (!in.Selection.Certificates || !in.Selection.DNSCredentials) {
			return fault.Invalid("导出 ACME 配置须同时选择证书与 DNS 凭据")
		}
	default:
		return fault.Invalid("配置包模式须为 portable 或 encrypted")
	}
	return nil
}

func selectedArchiveNames(m Manifest) map[string]bool {
	names := map[string]bool{"config/nginx-tree.json": true}
	for name, selected := range map[string]bool{
		"config/host-dns.json": m.Selection.HostDNS, "config/monitoring.json": m.Selection.Monitoring,
		"config/fail2ban.json": m.Selection.Fail2ban, "config/firewall.json": m.Selection.Firewall,
		"certificates/materials.json": m.Selection.Certificates, "secrets/dns-credentials.json": m.Selection.DNSCredentials,
		"config/acme.json": m.Selection.Automation, "secrets/notification-channels.json": m.Selection.Notifications,
	} {
		if selected {
			names[name] = true
		}
	}
	return names
}

func encodeArchive(manifest *Manifest, payload Payload, passphrase string) ([]byte, error) {
	if err := validateExport(ExportInput{Mode: manifest.Mode, Passphrase: passphrase, Selection: manifest.Selection}); err != nil {
		return nil, err
	}
	if manifest.Mode == "portable" {
		if err := nginxconfig.ValidatePortableFiles(payload.Files); err != nil {
			return nil, err
		}
	}
	entries := map[string][]byte{}
	nameset := selectedArchiveNames(*manifest)
	for name, value := range map[string]any{"config/host-dns.json": payload.HostDNS, "config/monitoring.json": payload.Monitoring, "config/fail2ban.json": payload.Fail2ban, "config/firewall.json": payload.Firewall, "config/nginx-tree.json": payload.Files, "certificates/materials.json": payload.Certificates, "secrets/dns-credentials.json": payload.Credentials, "config/acme.json": payload.Automation, "secrets/notification-channels.json": payload.Channels} {
		if !nameset[name] {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		entries[name] = raw
	}
	manifest.Files = map[string]string{}
	for name, raw := range entries {
		manifest.Files[name] = secure.Hash(raw)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	entries["manifest.json"] = raw
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := entries[name]
		if plain.Len()+len(raw)+2048 > MaxPackageBytes {
			return nil, fault.Invalid("迁移包超过 8 MiB，请减少导出范围")
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(raw); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if manifest.Mode == "portable" {
		return plain.Bytes(), nil
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain.Bytes()); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if encrypted.Len() > MaxPackageBytes {
		return nil, fault.Invalid("加密迁移包超过 8 MiB")
	}
	return encrypted.Bytes(), nil
}

func decodeStrict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeArchive(content []byte, passphrase string) (Manifest, Payload, error) {
	var m Manifest
	var p Payload
	invalid := fault.Invalid("迁移包损坏、口令错误、格式不受支持或超过限制")
	if len(content) == 0 || len(content) > MaxPackageBytes {
		return m, p, invalid
	}
	encrypted := bytes.HasPrefix(content, []byte("age-encryption.org/v1\n"))
	plain := content
	if encrypted {
		if !validPassphrase(passphrase) {
			return m, p, invalid
		}
		identity, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return m, p, invalid
		}
		identity.SetMaxWorkFactor(18)
		r, err := age.Decrypt(bytes.NewReader(content), identity)
		if err != nil {
			return m, p, invalid
		}
		// Authenticate the whole stream, including its final chunk, before parsing.
		plain, err = io.ReadAll(io.LimitReader(r, MaxPackageBytes+1))
		if err != nil || len(plain) > MaxPackageBytes {
			return m, p, invalid
		}
	} else if passphrase != "" {
		return m, p, invalid
	}
	buffer := bytes.NewReader(plain)
	tr := tar.NewReader(buffer)
	entries := map[string][]byte{}
	total := int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, p, invalid
		}
		if !archiveNames[h.Name] || h.Typeflag != tar.TypeReg || h.Linkname != "" || len(h.PAXRecords) > 0 || h.Size < 0 || h.Size > MaxPackageBytes || len(entries) >= len(archiveNames) {
			return m, p, invalid
		}
		if _, exists := entries[h.Name]; exists {
			return m, p, invalid
		}
		total += h.Size
		if total > MaxPackageBytes {
			return m, p, invalid
		}
		raw, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(raw)) != h.Size {
			return m, p, invalid
		}
		entries[h.Name] = raw
	}
	if trailing, err := io.ReadAll(buffer); err != nil || len(bytes.Trim(trailing, "\x00")) > 0 {
		return m, p, invalid
	}
	if decodeStrict(entries["manifest.json"], &m) != nil || m.Schema != Schema || len(m.SourceNode) > 64 || m.SourceNode == "" || len(m.SourceVersion) > 128 || len(m.Omissions) > 64 {
		return m, p, invalid
	}
	if (encrypted && m.Mode != "encrypted") || (!encrypted && m.Mode != "portable") || validateExport(ExportInput{Mode: m.Mode, Passphrase: passphrase, Selection: m.Selection}) != nil {
		return m, p, invalid
	}
	expected := selectedArchiveNames(m)
	if len(entries) != len(expected)+1 || len(m.Files) != len(expected) {
		return m, p, invalid
	}
	for name := range expected {
		if _, ok := entries[name]; !ok {
			return m, p, invalid
		}
	}
	for _, omission := range m.Omissions {
		if len(omission) > 1024 {
			return m, p, invalid
		}
	}
	for name, raw := range entries {
		if name != "manifest.json" && m.Files[name] != secure.Hash(raw) {
			return m, p, invalid
		}
	}
	decode := func(name string, out any) error {
		raw, ok := entries[name]
		if !ok {
			return nil
		}
		return decodeStrict(raw, out)
	}
	if decode("config/nginx-tree.json", &p.Files) != nil || decode("certificates/materials.json", &p.Certificates) != nil || decode("secrets/dns-credentials.json", &p.Credentials) != nil {
		return m, p, invalid
	}
	if decode("config/host-dns.json", &p.HostDNS) != nil || m.Selection.HostDNS != (p.HostDNS != nil) || hostdns.ValidateTransfer(p.HostDNS) != nil {
		return m, p, invalid
	}
	if decode("config/monitoring.json", &p.Monitoring) != nil || m.Selection.Monitoring != (p.Monitoring != nil) || p.Monitoring != nil && p.Monitoring.Validate() != nil {
		return m, p, invalid
	}
	if decode("config/fail2ban.json", &p.Fail2ban) != nil || m.Selection.Fail2ban != (p.Fail2ban != nil) || fail2ban.ValidateTransfer(p.Fail2ban) != nil {
		return m, p, invalid
	}
	if decode("config/firewall.json", &p.Firewall) != nil || (m.Selection.Firewall != (p.Firewall != nil)) || firewall.ValidateTransfer(p.Firewall) != nil {
		return m, p, invalid
	}
	if decode("config/acme.json", &p.Automation) != nil || decode("secrets/notification-channels.json", &p.Channels) != nil {
		return m, p, invalid
	}
	if !m.Selection.Certificates && len(p.Certificates) > 0 || !m.Selection.DNSCredentials && len(p.Credentials) > 0 {
		return m, p, invalid
	}
	if !m.Selection.Automation && (len(p.Automation.Accounts) > 0 || len(p.Automation.Profiles) > 0) || !m.Selection.Notifications && len(p.Channels) > 0 {
		return m, p, invalid
	}
	if m.Mode == "portable" {
		if nginxconfig.ValidatePortableFiles(p.Files) != nil {
			return m, p, invalid
		}
	}
	return m, p, nil
}
