package nginxconfig

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"sort"
	"time"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
)

type CertificateUse struct {
	FileID                    string
	Position                  int
	ResourceID, Path, Purpose string
}

func (p *Parsed) CertificateUses() ([]CertificateUse, error) {
	out := []CertificateUse{}
	unique := map[string]bool{}
	for _, doc := range p.Documents {
		var walk func([]*Node, string) error
		walk = func(nodes []*Node, owner string) error {
			for _, node := range nodes {
				nextOwner := owner
				if node.ResourceID != "" {
					nextOwner = node.ResourceID
				}
				switch node.Name {
				case "ssl_certificate", "ssl_certificate_key", "ssl_trusted_certificate", "proxy_ssl_trusted_certificate":
					if len(node.Args) != 1 {
						return errors.New("证书指令须引用一个受管不可变版本")
					}
					name := node.Args[0].Value
					_, _, kind, managed := certificates.Reference(name)
					if !managed {
						if (node.Name == "ssl_trusted_certificate" || node.Name == "proxy_ssl_trusted_certificate") && certificates.IsSystemCA(name) {
							continue
						}
						return errors.New("证书路径未登记为受管不可变版本")
					}
					if node.Name == "ssl_certificate_key" && kind != "privatekey" || node.Name != "ssl_certificate_key" && kind != "fullchain" {
						return errors.New("证书链与私钥路径用途不一致")
					}
					unique[name] = true
					if len(unique) > limits.CertificateReferences {
						return errors.New("证书引用超过限制")
					}
					out = append(out, CertificateUse{doc.File.ID, node.Start, nextOwner, name, node.Name})
				}
				if err := walk(node.Children, nextOwner); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(doc.Nodes, ""); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FileID != out[j].FileID {
			return out[i].FileID < out[j].FileID
		}
		return out[i].Position < out[j].Position
	})
	return out, nil
}

// ExpandNodes follows only the logical tree. Disabled policy files are empty in
// runtime candidates; native source remains available for projection and edits.
func (p *Parsed) ExpandNodes(nodes []*Node, depth int) ([]*Node, error) {
	if depth > limits.Depth {
		return nil, errors.New("include nesting limit")
	}
	out := []*Node{}
	for _, node := range nodes {
		if node.Name != "include" {
			out = append(out, node)
		} else {
			if len(node.Args) != 1 {
				return nil, errors.New("invalid include")
			}
			names := []string{}
			byPath := map[string]*Document{}
			for _, doc := range p.Documents {
				if !p.RuntimeFileEnabled(doc.File.Path) {
					continue
				}
				matched, _ := path.Match(node.Args[0].Value, doc.File.Path)
				if matched {
					names = append(names, doc.File.Path)
					byPath[doc.File.Path] = doc
				}
			}
			sort.Strings(names)
			for _, name := range names {
				children, err := p.ExpandNodes(byPath[name].Nodes, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, children...)
				if len(out) > limits.Directives {
					return nil, errors.New("expanded directive limit")
				}
			}
		}
		if len(out) > limits.Directives {
			return nil, errors.New("expanded directive limit")
		}
	}
	return out, nil
}

func (p *Parsed) ValidateTLS(materials []certificates.Material) error {
	pairs := map[string]*certificates.Pair{}
	for _, material := range materials {
		if !material.ValidIdentity() {
			return errors.New("证书身份无效")
		}
		if pairs[material.VersionID] != nil {
			return errors.New("证书版本重复")
		}
		pair, err := certificates.Parse(material.FullchainPEM, material.PrivateKeyPEM)
		if err != nil {
			return err
		}
		pairs[material.VersionID] = pair
	}
	var main *Document
	for _, doc := range p.Documents {
		if doc.File.Path == "nginx.conf" {
			main = doc
			break
		}
	}
	if main == nil {
		return errors.New("缺少主配置")
	}
	for _, block := range main.Nodes {
		if block.Name != "http" {
			continue
		}
		parent, err := p.ExpandNodes(block.Children, 0)
		if err != nil {
			return err
		}
		values := func(nodes []*Node, name string) []string {
			out := []string{}
			for _, node := range nodes {
				if node.Name == name {
					out = append(out, nodeValues(node)...)
				}
			}
			return out
		}
		for _, server := range parent {
			if server.Name != "server" || !server.Enabled() {
				continue
			}
			nodes, err := p.ExpandNodes(server.Children, 0)
			if err != nil {
				return err
			}
			tls := false
			for _, node := range nodes {
				if node.Name == "listen" && len(node.Args) > 1 {
					for _, arg := range node.Args[1:] {
						if arg.Value == "ssl" {
							tls = true
						}
					}
				}
			}
			if !tls {
				continue
			}
			certPaths, keyPaths := values(nodes, "ssl_certificate"), values(nodes, "ssl_certificate_key")
			if len(certPaths) == 0 {
				certPaths = values(parent, "ssl_certificate")
			}
			if len(keyPaths) == 0 {
				keyPaths = values(parent, "ssl_certificate_key")
			}
			if len(certPaths) != 1 || len(keyPaths) != 1 {
				return errors.New("HTTPS 站点需要唯一的证书链与私钥")
			}
			id, version, _, ok := certificates.Reference(certPaths[0])
			keyID, keyVersion, _, keyOK := certificates.Reference(keyPaths[0])
			if !ok || !keyOK || id != keyID || version != keyVersion {
				return errors.New("HTTPS 证书链与私钥须属于同一不可变版本")
			}
			pair := pairs[version]
			if pair == nil {
				return errors.New("HTTPS 证书材料缺失")
			}
			if err := pair.Validate(time.Now()); err != nil {
				return err
			}
			if err := pair.Covers(values(nodes, "server_name")); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) CertificateMaterials(ctx context.Context, tree Tree) ([]certificates.Material, error) {
	p, err := Parse(tree.Files, s.Policy)
	if err != nil {
		return nil, err
	}
	uses, err := p.CertificateUses()
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for _, use := range uses {
		paths = append(paths, use.Path)
	}
	if len(paths) == 0 {
		return []certificates.Material{}, nil
	}
	if s.Certificates == nil {
		return nil, errors.New("证书存储未连接")
	}
	return s.Certificates.Materials(ctx, s.DB, paths)
}
func (s *Service) validateCertificates(ctx context.Context, tx *sql.Tx, p *Parsed) ([]CertificateUse, error) {
	uses, err := p.CertificateUses()
	if err != nil {
		return nil, fault.Invalid(err.Error())
	}
	paths := []string{}
	for _, use := range uses {
		paths = append(paths, use.Path)
	}
	materials := []certificates.Material{}
	if len(paths) > 0 {
		if s.Certificates == nil {
			return nil, fault.Unavailable("证书存储未连接")
		}
		materials, err = s.Certificates.Materials(ctx, tx, paths)
		if err != nil {
			return nil, err
		}
	}
	if err := p.ValidateTLS(materials); err != nil {
		return nil, fault.Invalid(err.Error())
	}
	return uses, nil
}
