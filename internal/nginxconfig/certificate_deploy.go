package nginxconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type CertificateDeployInput struct {
	BaseVersion int64  `json:"base_version"`
	VersionID   string `json:"version_id"`
}
type CertificateDeployChange struct {
	FileID            string `json:"file_id"`
	ResourceID        string `json:"resource_id"`
	Purpose           string `json:"purpose"`
	PreviousVersionID string `json:"previous_version_id"`
}
type CertificateDeployPreview struct {
	CertificateID string                    `json:"certificate_id"`
	VersionID     string                    `json:"version_id"`
	BaseVersion   int64                     `json:"base_version"`
	BasisRevision string                    `json:"basis_revision"`
	Changes       []CertificateDeployChange `json:"changes"`
}
type CertificateDeployment struct {
	TaskID        string `json:"task_id"`
	CertificateID string `json:"certificate_id"`
	VersionID     string `json:"version_id"`
	BasisRevision string `json:"basis_revision"`
	RevisionID    string `json:"revision_id"`
	Automatic     bool   `json:"automatic"`
	State         string `json:"state"`
	Stage         string `json:"stage"`
	LastError     string `json:"last_error"`
	CreatedAt     int64  `json:"created_at"`
}
type CertificateDeploymentStatus struct {
	VersionID       string                  `json:"version_id"`
	State           string                  `json:"state"`
	CurrentBindings int64                   `json:"current_bindings"`
	AppliedBindings int64                   `json:"applied_bindings"`
	DesiredBindings int64                   `json:"desired_bindings"`
	History         []CertificateDeployment `json:"history"`
}

func (s *Service) certificateDeployment(ctx context.Context, task string) (CertificateDeployment, error) {
	var d CertificateDeployment
	err := s.DB.QueryRowContext(ctx, "SELECT d.task_id,d.certificate_id,d.version_id,d.basis_revision,d.revision_id,d.automatic,t.state,t.stage,t.last_error,d.created_at FROM certificate_deployments d JOIN tasks t ON t.id=d.task_id WHERE d.task_id=?", task).Scan(&d.TaskID, &d.CertificateID, &d.VersionID, &d.BasisRevision, &d.RevisionID, &d.Automatic, &d.State, &d.Stage, &d.LastError, &d.CreatedAt)
	return d, err
}
func (s *Service) CertificateDeployments(ctx context.Context, id string) (CertificateDeploymentStatus, error) {
	var out CertificateDeploymentStatus
	err := s.DB.QueryRowContext(ctx, `SELECT c.latest_version_id,
 COALESCE(SUM(r.revision_id=h.applied_revision),0),
 COALESCE(SUM(r.revision_id=h.applied_revision AND r.version_id=c.latest_version_id),0),
 COALESCE(SUM(r.revision_id=h.desired_revision AND r.version_id=c.latest_version_id),0)
 FROM certificates c CROSS JOIN config_head h
 LEFT JOIN nginx_certificate_references r ON r.certificate_id=c.id AND r.purpose='ssl_certificate'
 AND (r.revision_id=h.applied_revision OR r.revision_id=h.desired_revision)
 WHERE h.id=1 AND c.id=? GROUP BY c.id,c.latest_version_id`, id).Scan(&out.VersionID, &out.CurrentBindings, &out.AppliedBindings, &out.DesiredBindings)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound("证书不存在")
	}
	if err != nil {
		return out, err
	}
	out.State = "unbound"
	if out.CurrentBindings > 0 {
		out.State = "pending"
		if out.AppliedBindings == out.CurrentBindings {
			out.State = "applied"
		} else if out.AppliedBindings > 0 {
			out.State = "partial"
		}
	} else if out.DesiredBindings > 0 {
		out.State = "pending"
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT d.task_id,d.certificate_id,d.version_id,d.basis_revision,d.revision_id,d.automatic,t.state,t.stage,t.last_error,d.created_at FROM certificate_deployments d JOIN tasks t ON t.id=d.task_id WHERE d.certificate_id=? ORDER BY d.created_at DESC,d.task_id DESC LIMIT 32", id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.History = []CertificateDeployment{}
	for rows.Next() {
		var d CertificateDeployment
		if err := rows.Scan(&d.TaskID, &d.CertificateID, &d.VersionID, &d.BasisRevision, &d.RevisionID, &d.Automatic, &d.State, &d.Stage, &d.LastError, &d.CreatedAt); err != nil {
			return out, err
		}
		out.History = append(out.History, d)
	}
	return out, rows.Err()
}

func (s *Service) prepareCertificateDeploy(ctx context.Context, p auth.Principal, id string) (CertificateDeployPreview, []File, error) {
	out := CertificateDeployPreview{CertificateID: id, Changes: []CertificateDeployChange{}}
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return out, nil, err
	}
	var desired, applied sql.NullString
	if err := s.DB.QueryRowContext(ctx, "SELECT version,desired_revision,applied_revision FROM config_head WHERE id=1").Scan(&out.BaseVersion, &desired, &applied); err != nil {
		return out, nil, err
	}
	if !desired.Valid || desired.String != applied.String {
		return out, nil, fault.Conflict("存在待应用的 Nginx 配置，须先处理后再部署证书")
	}
	out.BasisRevision = desired.String
	if err := s.DB.QueryRowContext(ctx, "SELECT latest_version_id FROM certificates WHERE id=?", id).Scan(&out.VersionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return out, nil, fault.NotFound("证书不存在")
		}
		return out, nil, err
	}
	tree, err := s.Get(ctx, desired.String)
	if err != nil {
		return out, nil, err
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil {
		return out, nil, err
	}
	if len(parsed.Tree.Diagnostics) > 0 {
		return out, nil, ErrInvalid
	}
	if err := p.Require(parsed.RequiredScopes...); err != nil {
		return out, nil, err
	}
	uses, err := parsed.CertificateUses()
	if err != nil {
		return out, nil, fault.Invalid(err.Error())
	}
	bound := false
	for _, use := range uses {
		certID, _, _, _ := certificates.Reference(use.Path)
		if certID == id {
			if use.Purpose != "ssl_certificate" && use.Purpose != "ssl_certificate_key" {
				return out, nil, fault.Conflict("该证书还用于信任链配置，须在 Nginx 原文中明确处理后再部署")
			}
			if use.Purpose == "ssl_certificate" {
				bound = true
			}
		}
	}
	if !bound {
		return out, nil, fault.Conflict("证书尚未绑定到 Nginx，请先保存并应用站点绑定")
	}
	files := append([]File{}, tree.Files...)
	for i := range files {
		doc := parsed.Documents[files[i].ID]
		if doc == nil {
			return out, nil, errors.New("certificate deployment document missing")
		}
		edits := []Edit{}
		var walk func([]*Node, string)
		walk = func(nodes []*Node, owner string) {
			for _, node := range nodes {
				resource := owner
				if node.ResourceID != "" {
					resource = node.ResourceID
				}
				if (node.Name == "ssl_certificate" || node.Name == "ssl_certificate_key") && len(node.Args) == 1 {
					certID, version, kind, ok := certificates.Reference(node.Args[0].Value)
					if ok && certID == id && version != out.VersionID {
						edits = append(edits, Edit{Start: node.Args[0].Start, End: node.Args[0].End, Text: quote(certificates.Path(id, out.VersionID, kind))})
						out.Changes = append(out.Changes, CertificateDeployChange{files[i].ID, resource, node.Name, version})
					}
				}
				walk(node.Children, resource)
			}
		}
		walk(doc.Nodes, "")
		files[i].Content, err = applyEdits(files[i].Content, edits)
		if err != nil {
			return out, nil, err
		}
	}
	sort.Slice(out.Changes, func(i, j int) bool {
		a, b := out.Changes[i], out.Changes[j]
		if a.FileID != b.FileID {
			return a.FileID < b.FileID
		}
		if a.ResourceID != b.ResourceID {
			return a.ResourceID < b.ResourceID
		}
		return a.Purpose < b.Purpose
	})
	return out, files, nil
}
func (s *Service) PreviewCertificateDeploy(ctx context.Context, p auth.Principal, id string) (CertificateDeployPreview, error) {
	preview, _, err := s.prepareCertificateDeploy(ctx, p, id)
	return preview, err
}
func (s *Service) DeployCertificate(ctx context.Context, p auth.Principal, requestID, key, id string, in CertificateDeployInput, automatic bool) (CertificateDeployment, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return CertificateDeployment{}, err
	}
	if key == "" || len(key) > 128 {
		return CertificateDeployment{}, fault.Invalid("幂等键无效")
	}
	encoded, err := json.Marshal(struct {
		Action, ID string
		Input      CertificateDeployInput
		Automatic  bool
	}{"certificates.deploy", id, in, automatic})
	if err != nil {
		return CertificateDeployment{}, err
	}
	digest := secure.Hash(encoded)
	if saved, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		if err != nil {
			return CertificateDeployment{}, err
		}
		return s.certificateDeployment(ctx, saved.TaskID)
	}
	preview, files, err := s.prepareCertificateDeploy(ctx, p, id)
	if err != nil {
		return CertificateDeployment{}, err
	}
	if preview.BaseVersion != in.BaseVersion || preview.VersionID != in.VersionID {
		return CertificateDeployment{}, ErrConflict
	}
	if len(preview.Changes) == 0 {
		return CertificateDeployment{}, fault.Conflict("已应用的绑定已使用最新证书版本")
	}
	result, err := s.saveLinked(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files, Apply: true}, digest, true, func(tx *sql.Tx, saved SaveResult) error {
		var latest string
		if err := tx.QueryRowContext(ctx, "SELECT latest_version_id FROM certificates WHERE id=?", id).Scan(&latest); err != nil {
			return err
		}
		if latest != in.VersionID {
			return ErrConflict
		}
		var applied string
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(applied_revision,'') FROM config_head WHERE id=1").Scan(&applied); err != nil {
			return err
		}
		if applied != preview.BasisRevision {
			return ErrConflict
		}
		if automatic {
			var allowed bool
			if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM acme_profiles p JOIN acme_orders o ON o.id=p.current_order_id WHERE p.certificate_id=? AND p.auto_deploy=1 AND p.state='issued' AND o.certificate_version_id=?)", id, in.VersionID).Scan(&allowed); err != nil {
				return err
			}
			if !allowed {
				return fault.Conflict("自动部署策略或签发结果已变化")
			}
			if _, err := tx.ExecContext(ctx, "UPDATE acme_profiles SET deployment_observed_version=?,deployment_error='' WHERE certificate_id=?", in.VersionID, id); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO certificate_deployments(task_id,certificate_id,version_id,basis_revision,revision_id,automatic,created_at) VALUES(?,?,?,?,?,?,?)", saved.TaskID, id, in.VersionID, preview.BasisRevision, saved.Tree.RevisionID, automatic, time.Now().Unix())
		return err
	})
	if err != nil {
		return CertificateDeployment{}, err
	}
	return s.certificateDeployment(ctx, result.TaskID)
}
