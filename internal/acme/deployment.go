package acme

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxconfig"
)

func (s *Service) deployIssued(ctx context.Context) error {
	var id string
	now := time.Now().Unix()
	err := s.DB.QueryRowContext(ctx, `SELECT p.id FROM acme_profiles p JOIN acme_renewals r ON r.profile_id=p.id
 WHERE p.auto_deploy=1 AND p.state='issued' AND p.deploy_after<=? AND p.deployment_observed_version!=r.version_id
 AND NOT EXISTS(SELECT 1 FROM certificate_deployments d WHERE d.version_id=r.version_id AND d.automatic=1)
 ORDER BY p.deploy_after,p.id LIMIT 1`, now).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	p, err := profile(ctx, s.DB, id)
	if err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE acme_profiles SET deploy_after=? WHERE id=? AND version=?", now+300, id, p.Version); err != nil {
		return err
	}
	principal := auth.Principal{ID: "system:acme", Scopes: []string{"config.write", "config.secrets", "security.write"}}
	preview, deployErr := s.Config.PreviewCertificateDeploy(ctx, principal, p.CertificateID)
	if deployErr == nil && preview.VersionID != p.Renewal.VersionID {
		deployErr = fault.Conflict("签发证书版本已变化，请检查配置")
	}
	if deployErr == nil && len(preview.Changes) == 0 {
		_, err = s.DB.ExecContext(ctx, "UPDATE acme_profiles SET deployment_observed_version=?,deployment_error='' WHERE id=? AND version=? AND auto_deploy=1 AND EXISTS(SELECT 1 FROM config_head WHERE id=1 AND version=? AND desired_revision=applied_revision)", preview.VersionID, id, p.Version, preview.BaseVersion)
		return err
	}
	if deployErr == nil {
		_, deployErr = s.Config.DeployCertificate(ctx, principal, id, "acme:auto-deploy:"+preview.VersionID, p.CertificateID, nginxconfig.CertificateDeployInput{BaseVersion: preview.BaseVersion, VersionID: preview.VersionID}, true)
	}
	if deployErr == nil || ctx.Err() != nil {
		return nil
	}
	message := "自动部署准备失败，旧证书保持原绑定；请检查 Nginx 配置和节点能力"
	var issue *fault.Error
	if errors.As(deployErr, &issue) {
		message = issue.Message
	}
	if errors.Is(deployErr, nginxconfig.ErrConflict) {
		message = "Nginx 配置已变化，自动部署稍后重新检查"
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE acme_profiles SET deployment_error=? WHERE id=? AND version=?", message, id, p.Version)
	return err
}
