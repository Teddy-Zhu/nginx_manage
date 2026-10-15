package acme

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge/http01"
	"nginxpanel/internal/agent"
)

type managedHTTP01 struct {
	service *Service
	job     orderJob
}

func (p *managedHTTP01) Present(ctx context.Context, domain, token, keyAuthorization string) error {
	if err := p.service.stage(ctx, p.job, "http01_publishing"); err != nil {
		return err
	}
	_, err := p.service.Agent.PresentHTTP01(ctx, agent.HTTP01PresentRequest{Protocol: agent.Protocol, OrderID: p.job.ID, Epoch: p.job.HTTP01Epoch, Domain: strings.ToLower(domain), Token: token, KeyAuthorization: keyAuthorization})
	if err != nil {
		return issueFailure("http01_publish_failed", "HTTP-01 材料发布或本机 80 端口验证失败，请检查受管站点验证入口与 Agent", err)
	}
	return nil
}

// lego's per-challenge deferred cleanup uses the validation context and cannot
// report cleanup failures. The order worker owns durable cleanup separately,
// including when Present or validation times out, and records its outcome.
func (*managedHTTP01) CleanUp(context.Context, string, string, string) error { return nil }

func (s *Service) cleanHTTP01(ctx context.Context, job *orderJob) error {
	if job.HTTP01State == "none" || job.HTTP01State == "cleaned" {
		return nil
	}
	if s.Agent == nil {
		return errors.New("HTTP-01 agent unavailable")
	}
	_, err := s.Agent.CleanupHTTP01(ctx, job.ID, job.HTTP01Epoch)
	if err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET http01_state='cleaned',updated_at=? WHERE id=?", time.Now().Unix(), job.ID); err != nil {
		return err
	}
	job.HTTP01State = "cleaned"
	return nil
}

func (s *Service) prepareHTTP01(ctx context.Context, p Profile, job *orderJob) error {
	if !p.HTTP01Confirmed || s.Agent == nil {
		return issueFailure("http01_unavailable", "HTTP-01 需要公网入口确认和可用的宿主 Agent", nil)
	}
	if err := s.stage(ctx, *job, "http01_preflight"); err != nil {
		return err
	}
	for _, domain := range p.Domains {
		if strings.HasPrefix(domain, "*.") {
			return issueFailure("http01_unavailable", "HTTP-01 不支持通配域名", nil)
		}
		lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
		addresses, err := net.DefaultResolver.LookupIPAddr(lookup, domain)
		cancel()
		if err != nil || len(addresses) == 0 {
			return issueFailure("http01_dns_failed", "HTTP-01 域名未能通过本机系统解析；请核对公网 A/AAAA 记录后恢复原任务", err)
		}
	}
	var revision sql.NullString
	if err := s.DB.QueryRowContext(ctx, "SELECT applied_revision FROM config_head WHERE id=1").Scan(&revision); err != nil {
		return err
	}
	if !revision.Valid || revision.String == "" {
		return issueFailure("http01_unavailable", "须先应用包含域名和 80 端口验证入口的 Nginx 配置", nil)
	}
	// The order-owned cleanup key and expiry are persisted before IPC. Losing a
	// response therefore leaves a recoverable intent rather than an orphan lease.
	if job.HTTP01Epoch >= 1_000_000_000 {
		return issueFailure("http01_unavailable", "HTTP-01 租约序号已达上限，须创建新订单", nil)
	}
	job.HTTP01Epoch++
	job.HTTP01Revision, job.HTTP01ExpiresAt = revision.String, time.Now().Add(30*time.Minute).Unix()
	if _, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET http01_state='unknown',http01_revision=?,http01_expires_at=?,http01_epoch=?,updated_at=? WHERE id=?", job.HTTP01Revision, job.HTTP01ExpiresAt, job.HTTP01Epoch, time.Now().Unix(), job.ID); err != nil {
		return err
	}
	job.HTTP01State = "unknown"
	if _, err := s.Agent.ReserveHTTP01(ctx, agent.HTTP01LeaseRequest{Protocol: agent.Protocol, OrderID: job.ID, Epoch: job.HTTP01Epoch, ExpectedRevision: job.HTTP01Revision, Domains: p.Domains, ExpiresAt: job.HTTP01ExpiresAt}); err != nil {
		return issueFailure("http01_unavailable", "HTTP-01 运行入口预检未通过；请确认各域名具有唯一且已生效的 80 端口验证入口，Agent 和 Nginx 正常运行", err)
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET http01_state='active',updated_at=? WHERE id=?", time.Now().Unix(), job.ID); err != nil {
		return err
	}
	job.HTTP01State = "active"
	return nil
}

func (s *Service) runHTTP01(work, ctx context.Context, p Profile, job *orderJob) (error, *caTransport, error) {
	// A resumed worker first reconciles the previous lease. It never creates a
	// second CA order to compensate for an uncertain response.
	cleanup, stop := context.WithTimeout(work, 15*time.Second)
	err := s.cleanHTTP01(cleanup, job)
	stop()
	if err != nil {
		return nil, nil, err
	}
	if job.CertificateVersionID != "" {
		return nil, nil, nil
	}
	if job.Terminal {
		return issueFailure("order_invalid", "原订单已失效，材料清理后须明确创建新订单", nil), nil, nil
	}
	if job.Started && job.OrderURL == "" {
		return errOrderUncertain, nil, nil
	}
	operationErr := s.prepareHTTP01(work, p, job)
	var transport *caTransport
	if operationErr == nil {
		operationErr, transport = s.obtain(work, p, job, nil)
	}
	if ctx.Err() != nil {
		return operationErr, transport, nil
	}
	stageErr := s.stage(ctx, *job, "http01_cleaning")
	cleanup, stop = context.WithTimeout(ctx, 3*time.Minute)
	err = s.cleanHTTP01(cleanup, job)
	stop()
	return operationErr, transport, errors.Join(stageErr, err)
}

func (s *Service) solveHTTP01(ctx context.Context, core *api.Core, job orderJob, p Profile, order legoacme.ExtendedOrder, transport *caTransport) error {
	owners := map[string]string{}
	pending := []legoacme.Authorization{}
	for _, uri := range order.Authorizations {
		if !approvedCAURL(uri, transport.host) {
			return issueFailure("authorization_failed", "CA 授权地址无效", nil)
		}
		auth, err := core.Authorizations.Get(ctx, uri)
		if err != nil {
			return issueFailure("authorization_failed", "CA 授权查询失败，请恢复原订单", err)
		}
		if auth.Identifier.Type != "dns" || auth.Wildcard || !slices.Contains(p.Domains, strings.ToLower(auth.Identifier.Value)) || len(auth.Challenges) > 16 {
			return issueFailure("authorization_failed", "CA HTTP-01 授权与申请域名不一致", nil)
		}
		if auth.Status == legoacme.StatusValid {
			continue
		}
		if auth.Status != legoacme.StatusPending && auth.Status != legoacme.StatusProcessing {
			if err := s.markTerminal(ctx, job); err != nil {
				return err
			}
			return issueFailure("authorization_failed", "CA 域名授权已失效，请核对 HTTP 入口后创建新订单", nil)
		}
		for _, ch := range auth.Challenges {
			if ch.Type == "http-01" {
				if !approvedCAURL(ch.URL, transport.host) {
					return issueFailure("authorization_failed", "CA HTTP-01 验证地址无效", nil)
				}
				owners[ch.URL] = uri
			}
		}
		pending = append(pending, auth)
	}
	solver := http01.NewChallenge(core, func(ctx context.Context, core *api.Core, _ string, ch legoacme.Challenge) error {
		if err := s.stage(ctx, job, "http01_validating"); err != nil {
			return err
		}
		uri, ok := owners[ch.URL]
		if !ok {
			return issueFailure("authorization_failed", "HTTP-01 验证入口与授权不一致", nil)
		}
		return s.validateAuthorization(ctx, core, job, uri, ch, transport)
	}, &managedHTTP01{service: s, job: job})
	for _, auth := range pending {
		if err := solver.Solve(ctx, auth); err != nil {
			var phase *issueError
			if errors.As(err, &phase) {
				return err
			}
			return issueFailure("http01_validation_failed", "HTTP-01 CA 验证未完成，请核对公网 80 端口、A/AAAA 指向及所有入口的验证路径后恢复原订单", err)
		}
	}
	return nil
}
