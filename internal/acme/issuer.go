package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge/dns01"
	legolog "github.com/go-acme/lego/v5/log"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/secure"
)

type issueError struct {
	stage, message string
	cause          error
}

func (e *issueError) Error() string { return e.message }
func (e *issueError) Unwrap() error { return e.cause }
func issueFailure(stage, message string, cause error) error {
	return &issueError{stage, message, cause}
}

var errOrderUncertain = errors.New("ACME new-order outcome is uncertain")

type orderJob struct {
	HTTP01Epoch                                                                int64
	ID, ProfileID, TaskID, AccountID, Provider, OrderURL, CertificateVersionID string
	Started                                                                    bool
	Automatic                                                                  bool
	ReplacesID                                                                 string
	NextPollAt                                                                 int64
	Credentials, Key, CSR                                                      []byte
	ChallengeType, HTTP01State, HTTP01Revision                                 string
	HTTP01ExpiresAt                                                            int64
	Terminal                                                                   bool
}

func (s *Service) Run(ctx context.Context) error {
	legolog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	results := make(chan error, 3)
	workers.Add(3)
	go func() { defer workers.Done(); results <- s.RunAccounts(run) }()
	go func() { defer workers.Done(); results <- s.runOrders(run) }()
	go func() { defer workers.Done(); results <- s.runLifecycle(run) }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-results:
	}
	cancel()
	workers.Wait()
	return err
}
func (s *Service) runOrders(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.nextIssue(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (s *Service) stage(ctx context.Context, job orderJob, stage string) error {
	_, err := s.DB.ExecContext(ctx, "UPDATE tasks SET stage=?,updated_at=? WHERE id=? AND state='running'", stage, time.Now().Unix(), job.TaskID)
	return err
}
func (s *Service) nextIssue(ctx context.Context) error {
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var taskID, id string
	err = tx.QueryRowContext(ctx, "SELECT id,resource_id FROM tasks WHERE kind='acme.issue' AND state IN ('queued','running') ORDER BY CASE state WHEN 'running' THEN 0 ELSE 1 END,created_at,id LIMIT 1").Scan(&taskID, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	p, err := profile(ctx, tx, id)
	if err != nil {
		return err
	}
	if p.TaskID != taskID || p.State != "issuing" {
		return errors.New("issuance task ownership mismatch")
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return errors.New("ACME issuance task found with disabled Nginx module")
	}
	var job orderJob
	err = tx.QueryRowContext(ctx, "SELECT id,profile_id,task_id,COALESCE(account_id,''),provider,credentials,private_key,csr,submit_started,order_url,next_poll_at,COALESCE(certificate_version_id,''),automatic,replaces_id,challenge_type,http01_state,http01_revision,http01_expires_at,terminal,http01_epoch FROM acme_orders WHERE id=?", p.CurrentOrderID).Scan(&job.ID, &job.ProfileID, &job.TaskID, &job.AccountID, &job.Provider, &job.Credentials, &job.Key, &job.CSR, &job.Started, &job.OrderURL, &job.NextPollAt, &job.CertificateVersionID, &job.Automatic, &job.ReplacesID, &job.ChallengeType, &job.HTTP01State, &job.HTTP01Revision, &job.HTTP01ExpiresAt, &job.Terminal, &job.HTTP01Epoch)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state='running',stage='order_reconciling',attempts=attempts+1,lease_until=?,updated_at=? WHERE id=?", now+30*60, now, taskID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	work, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var operationErr error
	var transport *caTransport
	if job.ChallengeType == "http-01" {
		var cleanupErr error
		operationErr, transport, cleanupErr = s.runHTTP01(work, ctx, p, &job)
		if transport != nil {
			defer transport.base.CloseIdleConnections()
		}
		if ctx.Err() != nil {
			return nil
		}
		if cleanupErr != nil {
			return s.finishIssue(ctx, p, job, "recovery_required", "http01_cleanup_unconfirmed", "HTTP-01 临时材料清理未确认，请恢复原任务；已取得的证书版本会保留，验证材料到期后将停止响应", 0)
		}
	} else {
		plain, loadErr := s.Vault.Open(job.Credentials, "acme:order:"+job.ID+":dns")
		var secrets map[string]string
		if loadErr == nil {
			loadErr = json.Unmarshal(plain, &secrets)
		}
		var dnsClient *dnsAPI
		if loadErr == nil {
			dnsClient, loadErr = newDNSAPI(job.Provider, secrets)
		}
		if dnsClient != nil {
			defer dnsClient.http.CloseIdleConnections()
		}
		if loadErr != nil {
			var records int
			if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_dns_records WHERE order_id=? AND state!='cleaned'", job.ID).Scan(&records); err != nil {
				return err
			}
			if records > 0 {
				return s.finishIssue(ctx, p, job, "recovery_required", "dns_credentials_failed", "DNS 凭据快照或适配器无法读取，验证记录尚待清理；请检查本机密钥、凭据及 SDK 调试设置后恢复原任务", 0)
			}
			operationErr = issueFailure("dns_credentials_failed", "DNS 凭据快照无法读取或适配器配置无效，请检查本机密钥、凭据及 SDK 调试设置", loadErr)
		} else {
			provider := &journalDNS{service: s, orderID: job.ID, api: dnsClient}
			if job.Terminal {
				operationErr = issueFailure("order_invalid", "原订单已失效，材料清理后须明确创建新订单", nil)
			}
			if job.CertificateVersionID == "" && !job.Terminal {
				operationErr, transport = s.obtain(work, p, &job, provider)
			}
			if transport != nil {
				defer transport.base.CloseIdleConnections()
			}
			if ctx.Err() != nil {
				return nil
			}
			if err := s.stage(ctx, job, "dns_cleaning"); err != nil {
				return err
			}
			cleanup, stop := context.WithTimeout(ctx, 3*time.Minute)
			cleanupErr := provider.cleanup(cleanup)
			stop()
			if ctx.Err() != nil {
				return nil
			}
			if cleanupErr != nil {
				message := "DNS 验证记录清理未确认，请恢复原任务；已取得的证书版本会保留"
				if errors.Is(cleanupErr, errDNSCreateUnconfirmed) {
					message = "DNS 创建结果不确定，查询尚未发现记录；保留恢复记录并停止重复写入，请恢复原任务核对，持续无法确认须本机处理"
				}
				return s.finishIssue(ctx, p, job, "recovery_required", "dns_cleanup_unconfirmed", message, 0)
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if operationErr == nil {
		return s.finishIssue(ctx, p, job, "succeeded", "certificate_issued", "", 0)
	}
	state, stage, message, retry := "failed", "issuance_failed", "证书申请失败，请恢复原订单核对结果", time.Now().Add(5*time.Minute).Unix()
	var phase *issueError
	if errors.As(operationErr, &phase) {
		stage, message = phase.stage, phase.message
	}
	var problem *legoacme.ProblemDetails
	if errors.As(operationErr, &problem) {
		switch problem.Type {
		case legoacme.RateLimitedErrorType:
			message = "CA 请求受限，请在允许重试时间后恢复原订单"
			retry = time.Now().Add(time.Hour).Unix()
		case legoacme.CaaErrorType:
			message = "域名 CAA 策略阻止签发，请核对 CAA 后创建新订单"
		case legoacme.UnauthorizedErrorType:
			message = "CA 未能验证域名控制权，请核对所选验证方式、域名指向和可达性"
		}
	}
	if errors.Is(operationErr, errOrderUncertain) {
		state, stage, message = "recovery_required", "order_create_unconfirmed", "CA 订单创建结果不确定，未自动重复申请；可恢复核对，或明确确认后创建新订单"
		retry = 0
	}
	if transport != nil && transport.retryAfter.Load() > retry {
		retry = transport.retryAfter.Load()
	}
	return s.finishIssue(ctx, p, job, state, stage, message, retry)
}
func sameIdentifiers(identifiers []legoacme.Identifier, domains []string) bool {
	names := []string{}
	for _, id := range identifiers {
		if id.Type != "dns" {
			return false
		}
		names = append(names, strings.ToLower(id.Value))
	}
	slices.Sort(names)
	return slices.Equal(names, domains)
}
func approvedCAURL(value, host string) bool {
	parsed, err := url.Parse(value)
	return err == nil && len(value) <= 2048 && parsed.Scheme == "https" && parsed.Host == host && parsed.User == nil && parsed.Fragment == "" && parsed.RawQuery == "" && parsed.Path != ""
}
func (s *Service) obtain(ctx context.Context, p Profile, job *orderJob, provider *journalDNS) (error, *caTransport) {
	a, err := account(ctx, s.DB, job.AccountID)
	if err != nil {
		return issueFailure("account_load_failed", "签发账户无法读取", err), nil
	}
	client, transport, err := s.accountClient(ctx, a)
	if err != nil {
		return issueFailure("ca_unavailable", "无法连接 CA 或读取账户密钥，请恢复原任务", err), transport
	}
	core := client.Core
	transport.retryAfter.Store(max(transport.retryAfter.Load(), job.NextPollAt))
	// Persist polling deadlines as soon as headers arrive, including successful
	// processing responses. Restarting the worker must not bypass CA backoff.
	transport.onResponse = func(request *http.Request, response *http.Response) error {
		if next := transport.retryAfter.Load(); next > job.NextPollAt {
			if _, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET next_poll_at=MAX(next_poll_at,?),updated_at=? WHERE id=?", next, time.Now().Unix(), job.ID); err != nil {
				return err
			}
			job.NextPollAt = next
		}
		if request.Method != "POST" || request.URL.String() != core.GetDirectory().NewOrderURL || response.StatusCode != http.StatusCreated {
			return nil
		}
		location := response.Header.Get("Location")
		if !approvedCAURL(location, transport.host) {
			return errors.New("invalid new order Location")
		}
		result, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET order_url=?,updated_at=? WHERE id=? AND (order_url='' OR order_url=?)", location, time.Now().Unix(), job.ID, location)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return errors.New("new order Location changed")
		}
		return nil
	}
	if job.OrderURL == "" && job.Started {
		return errOrderUncertain, transport
	}
	if err := waitCA(ctx, transport, 0); err != nil {
		return issueFailure("order_timeout", "CA 要求继续等待，请在允许时间后恢复原订单", err), transport
	}
	if job.OrderURL == "" {
		if err := s.stage(ctx, *job, "order_creating"); err != nil {
			return err, transport
		}
		if _, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET submit_started=1,updated_at=? WHERE id=?", time.Now().Unix(), job.ID); err != nil {
			return err, transport
		}
		// Capture Location before decoding the response body. A truncated response
		// can then be reconciled without another newOrder request.
		_, createErr := core.Orders.New(ctx, p.Domains, &api.OrderOptions{ReplacesCertID: job.ReplacesID})
		if err := s.DB.QueryRowContext(ctx, "SELECT order_url FROM acme_orders WHERE id=?", job.ID).Scan(&job.OrderURL); err != nil {
			return err, transport
		}
		if job.OrderURL == "" {
			var rejection *legoacme.ProblemDetails
			if errors.As(createErr, &rejection) && rejection.HTTPStatus >= 400 && rejection.HTTPStatus < 500 && rejection.HTTPStatus != http.StatusRequestTimeout {
				if _, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET submit_started=0 WHERE id=?", job.ID); err != nil {
					return err, transport
				}
				return issueFailure("order_rejected", "CA 拒绝新订单，请核对域名、账户和限制", createErr), transport
			}
			return errOrderUncertain, transport
		}
	}
	if !approvedCAURL(job.OrderURL, transport.host) {
		return issueFailure("order_invalid", "已保存订单地址无法安全读取", nil), transport
	}
	for {
		if err := s.stage(ctx, *job, "order_reconciling"); err != nil {
			return err, transport
		}
		if err := waitCA(ctx, transport, 0); err != nil {
			return issueFailure("order_timeout", "订单尚未完成，请在允许时间后恢复原订单", err), transport
		}
		order, err := core.Orders.Get(ctx, job.OrderURL)
		if err != nil {
			return issueFailure("ca_unavailable", "CA 订单查询失败，请稍后恢复原任务", err), transport
		}
		if !sameIdentifiers(order.Identifiers, p.Domains) || len(order.Authorizations) > 128 {
			return issueFailure("order_invalid", "CA 订单域名或授权数量与申请不一致", nil), transport
		}
		switch order.Status {
		case legoacme.StatusInvalid:
			if err := s.markTerminal(ctx, *job); err != nil {
				return err, transport
			}
			return issueFailure("order_invalid", "CA 订单已失效，须在允许时间后创建新订单", order.Err()), transport
		case legoacme.StatusValid:
			if !approvedCAURL(order.Certificate, transport.host) {
				return issueFailure("order_invalid", "CA 未提供有效证书地址", nil), transport
			}
			raw, err := core.Certificates.Get(ctx, order.Certificate, true)
			if err != nil {
				return issueFailure("certificate_download_failed", "已签发证书下载未完成，请恢复原订单", err), transport
			}
			if raw == nil {
				return issueFailure("certificate_download_failed", "CA 未返回证书材料", nil), transport
			}
			if err := s.storeIssued(ctx, p, *job, raw.Cert, order.Certificate); err != nil {
				return issueFailure("certificate_store_failed", "已签发证书校验或不可变版本保存失败，请恢复原订单", err), transport
			}
			job.CertificateVersionID = job.ID
			return nil, transport
		case legoacme.StatusReady:
			csr, err := s.csr(ctx, p, *job)
			if err != nil {
				return issueFailure("csr_invalid", "已保存私钥或 CSR 校验失败", err), transport
			}
			if !approvedCAURL(order.Finalize, transport.host) {
				return issueFailure("order_invalid", "CA 订单缺少安全的签发入口", nil), transport
			}
			if err := s.stage(ctx, *job, "order_finalizing"); err != nil {
				return err, transport
			}
			if _, err := core.Orders.UpdateForCSR(ctx, order.Finalize, csr); err != nil {
				return issueFailure("order_finalization_unconfirmed", "提交 CSR 的结果未确认，请恢复原订单", err), transport
			}
		case legoacme.StatusPending:
			var solveErr error
			if job.ChallengeType == "http-01" {
				solveErr = s.solveHTTP01(ctx, core, *job, p, order, transport)
			} else {
				solveErr = s.solve(ctx, core, *job, p, order, provider, transport)
			}
			if solveErr != nil {
				return solveErr, transport
			}
		case legoacme.StatusProcessing:
		default:
			return issueFailure("order_invalid", "CA 返回未知订单状态", nil), transport
		}
		if err := waitACME(ctx, 5*time.Second); err != nil {
			return issueFailure("order_timeout", "订单尚未完成，请稍后恢复原订单", err), transport
		}
	}
}
func (s *Service) csr(ctx context.Context, p Profile, job orderJob) ([]byte, error) {
	key, err := s.Vault.Open(job.Key, "acme:order:"+job.ID+":key")
	if err != nil {
		return nil, err
	}
	private, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	csr, err := s.Vault.Open(job.CSR, "acme:order:"+job.ID+":csr")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}
	if err := parsed.CheckSignature(); err != nil {
		return nil, err
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid CSR key")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(public, parsed.RawSubjectPublicKeyInfo) || !slices.Equal(parsed.DNSNames, p.Domains) || len(parsed.IPAddresses) > 0 {
		return nil, errors.New("CSR differs from saved request")
	}
	return csr, nil
}
func (s *Service) solve(ctx context.Context, core *api.Core, job orderJob, p Profile, order legoacme.ExtendedOrder, provider *journalDNS, transport *caTransport) error {
	pending := []legoacme.Authorization{}
	owners := map[string]string{}
	for _, uri := range order.Authorizations {
		auth, err := core.Authorizations.Get(ctx, uri)
		if err != nil {
			return issueFailure("authorization_failed", "CA 授权查询失败，请恢复原订单", err)
		}
		name := strings.ToLower(auth.Identifier.Value)
		if auth.Wildcard {
			name = "*." + name
		}
		if auth.Identifier.Type != "dns" || !slices.Contains(p.Domains, name) || len(auth.Challenges) > 16 {
			return issueFailure("authorization_failed", "CA 授权与申请域名不一致", nil)
		}
		if auth.Status == legoacme.StatusValid {
			continue
		}
		if auth.Status != legoacme.StatusPending && auth.Status != legoacme.StatusProcessing {
			if err := s.markTerminal(ctx, job); err != nil {
				return err
			}
			return issueFailure("authorization_failed", "CA 域名授权已失效，请核对 DNS 后创建新订单", nil)
		}
		for _, ch := range auth.Challenges {
			if ch.Type == "dns-01" {
				owners[ch.URL] = uri
			}
		}
		pending = append(pending, auth)
	}
	solver := dns01.NewChallenge(core, func(ctx context.Context, core *api.Core, _ string, ch legoacme.Challenge) error {
		if err := s.stage(ctx, job, "dns_validating"); err != nil {
			return err
		}
		uri, ok := owners[ch.URL]
		if !ok {
			return issueFailure("authorization_failed", "验证入口与保存的授权不一致", nil)
		}
		return s.validateAuthorization(ctx, core, job, uri, ch, transport)
	}, provider)
	if err := s.stage(ctx, job, "dns_publishing"); err != nil {
		return err
	}
	for _, auth := range pending {
		if err := solver.PreSolve(ctx, auth); err != nil {
			return issueFailure("dns_publish_failed", "DNS 验证记录发布失败，请核对凭据权限、域名归属和连接", err)
		}
	}
	for _, auth := range pending {
		if err := s.stage(ctx, job, "dns_propagating"); err != nil {
			return err
		}
		if err := solver.Solve(ctx, auth); err != nil {
			var phase *issueError
			if errors.As(err, &phase) {
				return err
			}
			return issueFailure("dns_propagation_failed", "TXT 传播或 CA 验证未完成，请恢复原订单核对结果", err)
		}
	}
	return nil
}
func (s *Service) validateAuthorization(ctx context.Context, core *api.Core, job orderJob, uri string, ch legoacme.Challenge, transport *caTransport) error {
	current, err := core.Challenges.Get(ctx, ch.URL)
	if err != nil {
		return err
	}
	if current.Status == legoacme.StatusPending {
		current, err = core.Challenges.New(ctx, ch.URL)
		if err != nil {
			return err
		}
	}
	interval := max(current.RetryAfter, 5*time.Second)
	for {
		if err := waitCA(ctx, transport, interval); err != nil {
			return err
		}
		interval = min(interval*2, time.Minute)
		auth, err := core.Authorizations.Get(ctx, uri)
		if err != nil {
			return err
		}
		switch auth.Status {
		case legoacme.StatusValid:
			return nil
		case legoacme.StatusPending, legoacme.StatusProcessing:
		default:
			if err := s.markTerminal(ctx, job); err != nil {
				return err
			}
			return issueFailure("authorization_failed", "CA 域名验证失败，请核对所选验证方式、域名指向与验证入口", authError(auth))
		}
	}
}
func authError(auth legoacme.Authorization) error {
	for _, ch := range auth.Challenges {
		if ch.Error != nil {
			return ch.Err()
		}
	}
	return errors.New("authorization not valid")
}
func waitACME(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func waitCA(ctx context.Context, transport *caTransport, delay time.Duration) error {
	return waitACME(ctx, max(delay, time.Until(time.Unix(transport.retryAfter.Load(), 0))))
}
func (s *Service) storeIssued(ctx context.Context, p Profile, job orderJob, chain []byte, uri string) error {
	if s.Certificates == nil {
		return errors.New("certificate store unavailable")
	}
	key, err := s.Vault.Open(job.Key, "acme:order:"+job.ID+":key")
	if err != nil {
		return err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	pair, err := certificates.Parse(string(chain), keyPEM)
	if err != nil {
		return err
	}
	names := append([]string{}, pair.Summary.DNSNames...)
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	slices.Sort(names)
	if !slices.Equal(names, p.Domains) || len(pair.Summary.IPAddresses) > 0 {
		return errors.New("issued SAN differs from requested domains")
	}
	if _, err := s.csr(ctx, p, job); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.Certificates.StoreIssued(ctx, tx, p.ID, job.ID, p.Name, p.Notes, string(chain), keyPEM, p.Environment); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE acme_orders SET certificate_url=?,certificate_version_id=?,updated_at=? WHERE id=?", uri, job.ID, time.Now().Unix(), job.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE acme_profiles SET certificate_id=?,deploy_after=0,deployment_error='',deployment_observed_version='' WHERE id=? AND current_order_id=?", p.ID, p.ID, job.ID); err != nil {
		return err
	}
	if err := s.scheduleIssued(ctx, tx, p, job.ID, pair.Chain[0]); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) markTerminal(ctx context.Context, job orderJob) error {
	_, err := s.DB.ExecContext(ctx, "UPDATE acme_orders SET terminal=1 WHERE id=?", job.ID)
	return err
}
func (s *Service) finishIssue(ctx context.Context, p Profile, job orderJob, state, stage, message string, retry int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	profileState := state
	if state == "succeeded" {
		profileState = "issued"
	}
	now := time.Now().Unix()
	if state == "succeeded" {
		if _, err := tx.ExecContext(ctx, "UPDATE acme_renewals SET failures=0,paused=0 WHERE profile_id=? AND version_id=?", p.ID, job.CertificateVersionID); err != nil {
			return err
		}
	}
	if job.Automatic && state != "succeeded" {
		r, err := renewal(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		r.Failures++
		r.Paused = state == "recovery_required" || r.Failures >= 6
		if !r.Paused {
			next, err := backoff(r.Failures, 5*time.Minute, 6*time.Hour)
			if err != nil {
				return err
			}
			retry = max(retry, next)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE acme_renewals SET failures=?,paused=? WHERE profile_id=?", r.Failures, r.Paused, p.ID); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, "UPDATE acme_profiles SET state=?,last_error=?,retry_after=?,version=version+1,updated_at=? WHERE id=? AND current_order_id=? AND state='issuing' AND EXISTS(SELECT 1 FROM acme_orders WHERE id=? AND task_id=?)", profileState, message, retry, now, p.ID, job.ID, job.ID, job.TaskID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("issuance completion ownership mismatch")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,lease_until=NULL,updated_at=? WHERE id=? AND state='running'", state, stage, message, now, job.TaskID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,'system:acme','acme.issue',?,?,?)", secure.ID(), job.TaskID, p.ID, state, now); err != nil {
		return err
	}
	return tx.Commit()
}
