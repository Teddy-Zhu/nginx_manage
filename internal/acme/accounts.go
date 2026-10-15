package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"

	"nginxpanel/internal/secure"
)

type accountUser struct {
	email string
	key   crypto.Signer
}

var errAccountKey = errors.New("ACME account key unavailable")
var errAccountInactive = errors.New("ACME account is not active")

func (u *accountUser) GetEmail() string                           { return u.email }
func (u *accountUser) GetPrivateKey() crypto.Signer               { return u.key }
func (u *accountUser) GetRegistration() *legoacme.ExtendedAccount { return nil }

func directory(environment string) (string, error) {
	switch environment {
	case "production":
		return lego.DirectoryURLLetsEncrypt, nil
	case "staging":
		return lego.DirectoryURLLetsEncryptStaging, nil
	default:
		return "", errors.New("unknown ACME environment")
	}
}

// The CA is selected from the product's fixed environments. Redirects and
// response links cannot expand that trust boundary or override system TLS roots.
type caTransport struct {
	base       *http.Transport
	host       string
	retryAfter atomic.Int64
	onResponse func(*http.Request, *http.Response) error
}

func (t *caTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != t.host || request.URL.User != nil {
		return nil, errors.New("ACME endpoint outside approved CA")
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = http.MaxBytesReader(nil, response.Body, 1<<20)
	if response.Header.Get("Retry-After") != "" {
		raw := response.Header.Get("Retry-After")
		when, parseErr := http.ParseTime(raw)
		if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds > 0 && seconds <= 365*24*60*60 {
			when, parseErr = time.Now().Add(time.Duration(seconds)*time.Second), nil
		}
		if parseErr == nil && when.After(time.Now()) {
			for prior := t.retryAfter.Load(); when.Unix() > prior; prior = t.retryAfter.Load() {
				if t.retryAfter.CompareAndSwap(prior, when.Unix()) {
					break
				}
			}
		}
	}
	if t.onResponse != nil {
		if err := t.onResponse(request, response); err != nil {
			response.Body.Close()
			return nil, err
		}
	}
	return response, nil
}

type caClient struct {
	Core         *api.Core
	Registration *registration.Registrar
}

func (s *Service) accountClient(ctx context.Context, a Account) (*caClient, *caTransport, error) {
	var sealed []byte
	if err := s.DB.QueryRowContext(ctx, "SELECT private_key FROM acme_accounts WHERE id=?", a.ID).Scan(&sealed); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errAccountKey, err)
	}
	der, err := s.Vault.Open(sealed, "acme:account:"+a.ID+":key")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errAccountKey, err)
	}
	private, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errAccountKey, err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		return nil, nil, errAccountKey
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || secure.Hash(pub) != a.KeyFingerprint {
		return nil, nil, errAccountKey
	}
	dir, err := directory(a.Environment)
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := url.Parse(dir)
	if err != nil {
		return nil, nil, err
	}
	transport := &caTransport{host: endpoint.Host, base: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
	}}
	// Construct the client explicitly; no process-wide lego TLS overrides.
	client, err := api.New(&http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("ACME redirects disabled") }}, "nginxpanel/acme", dir, a.AccountURL, signer)
	if err != nil {
		transport.base.CloseIdleConnections()
		return nil, transport, err
	}
	return &caClient{Core: client, Registration: registration.NewRegistrar(client, &accountUser{email: a.Email, key: signer})}, transport, nil
}

func accountFailure(err error, transport *caTransport) (string, int64) {
	message := "CA 通信失败或响应无法确认；重试时将先核对原账户密钥"
	delay := 5 * time.Minute
	if errors.Is(err, errAccountKey) {
		message = "账户密钥无法读取、解密或公钥散列不匹配，请检查本机密钥与备份"
	}
	if errors.Is(err, errAccountInactive) {
		message = "CA 账户已停用或撤销，请核对 CA 账户状态或创建新账户"
	}
	var problem *legoacme.ProblemDetails
	if errors.As(err, &problem) {
		switch {
		case problem.Type == legoacme.RateLimitedErrorType || problem.HTTPStatus == http.StatusTooManyRequests:
			message, delay = "CA 请求受限，请在允许重试时间后再试", time.Hour
		case problem.Type == legoacme.InvalidContactErrorType:
			message = "CA 拒绝账户邮箱，请移除本机记录后使用有效邮箱重新创建"
		case problem.Type == legoacme.UserActionRequiredErrorType:
			message = "CA 要求账户持有人处理服务条款或账户状态，请核对 CA 账户要求后重试"
		case problem.Type == legoacme.UnauthorizedErrorType:
			message = "CA 拒绝账户授权，请核对账户状态"
		}
	}
	retry := time.Now().Add(delay).Unix()
	if transport != nil && transport.retryAfter.Load() > retry {
		retry = transport.retryAfter.Load()
	}
	return message, retry
}

func (s *Service) RunAccounts(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.nextAccount(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) nextAccount(ctx context.Context) error {
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
	err = tx.QueryRowContext(ctx, "SELECT id,resource_id FROM tasks WHERE kind='acme.account.register' AND state IN ('queued','running') ORDER BY CASE state WHEN 'running' THEN 0 ELSE 1 END,created_at,id LIMIT 1").Scan(&taskID, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	a, err := account(ctx, tx, id)
	if err != nil {
		return err
	}
	if a.TaskID != taskID || (a.State != "pending" && a.State != "registering") {
		return errors.New("ACME account task ownership mismatch")
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return errors.New("ACME account task found with disabled Nginx module")
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state='running',stage='account_reconciling',attempts=attempts+1,lease_until=?,updated_at=? WHERE id=?", now+120, now, taskID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE acme_accounts SET state='registering',version=version+CASE state WHEN 'registering' THEN 0 ELSE 1 END,updated_at=? WHERE id=?", now, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	work, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	client, transport, clientErr := s.accountClient(work, a)
	if transport != nil {
		defer transport.base.CloseIdleConnections()
	}
	var registered *legoacme.ExtendedAccount
	operationErr := clientErr
	if operationErr == nil {
		registered, operationErr = client.Registration.ResolveAccountByKey(work)
		var problem *legoacme.ProblemDetails
		// Absence is the only result authorizing a new registration. Network
		// uncertainty never creates another key or a second local account.
		if errors.As(operationErr, &problem) && problem.Type == legoacme.AccountDoesNotExistErrorType {
			if _, err := s.DB.ExecContext(ctx, "UPDATE tasks SET stage='account_registering',updated_at=? WHERE id=?", time.Now().Unix(), taskID); err != nil {
				return err
			}
			registered, operationErr = client.Registration.Register(work, registration.RegisterOptions{TermsOfServiceAgreed: true})
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if operationErr == nil && registered == nil {
		operationErr = errors.New("CA did not return an account")
	}
	var registrationJSON []byte
	if operationErr == nil {
		registrationJSON, operationErr = json.Marshal(registered)
		if registered.Status != "valid" {
			operationErr = errAccountInactive
		}
		location, locationErr := url.Parse(registered.Location)
		if locationErr != nil || location.Scheme != "https" || location.Host != transport.host || location.User != nil || location.RawQuery != "" || location.Fragment != "" || location.Path == "" || len(registered.Location) > 2048 || len(registrationJSON) > 64<<10 {
			operationErr = errors.New("CA account response could not be confirmed")
		}
	}
	return s.finishAccount(ctx, taskID, a, registered, registrationJSON, operationErr, transport)
}

func (s *Service) finishAccount(ctx context.Context, taskID string, a Account, registered *legoacme.ExtendedAccount, registrationJSON []byte, operationErr error, transport *caTransport) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, stage, message, retry := "succeeded", "account_ready", "", int64(0)
	now := time.Now().Unix()
	var result sql.Result
	if operationErr == nil {
		result, err = tx.ExecContext(ctx, "UPDATE acme_accounts SET state='ready',account_url=?,registration=?,last_error='',retry_after=0,version=version+1,updated_at=? WHERE id=? AND task_id=? AND state='registering'", registered.Location, s.Vault.Seal(registrationJSON, "acme:account:"+a.ID+":registration"), now, a.ID, taskID)
	} else {
		state, stage = "failed", "account_registration_failed"
		message, retry = accountFailure(operationErr, transport)
		result, err = tx.ExecContext(ctx, "UPDATE acme_accounts SET state='failed',last_error=?,retry_after=?,version=version+1,updated_at=? WHERE id=? AND task_id=? AND state='registering'", message, retry, now, a.ID, taskID)
	}
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("ACME account completion ownership mismatch")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,lease_until=NULL,updated_at=? WHERE id=?", state, stage, message, now, taskID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,'system:acme','acme.account.register',?,?,?)", secure.ID(), taskID, a.ID, state, now); err != nil {
		return err
	}
	return tx.Commit()
}
