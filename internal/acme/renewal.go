package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type RenewalState struct {
	VersionID      string `json:"version_id"`
	RenewAt        int64  `json:"renew_at"`
	Source         string `json:"source"`
	NextCheckAt    int64  `json:"next_check_at"`
	LastCheckAt    int64  `json:"last_check_at"`
	WindowStart    int64  `json:"window_start"`
	WindowEnd      int64  `json:"window_end"`
	ExplanationURL string `json:"explanation_url"`
	CheckFailures  int    `json:"check_failures"`
	Failures       int    `json:"failures"`
	Paused         bool   `json:"paused"`
	LastError      string `json:"last_error"`
}
type PolicyInput struct {
	BaseVersion   int64 `json:"base_version"`
	AutoRenew     bool  `json:"auto_renew"`
	AutoDeploy    bool  `json:"auto_deploy"`
	ResetFailures bool  `json:"reset_failures"`
}

func renewal(ctx context.Context, q reader, id string) (RenewalState, error) {
	var r RenewalState
	err := q.QueryRowContext(ctx, "SELECT version_id,renew_at,source,next_check_at,last_check_at,window_start,window_end,explanation_url,check_failures,failures,paused,last_error FROM acme_renewals WHERE profile_id=?", id).Scan(&r.VersionID, &r.RenewAt, &r.Source, &r.NextCheckAt, &r.LastCheckAt, &r.WindowStart, &r.WindowEnd, &r.ExplanationURL, &r.CheckFailures, &r.Failures, &r.Paused, &r.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return r, nil
	}
	return r, err
}
func (s *Service) UpdatePolicy(ctx context.Context, p auth.Principal, requestID, key, id string, in PolicyInput) (ChangeResult, error) {
	// This grants future publication of configurations that can contain ACL/WAF.
	if in.AutoDeploy {
		if err := p.Require("security.write"); err != nil {
			return ChangeResult{}, err
		}
	}
	return s.change(ctx, p, requestID, key, "acme.profiles.policy", id, in, func(tx *sql.Tx) (ChangeResult, error) {
		item, err := profile(ctx, tx, id)
		if err != nil {
			return ChangeResult{}, err
		}
		if item.Version != in.BaseVersion || item.State == "archived" {
			return ChangeResult{}, fault.Conflict("签发配置已变化或已停用，请刷新")
		}
		if in.ResetFailures && (item.State == "issuing" || item.State == "recovery_required") {
			return ChangeResult{}, fault.Conflict("须先完成或恢复原签发任务")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE acme_profiles SET auto_renew=?,auto_deploy=?,deploy_after=0,deployment_error='',version=version+1,updated_at=? WHERE id=?", in.AutoRenew, in.AutoDeploy, time.Now().Unix(), id); err != nil {
			return ChangeResult{}, err
		}
		if in.ResetFailures {
			if _, err := tx.ExecContext(ctx, "UPDATE acme_renewals SET failures=0,paused=0 WHERE profile_id=?", id); err != nil {
				return ChangeResult{}, err
			}
		}
		out, err := profile(ctx, tx, id)
		return ChangeResult{ID: id, Profile: &out}, err
	})
}

func randomBetween(start, end int64) (int64, error) {
	if start < 0 || end <= start {
		return 0, errors.New("invalid renewal window")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(end-start))
	if err != nil {
		return 0, err
	}
	return start + n.Int64(), nil
}
func backoff(attempt int, minimum, maximum time.Duration) (int64, error) {
	delay := minimum
	for i := 1; i < attempt && delay < maximum; i++ {
		delay = min(delay*2, maximum)
	}
	return randomBetween(time.Now().Add(delay).Unix(), time.Now().Add(delay+delay/4).Unix()+1)
}
func ariID(leaf *x509.Certificate) (string, error) {
	if len(leaf.AuthorityKeyId) == 0 || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return "", nil
	}
	return api.MakeARICertID(leaf)
}
func (s *Service) replacesID(ctx context.Context, q reader, p Profile) (string, error) {
	if p.Renewal.VersionID == "" {
		return "", nil
	}
	leaf, err := s.Certificates.Leaf(ctx, q, p.CertificateID, p.Renewal.VersionID)
	if err != nil {
		return "", err
	}
	return ariID(leaf)
}
func (s *Service) scheduleIssued(ctx context.Context, tx *sql.Tx, p Profile, version string, leaf *x509.Certificate) error {
	// Persist a single random choice between half and two thirds of the actual lifetime.
	// Restarting must not move the fallback window forward.
	lifetime := leaf.NotAfter.Unix() - leaf.NotBefore.Unix()
	at, err := randomBetween(leaf.NotBefore.Unix()+lifetime/2, leaf.NotBefore.Unix()+lifetime*2/3)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO acme_renewals(profile_id,version_id,renew_at,source,next_check_at) VALUES(?,?,?,'fallback',?) ON CONFLICT(profile_id) DO UPDATE SET version_id=excluded.version_id,renew_at=excluded.renew_at,source='fallback',next_check_at=excluded.next_check_at,last_check_at=0,window_start=0,window_end=0,explanation_url='',check_failures=0,failures=0,paused=0,last_error=''", p.ID, version, at, time.Now().Unix())
	return err
}
func (s *Service) runLifecycle(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		var enabled bool
		if err := s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if enabled {
			if err := s.checkRenewal(ctx); err != nil && ctx.Err() == nil {
				return err
			}
			if err := s.queueRenewal(ctx); err != nil && ctx.Err() == nil {
				return err
			}
			if err := s.deployIssued(ctx); err != nil && ctx.Err() == nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (s *Service) checkRenewal(ctx context.Context) error {
	var id string
	now := time.Now().Unix()
	err := s.DB.QueryRowContext(ctx, "SELECT p.id FROM acme_profiles p JOIN acme_renewals r ON r.profile_id=p.id WHERE p.state NOT IN ('archived','issuing','recovery_required') AND r.paused=0 AND r.next_check_at>0 AND r.next_check_at<=? AND (p.auto_renew=1 OR r.last_check_at=0) ORDER BY r.next_check_at,p.id LIMIT 1", now).Scan(&id)
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
	r := p.Renewal
	// A durable claim bounds request frequency across a process restart.
	if _, err := s.DB.ExecContext(ctx, "UPDATE acme_renewals SET next_check_at=? WHERE profile_id=? AND version_id=?", now+300, id, r.VersionID); err != nil {
		return err
	}
	work, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	leaf, checkErr := s.Certificates.Leaf(work, s.DB, p.CertificateID, r.VersionID)
	if checkErr == nil && !time.Now().Before(leaf.NotAfter) {
		_, err = s.DB.ExecContext(ctx, "UPDATE acme_renewals SET renew_at=MIN(renew_at,?),next_check_at=0,last_check_at=?,last_error='证书已过期，停止 ARI 检查' WHERE profile_id=? AND version_id=?", now, now, id, r.VersionID)
		return err
	}
	var info *legoacme.ExtendedRenewalInfo
	var transport *caTransport
	var requested int64
	if checkErr == nil {
		var certID string
		certID, checkErr = ariID(leaf)
		if checkErr == nil && certID == "" {
			checkErr = api.ErrNoARI
		}
		if checkErr == nil {
			var a Account
			a, checkErr = account(work, s.DB, p.AccountID)
			if checkErr == nil {
				var client *caClient
				client, transport, checkErr = s.accountClient(work, a)
				if transport != nil {
					defer transport.base.CloseIdleConnections()
				}
				if checkErr == nil {
					endpoint := client.Core.GetDirectory().RenewalInfo
					if !approvedCAURL(endpoint, transport.host) {
						checkErr = api.ErrNoARI
					} else {
						transport.onResponse = func(req *http.Request, resp *http.Response) error {
							if req.Method == http.MethodGet && req.URL.String() == endpoint+"/"+certID {
								requested = ariRetryAfter(resp.Header.Get("Retry-After"), time.Now())
								if requested > 0 {
									_, err := s.DB.ExecContext(work, "UPDATE acme_renewals SET next_check_at=? WHERE profile_id=? AND version_id=?", requested, id, r.VersionID)
									return err
								}
							}
							return nil
						}
						info, checkErr = client.Core.Certificates.GetRenewalInfo(work, certID)
					}
				}
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if checkErr == nil && (info == nil || !info.SuggestedWindow.End.After(info.SuggestedWindow.Start) || info.SuggestedWindow.Start.Unix() < 0 || requested == 0) {
		checkErr = errors.New("invalid ARI response or Retry-After")
	}
	r.LastCheckAt = time.Now().Unix()
	if checkErr == nil {
		start, end := info.SuggestedWindow.Start.Unix(), info.SuggestedWindow.End.Unix()
		if end <= start {
			checkErr = errors.New("ARI window is shorter than scheduler precision")
		} else {
			if r.Source != "ari" || r.WindowStart != start || r.WindowEnd != end {
				r.RenewAt, err = randomBetween(start, end)
				if err != nil {
					return err
				}
			}
			r.Source, r.WindowStart, r.WindowEnd = "ari", start, end
			r.NextCheckAt, r.CheckFailures, r.LastError = requested, 0, ""
			r.ExplanationURL = ""
			if u, e := url.Parse(info.ExplanationURL); e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(info.ExplanationURL) <= 2048 {
				r.ExplanationURL = info.ExplanationURL
			}
		}
	}
	if checkErr != nil {
		r.CheckFailures = min(r.CheckFailures+1, 6)
		r.LastError = "ARI 检查失败，保留已保存的续期时间"
		if errors.Is(checkErr, api.ErrNoARI) {
			r.LastError = "CA 未提供可用 ARI，保留已保存的续期时间"
		}
		delay := 6 * time.Hour
		var network net.Error
		var problem *legoacme.ProblemDetails
		if r.CheckFailures < 6 && (errors.As(checkErr, &network) && network.Timeout() || errors.As(checkErr, &problem) && problem.HTTPStatus >= 500) {
			delay = min(time.Minute*time.Duration(1<<r.CheckFailures), time.Hour)
		}
		r.NextCheckAt, err = backoff(1, delay, delay)
		if err != nil {
			return err
		}
		if transport != nil {
			r.NextCheckAt = max(r.NextCheckAt, transport.retryAfter.Load())
		}
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE acme_renewals SET renew_at=?,source=?,next_check_at=?,last_check_at=?,window_start=?,window_end=?,explanation_url=?,check_failures=?,last_error=? WHERE profile_id=? AND version_id=?", r.RenewAt, r.Source, r.NextCheckAt, r.LastCheckAt, r.WindowStart, r.WindowEnd, r.ExplanationURL, r.CheckFailures, r.LastError, id, r.VersionID)
	return err
}

// RFC 9773 allows reasonable bounds on the requested ARI polling interval.
func ariRetryAfter(raw string, now time.Time) int64 {
	var delay time.Duration
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds >= 0 && seconds <= 365*24*60*60 {
		delay = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(raw); err == nil {
		delay = at.Sub(now)
	} else {
		return 0
	}
	return now.Add(min(max(delay, time.Minute), 24*time.Hour)).Unix()
}
func (s *Service) queueRenewal(ctx context.Context) error {
	var id string
	now := time.Now().Unix()
	err := s.DB.QueryRowContext(ctx, "SELECT p.id FROM acme_profiles p JOIN acme_renewals r ON r.profile_id=p.id WHERE p.auto_renew=1 AND p.state IN ('issued','failed') AND r.paused=0 AND r.renew_at<=? AND p.retry_after<=? ORDER BY MAX(r.renew_at,p.retry_after),p.id LIMIT 1", now, now).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := profile(ctx, tx, id)
	if err != nil {
		return err
	}
	var terminal bool
	var state string
	if err := tx.QueryRowContext(ctx, "SELECT o.terminal,t.state FROM acme_orders o JOIN tasks t ON t.id=o.task_id WHERE o.id=?", p.CurrentOrderID).Scan(&terminal, &state); err != nil {
		return err
	}
	result, queueErr := s.queueIssue(ctx, tx, id, IssueInput{BaseVersion: p.Version, NewOrder: terminal || state == "succeeded"}, true)
	if queueErr == nil {
		if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,'system:acme','acme.renew',?,'queued',?)", secure.ID(), result.TaskID, id, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	tx.Rollback()
	message := "自动续期准备失败，请检查本机密钥、凭据及保留上限"
	var issue *fault.Error
	if errors.As(queueErr, &issue) {
		message = issue.Message
	}
	at, err := backoff(p.Renewal.Failures+1, 5*time.Minute, 6*time.Hour)
	if err != nil {
		return err
	}
	failed, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer failed.Rollback()
	updated, err := failed.ExecContext(ctx, "UPDATE acme_profiles SET last_error=?,retry_after=? WHERE id=? AND version=? AND auto_renew=1 AND state IN ('issued','failed')", message, at, id, p.Version)
	if err != nil {
		return err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if _, err := failed.ExecContext(ctx, "UPDATE acme_renewals SET failures=failures+1,paused=(failures+1>=6) WHERE profile_id=? AND version_id=?", id, p.Renewal.VersionID); err != nil {
		return err
	}
	if _, err := failed.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,'system:acme','acme.renew',?,'queue_failed',?)", secure.ID(), secure.ID(), id, now); err != nil {
		return err
	}
	return failed.Commit()
}
