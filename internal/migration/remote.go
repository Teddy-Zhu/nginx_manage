package migration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/secure"
)

type pullReservation struct{ Principal, Key, Digest string }

func remoteClient(remote Remote) (*http.Client, string, error) {
	return remoteapi.Client(remoteapi.Endpoint{URL: remote.URL, APIKey: remote.APIKey, Fingerprint: remote.Fingerprint})
}

func (s *Service) Pull(ctx context.Context, p auth.Principal, requestID, key string, in PullInput) (Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write", "nodes.manage"); err != nil {
		return Plan{}, err
	}
	if key == "" || len(key) > 128 || in.BaseVersion < 0 || (in.Mode != "preview" && in.Mode != "draft" && in.Mode != "save" && in.Mode != "apply") {
		return Plan{}, fault.Invalid("迁移幂等键、基础版本或执行模式无效")
	}
	if in.EnableNginx {
		if err := p.Require("system.write"); err != nil {
			return Plan{}, err
		}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return Plan{}, err
	}
	digest := secure.Hash(raw)
	var prior, id string
	err = s.DB.QueryRowContext(ctx, "SELECT request_hash,plan_id FROM migration_pulls WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &id)
	if err == nil {
		if prior != digest {
			return Plan{}, fault.Conflict("同一幂等键不能用于不同迁移")
		}
		plan, err := s.Get(ctx, p, id)
		if err != nil {
			return Plan{}, err
		}
		if plan.State == "failed" && plan.RevisionID == "" {
			return plan, nil
		}
		if in.Mode == "preview" {
			return plan, nil
		}
		return s.Execute(ctx, p, requestID, "migration-pull-"+secure.Hash([]byte(p.ID+":"+key)), id, ExecuteInput{in.Mode, in.EnableNginx})
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Plan{}, err
	}
	if !s.mu.TryLock() {
		return Plan{}, fault.Conflict("已有迁移包正在处理")
	}
	plan, err := func() (Plan, error) {
		defer s.mu.Unlock()
		client, base, err := remoteClient(in.Remote)
		if err != nil {
			return Plan{}, err
		}
		defer client.CloseIdleConnections()
		passphrase := secure.Token()
		body, err := json.Marshal(ExportInput{passphrase, in.Remote.Selection})
		if err != nil {
			return Plan{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/migrations/export", bytes.NewReader(body))
		if err != nil {
			return Plan{}, redactedRemoteError()
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+in.Remote.APIKey)
		response, err := client.Do(req)
		if err != nil {
			return Plan{}, redactedRemoteError()
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return Plan{}, redactedRemoteError()
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, MaxRequestBytes+1))
		if err != nil || len(data) > MaxRequestBytes {
			return Plan{}, redactedRemoteError()
		}
		var envelope struct {
			Code      string  `json:"code"`
			Message   string  `json:"message"`
			Data      Package `json:"data"`
			RequestID string  `json:"request_id"`
			NodeID    string  `json:"node_id"`
		}
		if decodeStrict(data, &envelope) != nil || envelope.Code != "OK" || envelope.NodeID == "" || envelope.NodeID == s.NodeID || in.Remote.NodeID != "" && in.Remote.NodeID != envelope.NodeID || secure.Hash(envelope.Data.Content) != envelope.Data.SHA256 {
			return Plan{}, redactedRemoteError()
		}
		manifest, payload, err := decodeArchive(envelope.Data.Content, passphrase)
		if err != nil {
			return Plan{}, redactedRemoteError()
		}
		if manifest.SourceNode != envelope.NodeID {
			return Plan{}, redactedRemoteError()
		}
		return s.prepare(ctx, p, requestID, manifest, payload, in.BaseVersion, in.Mappings, &pullReservation{p.ID, key, digest}, nil)
	}()
	if err != nil {
		return Plan{}, err
	}
	if in.Mode == "preview" {
		return plan, nil
	}
	return s.Execute(ctx, p, requestID, "migration-pull-"+secure.Hash([]byte(p.ID+":"+key)), plan.ID, ExecuteInput{in.Mode, in.EnableNginx})
}
