package acme

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"nginxpanel/internal/secure"
)

type Service struct {
	DB    *sql.DB
	Vault *secure.Vault
}

type Account struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	Environment    string `json:"environment"`
	Version        int64  `json:"version"`
	KeyFingerprint string `json:"key_fingerprint"`
	AccountURL     string `json:"account_url"`
	State          string `json:"state"`
	TaskID         string `json:"task_id"`
	LastError      string `json:"last_error"`
	RetryAfter     int64  `json:"retry_after"`
	TermsAgreedAt  int64  `json:"terms_agreed_at"`
	CreatedAt      int64  `json:"created_at"`
	UpdatedAt      int64  `json:"updated_at"`
}

type AccountInput struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Environment string `json:"environment"`
	TermsAgreed bool   `json:"terms_agreed"`
}

type AccountAction struct {
	BaseVersion int64 `json:"base_version"`
	TermsAgreed bool  `json:"terms_agreed"`
}

type DNSCredential struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Provider   string   `json:"provider"`
	Version    int64    `json:"version"`
	FieldNames []string `json:"field_names"`
	CreatedAt  int64    `json:"created_at"`
	UpdatedAt  int64    `json:"updated_at"`
}

type DNSInput struct {
	BaseVersion int64             `json:"base_version"`
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Secrets     map[string]string `json:"secrets"`
}

func (in *DNSInput) UnmarshalJSON(data []byte) error {
	var body struct {
		BaseVersion *int64          `json:"base_version"`
		Name        string          `json:"name"`
		Provider    string          `json:"provider"`
		Secrets     json.RawMessage `json:"secrets"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || body.BaseVersion == nil || *body.BaseVersion < 0 {
		return errors.New("DNS 凭据请求须提供有效基础版本、名称与提供商")
	}
	var secrets map[string]string
	if len(body.Secrets) > 0 {
		if len(body.Secrets) > 8192 || json.Unmarshal(body.Secrets, &secrets) != nil || secrets == nil || len(secrets) > 2 {
			return errors.New("DNS 凭据字段须为非 null 对象，且不得超过两个字段或 8 KiB")
		}
	}
	*in = DNSInput{BaseVersion: *body.BaseVersion, Name: body.Name, Provider: body.Provider, Secrets: secrets}
	return nil
}

type ChangeResult struct {
	ID         string         `json:"id"`
	Account    *Account       `json:"account"`
	Credential *DNSCredential `json:"credential"`
	TaskID     string         `json:"task_id"`
	Deleted    bool           `json:"deleted"`
}

type CredentialField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Required bool   `json:"required"`
}

type DNSProvider struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Fields []CredentialField `json:"fields"`
}

// Only providers with an explicit credential schema are offered. The registry
// does not imply that a credential has been checked against its remote API.
func DNSProviders() []DNSProvider {
	return []DNSProvider{
		{ID: "cloudflare", Name: "Cloudflare", Fields: []CredentialField{{Key: "api_token", Label: "DNS API Token", Required: true}, {Key: "zone_token", Label: "Zone Read Token（可选，默认使用 DNS Token）"}}},
		{ID: "alidns", Name: "阿里云 DNS", Fields: []CredentialField{{Key: "access_key_id", Label: "AccessKey ID", Required: true}, {Key: "access_key_secret", Label: "AccessKey Secret", Required: true}}},
		{ID: "tencentcloud", Name: "腾讯云 DNSPod", Fields: []CredentialField{{Key: "secret_id", Label: "SecretId", Required: true}, {Key: "secret_key", Label: "SecretKey", Required: true}}},
	}
}
