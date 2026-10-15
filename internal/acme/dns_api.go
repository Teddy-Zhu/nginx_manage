package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	alidns "github.com/go-acme/alidns-20150109/v5/client"
	"github.com/go-acme/lego/v5/challenge/dns01"
	dnspod "github.com/go-acme/tencentclouddnspod/v20210323"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

type dnsRecord struct {
	ID    string
	Value string
}
type dnsAPI struct {
	provider string
	secrets  map[string]string
	ali      *alidns.Client
	tencent  *dnspod.Client
	http     *http.Client
}
type dnsTransport struct {
	*http.Transport
	host string
}
type aliHTTP struct{ client *http.Client }

func (a aliHTTP) Call(request *http.Request, _ *http.Transport) (*http.Response, error) {
	return a.client.Do(request)
}
func (t *dnsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != t.host || request.URL.User != nil {
		return nil, errors.New("DNS endpoint outside approved provider")
	}
	response, err := t.Transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response.Body.Close()
		return nil, errors.New("DNS API redirects disabled")
	}
	response.Body = http.MaxBytesReader(nil, response.Body, 1<<20)
	return response, nil
}

var errDNSRejected = errors.New("DNS provider rejected request")

// The SDK captures DEBUG at package initialization and can print signed requests.
// Reject that mode without changing the environment shared by other workers.
var aliDebugEnabled = hasDaraDebugFlag()

func hasDaraDebugFlag() bool {
	for _, flag := range strings.Split(os.Getenv("DEBUG"), ",") {
		if flag == "dara" {
			return true
		}
	}
	return false
}
func pointer[T any](v T) *T { return &v }
func newDNSAPI(provider string, secrets map[string]string) (*dnsAPI, error) {
	if _, err := validateSecrets(provider, secrets); err != nil {
		return nil, err
	}
	if provider == "alidns" && aliDebugEnabled {
		return nil, errors.New("AliDNS SDK debug output must be disabled")
	}
	d := &dnsAPI{provider: provider, secrets: secrets, http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS API redirects disabled") }}}
	host := map[string]string{"cloudflare": "api.cloudflare.com", "alidns": "alidns.aliyuncs.com", "tencentcloud": "dnspod.tencentcloudapi.com"}[provider]
	d.http.Transport = &dnsTransport{host: host, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}}
	var err error
	switch provider {
	case "alidns":
		d.ali, err = alidns.NewClient(new(openapi.Config).SetAccessKeyId(secrets["access_key_id"]).SetAccessKeySecret(secrets["access_key_secret"]).SetRegionId("cn-hangzhou").SetConnectTimeout(10000).SetReadTimeout(20000))
	case "tencentcloud":
		config := profile.NewClientProfile()
		config.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
		config.HttpProfile.ReqTimeout = 20
		config.DisableRegionBreaker = true
		config.UnsafeRetryOnConnectionFailure = false
		config.NetworkFailureMaxRetries = 0
		config.RateLimitExceededMaxRetries = 0
		d.tencent, err = dnspod.NewClient(common.NewCredential(secrets["secret_id"], secrets["secret_key"]), "", config)
	}
	if d.ali != nil {
		d.ali.Client.DisableSDKError = pointer(true)
		d.ali.Client.HttpClient = aliHTTP{client: d.http}
	}
	if d.tencent != nil {
		d.tencent.WithHttpTransport(d.http.Transport)
	}
	return d, err
}

type cloudflareEnvelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (d *dnsAPI) cf(ctx context.Context, method, path string, zoneAuth bool, input any, out any) (int, error) {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, body)
	if err != nil {
		return 0, err
	}
	token := d.secrets["api_token"]
	if zoneAuth && d.secrets["zone_token"] != "" {
		token = d.secrets["zone_token"]
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := d.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	var envelope cloudflareEnvelope
	if err := json.NewDecoder(http.MaxBytesReader(nil, response.Body, 1<<20)).Decode(&envelope); err != nil {
		return 0, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		if response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusRequestTimeout {
			return 0, errDNSRejected
		}
		return 0, errors.New("Cloudflare API did not confirm the DNS request")
	}
	if out != nil {
		if err := json.Unmarshal(envelope.Result, out); err != nil {
			return 0, err
		}
	}
	return envelope.ResultInfo.TotalPages, nil
}
func dnsRejected(err error) bool {
	if errors.Is(err, errDNSRejected) {
		return true
	}
	var status interface {
		error
		GetStatusCode() *int
	}
	if errors.As(err, &status) {
		code := status.GetStatusCode()
		if code != nil && *code >= 400 && *code < 500 && *code != http.StatusRequestTimeout {
			return true
		}
	}
	var tc *tcerrors.TencentCloudSDKError
	if errors.As(err, &tc) && tc.RequestId != "" {
		for _, prefix := range []string{"AuthFailure", "InvalidParameter", "MissingParameter", "UnauthorizedOperation", "LimitExceeded", "RequestLimitExceeded", "UnsupportedOperation"} {
			if tc.Code == prefix || strings.HasPrefix(tc.Code, prefix+".") {
				return true
			}
		}
	}
	return false
}
func (d *dnsAPI) zone(ctx context.Context, fqdn string) (string, string, error) {
	zone, err := dns01.DefaultClient().FindZoneByFqdn(ctx, fqdn)
	if err != nil {
		return "", "", err
	}
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	name := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return "", "", errors.New("DNS challenge outside authoritative zone")
	}
	if d.provider == "cloudflare" {
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		_, err := d.cf(ctx, "GET", "/zones?"+url.Values{"name": {zone}, "per_page": {"50"}}.Encode(), true, nil, &zones)
		if err != nil {
			return "", "", err
		}
		if len(zones) != 1 || zones[0].Name != zone || zones[0].ID == "" {
			return "", "", errors.New("Cloudflare zone not uniquely accessible")
		}
		return zone, zones[0].ID, nil
	}
	return zone, zone, nil
}
func recordLabel(fqdn, zone string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	if name == zone {
		return "@", nil
	}
	if !strings.HasSuffix(name, "."+zone) {
		return "", errors.New("DNS record outside saved zone")
	}
	return strings.TrimSuffix(name, "."+zone), nil
}
func (d *dnsAPI) list(ctx context.Context, fqdn, zone, zoneID string) ([]dnsRecord, error) {
	label, err := recordLabel(fqdn, zone)
	if err != nil {
		return nil, err
	}
	out := []dnsRecord{}
	for page := 1; page <= 20; page++ {
		count := 0
		totalPages := 0
		switch d.provider {
		case "cloudflare":
			var records []struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Type    string `json:"type"`
				Content string `json:"content"`
			}
			totalPages, err = d.cf(ctx, "GET", "/zones/"+url.PathEscape(zoneID)+"/dns_records?"+url.Values{"type": {"TXT"}, "name": {strings.TrimSuffix(fqdn, ".")}, "page": {strconv.Itoa(page)}, "per_page": {"100"}}.Encode(), false, nil, &records)
			if err != nil {
				return nil, err
			}
			count = len(records)
			for _, r := range records {
				if r.ID == "" || r.Type != "TXT" || strings.TrimSuffix(strings.ToLower(r.Name), ".") != strings.TrimSuffix(fqdn, ".") {
					return nil, errors.New("unexpected Cloudflare record response")
				}
				out = append(out, dnsRecord{r.ID, strings.Trim(r.Content, "\"")})
			}
		case "alidns":
			req := new(alidns.DescribeDomainRecordsRequest).SetDomainName(zone).SetRRKeyWord(label).SetTypeKeyWord("TXT").SetPageNumber(int64(page)).SetPageSize(100)
			result, callErr := alidns.DescribeDomainRecordsWithContext(ctx, d.ali, req, &dara.RuntimeOptions{Autoretry: pointer(false)})
			if callErr != nil {
				return nil, callErr
			}
			if result == nil || result.Body == nil || result.Body.DomainRecords == nil {
				return nil, errors.New("incomplete AliDNS response")
			}
			count = len(result.Body.DomainRecords.Record)
			for _, r := range result.Body.DomainRecords.Record {
				if r == nil || r.RR == nil || r.Type == nil || r.Value == nil || r.RecordId == nil || *r.RecordId == "" {
					return nil, errors.New("incomplete AliDNS record")
				}
				if strings.EqualFold(*r.RR, label) && strings.EqualFold(*r.Type, "TXT") {
					out = append(out, dnsRecord{*r.RecordId, strings.Trim(*r.Value, "\"")})
				}
			}
		case "tencentcloud":
			req := dnspod.NewDescribeRecordListRequest()
			req.Domain = &zone
			req.Subdomain = &label
			req.RecordType = pointer("TXT")
			req.Offset = pointer(uint64((page - 1) * 100))
			req.Limit = pointer(uint64(100))
			req.ErrorOnEmpty = pointer("no")
			result, callErr := dnspod.DescribeRecordListWithContext(ctx, d.tencent, req)
			if callErr != nil {
				return nil, callErr
			}
			if result == nil || result.Response == nil {
				return nil, errors.New("incomplete DNSPod response")
			}
			count = len(result.Response.RecordList)
			for _, r := range result.Response.RecordList {
				if r == nil || r.Name == nil || r.Type == nil || r.Value == nil || r.RecordId == nil || *r.RecordId == 0 {
					return nil, errors.New("incomplete DNSPod record")
				}
				if strings.EqualFold(*r.Name, label) && strings.EqualFold(*r.Type, "TXT") {
					out = append(out, dnsRecord{strconv.FormatUint(*r.RecordId, 10), strings.Trim(*r.Value, "\"")})
				}
			}
		default:
			return nil, errors.New("unsupported DNS provider")
		}
		if count < 100 || totalPages > 0 && page >= totalPages {
			return out, nil
		}
	}
	return nil, errors.New("DNS record query exceeds 2000 records")
}
func (d *dnsAPI) create(ctx context.Context, fqdn, zone, zoneID, value string) (string, error) {
	label, err := recordLabel(fqdn, zone)
	if err != nil {
		return "", err
	}
	switch d.provider {
	case "cloudflare":
		var record struct {
			ID string `json:"id"`
		}
		_, err := d.cf(ctx, "POST", "/zones/"+url.PathEscape(zoneID)+"/dns_records", false, map[string]any{"type": "TXT", "name": strings.TrimSuffix(fqdn, "."), "content": value, "ttl": 120}, &record)
		if err != nil {
			return "", err
		}
		if record.ID == "" {
			return "", errors.New("missing created DNS record ID")
		}
		return record.ID, nil
	case "alidns":
		result, err := alidns.AddDomainRecordWithContext(ctx, d.ali, new(alidns.AddDomainRecordRequest).SetDomainName(zone).SetRR(label).SetType("TXT").SetValue(value).SetTTL(600), &dara.RuntimeOptions{Autoretry: pointer(false)})
		if err != nil {
			return "", err
		}
		if result == nil || result.Body == nil || result.Body.RecordId == nil || *result.Body.RecordId == "" {
			return "", errors.New("missing created DNS record ID")
		}
		return *result.Body.RecordId, nil
	case "tencentcloud":
		req := dnspod.NewCreateRecordRequest()
		req.Domain = &zone
		req.SubDomain = &label
		req.RecordType = pointer("TXT")
		req.RecordLine = pointer("默认")
		req.Value = &value
		req.TTL = pointer(uint64(600))
		result, err := dnspod.CreateRecordWithContext(ctx, d.tencent, req)
		if err != nil {
			return "", err
		}
		if result == nil || result.Response == nil || result.Response.RecordId == nil || *result.Response.RecordId == 0 {
			return "", errors.New("missing created DNS record ID")
		}
		return strconv.FormatUint(*result.Response.RecordId, 10), nil
	}
	return "", errors.New("unsupported DNS provider")
}
func (d *dnsAPI) delete(ctx context.Context, zone, zoneID, id string) error {
	switch d.provider {
	case "cloudflare":
		_, err := d.cf(ctx, "DELETE", "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), false, nil, nil)
		return err
	case "alidns":
		_, err := alidns.DeleteDomainRecordWithContext(ctx, d.ali, new(alidns.DeleteDomainRecordRequest).SetRecordId(id), &dara.RuntimeOptions{Autoretry: pointer(false)})
		return err
	case "tencentcloud":
		recordID, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			return err
		}
		req := dnspod.NewDeleteRecordRequest()
		req.Domain = &zone
		req.RecordId = &recordID
		_, err = dnspod.DeleteRecordWithContext(ctx, d.tencent, req)
		return err
	}
	return errors.New("unsupported DNS provider")
}
