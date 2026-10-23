package firewall

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const geoIPDownloadBytes = 64 << 20
const geoIPIndexBytes = 64 << 20
const MaxSourcePrefixes = 262144
const MaxPolicyPrefixes = 524288

type GeoIPSource struct {
	Name                string `json:"name"`
	Format              string `json:"format"`
	URL                 string `json:"url"`
	IPv6URL             string `json:"ipv6_url"`
	AllowPrivateNetwork bool   `json:"allow_private_network"`
}
type GeoIPState struct {
	Version   int64          `json:"version"`
	Source    GeoIPSource    `json:"source"`
	Ready     bool           `json:"ready"`
	UpdatedAt int64          `json:"updated_at"`
	SHA256    string         `json:"sha256"`
	Countries map[string]int `json:"countries"`
}
type GeoIPSourceInput struct {
	BaseVersion int64       `json:"base_version"`
	Source      GeoIPSource `json:"source"`
}
type GeoIPUpdateInput struct {
	Version   int64    `json:"version"`
	Countries []string `json:"countries"`
}
type GeoIPResolveInput struct {
	Version   int64    `json:"version"`
	Countries []string `json:"countries"`
}
type GeoIPResolved struct {
	Version   int64    `json:"version"`
	Countries []string `json:"countries"`
	Sources   []string `json:"sources"`
	UpdatedAt int64    `json:"updated_at"`
}
type geoIPDataset map[string][]string

func DefaultGeoIPSource() GeoIPSource {
	return GeoIPSource{Name: "Loyalsoldier GeoIP", Format: "mmdb", URL: "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"}
}
func sourceHash(source GeoIPSource) string { raw, _ := json.Marshal(source); return secure.Hash(raw) }
func validCountry(country string) bool {
	return len(country) == 2 && country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z'
}
func normalizeCountries(countries []string) ([]string, error) {
	if len(countries) == 0 || len(countries) > 250 {
		return nil, fault.Invalid("请选择国家或地区")
	}
	out := slices.Clone(countries)
	for i, code := range out {
		out[i] = strings.ToUpper(strings.TrimSpace(code))
		if !validCountry(out[i]) {
			return nil, fault.Invalid("国家或地区代码无效")
		}
	}
	sort.Strings(out)
	return slices.Compact(out), nil
}
func (source GeoIPSource) validate() error {
	if source.Name == "" || !policyText(source.Name, 256) || len(source.URL) > 2048 || len(source.IPv6URL) > 2048 || !slices.Contains([]string{"mmdb", "cidr"}, source.Format) {
		return fault.Invalid("GeoIP 来源名称、格式或地址无效")
	}
	for _, raw := range []string{source.URL, source.IPv6URL} {
		if raw == "" {
			continue
		}
		if source.Format == "cidr" && strings.Count(raw, "{country}") != 1 {
			return fault.Invalid("CIDR 下载地址须包含一个 {country} 国家代码占位符")
		}
		if source.Format == "mmdb" && strings.ContainsAny(raw, "{}") {
			return fault.Invalid("MMDB 来源须为完整数据库下载地址")
		}
		u, err := url.Parse(strings.ReplaceAll(raw, "{country}", "cn"))
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return fault.Invalid("GeoIP 下载地址须为 HTTPS 地址，且不能包含账户或片段")
		}
	}
	if source.URL == "" || source.Format == "mmdb" && source.IPv6URL != "" {
		return fault.Invalid("请填写与数据格式相符的下载地址")
	}
	return nil
}

func (s *Service) readGeoIP(ctx context.Context) (GeoIPState, geoIPDataset, string, error) {
	out := GeoIPState{Source: DefaultGeoIPSource(), Countries: map[string]int{}}
	var source, compressed []byte
	var datasetSource string
	err := s.DB.QueryRowContext(ctx, "SELECT version,source,dataset,dataset_source,dataset_hash,updated_at FROM firewall_geoip WHERE id=1").Scan(&out.Version, &source, &compressed, &datasetSource, &out.SHA256, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, geoIPDataset{}, "", nil
	}
	if err != nil {
		return out, nil, "", err
	}
	source, err = s.Vault.Open(source, "firewall:geoip:source")
	if err != nil {
		return out, nil, "", err
	}
	if err = json.Unmarshal(source, &out.Source); err != nil {
		return out, nil, "", err
	}
	if err = out.Source.validate(); err != nil {
		return out, nil, "", fault.Unavailable("已保存的 GeoIP 来源无效")
	}
	dataset := geoIPDataset{}
	if len(compressed) > 0 {
		reader, e := gzip.NewReader(bytes.NewReader(compressed))
		if e != nil {
			return out, nil, "", e
		}
		raw, e := io.ReadAll(io.LimitReader(reader, geoIPIndexBytes+1))
		reader.Close()
		if e != nil {
			return out, nil, "", e
		}
		if len(raw) > geoIPIndexBytes || secure.Hash(raw) != out.SHA256 {
			return out, nil, "", fault.Unavailable("GeoIP 数据摘要或大小无效")
		}
		if err = json.Unmarshal(raw, &dataset); err != nil {
			return out, nil, "", err
		}
	}
	for code, prefixes := range dataset {
		out.Countries[code] = len(prefixes)
	}
	out.Ready = datasetSource == sourceHash(out.Source) && len(dataset) > 0
	return out, dataset, datasetSource, nil
}
func (s *Service) GeoIP(ctx context.Context) (GeoIPState, error) {
	out, _, _, err := s.readGeoIP(ctx)
	return out, err
}
func (s *Service) SaveGeoIPSource(ctx context.Context, p auth.Principal, requestID, key string, in GeoIPSourceInput) (GeoIPState, error) {
	if err := in.Source.validate(); err != nil {
		return GeoIPState{}, err
	}
	return s.mutateGeoIP(ctx, p, requestID, key, in.BaseVersion, &in.Source, nil)
}
func (s *Service) UpdateGeoIP(ctx context.Context, p auth.Principal, requestID, key string, in GeoIPUpdateInput) (GeoIPState, error) {
	return s.mutateGeoIP(ctx, p, requestID, key, in.Version, nil, in.Countries)
}
func (s *Service) mutateGeoIP(ctx context.Context, p auth.Principal, requestID, key string, version int64, source *GeoIPSource, countries []string) (GeoIPState, error) {
	var out GeoIPState
	if err := p.Require("security.write"); err != nil {
		return out, err
	}
	if version < 0 || version >= 1<<62 || key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("GeoIP 版本或幂等键无效")
	}
	if !s.geoIPBusy.CompareAndSwap(false, true) {
		return out, fault.New(429, "GEOIP_BUSY", "GeoIP 数据正在更新，请稍后重试")
	}
	defer s.geoIPBusy.Store(false)
	action := "firewall.geoip.update"
	if source != nil {
		action = "firewall.geoip.source"
	}
	request, _ := json.Marshal(struct {
		Action    string
		Version   int64
		Source    *GeoIPSource
		Countries []string
	}{action, version, source, countries})
	digest := secure.Hash(request)
	var previous string
	var response []byte
	err := s.DB.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&previous, &response)
	if err == nil {
		if previous != digest {
			return out, fault.Conflict("同一幂等键不能用于不同请求")
		}
		raw, e := s.Vault.Open(response, "idempotency:"+p.ID+":"+key)
		if e != nil {
			return out, e
		}
		e = json.Unmarshal(raw, &out)
		return out, e
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	old, dataset, datasetSource, err := s.readGeoIP(ctx)
	if err != nil {
		return out, err
	}
	if old.Version != version {
		return out, fault.Conflict("GeoIP 配置已变化，请刷新后重试")
	}
	out = old
	if source != nil {
		out.Source = *source
	} else {
		if old.Source.Format == "mmdb" {
			raw, e := downloadGeoIP(ctx, old.Source, old.Source.URL)
			if e != nil {
				return out, e
			}
			dataset, e = parseMMDB(ctx, raw)
			if e != nil {
				return out, e
			}
		} else {
			countries, err = normalizeCountries(countries)
			if err != nil {
				return out, err
			}
			if datasetSource != sourceHash(old.Source) {
				dataset = geoIPDataset{}
			}
			for _, code := range countries {
				var prefixes []string
				for index, template := range []string{old.Source.URL, old.Source.IPv6URL} {
					if template == "" {
						continue
					}
					raw, e := downloadGeoIP(ctx, old.Source, strings.ReplaceAll(template, "{country}", strings.ToLower(code)))
					if e != nil {
						return out, e
					}
					values, e := parseCIDR(raw, index == 1)
					if e != nil {
						return out, e
					}
					prefixes = append(prefixes, values...)
				}
				if len(prefixes) == 0 {
					return out, fault.Invalid("下载的国家 IP 列表为空：" + code)
				}
				dataset[code] = compactPrefixes(prefixes)
			}
		}
		datasetSource = sourceHash(old.Source)
		out.UpdatedAt = time.Now().Unix()
	}
	raw, err := json.Marshal(dataset)
	if err != nil {
		return out, err
	}
	if len(raw) > geoIPIndexBytes {
		return out, fault.Invalid("GeoIP 数据超过容量限制")
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(raw); err != nil {
		return out, err
	}
	if err = writer.Close(); err != nil {
		return out, err
	}
	out.Version++
	out.SHA256 = secure.Hash(raw)
	out.Ready = len(dataset) > 0 && datasetSource == sourceHash(out.Source)
	out.Countries = map[string]int{}
	for code, prefixes := range dataset {
		out.Countries[code] = len(prefixes)
	}
	sourceBytes, _ := json.Marshal(out.Source)
	sourceBytes = s.Vault.Seal(sourceBytes, "firewall:geoip:source")
	result, _ := json.Marshal(out)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = s.migrationIdle(ctx, tx); err != nil {
		return out, err
	}
	if version == 0 {
		_, err = tx.ExecContext(ctx, "INSERT INTO firewall_geoip(id,version,source,dataset,dataset_source,dataset_hash,updated_at) VALUES(1,?,?,?,?,?,?)", out.Version, sourceBytes, compressed.Bytes(), datasetSource, out.SHA256, out.UpdatedAt)
	} else {
		var changed sql.Result
		changed, err = tx.ExecContext(ctx, "UPDATE firewall_geoip SET version=?,source=?,dataset=?,dataset_source=?,dataset_hash=?,updated_at=? WHERE id=1 AND version=?", out.Version, sourceBytes, compressed.Bytes(), datasetSource, out.SHA256, out.UpdatedAt, version)
		if err == nil {
			n, e := changed.RowsAffected()
			if e != nil {
				err = e
			} else if n != 1 {
				err = fault.Conflict("GeoIP 配置已变化，请刷新后重试")
			}
		}
	}
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(result, "idempotency:"+p.ID+":"+key), time.Now().Unix()); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'saved',?)", secure.ID(), requestID, p.ID, action, "geoip", time.Now().Unix()); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Service) ResolveGeoIP(ctx context.Context, in GeoIPResolveInput) (GeoIPResolved, error) {
	var out GeoIPResolved
	countries, err := normalizeCountries(in.Countries)
	if err != nil {
		return out, err
	}
	state, dataset, _, err := s.readGeoIP(ctx)
	if err != nil {
		return out, err
	}
	if in.Version != state.Version || !state.Ready {
		return out, fault.Conflict("GeoIP 数据尚未更新，或配置已变化，请先更新数据")
	}
	out = GeoIPResolved{Version: state.Version, Countries: countries, Sources: []string{}, UpdatedAt: state.UpdatedAt}
	for _, code := range countries {
		prefixes, ok := dataset[code]
		if !ok || len(prefixes) == 0 {
			return out, fault.Invalid("GeoIP 数据不包含所选国家或地区：" + code)
		}
		out.Sources = append(out.Sources, prefixes...)
	}
	out.Sources = compactPrefixes(out.Sources)
	if len(out.Sources) > MaxSourcePrefixes {
		return out, fault.Invalid("所选国家 IP 数量过多，请拆分为多个名单")
	}
	return out, nil
}

func downloadGeoIP(ctx context.Context, source GeoIPSource, address string) ([]byte, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() && !source.AllowPrivateNetwork {
				return nil, errors.New("GeoIP 来源解析到受限网络地址")
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			last = errors.New("GeoIP 来源没有可连接的地址")
		}
		return nil, last
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || r.URL.Scheme != "https" || r.URL.User != nil {
			return errors.New("GeoIP 下载重定向无效")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, fault.Invalid("GeoIP 下载地址无效")
	}
	req.Header.Set("User-Agent", "NginxPanel-GeoIP/1")
	res, err := client.Do(req)
	if err != nil {
		return nil, fault.Unavailable("GeoIP 下载失败，请检查来源地址和网络连接")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fault.Unavailable(fmt.Sprintf("GeoIP 来源返回 HTTP %d", res.StatusCode))
	}
	if res.ContentLength > geoIPDownloadBytes {
		return nil, fault.Invalid("GeoIP 文件超过 64 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, geoIPDownloadBytes+1))
	if err != nil {
		return nil, fault.Unavailable("GeoIP 文件下载中断")
	}
	if len(raw) == 0 || len(raw) > geoIPDownloadBytes {
		return nil, fault.Invalid("GeoIP 文件为空或超过 64 MiB")
	}
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		reader, e := gzip.NewReader(bytes.NewReader(raw))
		if e != nil {
			return nil, fault.Invalid("GeoIP 压缩文件无效")
		}
		decoded, e := io.ReadAll(io.LimitReader(reader, geoIPDownloadBytes+1))
		reader.Close()
		if e != nil || len(decoded) == 0 || len(decoded) > geoIPDownloadBytes {
			return nil, fault.Invalid("GeoIP 解压失败或超过 64 MiB")
		}
		raw = decoded
	}
	return raw, nil
}
func parseCIDR(raw []byte, ipv6 bool) ([]string, error) {
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil || prefix.Addr().Is4() == ipv6 {
			return nil, fault.Invalid("CIDR 数据包含无效地址或地址族不匹配")
		}
		out = append(out, prefix.Masked().String())
		if len(out) > MaxSourcePrefixes {
			return nil, fault.Invalid("CIDR 数据条目过多")
		}
	}
	return out, nil
}
func parseMMDB(ctx context.Context, raw []byte) (geoIPDataset, error) {
	reader, err := maxminddb.OpenBytes(raw)
	if err != nil {
		return nil, fault.Invalid("文件不是有效的 MMDB 数据库")
	}
	defer reader.Close()
	dataset := geoIPDataset{}
	count := 0
	for result := range reader.Networks(maxminddb.SkipEmptyValues()) {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var record struct {
			Country struct {
				Code string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			RegisteredCountry struct {
				Code string `maxminddb:"iso_code"`
			} `maxminddb:"registered_country"`
			CountryCode string `maxminddb:"country_code"`
		}
		if err = result.Decode(&record); err != nil {
			return nil, fault.Invalid("MMDB 国家数据无法读取")
		}
		code := strings.ToUpper(record.Country.Code)
		if code == "" {
			code = strings.ToUpper(record.RegisteredCountry.Code)
		}
		if code == "" {
			code = strings.ToUpper(record.CountryCode)
		}
		if !validCountry(code) {
			continue
		}
		prefix := result.Prefix()
		if !prefix.IsValid() {
			return nil, fault.Invalid("MMDB 网络地址无效")
		}
		dataset[code] = append(dataset[code], prefix.Masked().String())
		count++
		if count > 4000000 {
			return nil, fault.Invalid("MMDB 网络条目超过容量限制")
		}
	}
	if len(dataset) == 0 {
		return nil, fault.Invalid("MMDB 未包含可识别的国家代码")
	}
	for code, prefixes := range dataset {
		dataset[code] = compactPrefixes(prefixes)
	}
	return dataset, nil
}

// Collapse adjacent CIDR blocks before persisting snapshots or compiling sets.
func compactPrefixes(values []string) []string {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	stack := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if len(stack) > 0 && stack[len(stack)-1].Addr().BitLen() == prefix.Addr().BitLen() && stack[len(stack)-1].Contains(prefix.Addr()) {
			continue
		}
		stack = append(stack, prefix)
		for len(stack) > 1 {
			a, b := stack[len(stack)-2], stack[len(stack)-1]
			if a.Bits() == 0 || a.Bits() != b.Bits() || a.Addr().BitLen() != b.Addr().BitLen() {
				break
			}
			parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
			if !parent.Contains(b.Addr()) {
				break
			}
			stack = append(stack[:len(stack)-2], parent)
		}
	}
	out := make([]string, 0, len(stack))
	for _, prefix := range stack {
		out = append(out, prefix.String())
	}
	return out
}
