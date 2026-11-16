package releases

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func assetHost(host string) bool {
	return host == "release-assets.githubusercontent.com" || host == "objects.githubusercontent.com"
}

func githubHTTP() (*http.Client, *http.Transport) {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" || host != "api.github.com" && !assetHost(host) {
			return nil, errors.New("发行下载目标未获许可")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 || len(ips) > 32 {
			return nil, errors.New("发行下载目标 DNS 结果无效")
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
				return nil, errors.New("发行下载目标解析到非公网地址")
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: 32 << 10, MaxConnsPerHost: 1, IdleConnTimeout: 30 * time.Second, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// API metadata never follows redirects, including repository transfers.
		// Only asset GETs may reach the two fixed GitHub storage hosts.
		req.Header.Del("Authorization")
		req.Header.Del("If-None-Match")
		if len(via) == 0 || len(via) > 2 || via[0].Header.Get("Accept") != "application/octet-stream" || req.Method != http.MethodGet || !assetHost(req.URL.Host) || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" || len(req.URL.String()) > 8192 {
			return errors.New("发行下载重定向未获许可")
		}
		return nil
	}}
	return client, transport
}

type onlineSession struct {
	input            OnlineInput
	publisher        publisher
	token, tokenHash string
	cache            onlineCache
	client           *http.Client
}

func readGithubToken(name string) (string, string, error) {
	if name == "" {
		return "", "", nil
	}
	f, before, err := openRoot(name, 2048)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	if before.Mode().Perm() != 0600 {
		return "", "", errors.New("GitHub Token 文件须为 root 持有的 0600 文件")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil {
		return "", "", err
	}
	if int64(len(raw)) != before.Size() || !unchanged(f, before) {
		return "", "", errors.New("GitHub Token 文件在读取期间发生变化")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(token) < 20 || len(token) > 1024 {
		return "", "", errors.New("GitHub Token 长度无效")
	}
	for _, c := range token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return "", "", errors.New("GitHub Token 格式无效")
		}
	}
	return token, hash(raw), nil
}

func (s *onlineSession) currentSource() error {
	raw, err := readRoot(s.input.TrustPath, 16<<10)
	if err != nil {
		return err
	}
	if hash(raw) != hash(s.publisher.raw) {
		return errors.New("本机发行信任已变化，须重新发起在线准备")
	}
	_, tokenHash, err := readGithubToken(s.input.TokenPath)
	if err != nil {
		return err
	}
	if tokenHash != s.tokenHash {
		return errors.New("GitHub Token 已变化，须重新发起在线准备")
	}
	return nil
}

func validETag(tag string) bool {
	if len(tag) > 512 {
		return false
	}
	for _, c := range tag {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func cacheLifetime(header http.Header) (int64, bool) {
	age, noCache, store := int64(60), false, true
	for _, field := range strings.Split(header.Get("Cache-Control"), ",") {
		parts := strings.SplitN(strings.TrimSpace(strings.ToLower(field)), "=", 2)
		switch parts[0] {
		case "no-store":
			store = false
		case "no-cache":
			noCache = true
		case "max-age":
			if len(parts) == 2 {
				if seconds, err := strconv.ParseInt(strings.Trim(parts[1], `"`), 10, 64); err == nil && seconds >= 0 {
					age = min(seconds, 3600)
				}
			}
		}
	}
	if noCache || !store {
		age = 0
	}
	if servedAge, err := strconv.ParseInt(header.Get("Age"), 10, 64); err == nil && servedAge > 0 {
		age = max(0, age-servedAge)
	}
	return age, store
}

func (s *onlineSession) get(ctx context.Context, endpoint, accept, etag string) (*http.Response, error) {
	if err := s.currentSource(); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if s.cache.BlockedUntil > now {
		return nil, fmt.Errorf("GitHub 请求处于限流等待期，最早重试时间 %s", time.Unix(s.cache.BlockedUntil, 0).UTC().Format(time.RFC3339))
	}
	// Endpoints are constructed locally; no URL returned by GitHub is used here.
	suffix := "/" + endpoint
	if endpoint == "?per_page=100" {
		suffix = endpoint
	}
	u := "https://api.github.com/repos/" + s.publisher.trust.Repository + "/releases" + suffix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, errors.New("GitHub 请求路径无效")
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "nginxpanel-release/1")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	response, err := s.client.Do(req)
	if err != nil {
		// net/http errors can contain signed storage URLs. Never expose those.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, errors.New("GitHub 请求超时")
		}
		return nil, errors.New("GitHub HTTPS 请求失败，请检查证书、DNS、网络和重定向目标")
	}
	blocked := s.cache.BlockedUntil
	if response.StatusCode == http.StatusTooManyRequests {
		blocked = max(blocked, now+60)
	}
	if response.Header.Get("X-RateLimit-Remaining") == "0" {
		blocked = max(blocked, now+60)
		if reset, err := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && reset > now {
			blocked = max(blocked, min(reset, now+366*86400))
		}
	}
	if value := response.Header.Get("Retry-After"); value != "" {
		if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
			blocked = max(blocked, now+min(seconds, 366*86400))
		} else if until, err := http.ParseTime(value); err == nil {
			blocked = max(blocked, min(until.Unix(), now+366*86400))
		}
	}
	if blocked != s.cache.BlockedUntil {
		s.cache.BlockedUntil = blocked
		if err := writeOnlineCache(s.cache); err != nil {
			response.Body.Close()
			return nil, err
		}
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified {
		response.Body.Close()
		switch response.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("软件源 %s 未找到可用发行或资产（HTTP 404）；请检查仓库、发行标签及私有仓库访问权限", s.publisher.trust.Repository)
		case http.StatusUnauthorized:
			return nil, errors.New("GitHub 访问令牌无效或已过期（HTTP 401）")
		case http.StatusForbidden, http.StatusTooManyRequests:
			if blocked > now {
				return nil, fmt.Errorf("GitHub 暂时拒绝请求（HTTP %d），可重试时间 %s", response.StatusCode, time.Unix(blocked, 0).UTC().Format(time.RFC3339))
			}
			return nil, errors.New("GitHub 拒绝访问，请检查仓库读取权限（HTTP 403）")
		default:
			return nil, fmt.Errorf("GitHub 软件源请求失败（HTTP %d）", response.StatusCode)
		}
	}
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		response.Body.Close()
		return nil, errors.New("GitHub 响应使用了不支持的内容编码")
	}
	return response, nil
}

func (s *onlineSession) download(ctx context.Context, directory string, asset githubAsset, expected string) error {
	if asset.Digest != "" {
		digest := strings.TrimPrefix(asset.Digest, "sha256:")
		if !strings.HasPrefix(asset.Digest, "sha256:") || !validHash(digest) || expected != "" && digest != expected {
			return errors.New("GitHub 资产散列与签名清单不一致或格式无效")
		}
		if expected == "" {
			expected = digest
		}
	}
	response, err := s.get(ctx, "assets/"+strconv.FormatInt(asset.ID, 10), "application/octet-stream", "")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength >= 0 && response.ContentLength != asset.Size {
		return errors.New("GitHub 资产状态或长度不匹配")
	}
	f, err := os.OpenFile(filepath.Join(directory, asset.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = f.Chmod(0600)
	h := sha256.New()
	var copied int64
	if err == nil {
		copied, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx: ctx, reader: response.Body}, asset.Size+1))
		if err != nil {
			var fileErr *os.PathError
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if errors.As(err, &fileErr) {
				err = fmt.Errorf("写入资产暂存失败：%w", fileErr)
			} else {
				err = errors.New("GitHub 资产传输中断")
			}
		}
	}
	if err == nil && (copied != asset.Size || expected != "" && hex.EncodeToString(h.Sum(nil)) != expected) {
		err = errors.New("GitHub 资产长度或 SHA-256 不匹配")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func tagEndpoint(tag string) string {
	if tag == "" {
		return "latest"
	}
	return "tags/" + url.PathEscape(tag)
}
