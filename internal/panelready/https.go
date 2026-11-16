package panelready

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

const frontendFileLimit = 8 << 20
const frontendEntryLimit = 64
const frontendModuleLimit = 16
const frontendCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

type HTTPSResult struct {
	FrontendFiles     int    `json:"frontend_files"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

func localCertificate(d panelruntime.Deployment) (*x509.Certificate, error) {
	return readCertificate(d, []string{"run/readiness"})
}

func readCertificate(d panelruntime.Deployment, directories []string) (*x509.Certificate, error) {
	for _, relative := range directories {
		info, err := os.Lstat(filepath.Join(d.DataDir, relative))
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || int(st.Uid) != d.UID || int(st.Gid) != d.GID {
			return nil, errors.New("管理证书目录归属无效")
		}
	}
	name := filepath.Join(d.DataDir, directories[len(directories)-1], "cert.pem")
	fd, err := secure.OpenReadNoSymlinks(unix.AT_FDCWD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1 || int(st.Uid) != d.UID || int(st.Gid) != d.GID || info.Size() <= 0 || info.Size() > 64<<10 {
		return nil, errors.New("管理证书文件身份无效")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != info.Size() || !secure.RootFileUnchanged(f, info) {
		return nil, errors.New("管理证书在读取期间发生变化")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("本机管理证书格式无效")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readResponse(ctx context.Context, c *http.Client, scheme, address, path string, limit int64) ([]byte, http.Header, error) {
	u := url.URL{Scheme: scheme, Host: address, Path: path}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("Cache-Control", "no-cache")
	response, err := c.Do(r)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("面板就绪请求 %s 返回 HTTP %d", path, response.StatusCode)
	}
	if response.Header.Get("Content-Encoding") != "" {
		return nil, nil, errors.New("面板就绪请求不接受压缩响应")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(raw)) > limit {
		return nil, nil, errors.New("面板就绪响应超过发布限制")
	}
	return raw, response.Header, nil
}

func apiData(raw []byte, header http.Header, node string, out any) error {
	media, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return errors.New("实际 API 响应类型无效")
	}
	var e struct {
		Code      string          `json:"code"`
		Message   string          `json:"message"`
		Data      json.RawMessage `json:"data"`
		RequestID string          `json:"request_id"`
		NodeID    string          `json:"node_id"`
	}
	if err := decode(raw, &e); err != nil {
		return err
	}
	if e.Code != "OK" || e.NodeID != node || !idValue.MatchString(e.RequestID) || header.Get("X-Request-ID") != e.RequestID {
		return errors.New("实际 API 响应身份或统一格式无效")
	}
	return decode(e.Data, out)
}

func frontendAssetPath(source string) (string, error) {
	if len(source) > 512 || !strings.HasPrefix(source, "/assets/") || strings.HasPrefix(source, "//") || strings.ContainsAny(source, "?#%\\") || path.Clean(source) != source {
		return "", errors.New("前端入口资源路径无效")
	}
	for _, c := range source {
		if c > 127 || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-", c)) {
			return "", errors.New("前端入口资源路径无效")
		}
	}
	switch strings.ToLower(path.Ext(source)) {
	case ".js", ".mjs", ".css", ".svg", ".png", ".ico", ".webp", ".jpg", ".jpeg", ".avif":
		return source, nil
	default:
		return "", errors.New("前端入口资源类型无效")
	}
}

func frontendEntries(entries []string) (map[string]struct{}, error) {
	if len(entries) == 0 || len(entries) > frontendEntryLimit || !sort.StringsAreSorted(entries) {
		return nil, errors.New("前端入口资源清单无效")
	}
	want := make(map[string]struct{}, len(entries))
	hasScript := false
	for _, entry := range entries {
		asset, err := frontendAssetPath(entry)
		if err != nil {
			return nil, err
		}
		if _, exists := want[asset]; exists {
			return nil, errors.New("前端入口资源清单包含重复项")
		}
		want[asset] = struct{}{}
		ext := strings.ToLower(path.Ext(asset))
		if extIsJavaScript(ext) {
			hasScript = true
		}
	}
	if !hasScript {
		return nil, errors.New("前端入口缺少 JavaScript 模块")
	}
	return want, nil
}

func extIsJavaScript(ext string) bool { return ext == ".js" || ext == ".mjs" }

func checkFrontendAsset(ctx context.Context, c *http.Client, scheme, address, name string) error {
	raw, headers, err := readResponse(ctx, c, scheme, address, name, frontendFileLimit)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("前端入口资源内容为空")
	}
	media, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil {
		return errors.New("前端入口资源响应类型无效")
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs":
		if media != "text/javascript" && media != "application/javascript" && media != "text/ecmascript" && media != "application/ecmascript" {
			return errors.New("前端脚本响应类型无效")
		}
	case ".css":
		if media != "text/css" {
			return errors.New("前端样式响应类型无效")
		}
	case ".svg", ".png", ".ico", ".webp", ".jpg", ".jpeg", ".avif":
		if !strings.HasPrefix(media, "image/") {
			return errors.New("前端图标响应类型无效")
		}
	}
	return nil
}

func checkFrontendPage(raw []byte, headers http.Header, want map[string]struct{}) error {
	media, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil || media != "text/html" || headers.Get("Cache-Control") != "no-store" || !strings.EqualFold(headers.Get("X-Content-Type-Options"), "nosniff") || headers.Get("Referrer-Policy") != "no-referrer" || headers.Get("Content-Security-Policy") != frontendCSP {
		return errors.New("前端首页响应类型或安全策略无效")
	}
	seen := make(map[string]struct{}, len(want))
	hasHTML, hasBody, hasApp, modules := false, false, false, 0
	add := func(source string, script bool) error {
		asset, err := frontendAssetPath(source)
		if err != nil {
			return err
		}
		if script && !extIsJavaScript(strings.ToLower(path.Ext(asset))) {
			return errors.New("前端脚本入口扩展名无效")
		}
		if _, exists := want[asset]; !exists {
			return errors.New("前端首页引用不匹配入口清单")
		}
		seen[asset] = struct{}{}
		return nil
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(raw))
	for {
		typeOf := tokenizer.Next()
		if typeOf == html.ErrorToken {
			if tokenizer.Err() != io.EOF {
				return errors.New("前端首页 HTML 格式无效")
			}
			break
		}
		if typeOf != html.StartTagToken && typeOf != html.SelfClosingTagToken {
			continue
		}
		tag := tokenizer.Token()
		attrs := make(map[string]string, len(tag.Attr))
		for _, attr := range tag.Attr {
			if _, exists := attrs[attr.Key]; exists {
				return errors.New("前端首页包含重复属性")
			}
			attrs[attr.Key] = attr.Val
		}
		switch tag.Data {
		case "html":
			hasHTML = true
		case "body":
			hasBody = true
		case "base":
			return errors.New("前端首页不能重定义资源基址")
		case "div":
			if attrs["id"] == "app" {
				hasApp = true
			}
		case "script":
			if attrs["src"] == "" || attrs["type"] != "module" {
				return errors.New("前端首页包含未授权脚本")
			}
			if err := add(attrs["src"], true); err != nil {
				return err
			}
			modules++
		case "link":
			rels := strings.Fields(strings.ToLower(attrs["rel"]))
			stylesheet := containsString(rels, "stylesheet")
			modulepreload := containsString(rels, "modulepreload")
			icon := containsString(rels, "icon")
			resource := stylesheet || modulepreload || icon
			if resource {
				if attrs["href"] == "" {
					return errors.New("前端首页入口链接缺少地址")
				}
				ext := strings.ToLower(path.Ext(attrs["href"]))
				if stylesheet && ext != ".css" || modulepreload && !extIsJavaScript(ext) || icon && ext != ".svg" && ext != ".png" && ext != ".ico" && ext != ".webp" && ext != ".jpg" && ext != ".jpeg" && ext != ".avif" {
					return errors.New("前端首页入口链接类型无效")
				}
				if err := add(attrs["href"], modulepreload); err != nil {
					return err
				}
			}
		}
	}
	if !hasHTML || !hasBody || !hasApp || modules == 0 || modules > frontendModuleLimit || len(seen) != len(want) {
		return errors.New("前端首页内容或入口资源不完整")
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// CheckListener uses the configured management protocol and published routes.
// HTTPS pins the saved certificate; HTTP remains confined to the local listener.
func CheckListener(ctx context.Context, s panelruntime.Snapshot, nodeID string) (HTTPSResult, error) {
	var out HTTPSResult
	cert, err := localCertificate(s.Deployment)
	if err != nil {
		return out, err
	}
	out.CertificateSHA256 = secure.Hash(cert.Raw)
	scheme := "https"
	if s.Deployment.HTTP {
		scheme = "http"
	}
	address := panelruntime.LocalListen(s.Deployment.Listen)
	// This local endpoint is identified by its saved certificate, including
	// installations whose public certificate has no loopback DNS/IP SAN.
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			if address != panelruntime.LocalListen(s.Deployment.Listen) {
				return nil, errors.New("就绪探测只能访问原管理监听")
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", address)
		},
		TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, cert.Raw) {
				return errors.New("实际管理 TLS 证书与本机记录不一致")
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				return errors.New("实际管理 TLS 证书不在有效期内")
			}
			return nil
		}}}
	defer t.CloseIdleConnections()
	c := &http.Client{Transport: t, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("面板就绪请求不接受重定向") }}
	raw, headers, err := readResponse(ctx, c, scheme, address, "/api/v1/system/health", ResponseLimit)
	if err != nil {
		return out, err
	}
	var health struct {
		Status      string `json:"status"`
		Development bool   `json:"development"`
	}
	if err = apiData(raw, headers, nodeID, &health); err != nil {
		return out, err
	}
	if health.Status != "ok" || health.Development {
		return out, errors.New("实际 API 健康状态无效")
	}
	raw, headers, err = readResponse(ctx, c, scheme, address, "/api/v1/system/version", ResponseLimit)
	if err != nil {
		return out, err
	}
	var version struct {
		FrontendID          string   `json:"frontend_id"`
		FrontendEntrypoints []string `json:"frontend_entries"`
		Version             string   `json:"version"`
		APIVersion          int      `json:"api_version"`
		AgentProtocol       int      `json:"agent_protocol"`
		LauncherVersion     int      `json:"launcher_version"`
		ParserVersion       string   `json:"parser_version"`
		PolicyVersion       string   `json:"policy_version"`
		Runtime             string   `json:"runtime"`
	}
	if err = apiData(raw, headers, nodeID, &version); err != nil {
		return out, err
	}
	if version.Version != s.Release.Version || version.APIVersion != 1 || version.AgentProtocol != s.Release.AgentProtocol || version.LauncherVersion != s.Release.LauncherVersion || version.Runtime != s.Deployment.Mode || version.ParserVersion == "" || version.PolicyVersion == "" {
		return out, errors.New("实际 API 版本或运行模式与当前发布不一致")
	}
	if version.FrontendID != s.Release.FrontendID {
		return out, errors.New("实际页面身份与目标核心发布不一致")
	}
	want, err := frontendEntries(version.FrontendEntrypoints)
	if err != nil {
		return out, err
	}
	for _, name := range version.FrontendEntrypoints {
		if err = checkFrontendAsset(ctx, c, scheme, address, name); err != nil {
			return out, err
		}
		out.FrontendFiles++
	}
	// The root route must serve the active application's HTML entry point.
	raw, headers, err = readResponse(ctx, c, scheme, address, "/", frontendFileLimit)
	if err != nil {
		return out, err
	}
	if err = checkFrontendPage(raw, headers, want); err != nil {
		return out, err
	}
	return out, nil
}
