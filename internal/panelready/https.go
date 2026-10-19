package panelready

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

type HTTPSResult struct {
	FrontendFiles     int    `json:"frontend_files"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

func localCertificate(d panelruntime.Deployment) (*x509.Certificate, error) {
	for _, relative := range []string{"secrets", "secrets/node-tls"} {
		info, err := os.Lstat(filepath.Join(d.DataDir, relative))
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || int(st.Uid) != d.UID || int(st.Gid) != d.GID {
			return nil, errors.New("管理证书目录归属无效")
		}
	}
	name := filepath.Join(d.DataDir, "secrets", "node-tls", "cert.pem")
	fd, err := unix.Openat2(unix.AT_FDCWD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
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

func readResponse(ctx context.Context, c *http.Client, address, path string, limit int64) ([]byte, http.Header, error) {
	u := url.URL{Scheme: "https", Host: address, Path: path}
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

// CheckHTTPS uses the real listener and published routes. It checks each
// immutable frontend file, without an npm build or browser execution.
func CheckHTTPS(ctx context.Context, s panelruntime.Snapshot, nodeID string) (HTTPSResult, error) {
	var out HTTPSResult
	cert, err := localCertificate(s.Deployment)
	if err != nil {
		return out, err
	}
	out.CertificateSHA256 = secure.Hash(cert.Raw)
	// This local endpoint is identified by its saved certificate, including
	// installations whose public certificate has no loopback DNS/IP SAN.
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			if address != s.Deployment.Listen {
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
	raw, headers, err := readResponse(ctx, c, s.Deployment.Listen, "/api/v1/system/health", ResponseLimit)
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
	raw, headers, err = readResponse(ctx, c, s.Deployment.Listen, "/api/v1/system/version", ResponseLimit)
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
	frontend, _, err := panelruntime.Frontends(s.Deployment.DataDir, s.Release.ID)
	if err != nil {
		return out, err
	}
	if version.FrontendID != frontend.Source.ID {
		return out, errors.New("实际前端身份与已批准选择不一致")
	}
	web := frontend.Files
	files := make([]string, 0, len(web))
	for name := range web {
		files = append(files, name)
	}
	sort.Strings(files)
	for _, name := range files {
		f := web[name]
		raw, headers, err = readResponse(ctx, c, s.Deployment.Listen, "/"+name, f.Size)
		if err != nil {
			return out, err
		}
		h := sha256.Sum256(raw)
		if int64(len(raw)) != f.Size || hex.EncodeToString(h[:]) != f.SHA256 {
			return out, fmt.Errorf("实际前端文件 %s 与受信发布不一致", name)
		}
		media, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
		switch strings.ToLower(filepath.Ext(name)) {
		case ".html":
			if err != nil || media != "text/html" {
				return out, errors.New("实际前端 HTML 响应类型无效")
			}
		case ".js", ".mjs":
			if err != nil || media != "text/javascript" && media != "application/javascript" {
				return out, errors.New("实际前端脚本响应类型无效")
			}
		case ".css":
			if err != nil || media != "text/css" {
				return out, errors.New("实际前端样式响应类型无效")
			}
		}
		out.FrontendFiles++
	}
	// The browser entry route must resolve to this same signed index.
	raw, headers, err = readResponse(ctx, c, s.Deployment.Listen, "/", web["index.html"].Size)
	if err != nil {
		return out, err
	}
	if secure.Hash(raw) != web["index.html"].SHA256 {
		return out, errors.New("实际前端入口与受信发布不一致")
	}
	media, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil || media != "text/html" {
		return out, errors.New("实际前端入口响应类型无效")
	}
	again, _, err := panelruntime.Frontends(s.Deployment.DataDir, s.Release.ID)
	if err != nil || again.Source != frontend.Source {
		return out, errors.New("就绪观察期间前端选择变化")
	}
	return out, nil
}
