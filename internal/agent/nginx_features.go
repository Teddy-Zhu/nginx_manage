package agent

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxmodules"
)

type Feature struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}
type NginxFeatures struct {
	Available bool               `json:"available"`
	Version   string             `json:"version"`
	Features  map[string]Feature `json:"features"`
	Reason    string             `json:"reason"`
	Modules   []NativeModule     `json:"modules"`

	// These compile-time defaults become usable with a confirmed running
	// dynamic Stream core. They are not independently loadable modules.
	streamDefaults map[string]Feature
}
type boundedOutput struct {
	value strings.Builder
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.value.Len()+len(p) > b.limit {
		return 0, errors.New("Nginx diagnostic output exceeds limit")
	}
	return b.value.Write(p)
}
func (n *Nginx) Features(ctx context.Context) NginxFeatures {
	out := NginxFeatures{Features: map[string]Feature{}, Modules: []NativeModule{}}
	if n.Container != nil {
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if _, err := n.Container.Version(call); err != nil {
			out.Reason = "固定 Nginx 镜像运行身份或编译能力未确认"
			return out
		}
		verified, err := containerFeatures(n.Container.Binding)
		if err != nil {
			out.Reason = err.Error()
			return out
		}
		return verified
	}
	binary, err := trustedFile(n.Binary, true)
	if err != nil || binary != n.Binary {
		out.Reason = "可信 Nginx 二进制不可用"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-V")
	command.WaitDelay = time.Second
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var output boundedOutput
	output.limit = 64 << 10
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		out.Reason = "无法读取 Nginx 编译能力"
		return out
	}
	out = parseNginxFeatures(output.value.String())
	n.nativeModuleFeatures(ctx, &out)
	return out
}
func configureWords(value string) ([]string, error) {
	out := []string{}
	var word strings.Builder
	var quote rune
	escaped, active := false, false
	flush := func() {
		if active {
			out = append(out, word.String())
			word.Reset()
			active = false
		}
	}
	for _, char := range value {
		if escaped {
			word.WriteRune(char)
			escaped = false
			active = true
			continue
		}
		if char == '\\' && quote != '\'' {
			escaped = true
			active = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				word.WriteRune(char)
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			active = true
			continue
		}
		if char == ' ' || char == '\t' {
			flush()
			continue
		}
		active = true
		word.WriteRune(char)
	}
	if escaped || quote != 0 {
		return nil, errors.New("invalid configure arguments")
	}
	flush()
	return out, nil
}
func parseNginxFeatures(value string) NginxFeatures {
	out := NginxFeatures{Features: map[string]Feature{}, Modules: []NativeModule{}}
	version := regexp.MustCompile(`(?m)^nginx version: nginx/(\d+)\.(\d+)\.(\d+)(?:\s|$)`).FindStringSubmatch(value)
	if len(version) != 4 {
		out.Reason = "未识别 Nginx 版本，模块能力保持未知"
		return out
	}
	major, _ := strconv.Atoi(version[1])
	minor, _ := strconv.Atoi(version[2])
	patch, _ := strconv.Atoi(version[3])
	out.Version = strings.Join(version[1:], ".")
	var args []string
	found := false
	for _, line := range strings.Split(value, "\n") {
		if strings.HasPrefix(line, "configure arguments:") {
			var err error
			args, err = configureWords(strings.TrimSpace(strings.TrimPrefix(line, "configure arguments:")))
			if err != nil {
				out.Reason = "无法解析 Nginx 编译参数"
				return out
			}
			found = true
			break
		}
	}
	if !found {
		out.Reason = "Nginx 未提供编译参数"
		return out
	}
	flags := map[string]bool{}
	for _, arg := range args {
		flags[arg] = true
	}
	atLeast := func(ma, mi, pa int) bool {
		return major > ma || major == ma && (minor > mi || minor == mi && patch >= pa)
	}
	http := !flags["--without-http"]
	set := func(name string, available bool, reason string) {
		if available {
			reason = ""
		}
		out.Features[name] = Feature{Available: available, Reason: reason}
	}
	set("http", http, "缺少 HTTP 核心模块")
	for _, module := range []string{"proxy", "access", "log", "headers", "geo", "split_clients", "charset", "gzip"} {
		set("http_"+module, http && !flags["--without-http_"+module+"_module"], "缺少 HTTP "+module+" 模块")
	}
	set("http_cache", http && !flags["--without-http_proxy_module"] && !flags["--without-http-cache"], "缺少 HTTP 代理缓存支持")
	set("http2", http && flags["--with-http_v2_module"] && atLeast(1, 9, 5), "缺少 HTTP/2 模块")
	for _, module := range []struct {
		name    string
		version bool
	}{
		{"hash", atLeast(1, 7, 2)},
		{"ip_hash", true},
		{"least_conn", atLeast(1, 2, 2)},
		{"keepalive", atLeast(1, 1, 4)},
		{"zone", atLeast(1, 9, 0)},
	} {
		set("http_upstream_"+module.name, http && !flags["--without-http_upstream_"+module.name+"_module"] && module.version, "缺少匹配版本的 HTTP upstream "+module.name+" 模块")
	}
	set("map", http && !flags["--without-http_map_module"], "缺少 HTTP map 模块")
	set("map_volatile", http && !flags["--without-http_map_module"] && atLeast(1, 11, 7), "路径规则需要 Nginx 1.11.7 或更新版本的 map 模块")
	set("rewrite", http && !flags["--without-http_rewrite_module"], "缺少 HTTP rewrite 模块")
	set("http01", http && !flags["--without-http_rewrite_module"] && !flags["--without-http_proxy_module"], "HTTP-01 需要 HTTP rewrite 和 proxy 模块")
	req := http && !flags["--without-http_limit_req_module"]
	conn := http && !flags["--without-http_limit_conn_module"]
	set("limit_req", req, "缺少 HTTP 请求限速模块")
	set("limit_conn", conn, "缺少 HTTP 并发限制模块")
	set("limit_req_status", req && atLeast(1, 17, 6), "请求限速状态观测需要 Nginx 1.17.6 或更新版本")
	set("limit_conn_status", conn && atLeast(1, 17, 6), "并发限制状态观测需要 Nginx 1.17.6 或更新版本")
	set("limit_req_observe", req && atLeast(1, 17, 1), "限速观察模式需要 Nginx 1.17.1 或更新版本")
	set("limit_conn_observe", conn && atLeast(1, 17, 6), "并发观察模式需要 Nginx 1.17.6 或更新版本")
	set("real_ip", http && flags["--with-http_realip_module"], "缺少 HTTP realip 模块")
	set("tls", http && flags["--with-http_ssl_module"], "缺少 HTTP SSL 模块")
	set("https_redirect", http && flags["--with-http_ssl_module"] && !flags["--without-http_rewrite_module"] && atLeast(1, 13, 0), "HTTPS 308 跳转需要 HTTP SSL、rewrite 模块及 Nginx 1.13.0 或更新版本")
	set("hsts", http && flags["--with-http_ssl_module"] && !flags["--without-http_headers_module"] && atLeast(1, 7, 5), "HSTS 需要 HTTP SSL、headers 模块及 Nginx 1.7.5 或更新版本")
	set("stream", flags["--with-stream"], "缺少静态 Stream 模块，或批准的动态模块尚未确认运行")
	set("stream_tls", flags["--with-stream"] && flags["--with-stream_ssl_module"], "Stream TLS 模块尚未确认可用")
	set("stream_real_ip", flags["--with-stream"] && flags["--with-stream_realip_module"], "Stream realip 模块尚未确认可用")
	set("stream_ssl_preread", flags["--with-stream"] && flags["--with-stream_ssl_preread_module"], "Stream SSL preread 模块尚未确认可用")
	out.streamDefaults = map[string]Feature{}
	streamCompiled := flags["--with-stream"] || flags["--with-stream=dynamic"]
	for _, module := range []struct {
		feature, flag string
		version       bool
	}{
		{"stream_map", "map", atLeast(1, 11, 2)},
		{"stream_map_volatile", "map", atLeast(1, 11, 7)},
		{"stream_access", "access", atLeast(1, 9, 2)},
		{"stream_log", "log", atLeast(1, 11, 4)},
		{"stream_geo", "geo", atLeast(1, 11, 3)},
		{"stream_split_clients", "split_clients", atLeast(1, 11, 3)},
		{"stream_limit_conn", "limit_conn", atLeast(1, 9, 3)},
		{"stream_limit_conn_observe", "limit_conn", atLeast(1, 17, 6)},
		{"stream_return", "return", atLeast(1, 11, 2)},
		{"stream_set", "set", atLeast(1, 19, 3)},
		{"stream_upstream_hash", "upstream_hash", atLeast(1, 9, 0)},
		{"stream_upstream_least_conn", "upstream_least_conn", atLeast(1, 9, 0)},
		{"stream_upstream_zone", "upstream_zone", atLeast(1, 9, 0)},
	} {
		compiled := streamCompiled && !flags["--without-stream_"+module.flag+"_module"] && module.version
		reason := "缺少匹配版本的 Stream " + module.flag + " 模块"
		out.streamDefaults[module.feature] = Feature{Available: compiled, Reason: reason}
		if compiled {
			out.streamDefaults[module.feature] = Feature{Available: true}
			reason = "Stream 核心模块尚未确认运行"
		}
		set(module.feature, flags["--with-stream"] && compiled, reason)
	}
	out.Available = true
	return out
}
func (c *Client) NginxFeatures(ctx context.Context) (NginxFeatures, error) {
	var out NginxFeatures
	err := c.request(ctx, "GET", "/v1/nginx/features", nil, &out)
	return out, err
}
func (c *Client) RequireFeatures(ctx context.Context, names []string) error {
	out, err := c.NginxFeatures(ctx)
	if err != nil {
		return fault.Unavailable("无法连接 Nginx 能力探测")
	}
	if !out.Available {
		return fault.Unavailable(out.Reason)
	}
	for _, name := range names {
		feature, ok := out.Features[name]
		if !ok {
			return fault.Unavailable("无法确认 Nginx 能力：" + name)
		}
		if !feature.Available {
			return fault.Unavailable(feature.Reason)
		}
	}
	return nil
}

// A compiled dynamic module is usable only after the selected immutable copy
// belongs to a publication whose running probe was confirmed. Catalog presence
// and a matching ELF symbol alone never establish a running capability.
func (n *Nginx) nativeModuleFeatures(ctx context.Context, out *NginxFeatures) {
	if len(n.Modules) == 0 {
		if _, header, err := n.activeMetadata(); err != nil || len(header.Modules) == 0 {
			return
		}
	}
	binaryHash, hashErr := nginxmodules.HashTrusted(n.Binary, limits.NginxBinaryBytes)
	running := map[string]ModuleDependency{}
	if _, active, err := n.active(); err == nil {
		observed, cancel := context.WithTimeout(ctx, time.Second)
		err = n.observe(observed, active)
		cancel()
		if err == nil {
			running = active.Modules
		}
	}
	reported := map[string]bool{}
	for _, item := range n.Modules {
		reported[item.Path()] = true
		status := NativeModule{ID: item.ID, Name: item.Name, Path: item.Path(), SHA256: item.SHA256, Features: []string{}}
		if hashErr != nil {
			status.Reason = "无法核对 Nginx 二进制散列"
		} else {
			_, features, err := n.approvedModule(item, binaryHash)
			if err != nil {
				status.Reason = "模块未安装、散列或权限已变化，或批准的 Nginx 二进制不匹配"
			} else {
				status.Available = true
				status.Features = append([]string{}, features...)
				for _, feature := range features {
					if feature == "stream" {
						for name, capability := range out.streamDefaults {
							if capability.Available {
								status.Features = append(status.Features, name)
							}
						}
						break
					}
				}
				sort.Strings(status.Features)
			}
		}
		dependency, ok := running[item.Path()]
		status.Running = ok && dependency.SHA256 == item.SHA256 && dependency.BinarySHA256 == binaryHash
		out.Modules = append(out.Modules, status)
	}
	retired := []string{}
	for name := range running {
		if !reported[name] {
			retired = append(retired, name)
		}
	}
	sort.Strings(retired)
	for _, name := range retired {
		dependency := running[name]
		if !reported[name] {
			parts := strings.Split(name, "/")
			out.Modules = append(out.Modules, NativeModule{ID: parts[1], Name: parts[1], Path: name, SHA256: dependency.SHA256, Running: true, Features: dependency.Features, Reason: "运行版本已不在本机批准清单中；后续配置须移除此版本或由本机管理员重新批准"})
		}
	}
	if !out.Available {
		return
	}
	for _, dependency := range running {
		for _, name := range dependency.Features {
			out.Features[name] = Feature{Available: true}
		}
	}
	if out.Features["stream"].Available {
		for name, feature := range out.streamDefaults {
			out.Features[name] = feature
		}
	}
}
