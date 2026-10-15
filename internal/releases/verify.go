package releases

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var repository = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
var pythonInterpreter = regexp.MustCompile(`^/usr/bin/python3(\.[0-9]+)?$`)

// Check duplicate names before typed decoding: signatures cover bytes, and all
// consumers must agree on their meaning. Bound nesting and token allocations.
func strictJSON(raw []byte, out any) error {
	return decodeJSON(raw, out, true)
}
func decodeJSON(raw []byte, out any, rejectUnknown bool) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON 编码无效")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		tokens++
		if depth > 32 || tokens > 100000 {
			return errors.New("JSON 结构超过上限")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := t.(string)
				if !ok || seen[name] {
					return errors.New("JSON 字段重复或无效")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("JSON 容器无效")
		}
		end, err := d.Token()
		if err != nil {
			return err
		}
		if delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return errors.New("JSON 容器未结束")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("JSON 存在尾随内容")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	if rejectUnknown {
		d.DisallowUnknownFields()
	}
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("JSON 存在尾随内容")
	}
	return nil
}
func validHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}
func text(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func validVersion(s string) bool {
	if len(s) > 96 || !semver.MatchString(s) {
		return false
	}
	base := strings.Split(s, "+")[0]
	_, prerelease, ok := strings.Cut(base, "-")
	if ok {
		for _, part := range strings.Split(prerelease, ".") {
			if len(part) > 1 && part[0] == '0' && strings.Trim(part, "0123456789") == "" {
				return false
			}
		}
	}
	return true
}
func validateAsset(a Asset) error {
	if !identifier.MatchString(a.ID) || slices.Contains([]string{"plan.json", "release-manifest.json", "release-manifest.sig"}, a.ID) || !slices.Contains([]string{"panel", "web", "nginx", "fail2ban"}, a.Component) || !validVersion(a.Version) || a.OS != "linux" || !slices.Contains([]string{"amd64", "arm64", "any"}, a.Architecture) || a.Architecture == "any" && a.Component != "web" {
		return errors.New("资产标识、类型、版本或架构无效")
	}
	if !identifier.MatchString(a.Distribution) || !text(a.DistributionVersion, 64) || a.ABI != "static" && a.ABI != "constrained" || a.ABI == "constrained" && (a.Distribution == "any" || len(a.RuntimeFiles) == 0) || a.ABI == "static" && len(a.RuntimeFiles) != 0 {
		return errors.New("资产 ABI 或系统约束无效")
	}
	if !safePath(a.Archive) || strings.Contains(a.Archive, "/") || !strings.HasSuffix(a.Archive, ".tar.gz") || !validHash(a.SHA256) || a.Size <= 0 || a.Size > MaxArchiveBytes || a.UnpackedBytes <= 0 || a.UnpackedBytes > MaxUnpackedBytes || len(a.Files) == 0 || len(a.Files) > MaxFiles || len(a.RuntimeFiles) > 64 || len(a.Dependencies) > 8 {
		return errors.New("资产归档或资源预算无效")
	}
	if !text(a.License, 256) || len(a.LicenseFiles) == 0 || len(a.LicenseFiles) > 32 || !slices.Contains([]string{"maintained", "superseded", "end-of-life"}, a.Maintenance) {
		return errors.New("资产许可或维护状态缺失")
	}
	u, err := url.Parse(a.SourceURL)
	if err != nil || len(a.SourceURL) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(a.SourceURL, "\x00\r\n") {
		return errors.New("资产来源须为无凭据的 HTTPS 地址")
	}
	files := map[string]File{}
	var total int64
	for _, f := range a.Files {
		if !safePath(f.Path) || f.Path == ".nginxpanel-package.json" || !validHash(f.SHA256) || f.Size < 0 || f.Size > 192<<20 || f.Mode != 0644 && f.Mode != 0755 {
			return errors.New("资产文件清单无效")
		}
		if _, ok := files[f.Path]; ok {
			return errors.New("资产文件重复")
		}
		files[f.Path] = f
		total += f.Size
	}
	if total != a.UnpackedBytes {
		return errors.New("资产展开长度与文件清单不一致")
	}
	for name := range files {
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if _, ok := files[dir]; ok {
				return errors.New("资产文件与目录冲突")
			}
		}
	}
	for _, name := range a.LicenseFiles {
		f, ok := files[name]
		if !ok || f.Mode != 0644 || f.Size == 0 {
			return errors.New("资产缺少有效许可文件")
		}
	}
	entry := map[string]string{"panel": "nginxpanel", "web": "index.html", "nginx": "bin/nginx", "fail2ban": "bin/fail2ban-server"}[a.Component]
	f, ok := files[entry]
	if !ok || f.Size == 0 || a.Component == "web" && f.Mode != 0644 || a.Component != "web" && f.Mode != 0755 {
		return errors.New("资产缺少固定入口文件")
	}
	if a.Component == "panel" {
		f, ok := files["web/index.html"]
		if !ok || f.Size == 0 || f.Mode != 0644 {
			return errors.New("面板资产须包含配套前端")
		}
	}
	seenRuntime := map[string]bool{}
	for _, f := range a.RuntimeFiles {
		if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || !text(f.Path, 256) || !(strings.HasPrefix(f.Path, "/usr/lib/") || strings.HasPrefix(f.Path, "/lib/") || strings.HasPrefix(f.Path, "/lib64/") || pythonInterpreter.MatchString(f.Path)) || !validHash(f.SHA256) || f.Size <= 0 || f.Size > 64<<20 || f.Mode != 0644 && f.Mode != 0755 || seenRuntime[f.Path] {
			return errors.New("系统运行依赖约束无效")
		}
		seenRuntime[f.Path] = true
	}
	if a.Component == "fail2ban" {
		found := false
		for _, file := range a.RuntimeFiles {
			if pythonInterpreter.MatchString(file.Path) && file.Mode == 0755 {
				found = true
			}
		}
		if a.ABI != "constrained" || !found {
			return errors.New("Fail2ban 须声明宿主机 Python 解释器约束")
		}
	}
	if len(a.Features) > 64 || a.Component != "nginx" && len(a.Features) != 0 {
		return errors.New("模块能力清单无效")
	}
	seen := map[string]bool{}
	for _, feature := range a.Features {
		if !identifier.MatchString(feature) || seen[feature] {
			return errors.New("模块能力无效或重复")
		}
		seen[feature] = true
	}
	return nil
}

type publisher struct {
	trust Trust
	raw   []byte
	keys  map[string]ed25519.PublicKey
}

func readTrust(name string) (publisher, error) {
	trustRaw, err := readRoot(name, 16<<10)
	if err != nil {
		return publisher{}, err
	}
	var trust Trust
	if err := strictJSON(trustRaw, &trust); err != nil {
		return publisher{}, fmt.Errorf("发行信任配置：%w", err)
	}
	if trust.Schema != Schema || !repository.MatchString(trust.Repository) || len(trust.Keys) == 0 || len(trust.Keys) > 8 {
		return publisher{}, errors.New("发行信任配置无效")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, key := range trust.Keys {
		raw, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != key.PublicKey || !identifier.MatchString(key.ID) || keys[key.ID] != nil {
			return publisher{}, errors.New("发行信任公钥无效或重复")
		}
		keys[key.ID] = ed25519.PublicKey(raw)
	}
	return publisher{trust: trust, raw: trustRaw, keys: keys}, nil
}

func manifestCatalog(m Manifest) (map[string]Asset, error) {
	if len(m.Assets) == 0 || len(m.Assets) > 16 {
		return nil, errors.New("发行资产须为 1–16 项")
	}
	assets := map[string]Asset{}
	archiveNames := map[string]bool{}
	files := 0
	for _, asset := range m.Assets {
		if err := validateAsset(asset); err != nil {
			return nil, fmt.Errorf("资产 %s：%w", asset.ID, err)
		}
		if asset.Component == "panel" && asset.Version != m.Version || asset.Component == "web" && asset.Version != m.FrontendVersion {
			return nil, errors.New("面板或前端资产版本与发行清单不一致")
		}
		if _, ok := assets[asset.ID]; ok || archiveNames[asset.Archive] {
			return nil, errors.New("发行资产或归档名重复")
		}
		assets[asset.ID] = asset
		archiveNames[asset.Archive] = true
		files += len(asset.Files)
		if files > MaxFiles {
			return nil, errors.New("发行文件清单合计超过 4096 项")
		}
	}
	colors := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		a, ok := assets[id]
		if !ok {
			return errors.New("依赖引用了清单外资产")
		}
		if colors[id] == 1 {
			return errors.New("发行依赖存在循环")
		}
		if colors[id] == 2 {
			return nil
		}
		colors[id] = 1
		seen := map[string]bool{}
		for _, dep := range a.Dependencies {
			if seen[dep] {
				return errors.New("资产依赖重复")
			}
			seen[dep] = true
			if err := visit(dep); err != nil {
				return err
			}
		}
		colors[id] = 2
		return nil
	}
	for _, a := range m.Assets {
		if err := visit(a.ID); err != nil {
			return nil, err
		}
	}
	return assets, nil
}

func Verify(in Input) (*Verified, error) {
	return verifyAt(in, time.Now().Unix())
}

func verifyAt(in Input, now int64) (*Verified, error) {
	publisher, err := readTrust(in.TrustPath)
	if err != nil {
		return nil, err
	}
	raw, err := readRoot(in.ManifestPath, MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	sigRaw, err := readRoot(in.SignaturePath, 4096)
	if err != nil {
		return nil, err
	}
	var sig Signature
	if err := strictJSON(sigRaw, &sig); err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(sig.Signature)
	key := publisher.keys[sig.KeyID]
	if err != nil || sig.Schema != Schema || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != sig.Signature || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(SignatureDomain), raw...), signature) {
		return nil, errors.New("发行清单签名无效或公钥未获本机信任")
	}
	var m Manifest
	if err := strictJSON(raw, &m); err != nil {
		return nil, fmt.Errorf("发行清单：%w", err)
	}
	if m.Schema != Schema || m.Repository != publisher.trust.Repository || !validVersion(m.Version) || !validVersion(m.FrontendVersion) || m.APIMajor != 1 || m.APIMajor != in.Receiver.APIMajor || m.DatabaseSchema < 1 || m.MinimumAgentProtocol < 1 || m.MinimumAgentProtocol > in.Receiver.AgentProtocol || m.MinimumLauncher < 1 || m.MinimumLauncher > in.Receiver.Launcher || m.CreatedAt > now+300 || m.CreatedAt <= 0 || m.ExpiresAt <= now || m.ExpiresAt <= m.CreatedAt || m.ExpiresAt-m.CreatedAt > 2*366*86400 {
		return nil, errors.New("发行清单身份、有效期或接收端协议条件不满足")
	}
	if m.Channel != "stable" && m.Channel != "prerelease" || m.Channel == "prerelease" && !in.AllowPrerelease || m.Channel == "stable" && strings.Contains(strings.Split(m.Version, "+")[0], "-") {
		return nil, errors.New("发行渠道或预发布授权无效")
	}
	if in.Host.OS != "linux" || !slices.Contains([]string{"amd64", "arm64"}, in.Host.Architecture) || !identifier.MatchString(in.Host.Distribution) || !text(in.Host.Version, 64) {
		return nil, errors.New("宿主机平台尚未确认")
	}
	if err := selectors(in.Assets, in.Components); err != nil {
		return nil, err
	}
	assets, err := manifestCatalog(m)
	if err != nil {
		return nil, err
	}
	selected, err := selectAssets(m, in.Host, in.Assets, in.Components)
	if err != nil {
		return nil, err
	}
	sort.Strings(selected)
	for i, id := range selected {
		if i > 0 && id == selected[i-1] {
			return nil, errors.New("所选资产重复")
		}
		if _, ok := assets[id]; !ok {
			return nil, errors.New("所选资产不存在")
		}
	}
	p := Plan{State: "manifest_verified", ManifestSHA256: hash(raw), TrustSHA256: hash(publisher.raw), KeyID: sig.KeyID, Manifest: m, Host: in.Host, Receiver: in.Receiver, Selected: selected, Assets: []Asset{}}
	added := map[string]bool{}
	components := map[string]string{}
	var include func(string) error
	include = func(id string) error {
		if added[id] {
			return nil
		}
		a := assets[id]
		if len(in.AllowedComponents) != 0 && !slices.Contains(in.AllowedComponents, a.Component) {
			return errors.New("所选资产依赖包含未授权组件")
		}
		if !hostAsset(a, in.Host) {
			return fmt.Errorf("资产 %s 不满足目标系统或维护条件", id)
		}
		if previous := components[a.Component]; previous != "" && previous != id {
			return errors.New("依赖闭包包含同一组件的不同资产")
		}
		components[a.Component] = id
		for _, dep := range a.Dependencies {
			if err := include(dep); err != nil {
				return err
			}
		}
		added[id] = true
		p.Assets = append(p.Assets, a)
		p.ArchiveBytes += a.Size
		p.UnpackedBytes += a.UnpackedBytes
		if p.ArchiveBytes+p.UnpackedBytes > MaxSelectionBytes {
			return errors.New("所选依赖闭包超过 512 MiB")
		}
		return nil
	}
	for _, id := range selected {
		if err := include(id); err != nil {
			return nil, err
		}
	}
	if err := runtimeTotal(p.Assets); err != nil {
		return nil, err
	}
	if planEntries(p.Assets) > MaxEntries {
		return nil, errors.New("准备文件及目录合计超过 8192 项")
	}
	planRaw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	p.ID = hash(planRaw)
	sealed, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(sealed) > MaxPlanBytes {
		return nil, errors.New("发行准备计划超过 4 MiB")
	}
	return &Verified{plan: p, manifest: raw, signature: sigRaw, seal: hash(sealed), trustPath: in.TrustPath}, nil
}
