package releases

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type OnlineInput struct {
	PanelStaging                                                bool
	TrustPath, TokenPath, Tag                                   string
	Assets                                                      []string
	Components                                                  []string
	AllowedComponents                                           []string
	ExpectedPlanID, ExpectedManifestSHA256, ExpectedTrustSHA256 string
	AllowPrerelease, Prepare                                    bool
	Host                                                        Host
	Receiver                                                    Receiver
}

type ReleaseSource struct {
	Repository     string `json:"repository"`
	Tag            string `json:"tag"`
	ReleaseID      int64  `json:"release_id"`
	MetadataCached bool   `json:"metadata_cached"`
	ManifestCached bool   `json:"manifest_cached"`
}

type OnlineResult struct {
	Announcement *Announcement `json:"announcement,omitempty"`
	Result
	Source ReleaseSource `json:"source"`
}

type githubAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type githubRelease struct {
	ID          int64         `json:"id"`
	Tag         string        `json:"tag_name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt time.Time     `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

func parseGithubRelease(raw []byte, in OnlineInput) (githubRelease, error) {
	var release githubRelease
	if err := decodeJSON(raw, &release, false); err != nil {
		return githubRelease{}, errors.New("GitHub 发行元数据 JSON 无效")
	}
	if release.ID <= 0 || release.Draft || !strings.HasPrefix(release.Tag, "v") || !validVersion(strings.TrimPrefix(release.Tag, "v")) || in.Tag != "" && in.Tag != release.Tag || release.Prerelease && (!in.AllowPrerelease || in.Tag == "") || release.PublishedAt.IsZero() || release.PublishedAt.After(time.Now().Add(5*time.Minute)) || len(release.Assets) < 2 || len(release.Assets) > MaxReleaseAssets {
		return githubRelease{}, errors.New("GitHub 发行身份、渠道或资产数量不满足条件")
	}
	ids, names := map[int64]bool{}, map[string]bool{}
	for _, asset := range release.Assets {
		if asset.ID <= 0 || ids[asset.ID] || names[asset.Name] || !safePath(asset.Name) || strings.Contains(asset.Name, "/") || asset.State != "uploaded" || asset.Size <= 0 || asset.Size > MaxArchiveBytes || asset.Digest != "" && (!strings.HasPrefix(asset.Digest, "sha256:") || !validHash(strings.TrimPrefix(asset.Digest, "sha256:"))) {
			return githubRelease{}, errors.New("GitHub 发行资产身份、名称、长度或散列无效")
		}
		ids[asset.ID], names[asset.Name] = true, true
	}
	return release, nil
}

func (s *onlineSession) discover(ctx context.Context) (githubRelease, bool, bool, error) {
	endpoint := tagEndpoint(s.input.Tag)
	key := hash([]byte(s.publisher.trust.Repository + "\n" + endpoint + "\n" + hash(s.publisher.raw) + "\n" + s.tokenHash))
	now := time.Now().Unix()
	if s.cache.Key == key && len(s.cache.Body) != 0 && s.cache.FreshUntil > now {
		release, err := parseGithubRelease(s.cache.Body, s.input)
		return release, true, true, err
	}
	if s.cache.NextCheck > now {
		return githubRelease{}, false, false, fmt.Errorf("发行检查间隔至少 60 秒，最早重试时间 %s", time.Unix(s.cache.NextCheck, 0).UTC().Format(time.RFC3339))
	}
	etag := ""
	if s.cache.Key == key {
		etag = s.cache.ETag
	}
	// Persist the attempt before networking, so process restarts and failures do
	// not bypass the metadata request interval. No stale response is a success.
	s.cache.NextCheck = now + 60
	if err := writeOnlineCache(s.cache); err != nil {
		return githubRelease{}, false, false, err
	}
	response, err := s.get(ctx, endpoint, "application/vnd.github+json", etag)
	if err != nil {
		return githubRelease{}, false, false, err
	}
	defer response.Body.Close()
	cached := response.StatusCode == http.StatusNotModified
	var raw []byte
	if cached {
		if etag == "" || s.cache.Key != key || len(s.cache.Body) == 0 {
			return githubRelease{}, false, false, errors.New("GitHub 返回 304，但本机没有对应缓存")
		}
		raw = s.cache.Body
	} else {
		if response.ContentLength > MaxManifestBytes {
			return githubRelease{}, false, false, errors.New("GitHub 发行元数据超过 2 MiB")
		}
		raw, err = io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: response.Body}, MaxManifestBytes+1))
		if err != nil {
			return githubRelease{}, false, false, errors.New("GitHub 发行元数据传输中断")
		}
		if len(raw) > MaxManifestBytes {
			return githubRelease{}, false, false, errors.New("GitHub 发行元数据超过 2 MiB")
		}
	}
	release, err := parseGithubRelease(raw, s.input)
	if err != nil {
		return githubRelease{}, false, false, err
	}
	age, store := cacheLifetime(response.Header)
	responseETag := response.Header.Get("ETag")
	if !validETag(responseETag) {
		return githubRelease{}, false, false, errors.New("GitHub ETag 无效")
	}
	if store {
		if s.cache.Key != key || hash(s.cache.Body) != hash(raw) {
			s.cache.Manifest, s.cache.Signature = nil, nil
		}
		s.cache.Key, s.cache.Body = key, raw
		if !cached || responseETag != "" {
			s.cache.ETag = responseETag
		}
		s.cache.FreshUntil = time.Now().Unix() + age
	} else {
		s.cache = onlineCache{Schema: Schema, NextCheck: s.cache.NextCheck, BlockedUntil: s.cache.BlockedUntil}
	}
	if err := writeOnlineCache(s.cache); err != nil {
		return githubRelease{}, false, false, err
	}
	return release, cached, store, nil
}

// Online checks a fixed repository and optionally prepares the explicitly
// selected signed asset closure. It never executes or activates a downloaded file.
func Online(ctx context.Context, in OnlineInput) (OnlineResult, error) {
	if os.Geteuid() != 0 {
		return OnlineResult{}, errors.New("在线发行检查和准备需要本机 root")
	}
	if err := ValidateOnlineSelection(in); err != nil {
		return OnlineResult{}, err
	}
	publisher, err := readTrust(in.TrustPath)
	if err != nil {
		return OnlineResult{}, err
	}
	if in.ExpectedTrustSHA256 != "" && in.ExpectedTrustSHA256 != hash(publisher.raw) {
		return OnlineResult{}, ErrReleaseChanged
	}
	token, tokenHash, err := readGithubToken(in.TokenPath)
	if err != nil {
		return OnlineResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	lock, err := lockOnline()
	if err != nil {
		return OnlineResult{}, err
	}
	defer lock.Close()
	used, groups, entries, err := downloadUsage()
	if err != nil {
		return OnlineResult{}, err
	}
	if groups >= 8 || entries+22 > 256 || used+2*maxCacheBytes+MaxManifestBytes+4096 > maxDownloadBytes {
		return OnlineResult{}, errors.New("在线发行缓存没有足够预算，须本机清理已核对的残留暂存")
	}
	cache, err := readOnlineCache()
	if err != nil {
		return OnlineResult{}, err
	}
	client, transport := githubHTTP()
	defer transport.CloseIdleConnections()
	s := onlineSession{input: in, publisher: publisher, token: token, tokenHash: tokenHash, cache: cache, client: client}
	release, metadataCached, storeManifest, err := s.discover(ctx)
	if err != nil {
		return OnlineResult{}, err
	}
	available := map[string]githubAsset{}
	for _, asset := range release.Assets {
		available[asset.Name] = asset
	}
	manifest, sig := available["release-manifest.json"], available["release-manifest.sig"]
	if manifest.ID == 0 || sig.ID == 0 || manifest.Size > MaxManifestBytes || sig.Size > 4096 {
		return OnlineResult{}, errors.New("GitHub 发行缺少有界签名清单及分离签名")
	}
	stage, err := os.MkdirTemp(DownloadStore, ".fetch-*")
	if err != nil {
		return OnlineResult{}, err
	}
	defer removeDownload(stage)
	if err := os.Chmod(stage, 0700); err != nil {
		return OnlineResult{}, err
	}
	manifestCached := len(s.cache.Manifest) != 0 && len(s.cache.Signature) != 0
	if manifestCached {
		if int64(len(s.cache.Manifest)) != manifest.Size || int64(len(s.cache.Signature)) != sig.Size || manifest.Digest != "" && manifest.Digest != "sha256:"+hash(s.cache.Manifest) || sig.Digest != "" && sig.Digest != "sha256:"+hash(s.cache.Signature) {
			return OnlineResult{}, errors.New("缓存签名清单与 GitHub 资产长度或散列不一致")
		}
		if err := writePrivate(filepath.Join(stage, manifest.Name), s.cache.Manifest); err != nil {
			return OnlineResult{}, err
		}
		if err := writePrivate(filepath.Join(stage, sig.Name), s.cache.Signature); err != nil {
			return OnlineResult{}, err
		}
	} else {
		if err := s.download(ctx, stage, manifest, ""); err != nil {
			return OnlineResult{}, err
		}
		if err := s.download(ctx, stage, sig, ""); err != nil {
			return OnlineResult{}, err
		}
	}
	verified, err := Verify(Input{TrustPath: in.TrustPath, ManifestPath: filepath.Join(stage, manifest.Name), SignaturePath: filepath.Join(stage, sig.Name), Assets: in.Assets, Components: in.Components, AllowedComponents: in.AllowedComponents, AllowPrerelease: in.AllowPrerelease, Host: in.Host, Receiver: in.Receiver, PanelStaging: in.PanelStaging})
	if err != nil {
		var incompatible *receiverCompatibilityError
		if errors.As(err, &incompatible) {
			a := incompatible.announcement
			if a.TrustSHA256 != hash(publisher.raw) || a.Tag != release.Tag || release.Prerelease != (a.Channel == "prerelease") {
				return OnlineResult{}, errors.New("签名说明与本机信任、GitHub 发行标签或渠道不一致")
			}
			if sourceErr := s.currentSource(); sourceErr != nil {
				return OnlineResult{}, sourceErr
			}
			if in.ExpectedManifestSHA256 != "" && in.ExpectedManifestSHA256 != a.ManifestSHA256 {
				return OnlineResult{}, ErrReleaseChanged
			}
			if time.Now().Unix() >= a.ExpiresAt {
				return OnlineResult{}, errors.New("发行清单已过期，须重新检查")
			}
			return OnlineResult{Announcement: &a, Source: ReleaseSource{Repository: a.Repository, Tag: a.Tag, ReleaseID: release.ID, MetadataCached: metadataCached, ManifestCached: manifestCached}}, err
		}
		return OnlineResult{}, err
	}
	if verified.plan.TrustSHA256 != hash(publisher.raw) || "v"+verified.plan.Manifest.Version != release.Tag || release.Prerelease != (verified.plan.Manifest.Channel == "prerelease") {
		return OnlineResult{}, errors.New("签名清单与本机信任、GitHub 发行标签或渠道不一致")
	}
	if err := s.currentSource(); err != nil {
		return OnlineResult{}, err
	}
	if in.ExpectedPlanID != "" && in.ExpectedPlanID != verified.plan.ID || in.ExpectedManifestSHA256 != "" && in.ExpectedManifestSHA256 != verified.plan.ManifestSHA256 {
		return OnlineResult{}, ErrReleaseChanged
	}
	// Validate every selected archive against the authenticated manifest before
	// requesting any archive, including dependency assets.
	for _, asset := range verified.plan.Assets {
		remote, ok := available[asset.Archive]
		if !ok || remote.Size != asset.Size || remote.Digest != "" && remote.Digest != "sha256:"+asset.SHA256 {
			return OnlineResult{}, fmt.Errorf("签名资产 %s 在 GitHub 中缺失或长度/散列不匹配", asset.ID)
		}
	}
	if storeManifest && !manifestCached {
		s.cache.Manifest, s.cache.Signature = verified.manifest, verified.signature
		if err := writeOnlineCache(s.cache); err != nil {
			return OnlineResult{}, err
		}
	}
	out := OnlineResult{Result: Result{State: "manifest_verified", Plan: verified.Plan()}, Source: ReleaseSource{Repository: publisher.trust.Repository, Tag: release.Tag, ReleaseID: release.ID, MetadataCached: metadataCached, ManifestCached: manifestCached}}
	if !in.Prepare {
		if err := currentTrust(verified); err != nil {
			return OnlineResult{}, err
		}
		return out, nil
	}
	if err := checkRuntime(ctx, verified.plan.Assets); err != nil {
		return OnlineResult{}, err
	}
	used, _, entries, err = downloadUsage()
	if err != nil {
		return OnlineResult{}, err
	}
	if entries+len(verified.plan.Assets)+1 > 256 || used+verified.plan.ArchiveBytes+maxCacheBytes > maxDownloadBytes {
		return OnlineResult{}, errors.New("签名资产下载超出在线缓存的 512 MiB 预算")
	}
	for _, asset := range verified.plan.Assets {
		if err := s.download(ctx, stage, available[asset.Archive], asset.SHA256); err != nil {
			return OnlineResult{}, fmt.Errorf("下载签名资产 %s：%w", asset.ID, err)
		}
	}
	if err := s.currentSource(); err != nil {
		return OnlineResult{}, err
	}
	out.Result, err = Prepare(ctx, verified, stage)
	if err != nil {
		return OnlineResult{}, err
	}
	return out, nil
}
