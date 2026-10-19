package components

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

func (m *Manager) CreateOffline(ctx context.Context, req OfflineRequest) (out OfflineUpload, resultErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.offlineAvailable(); err != nil {
		return out, err
	}
	if !req.Valid() {
		return out, fault.Invalid("离线上传请求无效")
	}
	if old, err := m.offlineBasis(req.ID); err == nil {
		if old.Upload.RequestHash != req.Hash() {
			return out, fault.Conflict("同一上传 UUID 不能用于不同材料")
		}
		if err = offlineSync(m.offlineRoot()); err != nil {
			return out, err
		}
		return m.offlineStatus(old)
	} else {
		var known *fault.Error
		if !errors.As(err, &known) || known.Status != 404 {
			return out, err
		}
	}
	if m.active {
		return out, fault.Conflict("组件任务尚未结束")
	}
	if err := secure.RootDirectory(m.offlineRoot(), 0700); err != nil {
		return out, err
	}
	used, count, err := m.offlineUsage()
	if err != nil {
		return out, err
	}
	if count >= 32 || used+int64(len(req.Input.Manifest)+len(req.Input.Signature))+(64<<10) > offlineStoreBytes {
		return out, fault.Conflict("离线上传保留容量已满，请清除未使用归档或执行本机维护")
	}
	dir, err := os.MkdirTemp(m.offlineRoot(), ".tmp-")
	if err != nil {
		return out, err
	}
	defer func() {
		if dir != "" {
			if err := os.RemoveAll(dir); err != nil {
				resultErr = errors.Join(fault.Unavailable("离线上传暂存清理未确认，须本机维护"), resultErr, err)
			}
		}
	}()
	if err = offlineWrite(filepath.Join(dir, "manifest.json"), req.Input.Manifest); err != nil {
		return out, err
	}
	if err = offlineWrite(filepath.Join(dir, "signature.json"), req.Input.Signature); err != nil {
		return out, err
	}
	v, err := releases.Verify(releases.Input{TrustPath: m.TrustPath, ManifestPath: filepath.Join(dir, "manifest.json"), SignaturePath: filepath.Join(dir, "signature.json"), Assets: req.Input.Assets, Components: req.Input.Components, AllowedComponents: []string{"nginx", "fail2ban", "panel", "web"}, AllowPrerelease: req.Input.Prerelease, Host: m.host(), Receiver: receiver()})
	if err != nil {
		return out, fault.Invalid("离线清单未获本机信任或不适用于目标：" + bounded(err.Error()))
	}
	p := v.Plan()
	if len(p.Assets) > 2 || len(p.Assets) != len(p.Selected) {
		return out, fault.Invalid("每次离线上传最多两个独立签名资产，须完整选择依赖")
	}
	if _, err = panelSelection(p); err != nil {
		return out, fault.Invalid(err.Error())
	}
	now := time.Now().Unix()
	expires := min(now+86400, p.Manifest.ExpiresAt)
	out = OfflineUpload{ID: req.ID, RequestHash: req.Hash(), CreatedAt: now, ExpiresAt: expires, Prerelease: req.Input.Prerelease, Release: release(p), Assets: []OfflineAsset{}}
	for _, a := range p.Assets {
		out.Assets = append(out.Assets, OfflineAsset{ID: a.ID, Archive: a.Archive, SHA256: a.SHA256, Size: a.Size})
	}
	if !out.Valid() {
		return out, errors.New("离线上传计划无法核对")
	}
	raw, err := json.Marshal(offlineBasis{Protocol: protocol.Agent, Upload: out, SignatureSHA256: secure.Hash(req.Input.Signature)})
	if err != nil {
		return out, err
	}
	if len(raw) > 32<<10 {
		return out, fault.Invalid("离线上传计划超出容量")
	}
	if err = offlineWrite(filepath.Join(dir, "basis.json"), raw); err != nil {
		return out, err
	}
	if err = offlineSync(dir); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if _, err = os.Lstat(m.offlineDir(req.ID)); !os.IsNotExist(err) {
		return out, errors.Join(errors.New("上传 UUID 已有未完成材料"), err)
	}
	if err = os.Rename(dir, m.offlineDir(req.ID)); err != nil {
		return out, err
	}
	dir = ""
	if err = offlineSync(m.offlineRoot()); err != nil {
		return out, err
	}
	return out, nil
}

func (m *Manager) UploadChunk(ctx context.Context, id, assetID string, chunk OfflineChunk) (OfflineUpload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.offlineAvailable(); err != nil {
		return OfflineUpload{}, err
	}
	if err := chunk.Validate(); err != nil {
		return OfflineUpload{}, err
	}
	if m.active {
		return OfflineUpload{}, fault.Conflict("组件任务尚未结束，暂不能修改上传")
	}
	b, err := m.offlineBasis(id)
	if err != nil {
		return OfflineUpload{}, err
	}
	if err = m.offlineWritable(b); err != nil {
		return OfflineUpload{}, err
	}
	var asset OfflineAsset
	for _, a := range b.Upload.Assets {
		if a.ID == assetID {
			asset = a
		}
	}
	if asset.ID == "" || chunk.Offset+int64(len(chunk.Data)) > asset.Size {
		return OfflineUpload{}, fault.Invalid("上传资产或分块范围不在签名计划中")
	}
	path := filepath.Join(m.offlineDir(id), asset.Archive)
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return OfflineUpload{}, err
	}
	f := os.NewFile(uintptr(fd), asset.Archive)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return OfflineUpload{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > asset.Size {
		return OfflineUpload{}, errors.New("上传归档归属、权限或长度变化")
	}
	if chunk.Offset > info.Size() {
		return OfflineUpload{}, fault.Conflict("分块不能跳过尚未接收的前缀，请刷新上传进度")
	}
	prefix := min(int64(len(chunk.Data)), info.Size()-chunk.Offset)
	if prefix > 0 {
		raw := make([]byte, int(prefix))
		if _, err = f.ReadAt(raw, chunk.Offset); err != nil {
			return OfflineUpload{}, err
		}
		if !bytes.Equal(raw, chunk.Data[:int(prefix)]) {
			return OfflineUpload{}, fault.Conflict("重试分块与已接收字节不一致，不覆盖原归档")
		}
	}
	if prefix < int64(len(chunk.Data)) {
		used, _, err := m.offlineUsage()
		if err != nil {
			return OfflineUpload{}, err
		}
		if used+int64(len(chunk.Data))-prefix+(64<<10) > offlineStoreBytes {
			return OfflineUpload{}, fault.Conflict("离线暂存达到 1 GiB，请先清除未使用归档")
		}
		if err = ctx.Err(); err != nil {
			return OfflineUpload{}, err
		}
		n, err := f.WriteAt(chunk.Data[int(prefix):], chunk.Offset+prefix)
		if err != nil {
			return OfflineUpload{}, err
		}
		if n != len(chunk.Data)-int(prefix) {
			return OfflineUpload{}, io.ErrShortWrite
		}
	}
	if err = f.Sync(); err != nil {
		return OfflineUpload{}, err
	}
	if err = f.Close(); err != nil {
		return OfflineUpload{}, err
	}
	if err = offlineSync(m.offlineDir(id)); err != nil {
		return OfflineUpload{}, err
	}
	return m.offlineStatus(b)
}

func (m *Manager) DiscardOffline(ctx context.Context, id string) (OfflineUpload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.offlineAvailable(); err != nil {
		return OfflineUpload{}, err
	}
	if m.active {
		return OfflineUpload{}, fault.Conflict("组件任务尚未结束，不能清除上传")
	}
	b, err := m.offlineBasis(id)
	if err != nil {
		return OfflineUpload{}, err
	}
	u, err := m.offlineStatus(b)
	if err != nil {
		return u, err
	}
	if err = ctx.Err(); err != nil {
		return u, err
	}
	if !u.Discarded {
		raw, _ := json.Marshal(struct {
			ID          string `json:"id"`
			RequestHash string `json:"request_hash"`
		}{id, u.RequestHash})
		if err = offlineDiscardMarker(m.offlineDir(id), raw); err != nil {
			return u, err
		}
	}
	// Preserve the signed source, immutable basis and discard marker. Only the
	// signed archive names are removable; prepared versions and audits survive.
	for _, a := range b.Upload.Assets {
		if err = os.Remove(filepath.Join(m.offlineDir(id), a.Archive)); err != nil && !os.IsNotExist(err) {
			return u, err
		}
	}
	if err = offlineSync(m.offlineDir(id)); err != nil {
		return u, err
	}
	return m.offlineStatus(b)
}

func (m *Manager) offline(ctx context.Context, in Input) (releases.OnlineResult, error) {
	m.mu.Lock()
	b, err := m.offlineBasis(in.OfflineID)
	if err == nil {
		err = m.offlineWritable(b)
	}
	if err == nil && (in.Tag != b.Upload.Release.Tag || in.Prerelease != b.Upload.Prerelease || !sameAssets(in.Assets, b.Upload.Release.Selected)) {
		err = releases.ErrReleaseChanged
	}
	var v *releases.Verified
	if err == nil {
		v, err = m.offlineVerify(b)
	}
	if err == nil && in.Action == "prepare" {
		u, e := m.offlineStatus(b)
		err = e
		if err == nil && (!u.Complete || in.PlanID != u.Release.PlanID || in.ManifestSHA256 != u.Release.ManifestSHA256 || in.TrustSHA256 != u.Release.TrustSHA256) {
			err = errors.New("离线归档未接收完整或准备基准变化")
		}
	}
	m.mu.Unlock()
	if err != nil {
		return releases.OnlineResult{}, err
	}
	result := releases.Result{State: "verified", Plan: v.Plan()}
	if in.Action == "prepare" {
		result, err = releases.Prepare(ctx, v, m.offlineDir(in.OfflineID))
	}
	return releases.OnlineResult{Result: result}, err
}
