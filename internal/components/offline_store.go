package components

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

const offlineStoreBytes int64 = 1 << 30

type offlineBasis struct {
	Protocol        int           `json:"protocol"`
	Upload          OfflineUpload `json:"upload"`
	SignatureSHA256 string        `json:"signature_sha256"`
}

func (m *Manager) offlineRoot() string         { return filepath.Join(m.DataDir, "agent", "component-uploads") }
func (m *Manager) offlineDir(id string) string { return filepath.Join(m.offlineRoot(), id) }
func offlineReadJSON(name string, out any, limit int64) error {
	raw, err := secure.ReadRootFile(name, limit)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("离线上传记录格式无效")
	}
	return nil
}
func offlineSync(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func offlineWrite(name string, raw []byte) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
func (m *Manager) offlineAvailable() error {
	if m.closed || m.poisoned || m.ctx == nil || m.ctx.Err() != nil || m.Dev || m.Scope != "host" {
		return fault.Unavailable("离线上传须由已配置的宿主机 root Agent 管理")
	}
	return nil
}
func (m *Manager) offlineUsage() (int64, int, error) {
	if _, err := os.Lstat(m.offlineRoot()); os.IsNotExist(err) {
		return 0, 0, nil
	} else if err != nil {
		return 0, 0, err
	}
	var total int64
	count, entries := 0, 0
	err := filepath.WalkDir(m.offlineRoot(), func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries++
		if entries > 512 {
			return errors.New("离线上传目录超过 512 项，须本机维护")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.IsDir() && info.Mode().Perm() != 0700 || !info.IsDir() && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1) {
			return errors.New("离线上传目录归属、权限或文件类型变化")
		}
		if name != m.offlineRoot() && entry.IsDir() {
			if filepath.Dir(name) != m.offlineRoot() || !ValidID(entry.Name()) && !strings.HasPrefix(entry.Name(), ".tmp-") {
				return errors.New("离线上传目录包含未知子目录")
			}
			count++
		}
		if !entry.IsDir() {
			total += info.Size()
			if total > offlineStoreBytes {
				return errors.New("离线上传暂存超过 1 GiB")
			}
		}
		return nil
	})
	return total, count, err
}

func offlineDiscardMarker(dir string, raw []byte) (resultErr error) {
	f, err := os.CreateTemp(dir, ".discard-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil && !os.IsNotExist(err) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	err = f.Chmod(0600)
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	marker := filepath.Join(dir, "discarded.json")
	if _, err = os.Lstat(marker); !os.IsNotExist(err) {
		return errors.Join(errors.New("离线上传清除标识已被占用"), err)
	}
	if err = os.Rename(f.Name(), marker); err != nil {
		return err
	}
	return offlineSync(dir)
}
func (m *Manager) offlineBasis(id string) (offlineBasis, error) {
	var b offlineBasis
	if !ValidID(id) {
		return b, fault.Invalid("离线上传 UUID 无效")
	}
	err := offlineReadJSON(filepath.Join(m.offlineDir(id), "basis.json"), &b, 32<<10)
	if os.IsNotExist(err) {
		return b, fault.NotFound("离线上传记录不存在")
	}
	if err != nil {
		return b, err
	}
	if b.Protocol != protocol.Agent || b.Upload.ID != id || !b.Upload.Valid() || b.Upload.Discarded || b.Upload.Complete || !digest(b.SignatureSHA256) {
		return b, errors.New("离线上传原材料无法核对")
	}
	for _, asset := range b.Upload.Assets {
		if asset.Received != 0 {
			return b, errors.New("离线上传原材料包含运行进度")
		}
	}
	return b, nil
}
func (m *Manager) offlineStatus(b offlineBasis) (OfflineUpload, error) {
	u := b.Upload
	u.Assets = append([]OfflineAsset{}, b.Upload.Assets...)
	var discarded struct {
		ID          string `json:"id"`
		RequestHash string `json:"request_hash"`
	}
	err := offlineReadJSON(filepath.Join(m.offlineDir(u.ID), "discarded.json"), &discarded, 1024)
	if err == nil {
		if discarded.ID != u.ID || discarded.RequestHash != u.RequestHash {
			return u, errors.New("离线上传清除标识冲突")
		}
		u.Discarded = true
	} else if !os.IsNotExist(err) {
		return u, err
	}
	u.Complete = !u.Discarded
	for i, a := range u.Assets {
		f, info, err := secure.OpenRootFile(filepath.Join(m.offlineDir(u.ID), a.Archive), a.Size)
		if err == nil {
			u.Assets[i].Received = info.Size()
			err = f.Close()
		}
		if err != nil && !os.IsNotExist(err) {
			return u, err
		}
		u.Complete = u.Complete && u.Assets[i].Received == a.Size
	}
	if !u.Valid() {
		return u, errors.New("离线上传状态无法核对")
	}
	return u, nil
}
func (m *Manager) offlineWritable(b offlineBasis) error {
	u, err := m.offlineStatus(b)
	if err != nil {
		return err
	}
	if u.Discarded {
		return fault.Conflict("离线上传已清除，请创建新上传")
	}
	if time.Now().Unix() >= u.ExpiresAt {
		return fault.Conflict("离线上传授权已过期，请创建新上传")
	}
	return nil
}
func (m *Manager) ListOffline() ([]OfflineUpload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.offlineAvailable(); err != nil {
		return nil, err
	}
	if _, _, err := m.offlineUsage(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(m.offlineRoot())
	if os.IsNotExist(err) {
		return []OfflineUpload{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []OfflineUpload{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		b, err := m.offlineBasis(entry.Name())
		if err != nil {
			return nil, err
		}
		u, err := m.offlineStatus(b)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// A preparation uses fresh signature/trust/platform checks. Saved upload
// progress never substitutes for archive hashing or the strict USTAR reader.
func (m *Manager) offlineVerify(b offlineBasis) (*releases.Verified, error) {
	dir := m.offlineDir(b.Upload.ID)
	hash, err := secure.HashRootFile(filepath.Join(dir, "signature.json"), 4096)
	if err != nil || hash != b.SignatureSHA256 {
		return nil, errors.Join(releases.ErrReleaseChanged, err)
	}
	v, err := releases.Verify(releases.Input{TrustPath: m.TrustPath, ManifestPath: filepath.Join(dir, "manifest.json"), SignaturePath: filepath.Join(dir, "signature.json"), Assets: b.Upload.Release.Selected, AllowedComponents: []string{"nginx", "fail2ban", "panel", "web"}, AllowPrerelease: b.Upload.Prerelease, Host: m.host(), Receiver: receiver()})
	if err != nil {
		return nil, err
	}
	p := v.Plan()
	if p.ID != b.Upload.Release.PlanID || p.ManifestSHA256 != b.Upload.Release.ManifestSHA256 || p.TrustSHA256 != b.Upload.Release.TrustSHA256 {
		return nil, releases.ErrReleaseChanged
	}
	return v, nil
}
