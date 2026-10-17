package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

const runtimeHistoryKind = "nginx.history.cleanup"
const historyEntryMax = 512
const historyBytesMax = 16 << 20

type runtimeHistoryEntry struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	GID       uint32 `json:"gid"`
	Mode      uint32 `json:"mode"`
	Size      int64  `json:"size"`
	Modified  int64  `json:"modified"`
	Changed   int64  `json:"changed"`
	SHA256    string `json:"sha256"`
}

type certificateHistory struct {
	CertificateID string `json:"certificate_id"`
	VersionID     string `json:"version_id"`
	ChainSHA256   string `json:"chain_sha256"`
	KeySHA256     string `json:"key_sha256"`
}

func certificateHistoryPath(data, id, version string) string {
	return filepath.Join(data, "agent", "certificate-history", id+"-"+version+".json")
}

func readCertificateHistory(data, id, version string) (certificateHistory, error) {
	var h certificateHistory
	raw, err := nginxmodules.ReadTrusted(certificateHistoryPath(data, id, version), 1024)
	if err != nil {
		return h, err
	}
	if json.Unmarshal(raw, &h) != nil || h.CertificateID != id || h.VersionID != version || !validSwitchDigest(h.ChainSHA256) || !validSwitchDigest(h.KeySHA256) {
		return h, errors.New("证书材料退役凭据无效")
	}
	return h, nil
}

// A removed material path must never allow the same certificate identity to be
// recreated with different bytes. The small root receipt outlives the files.
func checkCertificateHistory(data, id, version string, pair *certificates.Pair) error {
	h, err := readCertificateHistory(data, id, version)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if h.ChainSHA256 != secure.Hash([]byte(pair.ChainPEM)) || h.KeySHA256 != secure.Hash([]byte(pair.KeyPEM)) {
		return errors.New("证书版本与原退役材料不一致")
	}
	return nil
}

func (n *Nginx) saveCertificateHistory(target string, entries []runtimeHistoryEntry) error {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || parts[0] != "certificates" || !validID(parts[1]) || !validID(parts[2]) {
		return errors.New("证书清理目标无效")
	}
	h := certificateHistory{CertificateID: parts[1], VersionID: parts[2]}
	for _, e := range entries {
		if e.Path == target+"/fullchain.pem" {
			h.ChainSHA256 = e.SHA256
		}
		if e.Path == target+"/privatekey.pem" {
			h.KeySHA256 = e.SHA256
		}
	}
	if !validSwitchDigest(h.ChainSHA256) || !validSwitchDigest(h.KeySHA256) {
		return errors.New("证书退役缺少完整摘要")
	}
	old, err := readCertificateHistory(n.DataDir, h.CertificateID, h.VersionID)
	if err == nil && old != h {
		return ErrExternalChange
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	create := os.IsNotExist(err)
	dir := filepath.Dir(certificateHistoryPath(n.DataDir, h.CertificateID, h.VersionID))
	if err = secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	if create {
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		names, err := f.Readdirnames(8193)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(names) >= 8192 {
			return errors.New("证书退役凭据已达保留上限")
		}
	}
	return rootJSONWrite(certificateHistoryPath(n.DataDir, h.CertificateID, h.VersionID), h, 1024)
}

func historyPath(target, path string) bool {
	return path == target || strings.HasPrefix(path, target+"/")
}

func (n *Nginx) historyEntry(ctx context.Context, relative string) (runtimeHistoryEntry, error) {
	e := runtimeHistoryEntry{Path: relative}
	if !fs.ValidPath(relative) || len(relative) > 512 {
		return e, ErrExternalChange
	}
	name := filepath.Join(n.DataDir, filepath.FromSlash(relative))
	info, err := os.Lstat(name)
	if err != nil {
		return e, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && (!info.Mode().IsRegular() || st.Nlink != 1) {
		return e, ErrExternalChange
	}
	e.Directory = info.IsDir()
	e.Device = uint64(st.Dev)
	e.Inode = st.Ino
	e.GID = st.Gid
	e.Mode = uint32(info.Mode())
	if !e.Directory {
		if info.Size() < 0 || info.Size() > 512<<10 {
			return e, ErrExternalChange
		}
		if err = ctx.Err(); err != nil {
			return e, err
		}
		raw, err := nginxmodules.ReadTrusted(name, 512<<10)
		if err != nil {
			return e, err
		}
		after, err := os.Lstat(name)
		if err != nil {
			return e, err
		}
		latest, ok := after.Sys().(*syscall.Stat_t)
		if !ok || !os.SameFile(info, after) || info.Mode() != after.Mode() || info.Size() != after.Size() || latest.Uid != st.Uid || latest.Gid != st.Gid || latest.Nlink != st.Nlink || latest.Mtim != st.Mtim || latest.Ctim != st.Ctim {
			return e, ErrExternalChange
		}
		e.Size = info.Size()
		e.Modified = st.Mtim.Nano()
		e.Changed = st.Ctim.Nano()
		e.SHA256 = secure.Hash(raw)
		if int64(len(raw)) != e.Size {
			return e, ErrExternalChange
		}
	}
	return e, nil
}

func (n *Nginx) inventoryHistory(ctx context.Context, target string, wanted map[string]string) ([]runtimeHistoryEntry, int64, error) {
	entries := []runtimeHistoryEntry{}
	var size int64
	seen := 0
	err := filepath.WalkDir(filepath.Join(n.DataDir, filepath.FromSlash(target)), func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(n.DataDir, name)
		if err != nil {
			return err
		}
		e, err := n.historyEntry(ctx, filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if !e.Directory {
			local, err := filepath.Rel(filepath.Join(n.DataDir, filepath.FromSlash(target)), name)
			if err != nil || wanted[filepath.ToSlash(local)] != e.SHA256 {
				return ErrExternalChange
			}
			seen++
			size += e.Size
		}
		entries = append(entries, e)
		if len(entries) > historyEntryMax || size > historyBytesMax {
			return errors.New("运行材料超出单批清理预算")
		}
		return nil
	})
	if err == nil && seen != len(wanted) {
		err = ErrExternalChange
	}
	return entries, size, err
}

// Validate the entire remaining inventory before unlinking. Parent directory
// timestamps change during deletion; its original device/inode/mode must not.
func (n *Nginx) removeHistory(ctx context.Context, p runtimeHistoryPlan) error {
	expected := map[string]runtimeHistoryEntry{}
	for _, e := range p.Entries {
		expected[e.Path] = e
	}
	for _, target := range p.Preview.Targets {
		err := filepath.WalkDir(filepath.Join(n.DataDir, filepath.FromSlash(target)), func(name string, d fs.DirEntry, err error) error {
			if os.IsNotExist(err) && name == filepath.Join(n.DataDir, filepath.FromSlash(target)) {
				return nil
			}
			if err != nil {
				return err
			}
			rel, e := filepath.Rel(n.DataDir, name)
			if e != nil {
				return e
			}
			old, ok := expected[filepath.ToSlash(rel)]
			if !ok {
				return ErrExternalChange
			}
			current, e := n.historyEntry(ctx, old.Path)
			if e != nil {
				return e
			}
			if current != old {
				return ErrExternalChange
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	entries := append([]runtimeHistoryEntry(nil), p.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		a, b := strings.Count(entries[i].Path, "/"), strings.Count(entries[j].Path, "/")
		return a > b || a == b && entries[i].Path > entries[j].Path
	})
	for _, old := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := n.historyEntry(ctx, old.Path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if current != old {
			return ErrExternalChange
		}
		name := filepath.Join(n.DataDir, filepath.FromSlash(old.Path))
		if err = os.Remove(name); err != nil {
			return err
		}
		if err = syncDir(filepath.Dir(name)); err != nil {
			return err
		}
	}
	// A previous attempt may have unlinked the last directory before its
	// parent fsync failed. Reconfirm that unlink even when the path is absent.
	for _, target := range p.Preview.Targets {
		parent := filepath.Dir(filepath.Join(n.DataDir, filepath.FromSlash(target)))
		if err := existingRootDirectory(parent); err != nil {
			return err
		}
		if err := syncDir(parent); err != nil {
			return err
		}
	}
	return nil
}
