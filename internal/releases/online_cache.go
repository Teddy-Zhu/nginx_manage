package releases

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DownloadStore    = "/opt/nginxpanel/release-downloads"
	maxCacheBytes    = 6 << 20
	maxDownloadBytes = 512 << 20
)

// A single metadata slot bounds retained API data. Credentials are never stored;
// Key binds the slot to the local trust bytes, endpoint and credential identity.
type onlineCache struct {
	Schema       int             `json:"schema"`
	Key          string          `json:"key"`
	ETag         string          `json:"etag"`
	FreshUntil   int64           `json:"fresh_until"`
	NextCheck    int64           `json:"next_check"`
	BlockedUntil int64           `json:"blocked_until"`
	Body         json.RawMessage `json:"body,omitempty"`
	Manifest     []byte          `json:"manifest,omitempty"`
	Signature    []byte          `json:"signature,omitempty"`
}

func privateDownloadDirectory() error {
	if err := storeDirectory(filepath.Dir(DownloadStore)); err != nil {
		return err
	}
	if err := rootParents(DownloadStore); err != nil {
		return err
	}
	info, err := os.Lstat(DownloadStore)
	if os.IsNotExist(err) {
		if err := os.Mkdir(DownloadStore, 0700); err != nil {
			return err
		}
		if err := os.Chmod(DownloadStore, 0700); err != nil {
			return err
		}
		return syncDir(filepath.Dir(DownloadStore))
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != 0 || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("在线资产缓存目录须为 root 持有的 0700 目录")
	}
	return nil
}

func lockOnline() (*os.File, error) {
	if err := privateDownloadDirectory(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(DownloadStore, ".online.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm() != 0600 {
			err = errors.New("在线发行锁的归属、链接或权限无效")
		}
	}
	if err == nil {
		if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			err = errors.New("已有在线发行操作正在执行")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil // Closing the descriptor also releases the flock.
}

func readOnlineCache() (onlineCache, error) {
	raw, err := readRoot(filepath.Join(DownloadStore, "cache.json"), maxCacheBytes)
	if os.IsNotExist(err) {
		return onlineCache{Schema: Schema}, nil
	}
	if err != nil {
		return onlineCache{}, err
	}
	var cache onlineCache
	if err := strictJSON(raw, &cache); err != nil {
		return onlineCache{}, fmt.Errorf("在线发行缓存：%w", err)
	}
	now := time.Now().Unix()
	if cache.Schema != Schema || !validETag(cache.ETag) ||
		len(cache.Body) > MaxManifestBytes || len(cache.Manifest) > MaxManifestBytes || len(cache.Signature) > 4096 ||
		cache.FreshUntil < 0 || cache.NextCheck < 0 || cache.BlockedUntil < 0 ||
		cache.FreshUntil > now+366*86400 || cache.NextCheck > now+366*86400 || cache.BlockedUntil > now+366*86400 ||
		len(cache.Body) != 0 && !validHash(cache.Key) ||
		len(cache.Body) == 0 && (cache.Key != "" || cache.ETag != "" || cache.FreshUntil != 0 || len(cache.Manifest) != 0 || len(cache.Signature) != 0) ||
		(len(cache.Manifest) == 0) != (len(cache.Signature) == 0) {
		return onlineCache{}, errors.New("在线发行缓存结构或期限无效，须由本机管理员检查")
	}
	return cache, nil
}

func removeDownload(name string) {
	if err := os.RemoveAll(name); err != nil {
		slog.Error("清理本次在线发行暂存失败", "path", name, "error", err)
	}
}

func writeOnlineCache(cache onlineCache) error {
	raw, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	if len(raw) > maxCacheBytes {
		return errors.New("在线发行缓存超过 6 MiB")
	}
	f, err := os.CreateTemp(DownloadStore, ".cache-*")
	if err != nil {
		return err
	}
	defer removeDownload(f.Name())
	err = f.Chmod(0600)
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), filepath.Join(DownloadStore, "cache.json")); err != nil {
		return err
	}
	return syncDir(DownloadStore)
}

func downloadUsage() (int64, int, int, error) {
	var total int64
	groups, entries := 0, 0
	err := filepath.WalkDir(DownloadStore, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries++
		if entries > 256 {
			return errors.New("在线发行缓存超过 256 项，须本机维护")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0077 != 0 || !entry.IsDir() && (!info.Mode().IsRegular() || st.Nlink != 1) {
			return errors.New("在线发行缓存存在不受信任的条目或权限")
		}
		if name == DownloadStore {
			return nil
		}
		parent := filepath.Dir(name)
		if entry.IsDir() {
			if parent != DownloadStore || !strings.HasPrefix(entry.Name(), ".fetch-") {
				return errors.New("在线发行缓存出现未知目录")
			}
			groups++
		} else {
			if parent == DownloadStore {
				if entry.Name() != "cache.json" && entry.Name() != ".online.lock" && !strings.HasPrefix(entry.Name(), ".cache-") {
					return errors.New("在线发行缓存出现未知文件")
				}
			} else if filepath.Dir(parent) != DownloadStore {
				return errors.New("在线发行缓存层级无效")
			}
			total += info.Size()
		}
		if groups > 8 || total > maxDownloadBytes {
			return errors.New("在线发行缓存超过 8 组或 512 MiB，须本机维护")
		}
		return nil
	})
	return total, groups, entries, err
}
