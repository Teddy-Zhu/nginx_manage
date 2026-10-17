package releases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func checkRuntime(ctx context.Context, assets []Asset) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := runtimeTotal(assets); err != nil {
		return err
	}
	checked := map[string]File{}
	var python *SystemPython
	for _, a := range assets {
		if a.Python != nil {
			if python == nil {
				observed, err := InspectSystemPython(ctx)
				if err != nil {
					return fmt.Errorf("系统 Python 不可准备：%w", err)
				}
				python = &observed
			}
			if err := python.Check(*a.Python); err != nil {
				return err
			}
		}
		for _, file := range a.RuntimeFiles {
			if err := ctx.Err(); err != nil {
				return err
			}
			if previous, ok := checked[file.Path]; ok {
				if previous != file {
					return errors.New("组件的系统依赖约束相互冲突")
				}
				continue
			}
			checked[file.Path] = file
			name, err := filepath.EvalSymlinks(file.Path)
			if err != nil {
				return fmt.Errorf("解析目标运行依赖 %s：%w", file.Path, err)
			}
			h, err := fileHash(name, file.Size)
			if err != nil {
				return fmt.Errorf("核验目标运行依赖 %s：%w", file.Path, err)
			}
			if h != file.SHA256 {
				return fmt.Errorf("目标运行依赖不匹配 %s", file.Path)
			}
			info, err := os.Lstat(name)
			if err != nil || uint32(info.Mode().Perm()) != file.Mode {
				return errors.New("系统依赖权限不匹配")
			}
		}
	}
	return nil
}
func currentTrust(v *Verified) error {
	if time.Now().Unix() >= v.plan.Manifest.ExpiresAt {
		return errors.New("发行清单已过期，须重新验签")
	}
	raw, err := readRoot(v.trustPath, 16<<10)
	if err != nil {
		return err
	}
	if hash(raw) != v.plan.TrustSHA256 {
		return errors.New("本机发行信任已变化，须重新验签")
	}
	return nil
}
func storeDirectory(name string) error {
	if err := rootParents(name); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if os.IsNotExist(err) {
		if err := os.Mkdir(name, 0755); err != nil {
			return err
		}
		if err := os.Chmod(name, 0755); err != nil {
			return err
		}
		return syncDir(filepath.Dir(name))
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm() != 0755 {
		return errors.New("准备目录已有不同归属或权限")
	}
	return nil
}
func planEntries(assets []Asset) int {
	dirs := map[string]bool{}
	files := 0
	for _, a := range assets {
		dirs[a.ID] = true
		for _, f := range a.Files {
			files++
			for dir := filepath.Dir(a.ID + "/" + f.Path); dir != "."; dir = filepath.Dir(dir) {
				dirs[dir] = true
			}
		}
	}
	return len(dirs) + files + 4
}
func storeUsage(root string) (int64, int, int, error) {
	var total int64
	entries, groups := 0, 0
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries++
		if entries > 32768 {
			return errors.New("准备目录条目超过保留预算")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !entry.IsDir() && (!info.Mode().IsRegular() || st.Nlink != 1) {
			return errors.New("准备目录存在非受管文件或权限变化")
		}
		if entry.IsDir() && name != root && filepath.Dir(name) == root {
			groups++
		}
		if !entry.IsDir() {
			total += info.Size()
			if total > MaxStoreBytes {
				return errors.New("准备目录已达 2 GiB 保留上限")
			}
		}
		return nil
	})
	return total, groups, entries, err
}
func writePrivate(name string, raw []byte) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func syncTree(root string) error {
	dirs := []string{}
	if err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, name)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, name := range dirs {
		if err := os.Chmod(name, 0755); err != nil {
			return err
		}
		if err := syncDir(name); err != nil {
			return err
		}
	}
	return nil
}
func verifyPrepared(ctx context.Context, dir string, v *Verified, expected []byte) error {
	plan, err := readRoot(filepath.Join(dir, "plan.json"), MaxPlanBytes)
	if err != nil || string(plan) != string(expected) {
		return errors.New("已准备资产的计划记录不匹配")
	}
	m, err := readRoot(filepath.Join(dir, "release-manifest.json"), MaxManifestBytes)
	if err != nil || string(m) != string(v.manifest) {
		return errors.New("已准备资产的发行清单不匹配")
	}
	sig, err := readRoot(filepath.Join(dir, "release-manifest.sig"), 4096)
	if err != nil || string(sig) != string(v.signature) {
		return errors.New("已准备资产的签名记录不匹配")
	}
	wanted := map[string]File{}
	for _, asset := range v.plan.Assets {
		for _, file := range asset.Files {
			wanted[asset.ID+"/"+file.Path] = file
		}
	}
	seen := 0
	dirs := map[string]bool{}
	for name := range wanted {
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			dirs[parent] = true
		}
	}
	err = filepath.WalkDir(dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == dir {
			return nil
		}
		relative, err := filepath.Rel(dir, name)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if !dirs[relative] {
				return errors.New("已准备资产含未登记目录")
			}
			return rootParents(filepath.Join(name, ".inspection"))
		}
		if relative == "plan.json" || relative == "release-manifest.json" || relative == "release-manifest.sig" {
			return nil
		}
		file, ok := wanted[relative]
		if !ok {
			return errors.New("已准备资产含未登记文件")
		}
		h, err := fileHash(name, file.Size)
		if err != nil || h != file.SHA256 {
			return errors.New("已准备资产的文件已变化")
		}
		info, err := entry.Info()
		if err != nil || uint32(info.Mode().Perm()) != file.Mode {
			return errors.New("已准备资产的文件权限已变化")
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(wanted) {
		return errors.New("已准备资产不完整")
	}
	return nil
}

// Prepare is the only filesystem mutation entry. The root is fixed and is not
// selected by a Web request or by archive metadata. Publication is all-or-none.
func Prepare(ctx context.Context, v *Verified, assetDirectory string) (Result, error) {
	if os.Geteuid() != 0 {
		return Result{}, errors.New("资产准备需要本机 root")
	}
	if v == nil || v.seal == "" {
		return Result{}, errors.New("资产尚未验签")
	}
	planRaw, err := json.Marshal(v.plan)
	if err != nil {
		return Result{}, err
	}
	if hash(planRaw) != v.seal || time.Now().Unix() >= v.plan.Manifest.ExpiresAt {
		return Result{}, errors.New("验签计划已变化或过期")
	}
	if err := currentTrust(v); err != nil {
		return Result{}, err
	}
	if !filepath.IsAbs(assetDirectory) || filepath.Clean(assetDirectory) != assetDirectory {
		return Result{}, errors.New("离线资产目录须为规范绝对路径")
	}
	if err := rootParents(filepath.Join(assetDirectory, ".inspection")); err != nil {
		return Result{}, err
	}
	if err := checkRuntime(ctx, v.plan.Assets); err != nil {
		return Result{}, err
	}
	if err := storeDirectory(filepath.Dir(Store)); err != nil {
		return Result{}, err
	}
	if err := storeDirectory(Store); err != nil {
		return Result{}, err
	}
	lock, err := os.OpenFile(filepath.Join(Store, ".prepare.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil {
		return Result{}, err
	}
	lockStat, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok || !lockInfo.Mode().IsRegular() || lockStat.Uid != 0 || lockStat.Nlink != 1 || lockInfo.Mode().Perm() != 0600 {
		return Result{}, errors.New("资产准备锁的归属或权限无效")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return Result{}, errors.New("已有资产准备操作正在执行")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	final := filepath.Join(Store, v.plan.ID)
	if _, err := os.Lstat(final); err == nil {
		if err := verifyPrepared(ctx, final, v, planRaw); err != nil {
			return Result{}, err
		}
		if err := checkRuntime(ctx, v.plan.Assets); err != nil {
			return Result{}, err
		}
		if err := currentTrust(v); err != nil {
			return Result{}, err
		}
		return Result{State: "prepared", Directory: final, Reused: true, Plan: v.Plan()}, nil
	} else if !os.IsNotExist(err) {
		return Result{}, err
	}
	used, groups, entries, err := storeUsage(Store)
	if err != nil {
		return Result{}, err
	}
	if groups >= 32 || entries+planEntries(v.plan.Assets) > 32768 || used+v.plan.UnpackedBytes+int64(len(planRaw)+len(v.manifest)+len(v.signature)) > MaxStoreBytes {
		return Result{}, errors.New("准备目录保留预算不足，须先进行本机维护")
	}
	stage, err := os.MkdirTemp(Store, ".prepare-")
	if err != nil {
		return Result{}, err
	}
	published := false
	defer func() {
		if !published {
			if err := os.RemoveAll(stage); err != nil {
				slog.Error("release staging cleanup failed", "path", stage, "error", err)
			}
		}
	}()
	for _, asset := range v.plan.Assets {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		dir := filepath.Join(stage, asset.ID)
		if err := os.Mkdir(dir, 0755); err != nil {
			return Result{}, err
		}
		if err := extract(ctx, filepath.Join(assetDirectory, asset.Archive), dir, asset); err != nil {
			return Result{}, fmt.Errorf("准备 %s：%w", asset.ID, err)
		}
	}
	if err := checkRuntime(ctx, v.plan.Assets); err != nil {
		return Result{}, err
	}
	for name, raw := range map[string][]byte{"plan.json": planRaw, "release-manifest.json": v.manifest, "release-manifest.sig": v.signature} {
		if err := writePrivate(filepath.Join(stage, name), raw); err != nil {
			return Result{}, err
		}
	}
	if time.Now().Unix() >= v.plan.Manifest.ExpiresAt {
		return Result{}, errors.New("准备期间发行清单过期")
	}
	if err := syncTree(stage); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := currentTrust(v); err != nil {
		return Result{}, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); err != nil {
		return Result{}, err
	}
	published = true
	if err := syncDir(Store); err != nil {
		return Result{}, fmt.Errorf("已发布资产但目录同步未确认，请用原计划核对：%w", err)
	}
	return Result{State: "prepared", Directory: final, Reused: false, Plan: v.Plan()}, nil
}

func runtimeTotal(assets []Asset) error {
	var total int64
	for _, asset := range assets {
		for _, file := range asset.RuntimeFiles {
			total += file.Size
		}
	}
	if total > 128<<20 {
		return errors.New("系统依赖核验超过 128 MiB 预算")
	}
	return nil
}
