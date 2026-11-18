package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

// InstallCorePackage selects a local package explicitly approved by root.
func InstallCorePackage(parent context.Context, data, binary, trust string, approve func(current, target string, upgrade bool) bool, progress func(string)) error {
	if os.Geteuid() != 0 {
		return errors.New("覆盖安装需要本机 root")
	}
	if err := panelNativeUnit(data); err != nil {
		return err
	}
	before, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	candidate, err := panelruntime.DescribeBinary(parent, binary)
	if err != nil {
		return err
	}
	if candidate.DatabaseSchema < before.Release.DatabaseSchema {
		return errors.New("安装包的数据格式版本较旧，请使用支持当前数据格式的安装包")
	}
	comparison, _ := releases.CompareVersions(before.Release.Version, candidate.Version)
	if !approve(before.Release.Version, candidate.Version, comparison < 0) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 6*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".core-update.lock")
	if err != nil {
		return err
	}
	defer unlock()
	installation, err := (&Journal{Dir: "/run/nginxpanel-install"}).rootLock("lock")
	if err != nil {
		return err
	}
	defer installation()
	if err := panelNativeUnit(data); err != nil {
		return err
	}
	current, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	if current.Release.ID != before.Release.ID {
		return errors.New("当前版本已变化，请重新确认安装")
	}
	target, err := panelruntime.PublishNativeUpgrade(ctx, data, binary, candidate)
	if err != nil {
		return err
	}
	if trust != "" {
		if err = installPackageTrust(trust); err != nil {
			return err
		}
	}
	steps := map[string]string{"stopping": "正在停止面板", "selecting": "正在替换核心程序", "starting": "正在启动面板"}
	if err := activateCore(ctx, data, secure.ID(), current.Release.ID, target, func(step string) error {
		progress(steps[step])
		return nil
	}); err != nil {
		return err
	}
	progress("安装完成，面板已启动")
	return nil
}

func installPackageTrust(source string) error {
	const target = "/etc/nginxpanel/release-trust.json"
	if _, err := os.Lstat(target); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := releases.InspectTrust(source); err != nil {
		return err
	}
	raw, err := secure.ReadRootFile(source, 16<<10)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(target), ".release-trust-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(raw)
	if err = errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return syncDir(filepath.Dir(target))
}
