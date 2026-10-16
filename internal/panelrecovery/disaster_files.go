package panelrecovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

var disasterNames = []string{"panel.db", "master.key", "cert.pem", "key.pem"}

func checkedDisasterDirectory(i DisasterIntent) (string, error) {
	stored, err := ReadDisasterIntent(i.DataDir, i.OperationID)
	if err != nil {
		return "", err
	}
	if stored.SHA256() != i.SHA256() {
		return "", errors.New("独立恢复与原持久意图不一致")
	}
	fence, err := storage.ReadWriterFence(i.DataDir)
	if err != nil {
		return "", err
	}
	hold, err := storage.ReadServiceHold(i.DataDir)
	if err != nil {
		return "", err
	}
	if fence != i.Fence() || hold != i.Stop {
		return "", errors.New("独立恢复缺少原持久停机及写入屏障")
	}
	return disasterDirectory(i.DataDir, i.OperationID)
}

func disasterTargets(i DisasterIntent) []Original {
	out := make([]Original, len(restoreFiles))
	for index, spec := range restoreFiles {
		out[index] = Original{Name: spec.name}
		if spec.target >= 0 {
			f := i.Files[spec.target]
			out[index].Present = true
			out[index].Size = f.Size
			out[index].SHA256 = f.SHA256
		}
	}
	return out
}

// CheckDisasterMaterial hashes immutable root files only. SQL validation belongs
// to the unprivileged adoption helper and is bound by AdoptionSHA256.
func CheckDisasterMaterial(ctx context.Context, i DisasterIntent) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("独立恢复材料检查须由 root 执行")
	}
	dir := filepath.Join(i.DataDir, "agent", "disaster-recovery", i.OperationID)
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	for index, file := range i.Files {
		h, n, err := rootFileHash(ctx, filepath.Join(dir, disasterNames[index]), file.Size, 0400)
		if err != nil {
			return err
		}
		if h != file.SHA256 || n != file.Size {
			return errors.New("独立恢复材料已偏离原批准")
		}
	}
	return nil
}

// PreserveDisasterOriginals accepts only the target pinned at adoption. No live
// write is permitted until all six originals and the installing stage are durable.
func PreserveDisasterOriginals(ctx context.Context, i DisasterIntent) error {
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if err = CheckDisasterTarget(ctx, i, false); err != nil {
		return err
	}
	before := filepath.Join(dir, "before")
	if err = privateDir(before); err != nil {
		return err
	}
	items, err := disasterEntries(before, 12)
	if err != nil {
		return err
	}
	var stale []string
	for _, item := range items {
		known := false
		limit := DatabaseMax * 2
		for index, file := range i.Before {
			if item.Name() == fmt.Sprintf("%02d", index) && file.Present {
				known = true
				limit = file.Size
			}
		}
		tmp := temporary(item.Name(), ".before-")
		if !known && !tmp {
			return errors.New("独立恢复原件目录存在未知文件")
		}
		name := filepath.Join(before, item.Name())
		f, info, e := secure.OpenRootFile(name, limit)
		if e != nil {
			return e
		}
		f.Close()
		if info.Mode().Perm() != 0400 && (!tmp || info.Mode().Perm() != 0600) {
			return errors.New("独立恢复原件暂存权限无效")
		}
		if tmp {
			stale = append(stale, name)
		}
	}
	for _, name := range stale {
		if err = os.Remove(name); err != nil {
			return err
		}
	}
	actual, err := preserveOriginals(ctx, i.Rollback.Manifest, before)
	if err != nil {
		return err
	}
	if len(actual) != len(i.Before) {
		return errors.New("独立恢复原件清单不完整")
	}
	for index, file := range actual {
		if file != i.Before[index] {
			return errors.New("独立恢复原件在保留期间变化")
		}
	}
	return nil
}

func checkDisasterOriginals(ctx context.Context, dir string, i DisasterIntent) error {
	before := filepath.Join(dir, "before")
	if err := checkPrivateDir(before); err != nil {
		return err
	}
	items, err := disasterEntries(before, 6)
	if err != nil {
		return err
	}
	expected := 0
	for index, file := range i.Before {
		if !file.Present {
			continue
		}
		expected++
		h, n, err := rootFileHash(ctx, filepath.Join(before, fmt.Sprintf("%02d", index)), file.Size, 0400)
		if err != nil {
			return err
		}
		if h != file.SHA256 || n != file.Size {
			return errors.New("独立恢复原件不完整或已变化")
		}
	}
	if len(items) != expected {
		return errors.New("独立恢复原件目录含额外资源")
	}
	return nil
}

// InstallDisaster applies or compensates only the fixed resource set. A replay
// accepts exactly the original or approved material at every live basename.
func InstallDisaster(ctx context.Context, i DisasterIntent, rollback bool) error {
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if err = checkDisasterOriginals(ctx, dir, i); err != nil {
		return err
	}
	if !rollback {
		if err = CheckDisasterMaterial(ctx, i); err != nil {
			return err
		}
	}
	approved := disasterTargets(i)
	actual, err := ObserveTarget(ctx, i.Rollback)
	if err != nil {
		return err
	}
	for index, file := range actual {
		if file != i.Before[index] && file != approved[index] {
			return errors.New("目标已偏离原资源及批准材料，停止安装或补偿")
		}
	}
	order := []int{0, 1, 2, 3, 4, 5}
	if rollback {
		order = []int{2, 3, 4, 5, 0, 1}
	}
	for _, index := range order {
		from, to := i.Before[index], approved[index]
		source := ""
		if restoreFiles[index].target >= 0 {
			source = filepath.Join(i.DataDir, "agent", "disaster-recovery", i.OperationID, disasterNames[restoreFiles[index].target])
		}
		if rollback {
			from, to = to, from
			source = filepath.Join(dir, "before", fmt.Sprintf("%02d", index))
		}
		if err = installOne(ctx, i.Rollback.Manifest, i.OperationID, from, to, index, source); err != nil {
			return err
		}
	}
	for _, name := range []string{"app", "secrets", "secrets/node-tls"} {
		parent, e := businessDirectory(i.DataDir, name, i.Rollback.Manifest.UID, i.Rollback.Manifest.GID, false)
		if e != nil {
			return e
		}
		e = parent.Sync()
		parent.Close()
		if e != nil {
			return e
		}
	}
	return CheckDisasterTarget(ctx, i, !rollback)
}

func CheckDisasterTarget(ctx context.Context, i DisasterIntent, installed bool) error {
	if err := i.Validate(); err != nil {
		return err
	}
	actual, err := ObserveTarget(ctx, i.Rollback)
	if err != nil {
		return err
	}
	expected := i.Before
	if installed {
		expected = disasterTargets(i)
	}
	for index, file := range actual {
		if file != expected[index] {
			return errors.New("独立恢复目标尚未匹配本阶段的完整资源")
		}
	}
	return nil
}
