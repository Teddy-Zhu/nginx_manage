package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func readFail2banUpgradePreparationJSON(path string, value any) error {
	raw, err := listenerRead(path, fail2banUpgradePreparationLimit)
	if err != nil {
		return err
	}
	if err = decodeFail2banNginxJSON(raw, value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("升级准备材料字段不完整或规范格式已变化")
	}
	return nil
}

func readFail2banUpgradePreparation(data, id, dir string) (fail2banUpgradePreparation, fail2banUpgradePreparationReceipt, error) {
	var i fail2banUpgradePreparation
	var receipt fail2banUpgradePreparationReceipt
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return i, receipt, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return i, receipt, err
	}
	if len(entries) != 4 {
		return i, receipt, errors.New("升级准备目录材料缺失或包含额外文件")
	}
	for _, entry := range entries {
		if entry.Name() != "intent.json" && entry.Name() != "receipt.json" && entry.Name() != "candidate.service" && entry.Name() != "config" {
			return i, receipt, ErrExternalChange
		}
	}
	if err = readFail2banUpgradePreparationJSON(filepath.Join(dir, "intent.json"), &i); err != nil {
		return i, receipt, err
	}
	if err = i.validate(data, id); err != nil {
		return i, receipt, err
	}
	if err = readFail2banUpgradePreparationJSON(filepath.Join(dir, "receipt.json"), &receipt); err != nil {
		return i, receipt, err
	}
	expected, err := i.receipt()
	if err != nil {
		return i, receipt, err
	}
	if receipt != expected {
		return i, receipt, errors.New("升级准备完成回执与原意图或候选内容不匹配")
	}
	unit, err := listenerRead(filepath.Join(dir, "candidate.service"), 64<<10)
	if err != nil || string(unit) != i.Basis.Candidate.unit() || secure.Hash(unit) != receipt.UnitSHA256 {
		return i, receipt, errors.Join(errors.New("升级准备候选单元不匹配"), err)
	}
	if err = verifyFail2banJailConfig(&i.Basis.Candidate, filepath.Join(dir, "config"), i.Material.Bundle); err != nil {
		return i, receipt, err
	}
	return i, receipt, nil
}

// Count abandoned temporary directories too. Capacity pressure never deletes
// recovery input or the original audit. Each published preparation is bounded.
func fail2banUpgradePreparationQuota(store string) error {
	if err := fail2banStatePrivateDir(store, false); err != nil {
		return err
	}
	entries, err := os.ReadDir(store)
	if err != nil {
		return err
	}
	if len(entries) >= 8 {
		return errors.New("升级准备目录已达 8 项容量上限，须本机维护")
	}
	var total int64
	count := 0
	return filepath.WalkDir(store, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == store {
			return nil
		}
		count++
		relative, err := filepath.Rel(store, path)
		if err != nil {
			return err
		}
		if count > 1024 || strings.Count(relative, string(filepath.Separator)) > 3 {
			return errors.New("升级准备材料数量或层级超过限制")
		}
		if entry.IsDir() {
			return fail2banStatePrivateDir(path, false)
		}
		f, info, err := secure.OpenRootFile(path, fail2banUpgradePreparationLimit)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if info.Mode().Perm() != 0600 {
			return errors.New("升级准备材料须为 root 专用的 0600 文件")
		}
		total += info.Size()
		if total > 28<<20 {
			return errors.New("升级准备材料容量不足以保留完整候选和原恢复依据")
		}
		return nil
	})
}

func writeFail2banUpgradePreparationJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFail2banJailImmutable(path, raw, fail2banUpgradePreparationLimit)
}

func acknowledgeFail2banUpgradePreparation(i fail2banUpgradePreparation, receipt fail2banUpgradePreparationReceipt) error {
	j := &Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}
	expected := i.record(receipt)
	actual, err := j.Get(i.Request.OperationID)
	if err == nil {
		if !sameFail2banUpgradePreparationRecord(actual, expected) {
			return errors.New("升级准备 UUID 已被其他操作或不同审计内容使用")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return j.Put(expected)
}

func publishFail2banUpgradePreparation(tmp string, i fail2banUpgradePreparation) error {
	if err := syncTree(tmp); err != nil {
		return err
	}
	if _, _, err := readFail2banUpgradePreparation(i.Request.DataDir, i.Request.OperationID, tmp); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, i.dir(), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(filepath.Dir(i.dir()))
}

// A fixed upper bound also applies before publication, including the generated
// configuration. A successful quota check alone is never a size proof.
func fail2banUpgradePreparationSize(dir string) error {
	var total int64
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		f, info, err := secure.OpenRootFile(path, fail2banUpgradePreparationLimit)
		if err != nil {
			return err
		}
		closed := f.Close()
		total += info.Size()
		if total > 4<<20 {
			return errors.Join(errors.New("单项升级准备材料超过 4 MiB 限制"), closed)
		}
		return closed
	})
}

func writeFail2banUpgradeUnit(path, content string) error {
	if len(content) > 64<<10 {
		return errors.New("升级准备候选单元超过限制")
	}
	return writeFail2banJailImmutable(path, []byte(content), 64<<10)
}
