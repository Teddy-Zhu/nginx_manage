package backup

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

const preparationJournalMax = DatabaseMax + (16 << 20)

type PreparationStatus struct {
	Preparation Preparation `json:"preparation"`
	SHA256      string      `json:"preparation_sha256"`
	Expired     bool        `json:"expired"`
}

func preparationEntry(item os.DirEntry) (string, bool, error) {
	partial := strings.HasPrefix(item.Name(), ".preparing-")
	id := strings.TrimPrefix(item.Name(), ".preparing-")
	if !validID.MatchString(id) || !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
		return "", false, errors.New("恢复暂存存在未知资源")
	}
	return id, partial, nil
}

// Validate the entire fixed directory before deleting anything, including the
// bounded rollback journal a killed SQLite transaction can leave behind.
func preparationFiles(dir string) (os.FileInfo, []os.DirEntry, int64, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, 0, err
	}
	if err = privateDir(dir); err != nil {
		return nil, nil, 0, err
	}
	items, err := boundedEntries(dir, 7)
	if err != nil {
		return nil, nil, 0, err
	}
	var total int64
	for _, item := range items {
		var limit int64
		switch item.Name() {
		case "manifest.json":
			limit = 128 << 10
		case "prepared-at":
			limit = 32
		case "panel.db-journal":
			limit = preparationJournalMax
		}
		for _, r := range resources {
			if item.Name() == r.local {
				limit = r.limit
			}
		}
		if limit == 0 {
			return nil, nil, 0, errors.New("恢复暂存包含未知文件")
		}
		f, stat, err := openPrivate(filepath.Join(dir, item.Name()), limit)
		if err != nil {
			return nil, nil, 0, err
		}
		f.Close()
		total += stat.Size()
	}
	return info, items, total, nil
}

func removePreparationDirectory(dir string) error {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	_, items, _, err := preparationFiles(dir)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err = os.Remove(filepath.Join(dir, item.Name())); err != nil {
			return err
		}
	}
	if err = os.Remove(dir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dir))
}

func readPreparationJSON(dir, name string, limit int64, out any) error {
	f, info, err := openPrivate(filepath.Join(dir, name), limit)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) != info.Size() || !secure.RootFileUnchanged(f, info) || decodeStrict(raw, out) != nil {
		return errors.New("恢复准备记录无效或读取期间变化")
	}
	return nil
}

func readPreparation(dir, id string) (Preparation, error) {
	var p Preparation
	if err := readPreparationJSON(dir, "manifest.json", 128<<10, &p); err != nil {
		return p, err
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	if p.OperationID != id {
		return p, errors.New("恢复准备报告与目录身份不一致")
	}
	var created int64
	if err := readPreparationJSON(dir, "prepared-at", 32, &created); err != nil {
		return p, err
	}
	if created != p.PreparedAt {
		return p, errors.New("恢复准备期限记录不一致")
	}
	return p, nil
}

// GetPreparation rechecks private material as the bound unprivileged account.
// It does not inspect live SQLite as root or imply installation approval.
func GetPreparation(ctx context.Context, data, id string) (out PreparationStatus, err error) {
	if os.Geteuid() == 0 || !validID.MatchString(id) {
		return out, errors.New("恢复准备查询须使用非 root 面板账户及有效操作标识")
	}
	if err = panelruntime.CheckInit(data); err != nil {
		return out, err
	}
	if err = checkPreparationParents(data); err != nil {
		return out, err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	dir := preparationDir(data, id)
	_, items, _, err := preparationFiles(dir)
	if err != nil {
		return out, err
	}
	if len(items) != 6 {
		return out, errors.New("恢复准备资源不完整或仍含事务日志")
	}
	p, err := readPreparation(dir, id)
	if err != nil {
		return out, err
	}
	for i, r := range resources {
		file, e := digestFile(call, filepath.Join(dir, r.local), r.limit)
		if e != nil {
			return out, e
		}
		file.Name = r.name
		if file != p.Files[i] {
			return out, errors.New("恢复准备资源身份已变化")
		}
	}
	vault, err := secure.LoadKey(filepath.Join(dir, "master.key"))
	if err != nil {
		return out, err
	}
	probe, err := vault.Open(p.Source.KeyCheck, "backup-key-check:"+p.Source.ID)
	if err != nil || string(probe) != "nginxpanel-disaster:"+p.Source.ID {
		return out, errors.New("恢复准备业务密钥无效")
	}
	if _, err = tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")); err != nil {
		return out, errors.New("恢复准备管理入口 TLS 不匹配")
	}
	db, err := readDatabase(call, filepath.Join(dir, "panel.db"))
	if err != nil {
		return out, err
	}
	defer db.Close()
	if err = verifyPreparedDatabase(call, db, vault, p); err != nil {
		return out, err
	}
	out.Preparation = p
	out.SHA256, err = preparationHash(p)
	if err != nil {
		return out, err
	}
	out.Expired = p.ExpiresAt <= time.Now().Unix()
	return out, nil
}

// CleanupPreparation can remove a failed partial or a completed preparation;
// the same writer lock prevents racing an active helper or business process.
func CleanupPreparation(data, id string) error {
	if os.Geteuid() == 0 || !validID.MatchString(id) {
		return errors.New("恢复准备清理须使用非 root 面板账户及有效操作标识")
	}
	if err := panelruntime.CheckInit(data); err != nil {
		return err
	}
	unlock, err := storage.LockWriterForPreparation(data, os.Getegid())
	if err != nil {
		return err
	}
	defer unlock()
	if _, err = os.Lstat(preparationRoot(data)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err = checkPreparationParents(data); err != nil {
		return err
	}
	for _, name := range []string{id, ".preparing-" + id} {
		if err = removePreparationDirectory(filepath.Join(preparationRoot(data), name)); err != nil {
			return err
		}
	}
	return nil
}

// The live service owns the global writer lock; an offline helper therefore
// cannot concurrently create material while this bounded cleanup runs.
func cleanupPreparations(ctx context.Context, data string) error {
	root := preparationRoot(data)
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := checkPreparationParents(data); err != nil {
		return err
	}
	items, err := boundedEntries(root, PreparationMax)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, item := range items {
		if err = ctx.Err(); err != nil {
			return err
		}
		id, partial, e := preparationEntry(item)
		if e != nil {
			return e
		}
		dir := filepath.Join(root, item.Name())
		info, _, _, e := preparationFiles(dir)
		if e != nil {
			return e
		}
		var expires int64
		if partial {
			var created int64
			e = readPreparationJSON(dir, "prepared-at", 32, &created)
			if os.IsNotExist(e) {
				created = info.ModTime().Unix()
			} else if e != nil {
				return e
			}
			if created <= 0 || created > now+300 {
				return errors.New("恢复暂存创建时间无效")
			}
			expires = created + PreparationLifetime
		} else {
			p, e := readPreparation(dir, id)
			if e != nil {
				return e
			}
			expires = p.ExpiresAt
		}
		if expires <= now {
			if e = removePreparationDirectory(dir); e != nil {
				return e
			}
		}
	}
	return nil
}

func checkPreparationParents(data string) error {
	for _, dir := range []string{filepath.Join(data, "staging"), preparationRoot(data)} {
		if _, err := os.Lstat(dir); err != nil {
			return err
		}
		if err := privateDir(dir); err != nil {
			return err
		}
	}
	return nil
}
