package panelruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

// Frontend records are separate from the running program. A backend update
// selects its bundled UI; an independent UI is approved for one exact backend.
type FrontendRelease struct {
	Schema         int             `json:"schema"`
	ID             string          `json:"id"`
	Version        string          `json:"version"`
	PlanID         string          `json:"plan_id"`
	ManifestSHA256 string          `json:"manifest_sha256"`
	TrustSHA256    string          `json:"trust_sha256"`
	Files          map[string]File `json:"files"`
}
type FrontendSource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type FrontendSelection struct {
	Schema      int            `json:"schema"`
	OperationID string         `json:"operation_id"`
	BaseID      string         `json:"base_id"`
	Current     FrontendSource `json:"current"`
	Previous    FrontendSource `json:"previous"`
}
type FrontendSnapshot struct {
	Source             FrontendSource
	Version, Directory string
	Files              map[string]File
}
type FrontendStatus struct {
	Available  bool   `json:"available"`
	Reason     string `json:"reason"`
	BaseID     string `json:"base_id"`
	CurrentID  string `json:"current_id"`
	Version    string `json:"version"`
	PreviousID string `json:"previous_id"`
}
type FrontendActivation struct {
	Schema      int                `json:"schema"`
	OperationID string             `json:"operation_id"`
	Before      *FrontendSelection `json:"before"`
	After       FrontendSelection  `json:"after"`
}

var ErrFrontendUnselected = errors.New("前端激活未改变原选择")
var ErrFrontendNoActivation = errors.New("尚无前端激活意图")

func frontendID(r FrontendRelease) string {
	r.ID = ""
	raw, _ := json.Marshal(r)
	return secure.Hash(raw)
}
func (s FrontendSource) valid() bool {
	return (s.Kind == "panel" || s.Kind == "web") && digest.MatchString(s.ID)
}
func (s FrontendSelection) valid() bool {
	return s.Schema == Schema && selectionID.MatchString(s.OperationID) && digest.MatchString(s.BaseID) && s.Current.Kind == "web" && s.Current.valid() && s.Previous.valid()
}
func frontendJSON(name string, out any, limit int64) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0444 {
		return errors.New("前端运行记录须为 root 只读文件")
	}
	raw, err := secure.ReadRootFile(name, limit)
	if err != nil {
		return err
	}
	if err = decode(raw, out); err != nil {
		return err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("前端运行记录不是原始规范记录")
	}
	return nil
}
func frontendRoot(data string) (string, error) {
	root, err := Root(data)
	return filepath.Join(root, "frontend"), err
}
func frontendPublicDir(name string) error {
	if err := secure.RootDirectory(name, 0700); err != nil {
		return err
	}
	return runtimeDir(name)
}
func frontendSelection(data string) (*FrontendSelection, error) {
	root, err := Root(data)
	if err != nil {
		return nil, err
	}
	var s FrontendSelection
	err = frontendJSON(filepath.Join(root, "frontend.json"), &s, 4096)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err == nil && !s.valid() {
		err = errors.New("独立前端选择记录无效")
	}
	return &s, err
}
func bundledFrontend(data, id string) (FrontendSnapshot, error) {
	root, err := Root(data)
	if err != nil || !digest.MatchString(id) {
		return FrontendSnapshot{}, errors.New("面板前端身份无效")
	}
	var r Release
	dir := filepath.Join(root, "releases", id)
	if err = frontendJSON(filepath.Join(dir, "release.json"), &r, 1<<20); err != nil {
		return FrontendSnapshot{}, err
	}
	if err = r.validate(); err != nil || r.ID != id {
		return FrontendSnapshot{}, errors.Join(errors.New("面板前端清单身份不一致"), err)
	}
	return FrontendSnapshot{Source: FrontendSource{"panel", id}, Version: r.Version, Directory: filepath.Join(dir, "web"), Files: r.Web}, nil
}
func readFrontendRelease(data, id string) (FrontendRelease, error) {
	var r FrontendRelease
	root, err := frontendRoot(data)
	if err != nil || !digest.MatchString(id) {
		return r, errors.New("独立前端身份无效")
	}
	if err = frontendJSON(filepath.Join(root, id, "release.json"), &r, 1<<20); err != nil {
		return r, err
	}
	if r.Schema != Schema || r.ID != id || r.ID != frontendID(r) || r.Version == "" || len(r.Version) > 128 || !digest.MatchString(r.PlanID) || !digest.MatchString(r.ManifestSHA256) || !digest.MatchString(r.TrustSHA256) || len(r.Files) == 0 || len(r.Files) > FileCountLimit {
		return r, errors.New("独立前端清单无效")
	}
	var total int64
	for name, f := range r.Files {
		if !validRelative(name) || !digest.MatchString(f.SHA256) || f.Size < 0 || f.Size > WebFileLimit {
			return r, errors.New("独立前端文件清单无效")
		}
		total += f.Size
	}
	if _, ok := r.Files["index.html"]; !ok || total > WebLimit {
		return r, errors.New("独立前端入口或容量无效")
	}
	return r, nil
}
func frontendSource(data string, s FrontendSource) (FrontendSnapshot, error) {
	if !s.valid() {
		return FrontendSnapshot{}, errors.New("前端来源无效")
	}
	if s.Kind == "panel" {
		return bundledFrontend(data, s.ID)
	}
	r, err := readFrontendRelease(data, s.ID)
	root, _ := frontendRoot(data)
	return FrontendSnapshot{Source: s, Version: r.Version, Directory: filepath.Join(root, s.ID, "web"), Files: r.Files}, err
}

// Frontends reads root approvals, without executing or rehashing the backend.
// The static reader authenticates each opened file against this inventory.
func Frontends(data, baseID string) (FrontendSnapshot, *FrontendSnapshot, error) {
	base, err := bundledFrontend(data, baseID)
	if err != nil {
		return base, nil, err
	}
	s, err := frontendSelection(data)
	if err != nil {
		return base, nil, err
	}
	if s == nil {
		previous, err := previousBundledFrontend(data, baseID)
		return base, previous, err
	}
	current, err := frontendSource(data, s.Current)
	if err != nil {
		return base, nil, err
	}
	if s.BaseID != baseID {
		return base, &current, nil
	}
	previous, err := frontendSource(data, s.Previous)
	return current, &previous, err
}
func CurrentFrontend(data string) (FrontendStatus, error) {
	var out FrontendStatus
	root, err := Root(data)
	if err != nil {
		return out, err
	}
	if _, err = ReadDeployment(data); err != nil {
		return out, err
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || !strings.HasPrefix(target, "releases/") || !digest.MatchString(strings.TrimPrefix(target, "releases/")) {
		return out, errors.New("当前面板版本指针无效")
	}
	baseID := strings.TrimPrefix(target, "releases/")
	current, previous, err := Frontends(data, baseID)
	if err != nil {
		return out, err
	}
	if again, e := os.Readlink(filepath.Join(root, "current")); e != nil || again != target {
		return out, errors.New("核对前端期间面板版本变化")
	}
	out = FrontendStatus{Available: true, BaseID: baseID, CurrentID: current.Source.ID, Version: current.Version}
	if previous != nil {
		out.PreviousID = previous.Source.ID
	}
	return out, nil
}

// StageFrontend accepts only an already authenticated complete web preparation.
// Publication never selects it or changes any executable or database.
func StageFrontend(ctx context.Context, data string, source releases.Result) (out FrontendRelease, resultErr error) {
	if os.Geteuid() != 0 {
		return out, errors.New("前端发布需要宿主机 root")
	}
	p := source.Plan
	if len(p.Assets) != 1 || p.Assets[0].Component != "web" || len(p.Selected) != 1 {
		return out, errors.New("独立前端须使用单独签名 web 资产")
	}
	a := p.Assets[0]
	out = FrontendRelease{Schema: Schema, Version: a.Version, PlanID: p.ID, ManifestSHA256: p.ManifestSHA256, TrustSHA256: p.TrustSHA256, Files: map[string]File{}}
	var total int64
	for _, f := range a.Files {
		if !validRelative(f.Path) || f.Size > WebFileLimit || f.Mode != 0644 || len(out.Files) >= FileCountLimit {
			return out, errors.New("前端文件类型、权限或数量不受支持")
		}
		out.Files[f.Path] = File{SHA256: f.SHA256, Size: f.Size}
		total += f.Size
	}
	if _, ok := out.Files["index.html"]; !ok || total > WebLimit || a.Version != p.Manifest.FrontendVersion {
		return out, errors.New("前端版本、入口或容量无效")
	}
	out.ID = frontendID(out)
	root, err := Root(data)
	if err != nil {
		return out, err
	}
	unlock, err := publicationLock(root)
	if err != nil {
		return out, err
	}
	defer unlock()
	store, _ := frontendRoot(data)
	if err = frontendPublicDir(store); err != nil {
		return out, err
	}
	dir := filepath.Join(store, out.ID)
	if _, err = os.Lstat(dir); os.IsNotExist(err) {
		entries, e := os.ReadDir(store)
		if e != nil {
			return out, e
		}
		if len(entries) >= 16 {
			return out, errors.New("独立前端达到 16 份保留上限，须本机维护")
		}
		tmp, e := os.MkdirTemp(store, ".web-")
		if e != nil {
			return out, e
		}
		defer func() {
			if cleanupErr := os.RemoveAll(tmp); cleanupErr != nil {
				resultErr = errors.Join(resultErr, errors.New("前端暂存目录清理失败，须本机维护"), cleanupErr)
			}
		}()
		if e = os.Chmod(tmp, 0755); e != nil {
			return out, e
		}
		if e = os.Mkdir(filepath.Join(tmp, "web"), 0755); e != nil {
			return out, e
		}
		for name, f := range out.Files {
			if e = ctx.Err(); e != nil {
				return out, e
			}
			if e = os.MkdirAll(filepath.Dir(filepath.Join(tmp, "web", name)), 0755); e != nil {
				return out, e
			}
			if e = copyArtifact(filepath.Join(source.Directory, a.ID, name), filepath.Join(tmp, "web", name), f.SHA256, WebFileLimit, 0444); e != nil {
				return out, e
			}
		}
		raw, _ := json.Marshal(out)
		if len(raw) > 1<<20 {
			return out, errors.New("独立前端清单超过容量限制")
		}
		if e = publishFile(filepath.Join(tmp, "release.json"), raw); e != nil {
			return out, e
		}
		if e = filepath.WalkDir(tmp, func(name string, entry os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if entry.IsDir() {
				if e = os.Chmod(name, 0755); e != nil {
					return e
				}
				return syncDir(name)
			}
			return nil
		}); e != nil {
			return out, e
		}
		if e = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, dir, unix.RENAME_NOREPLACE); e != nil {
			return out, e
		}
		if e = syncDir(store); e != nil {
			return out, e
		}
	} else if err != nil {
		return out, err
	}
	saved, err := readFrontendRelease(data, out.ID)
	if err != nil {
		return out, err
	}
	if err = verifyFrontendFiles(filepath.Join(dir, "web"), saved.Files); err != nil {
		return out, err
	}
	if _, err = FrontendEntrypoints(FrontendSnapshot{Directory: filepath.Join(dir, "web"), Files: saved.Files}); err != nil {
		return out, err
	}
	if err = syncDir(store); err != nil {
		return out, err
	}
	if err = syncDir(root); err != nil {
		return out, err
	}
	return saved, nil
}
func verifyFrontendFiles(dir string, files map[string]File) error {
	actual, err := inventory(dir, true)
	if err != nil {
		return err
	}
	if len(actual) != len(files) {
		return errors.New("前端发布文件集合变化")
	}
	for name, f := range files {
		if actual[name] != f {
			return errors.New("前端发布内容变化")
		}
	}
	return nil
}

func writeFrontendSelection(data string, s *FrontendSelection) error {
	root, err := Root(data)
	if err != nil {
		return err
	}
	name := filepath.Join(root, "frontend.json")
	if s == nil {
		if err = os.Remove(name); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncDir(root)
	}
	raw, _ := json.Marshal(s)
	f, err := os.CreateTemp(root, ".frontend-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Chmod(0444); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), name); err != nil {
		return err
	}
	return syncDir(root)
}

// ActivateFrontend persists the before/after pointer before selecting the UI.
// A failed verification restores the original pointer; unreadable results remain
// recoverable through the original activation record instead of being replayed.
func ActivateFrontend(ctx context.Context, data, operation, baseID, expected string, release FrontendRelease) (FrontendStatus, error) {
	var out FrontendStatus
	if os.Geteuid() != 0 || !selectionID.MatchString(operation) || !digest.MatchString(baseID) || !digest.MatchString(expected) {
		return out, errors.New("前端激活身份无效")
	}
	root, err := Root(data)
	if err != nil {
		return out, err
	}
	unlock, err := publicationLock(root)
	if err != nil {
		return out, err
	}
	defer unlock()
	base, err := Read(data)
	if err != nil {
		return out, err
	}
	if base.Release.ID != baseID {
		return out, errors.New("当前后端已变化，请重新检查前端目标")
	}
	current, _, err := Frontends(data, baseID)
	if err != nil {
		return out, err
	}
	if current.Source.ID != expected {
		return out, errors.New("当前前端已变化，请刷新后重新确认")
	}
	if current.Source.ID == release.ID {
		return out, errors.New("此独立前端已经激活")
	}
	selected, err := frontendSource(data, FrontendSource{"web", release.ID})
	if err != nil {
		return out, err
	}
	if err = verifyFrontendFiles(selected.Directory, selected.Files); err != nil {
		return out, err
	}
	if _, err = FrontendEntrypoints(selected); err != nil {
		return out, err
	}
	before, err := frontendSelection(data)
	if err != nil {
		return out, err
	}
	after := FrontendSelection{Schema: Schema, OperationID: operation, BaseID: baseID, Current: selected.Source, Previous: current.Source}
	intent := FrontendActivation{Schema: Schema, OperationID: operation, Before: before, After: after}
	if err = frontendPublicDir(filepath.Join(root, "frontend-operations")); err != nil {
		return out, err
	}
	entries, err := os.ReadDir(filepath.Join(root, "frontend-operations"))
	if err != nil {
		return out, err
	}
	if len(entries) >= 64 {
		return out, errors.New("前端激活记录达到保留上限")
	}
	raw, _ := json.Marshal(intent)
	if err = publishFile(filepath.Join(root, "frontend-operations", operation+".json"), raw); err != nil {
		return out, err
	}
	if err = syncDir(root); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = writeFrontendSelection(data, &after); err == nil {
		out, err = frontendActivationStatus(data, operation, false)
	}
	if err == nil {
		return out, nil
	}
	if restoreErr := writeFrontendSelection(data, before); restoreErr != nil {
		return out, errors.Join(err, errors.New("原前端指针恢复未确认"), restoreErr)
	}
	return out, err
}
func ReconcileFrontendActivation(data, operation string) (FrontendStatus, error) {
	root, err := Root(data)
	if err != nil {
		return FrontendStatus{}, err
	}
	unlock, err := publicationLock(root)
	if err != nil {
		return FrontendStatus{}, err
	}
	defer unlock()
	return frontendActivationStatus(data, operation, true)
}
func frontendActivationStatus(data, operation string, restore bool) (FrontendStatus, error) {
	var out FrontendStatus
	root, err := Root(data)
	if err != nil || !selectionID.MatchString(operation) {
		return out, errors.New("前端激活记录身份无效")
	}
	var intent FrontendActivation
	if err = frontendJSON(filepath.Join(root, "frontend-operations", operation+".json"), &intent, 16<<10); err != nil {
		if os.IsNotExist(err) {
			selected, e := frontendSelection(data)
			if e != nil {
				return out, e
			}
			if selected != nil && selected.OperationID == operation {
				return out, errors.New("已选择前端缺少原激活意图，须本机恢复")
			}
			return out, ErrFrontendNoActivation
		}
		return out, err
	}
	if intent.Schema != Schema || intent.OperationID != operation || !intent.After.valid() || intent.After.OperationID != operation || intent.Before != nil && !intent.Before.valid() {
		return out, errors.New("前端激活原意图无效")
	}
	current, err := frontendSelection(data)
	if err != nil {
		return out, err
	}
	actual, _ := json.Marshal(current)
	wanted, _ := json.Marshal(intent.After)
	if !bytes.Equal(actual, wanted) {
		before, _ := json.Marshal(intent.Before)
		if bytes.Equal(actual, before) {
			if err = verifyFrontendSource(data, intent.After.Previous); err != nil {
				return out, err
			}
			if err = syncDir(root); err != nil {
				return out, err
			}
			return out, ErrFrontendUnselected
		}
		return out, errors.New("原前端激活已偏离前后选择，须本机恢复")
	}
	currentSource, err := frontendSource(data, intent.After.Current)
	if err == nil {
		err = verifyFrontendFiles(currentSource.Directory, currentSource.Files)
	}
	if err != nil {
		if !restore {
			return out, err
		}
		base, baseErr := Read(data)
		if baseErr != nil || base.Release.ID != intent.After.BaseID {
			return out, errors.Join(err, errors.New("原激活后端身份已变化，保留恢复材料"), baseErr)
		}
		if beforeErr := verifyFrontendSource(data, intent.After.Previous); beforeErr != nil {
			return out, errors.Join(err, beforeErr)
		}
		if restoreErr := writeFrontendSelection(data, intent.Before); restoreErr != nil {
			return out, errors.Join(err, restoreErr)
		}
		return out, errors.Join(ErrFrontendUnselected, err)
	}
	if err = syncDir(root); err != nil {
		return out, err
	}
	return FrontendStatus{Available: true, BaseID: intent.After.BaseID, CurrentID: currentSource.Source.ID, Version: currentSource.Version, PreviousID: intent.After.Previous.ID}, nil
}
func verifyFrontendSource(data string, source FrontendSource) error {
	s, err := frontendSource(data, source)
	if err != nil {
		return err
	}
	if err = verifyFrontendFiles(s.Directory, s.Files); err != nil {
		return err
	}
	_, err = FrontendEntrypoints(s)
	return err
}
