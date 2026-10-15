package agent

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

type InspectRequest struct {
	Protocol   int                `json:"protocol"`
	RevisionID string             `json:"revision_id"`
	Files      []nginxconfig.File `json:"files"`
	Path       string             `json:"path"`
}
type ExternalFile struct {
	Path           string `json:"path"`
	Status         string `json:"status"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ObservedSHA256 string `json:"observed_sha256"`
	Reason         string `json:"reason"`
}
type ExternalDetail struct {
	Path           string `json:"path"`
	BeforeContent  string `json:"before_content"`
	AfterContent   string `json:"after_content"`
	DraftContent   string `json:"draft_content"`
	CaptureAllowed bool   `json:"capture_allowed"`
	Note           string `json:"note"`
}
type ExternalSnapshot struct {
	RevisionID   string          `json:"revision_id"`
	Snapshot     string          `json:"snapshot"`
	Integrity    bool            `json:"integrity"`
	Complete     bool            `json:"complete"`
	Files        []ExternalFile  `json:"files"`
	Dependencies []ExternalFile  `json:"dependencies"`
	Detail       *ExternalDetail `json:"detail"`
}

func inspectPath(name string) bool {
	return name != "" && !path.IsAbs(name) && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00\r\n")
}

func inspectFileInfo(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Uid == 0 && stat.Nlink == 1 && info.Mode().Perm()&0022 == 0 && info.Size() <= 512<<10
}

// Only regular, singly linked files beneath trusted directories are readable.
// The returned content is never used as executable input by this endpoint.
func inspectText(root, name string) (string, string, string) {
	if !inspectPath(name) {
		return "", "unsafe", "路径不属于受管目录"
	}
	full := filepath.Join(root, filepath.FromSlash(name))
	info, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return "", "missing", "文件已缺失"
	}
	if err != nil {
		return "", "unreadable", "无法读取文件状态"
	}
	if !inspectFileInfo(info) || existingRootDirectory(filepath.Dir(full)) != nil {
		return "", "unsafe", "文件类型、权限、链接或大小不符合受管约束"
	}
	fd, err := unix.Open(full, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", "unreadable", "无法安全打开文件"
	}
	f := os.NewFile(uintptr(fd), full)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !inspectFileInfo(opened) {
		return "", "unreadable", "读取时文件已变化"
	}
	data, err := io.ReadAll(io.LimitReader(f, (512<<10)+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || !inspectFileInfo(after) || len(data) > 512<<10 || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || !utf8.Valid(data) {
		return "", "unreadable", "内容过大、不是 UTF-8 或读取时已变化"
	}
	return string(data), "readable", ""
}

// Reverse only substitutions proven by the renderer and exact byte counts.
// Ambiguous generated changes remain visible in a non-executable raw draft.
func reverseRuntime(expected, observed, source string, edits []renderReplacement) (string, string) {
	replacements := map[string]string{}
	for _, edit := range edits {
		if edit.From == edit.To {
			continue
		}
		if edit.From == "" {
			return observed, "运行副本含无法反向定位的移除区间，草稿保留磁盘原文；请对照差异整理生成指令"
		}
		if previous, exists := replacements[edit.From]; exists && previous != edit.To {
			return observed, "生成区间存在歧义，草稿保留磁盘原文"
		}
		replacements[edit.From] = edit.To
	}
	keys := []string{}
	for from := range replacements {
		if strings.Count(expected, from) != strings.Count(observed, from) {
			return observed, "生成控制或 include 已被修改，草稿保留磁盘原文；保存为有效修订前须解决安全诊断"
		}
		keys = append(keys, from)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) == len(keys[j]) {
			return keys[i] < keys[j]
		}
		return len(keys[i]) > len(keys[j])
	})
	pairs := []string{}
	for _, key := range keys {
		pairs = append(pairs, key, replacements[key])
	}
	replacer := strings.NewReplacer(pairs...)
	if replacer.Replace(expected) != source {
		return observed, "生成区间不能可靠还原，草稿保留磁盘原文"
	}
	return replacer.Replace(observed), "已移除可精确识别的生成控制并还原受管 include；导入仅保存草稿"
}

func (n *Nginx) Inspect(in InspectRequest) (ExternalSnapshot, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := ExternalSnapshot{RevisionID: in.RevisionID, Files: []ExternalFile{}, Dependencies: []ExternalFile{}, Complete: true, Integrity: true}
	if n.closed || n.unlock == nil {
		return out, ErrRuntimeUnavailable
	}
	if in.Protocol != Protocol || in.RevisionID != "" && !validID(in.RevisionID) || in.Path != "" && !inspectPath(in.Path) {
		return out, errors.New("invalid inspection request")
	}
	records, err := n.Journal.List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if strings.HasPrefix(record.Kind, "nginx.") && (record.State == "running" || record.State == "compensating") {
			return out, ErrBusy
		}
	}
	dir := revisionDir(in.RevisionID)
	target, err := os.Readlink(n.activePath())
	if err != nil || target != filepath.Join("revisions", dir) {
		return out, ErrExternalChange
	}
	m, err := n.manifestMetadata(dir)
	if err != nil {
		return out, err
	}
	p, err := nginxconfig.Parse(in.Files, n.Policy)
	if err != nil || len(p.Tree.Diagnostics) > 0 || n.sourceHash(p) != m.SourceHash {
		return out, errors.New("source revision does not match recorded publication")
	}
	trace := map[string][]renderReplacement{}
	expected, err := n.render(p, &m, trace)
	if err != nil {
		return out, err
	}
	if len(expected) != len(m.Files) {
		return out, ErrExternalChange
	}
	for name, text := range expected {
		if !inspectPath(name) || secure.Hash([]byte(text)) != m.Files[name] {
			return out, ErrExternalChange
		}
	}
	root := filepath.Dir(n.configPath(dir))
	names := map[string]bool{}
	for name := range expected {
		names[name] = true
	}
	entries := 0
	err = filepath.WalkDir(root, func(full string, entry fs.DirEntry, walkErr error) error {
		entries++
		if entries > limits.Files*4 {
			return errors.New("inspection entry budget exceeded")
		}
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.IsDir() {
			if strings.Count(rel, string(filepath.Separator)) >= limits.Depth || existingRootDirectory(full) != nil {
				return errors.New("untrusted inspection directory")
			}
			return nil
		}
		if rel != ".nginxpanel.json" {
			names[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		out.Complete = false
		out.Integrity = false
	}
	ordered := []string{}
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	budget := 0
	for _, name := range ordered {
		text, state, reason := inspectText(root, name)
		budget += len(text)
		if budget > limits.TreeBytes*4 {
			return out, errors.New("inspection content budget exceeded")
		}
		file := ExternalFile{Path: name, ExpectedSHA256: m.Files[name], Reason: reason, Status: state}
		if state == "readable" {
			file.ObservedSHA256 = secure.Hash([]byte(text))
			switch {
			case file.ExpectedSHA256 == "":
				file.Status = "added"
			case file.ExpectedSHA256 == file.ObservedSHA256:
				file.Status = "unchanged"
			default:
				file.Status = "modified"
			}
		}
		if file.Status != "unchanged" {
			out.Integrity = false
		}
		out.Files = append(out.Files, file)
		if name == in.Path {
			detail := &ExternalDetail{Path: name, BeforeContent: expected[name], AfterContent: text, CaptureAllowed: out.Complete && (state == "readable" || state == "missing") && file.Status != "unchanged"}
			detail.DraftContent = text
			if original, exists := expected[name]; exists && state == "readable" {
				for _, source := range p.Tree.Files {
					if source.Path == name {
						detail.DraftContent, detail.Note = reverseRuntime(original, text, source.Content, trace[name])
						break
					}
				}
			} else {
				detail.Note = "仅保存外部文件内容为草稿；有效修订仍须通过解析与安全校验"
			}
			if len(detail.DraftContent) > limits.FileBytes {
				detail.CaptureAllowed = false
				detail.Note = "外部内容超过原文单文件预算，请在本机整理后导入"
			}
			if name == "nginx.conf" && state == "missing" {
				detail.CaptureAllowed = false
				detail.Note = "主配置缺失，无法形成完整原文树；请在本机恢复主配置"
			}
			out.Detail = detail
		}
	}
	deps := []string{}
	for name := range m.Dependencies {
		deps = append(deps, name)
	}
	sort.Strings(deps)
	for _, name := range deps {
		file := ExternalFile{Path: name, ExpectedSHA256: m.Dependencies[name], Status: "unsafe", Reason: "证书材料不可读取或已改变；请在证书管理中导入新版本"}
		if data, err := n.certificateFile(name); err == nil {
			file.ObservedSHA256 = secure.Hash(data)
			file.Status = "modified"
			if file.ObservedSHA256 == file.ExpectedSHA256 {
				file.Status = "unchanged"
				file.Reason = ""
			}
		}
		if file.Status != "unchanged" {
			out.Integrity = false
		}
		out.Dependencies = append(out.Dependencies, file)
	}
	encoded, _ := json.Marshal(struct {
		Target, Manifest    string
		Files, Dependencies []ExternalFile
		Complete            bool
	}{target, manifestHash(m), out.Files, out.Dependencies, out.Complete})
	out.Snapshot = secure.Hash(encoded)
	if active, err := os.Readlink(n.activePath()); err != nil || active != target {
		return out, ErrExternalChange
	}
	if in.Path != "" && out.Detail == nil {
		return out, errors.New("inspection file not found")
	}
	encoded, err = json.Marshal(out)
	if err != nil || len(encoded) > limits.RequestBytes {
		return out, errors.New("inspection response exceeds size limit")
	}
	return out, nil
}
