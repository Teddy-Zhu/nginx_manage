package app

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

var hashedFrontendAsset = regexp.MustCompile(`^assets/[a-zA-Z0-9_./-]+[-.][a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9]+$`)

type frontendHandler struct {
	data, baseID string
	development  http.Handler
	dev          bool
	mu           sync.Mutex
	loaded       bool
	selection    os.FileInfo
	current      panelruntime.FrontendSnapshot
	previous     *panelruntime.FrontendSnapshot
	scripts      []string
}

func (h *frontendHandler) sources() (panelruntime.FrontendSnapshot, *panelruntime.FrontendSnapshot, []string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	root, err := panelruntime.Root(h.data)
	if err != nil {
		return h.current, nil, nil, err
	}
	info, err := os.Lstat(filepath.Join(root, "frontend.json"))
	if err != nil && !os.IsNotExist(err) {
		return h.current, nil, nil, err
	}
	if h.loaded && (info == nil && h.selection == nil || info != nil && h.selection != nil && os.SameFile(info, h.selection) && info.Size() == h.selection.Size() && info.ModTime().Equal(h.selection.ModTime())) {
		return h.current, h.previous, h.scripts, nil
	}
	current, previous, err := panelruntime.Frontends(h.data, h.baseID)
	if err != nil {
		return current, nil, nil, err
	}
	scripts, err := panelruntime.FrontendEntrypoints(current)
	if err != nil {
		return current, nil, nil, err
	}
	// A rename racing this read is observed on the next request. No cache entry
	// can suppress a later selection because it retains this pre-read inode.
	h.current, h.previous, h.scripts, h.selection, h.loaded = current, previous, scripts, info, true
	return current, previous, scripts, nil
}
func (h *frontendHandler) version() (string, []string, error) {
	if h.dev {
		return "", []string{}, nil
	}
	current, _, scripts, err := h.sources()
	return current.Source.ID, scripts, err
}
func (h *frontendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.dev {
		h.development.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if name == "" {
		name = "index.html"
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		http.NotFound(w, r)
		return
	}
	current, previous, _, err := h.sources()
	if err != nil {
		http.Error(w, "前端发布状态未确认", http.StatusServiceUnavailable)
		return
	}
	source := current
	file, exists := current.Files[name]
	if !exists && hashedFrontendAsset.MatchString(name) && previous != nil {
		if old, found := previous.Files[name]; found {
			source, file, exists = *previous, old, true
		}
	}
	if !exists {
		if filepath.Ext(name) != "" || name == "assets" || strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
		file = current.Files[name]
	}
	f, before, err := secure.OpenRootFile(filepath.Join(source.Directory, name), panelruntime.WebFileLimit)
	if err != nil {
		http.Error(w, "前端资源读取失败", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, panelruntime.WebFileLimit+1))
	if err != nil || n != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 || !secure.RootFileUnchanged(f, before) {
		http.Error(w, "前端资源与批准清单不一致", http.StatusServiceUnavailable)
		return
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "前端资源读取失败", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("ETag", `"`+file.SHA256+`"`)
	if hashedFrontendAsset.MatchString(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	http.ServeContent(w, r, name, before.ModTime(), f)
}

var _ http.Handler = (*frontendHandler)(nil)
