package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"nginxpanel/internal/webui"
)

const frontendFileLimit = 8 << 20

var hashedFrontendAsset = regexp.MustCompile(`^assets/[a-zA-Z0-9_./-]+[-.][a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9]+$`)

type frontendHandler struct {
	files        fs.FS
	development  http.Handler
	dev          bool
	identity     string
	entryScripts []string
}

func newFrontendHandler(development http.Handler, dev bool) (*frontendHandler, error) {
	if dev {
		return &frontendHandler{development: development, dev: true}, nil
	}
	files, err := webui.FS()
	if err != nil {
		return nil, err
	}
	identity, err := webui.Identity()
	if err != nil {
		return nil, err
	}
	entryScripts, err := webui.EntryScripts()
	if err != nil {
		return nil, err
	}
	return &frontendHandler{files: files, identity: identity, entryScripts: entryScripts}, nil
}

func (h *frontendHandler) version() (string, []string, error) {
	if h.dev {
		return "", []string{}, nil
	}
	return h.identity, append([]string(nil), h.entryScripts...), nil
}

func (h *frontendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.dev {
		h.development.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	data, err := fs.ReadFile(h.files, name)
	if err != nil {
		acceptsHTML := strings.Contains(r.Header.Get("Accept"), "text/html")
		if filepath.Ext(name) != "" && !acceptsHTML || name == "assets" || strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
		data, err = fs.ReadFile(h.files, name)
	}
	if err != nil || len(data) > frontendFileLimit {
		http.Error(w, "前端资源不可用", http.StatusServiceUnavailable)
		return
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	w.Header().Set("ETag", `"`+digest+`"`)
	if hashedFrontendAsset.MatchString(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

var _ http.Handler = (*frontendHandler)(nil)
