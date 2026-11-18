package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/webui"
)

const frontendFileLimit = 8 << 20

var hashedFrontendAsset = regexp.MustCompile(`^assets/[a-zA-Z0-9_./-]+[-.][a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9]+$`)

type frontendHandler struct {
	files        fs.FS
	assets       map[string]frontendAsset
	development  http.Handler
	dev          bool
	identity     string
	entryScripts []string
}

type frontendAsset struct {
	etag     string
	gzipETag string
	gzipSize int64
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
	assets, err := indexFrontend(files)
	if err != nil {
		return nil, err
	}
	return &frontendHandler{files: files, assets: assets, identity: identity, entryScripts: entryScripts}, nil
}

func indexFrontend(files fs.FS) (map[string]frontendAsset, error) {
	out := make(map[string]frontendAsset)
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	etag := func(name string) (string, error) {
		file, err := files.Open(name)
		if err != nil {
			return "", err
		}
		defer file.Close()
		hash.Reset()
		if _, err := io.CopyBuffer(hash, file, buffer); err != nil {
			return "", err
		}
		return `"` + hex.EncodeToString(hash.Sum(nil)) + `"`, nil
	}
	err := fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err == nil && name == "gzip" && entry.IsDir() {
			return fs.SkipDir
		}
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > frontendFileLimit {
			return nil
		}
		tag, err := etag(name)
		if err != nil {
			return err
		}
		asset := frontendAsset{etag: tag}
		zipped := path.Join("gzip", name)
		compressed, err := fs.Stat(files, zipped)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err == nil && compressed.Mode().IsRegular() && compressed.Size() < info.Size() {
			if asset.gzipETag, err = etag(zipped); err != nil {
				return err
			}
			asset.gzipSize = compressed.Size()
		}
		out[name] = asset
		return nil
	})
	return out, err
}

func acceptsGzip(values []string) bool {
	var gzipSeen bool
	var gzipQuality, wildcardQuality, identityQuality float64
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			name, param, _ := strings.Cut(item, ";")
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "gzip" && name != "*" && name != "identity" {
				continue
			}
			weight := 1.0
			if param != "" {
				key, quality, ok := strings.Cut(strings.TrimSpace(param), "=")
				q, err := strconv.ParseFloat(strings.TrimSpace(quality), 64)
				weight = 0
				if ok && strings.EqualFold(strings.TrimSpace(key), "q") && err == nil && q > 0 && q <= 1 {
					weight = q
				}
			}
			switch name {
			case "gzip":
				gzipSeen, gzipQuality = true, max(gzipQuality, weight)
			case "*":
				wildcardQuality = max(wildcardQuality, weight)
			case "identity":
				identityQuality = max(identityQuality, weight)
			}
		}
	}
	if !gzipSeen {
		gzipQuality = wildcardQuality
	}
	return gzipQuality > 0 && gzipQuality >= identityQuality
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
	asset, ok := h.assets[name]
	if !ok {
		acceptsHTML := strings.Contains(r.Header.Get("Accept"), "text/html")
		if filepath.Ext(name) != "" && !acceptsHTML || name == "assets" || strings.HasPrefix(name, "assets/") || name == "gzip" || strings.HasPrefix(name, "gzip/") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
		asset = h.assets[name]
	}
	filename := name
	tag := asset.etag
	gzipped := false
	if asset.gzipETag != "" {
		w.Header().Add("Vary", "Accept-Encoding")
		gzipped = r.Header.Get("Range") == "" && acceptsGzip(r.Header.Values("Accept-Encoding"))
		if gzipped {
			filename, tag = path.Join("gzip", name), asset.gzipETag
		}
	}
	if tag == "" {
		http.Error(w, "前端资源不可用", http.StatusServiceUnavailable)
		return
	}
	file, err := h.files.Open(filename)
	if err != nil {
		http.Error(w, "前端资源不可用", http.StatusServiceUnavailable)
		return
	}
	defer file.Close()
	content, ok := file.(io.ReadSeeker)
	if !ok {
		http.Error(w, "前端资源不可用", http.StatusServiceUnavailable)
		return
	}
	if hashedFrontendAsset.MatchString(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if gzipped {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.FormatInt(asset.gzipSize, 10))
	}
	w.Header().Set("ETag", tag)
	http.ServeContent(w, r, name, time.Time{}, content)
}

var _ http.Handler = (*frontendHandler)(nil)
