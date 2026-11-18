package app

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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
	compressed   map[string]frontendEncoding
	development  http.Handler
	dev          bool
	identity     string
	entryScripts []string
}

type frontendEncoding struct {
	data []byte
	etag string
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
	compressed, err := compressFrontend(files)
	if err != nil {
		return nil, err
	}
	return &frontendHandler{files: files, compressed: compressed, identity: identity, entryScripts: entryScripts}, nil
}

func frontendETag(data []byte) string {
	hash := sha256.Sum256(data)
	return `"` + hex.EncodeToString(hash[:]) + `"`
}

func compressFrontend(files fs.FS) (map[string]frontendEncoding, error) {
	out := make(map[string]frontendEncoding)
	writer := gzip.NewWriter(io.Discard)
	err := fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		switch path.Ext(name) {
		case ".html", ".js", ".mjs", ".css", ".svg", ".json", ".txt":
		default:
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 512 || info.Size() > frontendFileLimit {
			return nil
		}
		data, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		var buffer bytes.Buffer
		writer.Reset(&buffer)
		if _, err = writer.Write(data); err != nil {
			return err
		}
		if err = writer.Close(); err != nil {
			return err
		}
		if buffer.Len() < len(data) {
			out[name] = frontendEncoding{data: buffer.Bytes(), etag: frontendETag(buffer.Bytes())}
		}
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
	if hashedFrontendAsset.MatchString(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if compressed, ok := h.compressed[name]; ok {
		w.Header().Add("Vary", "Accept-Encoding")
		if r.Header.Get("Range") == "" && acceptsGzip(r.Header.Values("Accept-Encoding")) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(len(compressed.data)))
			w.Header().Set("ETag", compressed.etag)
			http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(compressed.data))
			return
		}
	}
	w.Header().Set("ETag", frontendETag(data))
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

var _ http.Handler = (*frontendHandler)(nil)
