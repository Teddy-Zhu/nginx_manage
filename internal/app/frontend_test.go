package app

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestFrontendGzipRepresentations(t *testing.T) {
	const asset = "assets/index-AbCdEf12.js"
	plain := bytes.Repeat([]byte("console.log('panel');\n"), 100)
	files := fstest.MapFS{asset: {Data: plain}}
	compressed, err := compressFrontend(files)
	if err != nil {
		t.Fatal(err)
	}
	h := &frontendHandler{files: files, compressed: compressed}
	request := func(method, encoding, etag, byteRange string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/"+asset, nil)
		r.Header.Set("Accept-Encoding", encoding)
		r.Header.Set("If-None-Match", etag)
		r.Header.Set("Range", byteRange)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	zipped := request(http.MethodGet, "br, gzip", "", "")
	if zipped.Code != 200 || zipped.Header().Get("Content-Encoding") != "gzip" || zipped.Header().Get("Vary") != "Accept-Encoding" ||
		zipped.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || zipped.Body.Len() >= len(plain) {
		t.Fatalf("unexpected compressed response: %d %v", zipped.Code, zipped.Header())
	}
	reader, err := gzip.NewReader(zipped.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if got, err := io.ReadAll(reader); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("unexpected gzip content: %v", err)
	}
	for _, encoding := range []string{"identity", "*;q=1, gzip;q=0", "identity;q=1, gzip;q=0.5"} {
		raw := request(http.MethodGet, encoding, zipped.Header().Get("ETag"), "")
		if raw.Code != 200 || raw.Header().Get("Content-Encoding") != "" || raw.Header().Get("Vary") != "Accept-Encoding" ||
			raw.Header().Get("ETag") == zipped.Header().Get("ETag") || !bytes.Equal(raw.Body.Bytes(), plain) {
			t.Fatalf("unexpected identity response for %q: %d %v", encoding, raw.Code, raw.Header())
		}
	}
	if cached := request(http.MethodGet, "gzip", zipped.Header().Get("ETag"), ""); cached.Code != 304 {
		t.Fatalf("gzip revalidation returned %d", cached.Code)
	}
	if head := request(http.MethodHead, "gzip", "", ""); head.Header().Get("Content-Encoding") != "gzip" || head.Body.Len() != 0 {
		t.Fatalf("unexpected HEAD response: %d %v", head.Code, head.Header())
	}
	if partial := request(http.MethodGet, "gzip", "", "bytes=0-7"); partial.Code != 206 || !bytes.Equal(partial.Body.Bytes(), plain[:8]) {
		t.Fatalf("unexpected range response: %d %v", partial.Code, partial.Header())
	}
}
