// Package webui serves the frontend that is compiled into the core program.
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

//go:embed dist
var files embed.FS

func FS() (fs.FS, error) {
	root, err := fs.Sub(files, "dist")
	if err != nil {
		return nil, err
	}
	if _, err = fs.Stat(root, "index.html"); err != nil {
		return nil, errors.New("core binary does not include the frontend")
	}
	return root, nil
}

func Identity() (string, error) {
	root, err := FS()
	if err != nil {
		return "", err
	}
	entries := []string{}
	err = fs.WalkDir(root, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "gzip" && entry.IsDir() {
			return fs.SkipDir
		}
		if !entry.IsDir() {
			entries = append(entries, name)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(entries)
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	for _, name := range entries {
		file, err := root.Open(name)
		if err != nil {
			return "", err
		}
		hash.Write([]byte(name))
		hash.Write([]byte{0})
		_, err = io.CopyBuffer(hash, file, buffer)
		file.Close()
		if err != nil {
			return "", err
		}
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func EntryScripts() ([]string, error) {
	root, err := FS()
	if err != nil {
		return nil, err
	}
	raw, err := fs.ReadFile(root, "index.html")
	if err != nil {
		return nil, err
	}
	tokenizer := html.NewTokenizer(strings.NewReader(string(raw)))
	entries := map[string]bool{}
	modules := 0
	for {
		typeOf := tokenizer.Next()
		if typeOf == html.ErrorToken {
			if tokenizer.Err() != io.EOF {
				return nil, tokenizer.Err()
			}
			break
		}
		if typeOf != html.StartTagToken && typeOf != html.SelfClosingTagToken {
			continue
		}
		tag := tokenizer.Token()
		if tag.Data == "base" {
			return nil, errors.New("embedded frontend cannot redefine its base path")
		}
		attrs := map[string]string{}
		for _, attr := range tag.Attr {
			if _, exists := attrs[attr.Key]; exists {
				return nil, errors.New("embedded frontend contains duplicate resource attributes")
			}
			attrs[attr.Key] = attr.Val
		}
		module := tag.Data == "script" && attrs["type"] == "module"
		var source string
		if tag.Data == "script" {
			source = attrs["src"]
		} else if tag.Data == "link" && (slices.Contains(strings.Fields(attrs["rel"]), "stylesheet") || slices.Contains(strings.Fields(attrs["rel"]), "modulepreload") || slices.Contains(strings.Fields(attrs["rel"]), "icon")) {
			source = attrs["href"]
		}
		if source == "" {
			if module {
				return nil, errors.New("embedded frontend has no module entry")
			}
			continue
		}
		parsed, parseErr := url.Parse(source)
		name := strings.TrimPrefix(source, "/")
		if parseErr != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(source, "/") || strings.HasPrefix(source, "//") || path.Clean(source) != source {
			return nil, errors.New("embedded frontend resources must use local absolute paths")
		}
		if _, statErr := fs.Stat(root, name); statErr != nil {
			return nil, errors.New("embedded frontend references a missing file")
		}
		if module {
			modules++
		}
		if module || tag.Data == "link" {
			entries[source] = true
		}
	}
	if modules == 0 || modules > 16 || len(entries) > 64 {
		return nil, errors.New("embedded frontend entry count is invalid")
	}
	out := make([]string, 0, len(entries))
	for name := range entries {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}
