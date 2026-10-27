package api

import (
	_ "embed"
	"encoding/json"
	"net/url"
	"path"
	"strings"
	"sync"
)

//go:embed realtime-resources.json
var realtimeContract []byte

var realtimeRoutes = sync.OnceValue(func() []struct {
	Topic string
	Paths []string
} { var routes []struct {
	Topic string
	Paths []string
}; if err := json.Unmarshal(realtimeContract, &routes); err != nil {
	panic(err)
}; return routes })

// RealtimeTopic only admits named read resources, never arbitrary HTTP routes.
func RealtimeTopic(resource string) (string, bool) {
	u, err := url.ParseRequestURI(resource)
	if err != nil || len(resource) > 8192 || u.Host != "" || u.Fragment != "" || path.Clean(u.Path) != u.Path || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "", false
	}
	parts := strings.Split(u.Path, "/")
	for _, route := range realtimeRoutes() {
		for _, pattern := range route.Paths {
			if pattern == u.Path {
				return route.Topic, true
			}
		}
	}
	for _, route := range realtimeRoutes() {
		for _, pattern := range route.Paths {
			expected := strings.Split(pattern, "/")
			if len(parts) != len(expected) {
				continue
			}
			match := true
			for i, part := range expected {
				if strings.HasPrefix(part, "{") {
					if parts[i] == "" {
						match = false
						break
					}
				} else if part != parts[i] {
					match = false
					break
				}
			}
			if match {
				return route.Topic, true
			}
		}
	}
	return "", false
}

// A remote realtime stream has the same read boundary as the HTTP node API.
func RealtimeRemoteAllowed(resource string) bool {
	u, err := url.ParseRequestURI(resource)
	if err != nil {
		return false
	}
	requested := u.Path
	if requested == "/logs/live" {
		requested = "/logs/stream"
	}
	for _, route := range RemoteRoutes() {
		if route.Method != "GET" {
			continue
		}
		actual, expected := strings.Split(requested, "/"), strings.Split(route.Path, "/")
		if len(actual) != len(expected) {
			continue
		}
		match := true
		for i, part := range expected {
			if strings.HasPrefix(part, "{") {
				if actual[i] == "" {
					match = false
					break
				}
			} else if actual[i] != part {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
