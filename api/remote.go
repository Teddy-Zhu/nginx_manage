package api

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed remote.openapi.json
var remoteContract []byte

type RemoteRoute struct {
	Pattern, Path, Method, Operation, Kind string
	Scopes, Query                          []string
	BodyLimit                              int64
}

// The executable allowlist is the explicit OpenAPI paths, not a wildcard proxy.
var RemoteRoutes = sync.OnceValue(func() []RemoteRoute {
	var contract struct {
		Paths map[string]map[string]struct {
			Operation string   `json:"x-local-operation"`
			Path      string   `json:"x-forward-path"`
			Kind      string   `json:"x-response-kind"`
			Scopes    []string `json:"x-scopes"`
			Query     []string `json:"x-query-keys"`
			BodyLimit int64    `json:"x-body-limit"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(remoteContract, &contract); err != nil {
		panic(err)
	}
	result := []RemoteRoute{}
	for pattern, methods := range contract.Paths {
		for method, op := range methods {
			if pattern != "/nodes/connections/{connection}"+op.Path || op.Operation == "" || op.BodyLimit <= 0 || op.BodyLimit > 20<<20 || (op.Kind != "json" && op.Kind != "sse" && op.Kind != "ndjson" && op.Kind != "text") {
				panic(fmt.Errorf("invalid remote contract: %s %s", method, pattern))
			}
			result = append(result, RemoteRoute{Pattern: pattern, Path: op.Path, Method: strings.ToUpper(method), Operation: op.Operation, Kind: op.Kind, Scopes: op.Scopes, Query: op.Query, BodyLimit: op.BodyLimit})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Pattern+result[i].Method < result[j].Pattern+result[j].Method })
	return result
})
