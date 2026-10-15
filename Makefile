.PHONY: dev generate build verify

dev:
	go run ./cmd/nginxpanel dev

generate:
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config api/oapi-codegen.yaml api/openapi.yaml
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate
	pnpm --dir web generate:api
	pnpm --dir web generate:routes

build:
	pnpm --dir web build
	go build -trimpath -o bin/nginxpanel ./cmd/nginxpanel

# 仅在本次实现及集成稳定后集中执行。
verify:
	go test ./...
	pnpm --dir web typecheck
	pnpm --dir web lint
