# syntax=docker/dockerfile:1
ARG GO_VERSION=1.27.2
ARG NODE_VERSION=24
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS frontend
ARG PNPM_VERSION=10.33.0
WORKDIR /src
RUN npm install --prefix /opt/build-tools pnpm@${PNPM_VERSION}
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./web/
RUN --mount=type=cache,target=/pnpm-store \
    /opt/build-tools/node_modules/.bin/pnpm --dir web install --frozen-lockfile --store-dir /pnpm-store
COPY web ./web
COPY api/openapi.yaml api/realtime-resources.json ./api/
RUN /opt/build-tools/node_modules/.bin/pnpm --dir web generate:routes && \
    /opt/build-tools/node_modules/.bin/pnpm --dir web build

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS go-source
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
COPY deploy/docker/templates.go deploy/docker/panel.compose.yaml ./deploy/docker/

FROM go-source AS panel-build
ARG TARGETARCH
ARG BUILD_VERSION=0.1.0-dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags "-X main.version=$BUILD_VERSION" -o /out/nginxpanel ./cmd/nginxpanel

FROM go-source AS release-tool-build
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -o /out/nginxpanel-release ./cmd/nginxpanel-release

FROM scratch AS release-tool
COPY --from=release-tool-build --chmod=0555 /out/nginxpanel-release /nginxpanel-release

FROM scratch AS bundle
COPY --from=panel-build --chmod=0555 /out/nginxpanel /nginxpanel
COPY --from=frontend /src/web/dist/ /web/
COPY --chmod=0555 install.sh manage.sh /
COPY --chmod=0555 deploy/native/install.sh /deploy/native/install.sh
COPY --chmod=0555 deploy/native/lifecycle.sh /deploy/native/lifecycle.sh
COPY deploy/native/README.md /deploy/native/README.md
COPY deploy/docker/README.md /deploy/docker/README.md
COPY docs /docs
COPY api/openapi.yaml /api/openapi.yaml
COPY README.md LICENSE Linux_Nginx_Manager_Design.md /
