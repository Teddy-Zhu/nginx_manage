# syntax=docker/dockerfile:1
# Copy only CA roots from the same fixed upstream runtime used by Nginx.
FROM nginx:1.30.6-alpine-slim@sha256:3028fc1419f99b95c1c69f844bbaf49dc1b881750c51b497fc721ac4f02a14e6 AS trust
FROM scratch
ARG TARGETARCH
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Build context: .release/binaries containing the matching CGO_ENABLED=0 outputs.
COPY --chown=0:0 --chmod=0555 nginxpanel-${TARGETARCH} /usr/local/bin/nginxpanel-launcher
COPY --chown=0:0 licenses-${TARGETARCH}/ /usr/share/licenses/nginxpanel/
WORKDIR /srv/nginxpanel
USER 10001:10001
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/usr/local/bin/nginxpanel-launcher", "launcher"]
CMD ["--data-dir", "/srv/nginxpanel"]
STOPSIGNAL SIGTERM
LABEL org.opencontainers.image.title="NginxPanel fixed launcher runtime" \
      org.nginxpanel.runtime.policy="persistent-root-approved-release" \
      org.nginxpanel.launcher.protocol="1"
