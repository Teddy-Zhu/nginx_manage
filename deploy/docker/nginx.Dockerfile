# syntax=docker/dockerfile:1
# Modules and their shared-library dependencies are supplied by this image.
FROM nginx:1.30.6-alpine-slim@sha256:3028fc1419f99b95c1c69f844bbaf49dc1b881750c51b497fc721ac4f02a14e6
ARG TARGETARCH
COPY --chown=0:0 --chmod=0555 .release/binaries/nginxpanel-${TARGETARCH} /usr/local/bin/nginxpanel-nginx-launcher
COPY deploy/docker/nginx-capabilities.json /usr/share/nginxpanel/capabilities.json
COPY deploy/docker/check-nginx-image.sh /usr/local/libexec/check-nginx-image
RUN /bin/sh /usr/local/libexec/check-nginx-image \
    && rm -rf /docker-entrypoint.d /docker-entrypoint.sh /etc/nginx/conf.d/default.conf \
    && chmod 0444 /usr/share/nginxpanel/capabilities.json /usr/share/nginxpanel/nginx-build.txt /usr/share/nginxpanel/nginx.sha256 /usr/share/nginxpanel/launcher.sha256
LABEL org.opencontainers.image.title="NginxPanel Nginx runtime" \
      org.opencontainers.image.description="HTTP/TLS, Stream/TLS/preread/realip, ACL, basic WAF, JSON logs and HTTP-01 modules supplied at build time" \
      org.nginxpanel.modules.policy="image-only" \
      org.nginxpanel.modules.manifest="/usr/share/nginxpanel/capabilities.json"
# The managed configuration and runtime state use an explicitly bound data path.
# No startup download, package installation, module compilation or config rewrite.
# The fixed bootstrap drops to the registered host Nginx UID before exec.
# Only NET_BIND_SERVICE survives; no host privileged-port sysctl is modified.
USER 0:0
WORKDIR /srv/nginxpanel
ENTRYPOINT ["/usr/local/bin/nginxpanel-nginx-launcher", "nginx-container-launch"]
CMD ["--data-dir", "/srv/nginxpanel"]
