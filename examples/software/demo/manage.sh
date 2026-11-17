#!/bin/sh
set -eu
cd "${NGINXPANEL_SOFTWARE_DIR:?missing application directory}"
project="np-demo-${NGINXPANEL_SOFTWARE_ID:?missing application identity}"
version=""
if [ -f .component-version ]; then version=$(cat .component-version); fi
compose() { DEMO_VERSION="$version" docker compose --project-name "$project" --file compose.yaml "$@"; }
target() {
  case "${NGINXPANEL_TARGET_VERSION:-}" in 1.0.0|1.1.0) version=$NGINXPANEL_TARGET_VERSION;; *) printf '%s\n' '不支持的演示软件版本' >&2; return 1;; esac
}
switch_version() {
  target
  compose config --quiet
  cp ".package/releases/$version.html" data/version.html
  chmod 644 data/version.html
  compose up -d --wait --wait-timeout 30
  printf '%s\n' "$version" > .component-version.next
  mv .component-version.next .component-version
}
case "${1:-}" in
  check-version) target; compose config --quiet ;;
  backup)
    mkdir -p .backup
    if [ -f data/version.html ]; then cp data/version.html .backup/version.html; fi
    ;;
  install|update) switch_version ;;
  restore) switch_version; if [ -f .backup/version.html ]; then cp .backup/version.html data/version.html; fi ;;
  uninstall) compose down ;;
  start) compose start ;;
  stop) compose stop ;;
  restart) compose restart ;;
  logs) compose logs --no-color --tail 100 ;;
  status)
    id=$(compose ps --all --quiet web)
    if [ -z "$id" ]; then printf '%s\n' '{"state":"missing"}'; exit 0; fi
    actual=$(docker inspect --format '{{index .Config.Labels "io.nginxpanel.demo.version"}}' "$id")
    case "$actual" in 1.0.0|1.1.0) ;; *) printf '%s\n' '软件未登记有效版本' >&2; exit 1;; esac
    state=$(docker inspect --format '{{.State.Status}}' "$id")
    case "$state" in
      running)
        addresses=$(compose port web 80)
        address=$(printf '%s\n' "$addresses" | head -n 1)
        port=${address##*:}
        case "$port" in ''|*[!0-9]*) printf '%s\n' '无法确定网站访问端口' >&2; exit 1;; esac
        printf '{"state":"running","version":"%s","entry":"http://{host}:%s/version.html"}\n' "$actual" "$port"
        ;;
      created|exited) printf '{"state":"stopped","version":"%s"}\n' "$actual" ;;
      restarting) printf '{"state":"starting","version":"%s"}\n' "$actual" ;;
      *) printf '{"state":"unhealthy","version":"%s","message":"演示网站运行异常，请查看服务日志"}\n' "$actual" ;;
    esac
    ;;
  *) printf '%s\n' '不支持的操作' >&2; exit 2 ;;
esac
