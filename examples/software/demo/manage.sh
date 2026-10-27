#!/bin/sh
set -eu
cd "${NGINXPANEL_SOFTWARE_DIR:?missing application directory}"
project="np-demo-${NGINXPANEL_SOFTWARE_ID:?missing application identity}"
compose() { docker compose --project-name "$project" --file compose.yaml "$@"; }
case "${1:-}" in
  install) compose up -d ;;
  update) compose pull && compose up -d ;;
  uninstall) compose down ;;
  start) compose start ;;
  stop) compose stop ;;
  restart) compose restart ;;
  logs) compose logs --no-color --tail 100 ;;
  status)
    id=$(compose ps --all --quiet web)
    if [ -z "$id" ]; then printf '%s\n' '{"state":"stopped"}'; exit 0; fi
    state=$(docker inspect --format '{{.State.Status}}' "$id")
    case "$state" in
      running)
        addresses=$(compose port web 80)
        address=$(printf '%s\n' "$addresses" | head -n 1)
        port=${address##*:}
        case "$port" in ''|*[!0-9]*) printf '%s\n' '无法确定网站访问端口' >&2; exit 1;; esac
        printf '{"state":"running","entry":"http://{host}:%s/"}\n' "$port"
        ;;
      created|exited) printf '%s\n' '{"state":"stopped"}' ;;
      restarting) printf '%s\n' '{"state":"starting"}' ;;
      *) printf '%s\n' '{"state":"unhealthy","message":"演示网站运行异常，请查看服务日志"}' ;;
    esac
    ;;
  *) printf '%s\n' '不支持的操作' >&2; exit 2 ;;
esac
