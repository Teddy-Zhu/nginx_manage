#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
export DOCKER_HOST=unix:///run/docker.sock
unset DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
用法：sudo bash manage.sh [命令] [组件] [选项]
不带参数打开管理菜单，自动从本机安装记录读取模式、数据目录及管理地址。

命令：
  info                         查看部署信息、版本和首次访问方法
  status [all|panel|agent|nginx] 查看服务状态，默认 all
  start|stop|restart [组件]     控制服务，默认 panel；all 包括已安装 Nginx
  logs [panel|agent|nginx]      查看服务日志，默认 panel
  bootstrap                    显示一次性初始化令牌（不能重置已有账户）
  fingerprint                  显示主入口证书 SHA-256
  set-port 端口                修改主入口端口，运行中的面板自动重启
  disable-remote               请求停用附加管理入口（不关闭主入口）

选项：
  --yes                        明确确认服务变更、端口修改或附加入口停用
  --lines N                    日志行数，默认 100，最多 10000
  --follow                     持续跟随服务日志

更新、备份恢复与限时网络变更使用面板中的原维护流程。
EOF
}
action=${1:-menu}
if (($#)); then shift; fi
case "$action" in -h|--help|help) usage; exit 0 ;; esac
component= yes=no lines=100 follow=no requested_port=
while (($#)); do
  case "$1" in
    --yes) yes=yes; shift ;;
    --follow) follow=yes; shift ;;
    --lines) (($# >= 2)) || die '--lines 缺少行数'; lines=$2; shift 2 ;;
    [0-9]*)
      [[ $action == set-port && -z $requested_port ]] || die '只有 set-port 接受一个端口参数'
      requested_port=$1; shift ;;
    all|panel|agent|nginx) [[ -z $component ]] || die '只能选择一个组件'; component=$1; shift ;;
    *) usage; die "未知参数：$1" ;;
  esac
done
case "$action" in menu|info|status|start|stop|restart|logs|bootstrap|fingerprint|disable-remote|set-port) ;; *) usage; die "未知命令：$action" ;; esac
if [[ $action != logs ]]; then [[ $follow == no && $lines == 100 ]] || die '日志选项只能用于 logs'; fi
case "$action" in status) component=${component:-all} ;; start|stop|restart|logs) component=${component:-panel} ;; *) [[ -z $component ]] || die '此命令不接受组件参数' ;; esac
[[ $action != logs || $component != all ]] || die '请分别选择 panel、agent 或 nginx 的服务日志'
[[ $lines =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$lines <= 10000)) || die '日志行数须为 1–10000'
if [[ $action == set-port ]]; then
  [[ $requested_port =~ ^[1-9][0-9]{3,4}$ ]] && ((requested_port >= 1024 && requested_port <= 65535)) || die '用法：manage.sh set-port 1024–65535 [--yes]'
fi
[[ $EUID == 0 ]] || die '管理本机部署需要 root，请使用 sudo bash manage.sh'

root_chain() {
  local path=$1 mode
  while [[ $path != / ]]; do
    [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 ]] || die "非可信 root 目录：$path"
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || die "目录可被其他账户修改：$path"
    path=${path%/*}; [[ -n $path ]] || path=/
  done
}
trusted_file() {
  local path=$1 mode
  root_chain "${path%/*}"
  [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %h "$path") == 1 ]] || die "非可信普通文件：$path"
  mode=$(stat -c %a "$path")
  (( (8#$mode & 07022) == 0 )) || die "文件权限不可信：$path"
}
intent=/etc/nginxpanel/install/intent
trusted_file "$intent"
[[ $(stat -c %s "$intent") -le 4096 ]] || die '安装记录超出读取限制'
data= panel_mode= listen= nginx_image= seen=:
while IFS='=' read -r key value; do
  case "$key" in
    data|panel_mode|listen|nginx_image)
      [[ $seen != *":$key:"* ]] || die "安装记录存在重复字段：$key"
      seen=$seen$key:
      case "$key" in data) data=$value ;; panel_mode) panel_mode=$value ;; listen) listen=$value ;; nginx_image) nginx_image=$value ;; esac ;;
  esac
done <"$intent"
[[ $data =~ ^/(srv|var/lib)/[a-zA-Z0-9_-][a-zA-Z0-9_./-]*$ && $data != */ && $data != *//* && $data != */./* && $data != */../* && $data != */. && $data != */.. ]] || die '安装数据路径无效'
case "$panel_mode" in native|docker) ;; *) die '安装记录缺少有效运行模式' ;; esac
compose=/etc/nginxpanel/docker/compose.yaml
binary=
load_binary() {
  root_chain /opt/nginxpanel
  [[ -L /opt/nginxpanel/current && $(stat -c %u /opt/nginxpanel/current) == 0 ]] || die '宿主机程序指针不是可信的安装指针'
  binary=$(readlink -e /opt/nginxpanel/current/nginxpanel) || die '宿主机程序尚未安装或指针已失效'
  trusted_file "$binary"
  [[ -x $binary ]] || die '宿主机程序不可执行'
}
load_listen() {
  load_binary
  listen=$("$binary" panel-listen --data-dir "$data") || die '无法读取当前生效的管理地址'
  [[ $listen =~ ^(\[[0-9a-f:]+\]|[0-9.]+):([0-9]{4,5})$ ]] || die '运行绑定中的管理地址无效'
  port=${BASH_REMATCH[2]}
  ((10#$port >= 1024 && 10#$port <= 65535)) || die '运行绑定中的管理端口无效'
}

compose_command() {
  trusted_file "$compose"
  command -v docker >/dev/null || die '缺少 Docker 命令'
  docker compose -f "$compose" "$@"
}
nginx_available() {
  local result
  if [[ -n $nginx_image ]]; then return 0; fi
  load_binary
  if "$binary" nginx-runtime-status --data-dir "$data"; then return 0; else result=$?; fi
  if ((result == 1)); then return 1; fi
  die 'Nginx 安装状态无法核对，请检查原组件绑定与恢复任务'
}
confirm_change() {
  local answer
  if [[ $yes == yes ]]; then return; fi
  [[ -t 0 && -t 1 ]] || die '非交互操作必须通过 --yes 明确确认'
  printf '%s\n' "$1"
  read -r -p '确认执行？[y/N]: ' answer || die '输入已结束'
  case "$answer" in y|Y|yes|YES) ;; *) printf '%s\n' '操作已取消'; exit 0 ;; esac
}
service_command() {
  local operation=$1 selected=$2
  if [[ $selected == panel && $panel_mode == docker || $selected == nginx && -n $nginx_image ]]; then
    local service=panel
    if [[ $selected == nginx ]]; then service=nginx; fi
    case "$operation" in
      status)
        compose_command ps -a "$service" || return
        if [[ $selected == panel ]]; then
          printf '%s\n' '面板实际进程（容器停止时查询不可用）：'
          load_binary
          "$binary" panel-service-status --data-dir "$data"
        fi ;;
      start) compose_command up -d --no-deps --pull never "$service" ;;
      stop|restart) compose_command "$operation" "$service" ;;
    esac
  else
    local unit=nginxpanel.service
    case "$selected" in agent) unit=nginxpanel-agent.service ;; nginx) unit=nginxpanel-nginx.service ;; esac
    if [[ $operation == status ]]; then systemctl --no-pager --full status "$unit"; else systemctl "$operation" "$unit"; fi
  fi
}
service_action() {
  local selected result=0
  local -a selections=("$component")
  if [[ $component == all ]]; then
    if [[ $action == stop ]]; then selections=(panel nginx agent); else selections=(agent nginx panel); fi
  fi
  if [[ $action != status ]]; then
    trusted_file /etc/nginxpanel/install/ready
    if [[ ( $action == start || $action == restart ) && ( $component == panel || $component == all ) ]]; then
      [[ ! -e $data/run/panel-service-hold.json && ! -L $data/run/panel-service-hold.json && ! -e $data/run/panel-writer-fence.json && ! -L $data/run/panel-writer-fence.json ]] || die '存在持久停机或恢复屏障，请沿原维护/恢复任务处理'
    fi
    confirm_change "操作：$action；组件：$component。请先结束在途变更。停止或重启 Nginx 会中断代理，停止或重启 Agent 会影响远程管理入口。"
  fi
  for selected in "${selections[@]}"; do
    if [[ $selected == nginx ]] && ! nginx_available; then
      if [[ $component == all ]]; then printf '%s\n' 'Nginx 尚未安装，跳过'; continue; fi
      die 'Nginx 尚未安装'
    fi
    printf '\n[%s]\n' "$selected"
    if service_command "$action" "$selected"; then :; else
      result=$?
      if [[ $action != status ]]; then return "$result"; fi
    fi
  done
  return "$result"
}
show_info() {
  load_listen
  local forward_host=${listen%:*}
  case "$forward_host" in '0.0.0.0') forward_host=127.0.0.1 ;; '[::]') forward_host='[::1]' ;; esac
  printf '部署模式：%s\n数据目录：%s\n管理监听：%s\n' "$panel_mode" "$data" "$listen"
  printf '%s\n' '本机访问地址（选择管理电脑可达的地址）：'
  "$binary" panel-access-urls --data-dir "$data"
  printf '%s\n' '公网 NAT 场景使用公网 IP 和映射端口；云安全组及外部防火墙需允许访问。'
  if [[ -f /etc/nginxpanel/install/ready ]]; then printf '%s\n' '安装记录：已就绪'; else printf '%s\n' '安装记录：尚未就绪，请续办原安装'; fi
  "$binary" version
  printf '可选 SSH 转发：ssh -N -L %s:%s:%s <SSH用户>@<部署主机>\n' "$port" "$forward_host" "$port"
  printf '初始化令牌：%s/bootstrap/token\n主入口证书：%s/secrets/node-tls/cert.pem\n' "$data" "$data"
  printf '%s\n' '版本输出为宿主机工具版本；面板当前选中版本与业务运行结果请在网页核对。'
}
set_port() {
  local target was_running=no state running_id result
  load_listen
  target=${listen%:*}:$requested_port
  if [[ $target == "$listen" ]]; then printf '%s\n' '端口未变化'; return; fi
  trusted_file /etc/nginxpanel/install/ready
  [[ ! -e $data/run/panel-service-hold.json && ! -L $data/run/panel-service-hold.json && ! -e $data/run/panel-writer-fence.json && ! -L $data/run/panel-writer-fence.json ]] || die '存在持久停机或恢复屏障，请沿原任务处理'
  confirm_change "管理地址由 $listen 改为 $target；运行中的面板将重启，请确保新端口可访问。"
  # Share the installer's host lock so two local configuration operations cannot
  # stop/restart each other's panel or race a pending installation.
  root_chain /run/nginxpanel-install
  if [[ -e /run/nginxpanel-install/lock || -L /run/nginxpanel-install/lock ]]; then trusted_file /run/nginxpanel-install/lock; fi
  exec 9>/run/nginxpanel-install/lock
  flock -n 9 || die '另一个安装或端口修改操作正在执行'
  load_listen
  target=${listen%:*}:$requested_port
  if [[ $target == "$listen" ]]; then printf '%s\n' '端口未变化'; return; fi
  if [[ $panel_mode == docker ]]; then
    running_id=$(compose_command ps --status running -q panel) || die '无法查询面板容器状态'
    if [[ -n $running_id ]]; then was_running=yes; fi
  else
    state=$(systemctl show --property=ActiveState --value nginxpanel.service) || die '无法查询面板服务状态'
    case "$state" in active) was_running=yes ;; inactive|failed) ;; *) die "面板状态为 $state，请等待服务操作结束后重试" ;; esac
  fi
  service_command stop panel || die '无法停止面板，未修改端口'
  if "$binary" panel-listen-set --data-dir "$data" --listen "$target"; then :; else
    result=$?
    if [[ $was_running == yes ]]; then
      service_command start panel || die '端口修改未确认且面板重启失败；请用 info 核对当前配置并检查服务日志'
    fi
    printf '%s\n' '端口修改未完成，请根据上方错误处理；用 info 查看当前配置。' >&2
    return "$result"
  fi
  load_listen
  if [[ $was_running == yes ]]; then
    service_command start panel || die '新端口已保存，但面板启动失败；请检查服务日志或改回原端口'
  fi
  show_info
  if [[ $was_running == no ]]; then printf '%s\n' '端口已保存；面板保持停止状态，下次启动使用新端口。'; fi
}
logs_action() {
  local unit=nginxpanel.service service=panel
  local -a args=()
  if [[ $component == nginx ]]; then nginx_available || die 'Nginx 尚未安装'; fi
  if [[ $component == panel && $panel_mode == docker || $component == nginx && -n $nginx_image ]]; then
    if [[ $component == nginx ]]; then service=nginx; fi
    if [[ $follow == yes ]]; then args+=(--follow); fi
    compose_command logs --tail "$lines" "${args[@]}" "$service"
  else
    case "$component" in agent) unit=nginxpanel-agent.service ;; nginx) unit=nginxpanel-nginx.service ;; esac
    if [[ $follow == yes ]]; then args+=(--follow); fi
    journalctl --no-pager -u "$unit" -n "$lines" "${args[@]}"
  fi
}
if [[ $action == menu ]]; then
  [[ -t 0 && -t 1 ]] || die '管理菜单需要交互终端，请使用明确命令'
  self=$(readlink -e -- "$0")
  while :; do
    printf '\nNginxPanel 管理（%s，%s）\n' "$panel_mode" "$data"
    printf '%s\n' '  1) 部署信息' '  2) 全部服务状态' '  3) 启动服务' '  4) 停止服务' '  5) 重启服务' '  6) 服务日志' '  7) 初始化令牌' '  8) 证书指纹' '  9) 停用附加管理入口' '  10) 修改主入口端口' '  0) 退出'
    read -r -p '请选择 [0]: ' selection || exit 0
    selected=
    case "$selection" in
      1) command=info ;; 2) command=status ;;
      3|4|5|6)
        case "$selection" in 3) command=start ;; 4) command=stop ;; 5) command=restart ;; 6) command=logs ;; esac
        prompt='组件 panel/agent/nginx/all [panel]: '
        if [[ $command == logs ]]; then prompt='组件 panel/agent/nginx [panel]: '; fi
        read -r -p "$prompt" selected || exit 0
        selected=${selected:-panel}
        case "$selected" in
          panel|agent|nginx) ;;
          all) if [[ $command == logs ]]; then printf '%s\n' '请分别选择服务日志'; continue; fi ;;
          *) printf '%s\n' '组件无效'; continue ;;
        esac ;;
      7) command=bootstrap ;; 8) command=fingerprint ;; 9) command=disable-remote ;;
      10)
        command=set-port
        read -r -p '新管理端口（1024–65535）: ' selected || exit 0 ;;
      ''|0) exit 0 ;; *) printf '%s\n' '请输入列表中的编号'; continue ;;
    esac
    arguments=("$command")
    if [[ -n $selected ]]; then arguments+=("$selected"); fi
    if /bin/bash "$self" "${arguments[@]}"; then :; else printf '%s\n' '命令未成功完成，请根据上方错误处理' >&2; fi
  done
fi
case "$action" in
  info) show_info ;;
  set-port) set_port ;;
  status|start|stop|restart) service_action ;;
  logs) logs_action ;;
  bootstrap)
    [[ -d $data/bootstrap && ! -L $data/bootstrap && -f $data/bootstrap/token && ! -L $data/bootstrap/token ]] || die '未找到初始化令牌'
    printf '%s\n' '令牌仅用于首次创建管理员，不能重置已有账户：'
    cat -- "$data/bootstrap/token"; printf '\n' ;;
  fingerprint)
    command -v openssl >/dev/null || die '需要已有 openssl 命令读取证书指纹'
    openssl x509 -in "$data/secrets/node-tls/cert.pem" -noout -fingerprint -sha256 ;;
  disable-remote)
    confirm_change '停用附加管理入口；主入口继续按当前地址监听。'
    load_binary
    "$binary" management-listener-disable --data-dir "$data"
    printf '%s\n' '请查看返回状态；requested 仅表示请求已保存，由 Agent 处理。' ;;
esac
