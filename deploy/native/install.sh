#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
用法：install.sh --binary /可信目录/nginxpanel --web-dir /可信目录/web (--without-nginx | --nginx-binary /usr/sbin/nginx | --nginx-plan <计划ID> --nginx-asset <资产ID>) [--data-dir /srv/nginxpanel] [--listen 127.0.0.1:9443] [--start]
仅安装本机 root 已批准的构建产物。--without-nginx 只安装面板和 Agent；不下载、编译或接管系统 Nginx。
EOF
}
binary= web= nginx= nginx_plan= nginx_asset= release_trust=/etc/nginxpanel/release-trust.json prerelease=no without_nginx=no data=/srv/nginxpanel listen=127.0.0.1:9443 start=no
while (($#)); do
  case "$1" in
    --binary|--web-dir|--nginx-binary|--nginx-plan|--nginx-asset|--release-trust|--data-dir|--listen)
      (($# >= 2)) || die "参数缺少值：$1"
      case "$1" in
        --binary) binary=$2 ;; --web-dir) web=$2 ;; --nginx-binary) nginx=$2 ;;
        --nginx-plan) nginx_plan=$2 ;; --nginx-asset) nginx_asset=$2 ;; --release-trust) release_trust=$2 ;;
        --data-dir) data=$2 ;; --listen) listen=$2 ;;
      esac
      shift 2 ;;
    --release-prerelease) prerelease=yes; shift ;;
    --without-nginx) without_nginx=yes; shift ;;
    --start) start=yes; shift ;;
    --help) usage; exit 0 ;;
    *) usage; die "未知参数：$1" ;;
  esac
done
[[ $EUID == 0 ]] || die '安装需要本机 root'
[[ -n $binary && -n $web ]] || { usage; exit 1; }
if [[ $without_nginx == yes ]]; then
  [[ -z $nginx && -z $nginx_plan && -z $nginx_asset && $prerelease == no ]] || die '仅面板安装不能同时选择 Nginx 程序或签名组件'
elif [[ -n $nginx ]]; then
  [[ -z $nginx_plan && -z $nginx_asset && $prerelease == no ]] || die '本机程序与签名组件不能混用'
else
  [[ $nginx_plan =~ ^[0-9a-f]{64}$ && $nginx_asset =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ ]] || die '须显式选择仅面板、本机 Nginx 或完整的签名计划与资产 ID'
fi
for tool in stat readlink install sha256sum cmp sync flock getent groupadd useradd runuser systemctl mktemp find cut id uname dirname mv ln rm touch chmod od; do
  command -v "$tool" >/dev/null || die "缺少已有系统工具：$tool"
done
[[ -d /run/systemd/system ]] || die '仅支持实际运行 systemd 的宿主机'
machine=$(uname -m)
case "$machine" in x86_64|aarch64) ;; *) die '仅支持 linux/amd64 与 linux/arm64' ;; esac
[[ $listen =~ ^(127\.0\.0\.1|\[::1\]):([0-9]{2,5})$ ]] || die '管理地址仅允许回环 HTTPS'
port=${BASH_REMATCH[2]}
((10#$port >= 1024 && 10#$port <= 65535)) || die '管理端口须为 1024–65535'
[[ $data =~ ^/(srv|var/lib)/[a-zA-Z0-9_-][a-zA-Z0-9_./-]*$ ]] || die '数据目录须位于 /srv 或 /var/lib，且不含空格及控制符'

canonical() {
  [[ $1 == /* && $1 != */ && $1 != *//* && $1 != */./* && $1 != */../* && $1 != */. && $1 != */.. ]] || die "路径不是规范绝对路径：$1"
  [[ $1 =~ ^/[a-zA-Z0-9_./-]+$ ]] || die "路径包含不支持的字符：$1"
}
# Do not follow a writable ancestor, even when the final file belongs to root.
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
  local path=$1 max=$2 mode
  canonical "$path"
  root_chain "${path%/*}"
  [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %h "$path") == 1 ]] || die "非可信普通文件：$path"
  mode=$(stat -c %a "$path")
  (( (8#$mode & 07022) == 0 && $(stat -c %s "$path") <= max )) || die "文件权限或长度无效：$path"
}
native_elf() {
  local path=$1 header elf_machine low high
  header=$(od -An -v -tx1 -N6 "$path")
  header=${header//[[:space:]]/}
  elf_machine=$(od -An -v -tu1 -j18 -N2 "$path")
  read -r low high <<<"$elf_machine"
  [[ $header == 7f454c460201 && $high == 0 ]] || die "产物不是受支持的 64 位 Linux ELF：$path"
  [[ $machine == x86_64 && $low == 62 || $machine == aarch64 && $low == 183 ]] || die "产物架构不匹配：$path"
}
ensure_dir() {
  local path=$1 mode=$2 owner=$3 group=$4
  if [[ ! -e $path && ! -L $path ]]; then
    root_chain "${path%/*}"
    install -d -m "$mode" -o "$owner" -g "$group" "$path"
  fi
  [[ -d $path && ! -L $path && $(stat -c %U "$path") == "$owner" && $(stat -c %G "$path") == "$group" && $(stat -c %a "$path") == "$mode" ]] || die "目录已有不同归属或权限，停止接管：$path"
}
write_owned() {
  local source=$1 destination=$2 mode=${3:-644}
  root_chain "${destination%/*}"
  if [[ -e $destination || -L $destination ]]; then
    trusted_file "$destination" $((64 * 1024))
    cmp -s "$source" "$destination" || die "目标配置已存在不同内容：$destination"
  else
    pending_file=$(mktemp "${destination%/*}/.nginxpanel-install.XXXXXXXX")
    install -m "$mode" "$source" "$pending_file"
    sync -f "$pending_file"
    mv -T "$pending_file" "$destination"
    pending_file=
    sync -f "${destination%/*}"
  fi
}
canonical "$data"
binary=$(readlink -e "$binary")
canonical "$binary"; canonical "$web"
trusted_file "$binary" $((192 * 1024 * 1024))
[[ -x $binary ]] || die '指定面板程序不可执行'
native_elf "$binary"
nginx_source=()
if [[ $without_nginx == yes ]]; then
  nginx_source=(--nginx-uninstalled)
elif [[ -n $nginx ]]; then
  nginx=$(readlink -e "$nginx")
  nginx_source=(--nginx-binary "$nginx")
else
  canonical "$release_trust"
  [[ $release_trust == /etc/nginxpanel/* ]] || die '原生服务发行信任须位于 /etc/nginxpanel'
  nginx_source=(--release-plan "$nginx_plan" --release-select "$nginx_asset" --release-trust "$release_trust")
  if [[ $prerelease == yes ]]; then nginx_source+=(--release-prerelease); fi
fi
if [[ $without_nginx == no ]]; then
  nginx=$("$binary" component-path --data-dir "$data" "${nginx_source[@]}")
  canonical "$nginx"
  trusted_file "$nginx" $((64 * 1024 * 1024))
  [[ -x $nginx ]] || die '指定 Nginx 程序不可执行'
  native_elf "$nginx"
fi
root_chain "$web"
[[ -f $web/index.html ]] || die '前端目录缺少构建后的 index.html'
root_chain "${data%/*}"

ensure_dir /run/nginxpanel-install 700 root root
exec 9>/run/nginxpanel-install/lock
flock -n 9 || die '另一个安装操作正在执行'
ensure_dir /opt/nginxpanel 755 root root
ensure_dir /opt/nginxpanel/releases 755 root root
ensure_dir /opt/nginxpanel/prepared 755 root root
ensure_dir /opt/nginxpanel/release-downloads 700 root root
ensure_dir /etc/nginxpanel 755 root root
ensure_dir /etc/nginxpanel/install 700 root root
state=/etc/nginxpanel/install
work=$(mktemp -d "$state/work.XXXXXXXX")
release_work=
pending_file=
cleanup() {
  local result=$?
  rm -rf -- "$work"
  if [[ -n $release_work ]]; then rm -rf -- "$release_work"; fi
  if [[ -n $pending_file ]]; then rm -f -- "$pending_file"; fi
  if ((result != 0)); then
    printf '%s\n' '安装未完成；已写入的节点数据、账户和安装记录均保留。修复原因后以相同参数继续。' >&2
  fi
}
trap cleanup EXIT
manifest=$work/web.sha256
touch "$manifest"
count=0 total=0
shopt -s nullglob dotglob
inventory() {
  local dir=$1 depth=$2 path relative size
  ((depth <= 12)) || die '前端目录层级超过上限'
  root_chain "$dir"
  for path in "$dir"/*; do
    relative=${path#"$web/"}
    [[ $relative =~ ^[a-zA-Z0-9_./-]+$ && $relative != .web.sha256 ]] || die '前端产物路径无效或与清单保留路径冲突'
    count=$((count + 1)); ((count <= 4096)) || die '前端文件清单超过上限'
    if [[ -d $path && ! -L $path ]]; then
      inventory "$path" $((depth + 1))
    else
      trusted_file "$path" $((8 * 1024 * 1024))
      size=$(stat -c %s "$path"); total=$((total + size))
      ((total <= 64 * 1024 * 1024)) || die '前端产物超过 64 MiB'
      printf '%s  %s\n' "$(sha256sum "$path" | cut -d ' ' -f1)" "$relative" >>"$manifest"
    fi
  done
}
inventory "$web" 0
binary_hash=$(sha256sum "$binary" | cut -d ' ' -f1)
web_hash=$(sha256sum "$manifest" | cut -d ' ' -f1)
nginx_hash=
if [[ $without_nginx == no ]]; then nginx_hash=$(sha256sum "$nginx" | cut -d ' ' -f1); fi
release=$(printf '%s\n%s\n' "$binary_hash" "$web_hash" | sha256sum | cut -d ' ' -f1)
release_dir=/opt/nginxpanel/releases/$release
printf 'native-install-v4\ndata=%s\nlisten=%s\nrelease=%s\nwithout_nginx=%s\nnginx=%s\nnginx_sha256=%s\nnginx_plan=%s\nnginx_asset=%s\nrelease_trust=%s\nprerelease=%s\n' "$data" "$listen" "$release" "$without_nginx" "$nginx" "$nginx_hash" "$nginx_plan" "$nginx_asset" "$release_trust" "$prerelease" >"$work/intent"
if [[ -e $state/intent || -L $state/intent ]]; then
  trusted_file "$state/intent" 4096
  cmp -s "$work/intent" "$state/intent" || die '已有不同安装计划；版本更新和路径迁移须走维护流程'
else
  [[ ! -e $data && ! -L $data || -d $data && ! -L $data && -z $(find "$data" -mindepth 1 -maxdepth 1 -print -quit) ]] || die '数据目录非空，禁止将首次安装覆盖到已有数据'
  for unit in nginxpanel.service nginxpanel-agent.service nginxpanel-nginx.service nginxpanel-install@.service; do
    [[ $(systemctl show --property=LoadState --value "$unit") == not-found ]] || die "已有同名服务，停止接管：$unit"
  done
  [[ ! -e /opt/nginxpanel/current && ! -L /opt/nginxpanel/current ]] || die '已有程序指针，停止接管'
  write_owned "$work/intent" "$state/intent" 600
fi

# Existing accounts are accepted only when they already have the exact dedicated
# identity. Never alter an unrelated account or add it to a privileged group.
ensure_group() {
  local entry gid
  if ! getent group "$1" >/dev/null; then groupadd --system "$1"; fi
  entry=$(getent group "$1")
  gid=$(getent group "$1" | cut -d: -f3)
  [[ $entry == "$1:x:"* && ${entry##*:} == '' && $gid =~ ^[1-9][0-9]*$ ]] || die "专用组已有外部成员或非本机配置：$1"
}
ensure_user() {
  local name=$1 group=$2 entry gid uid groups account_home account_shell account_name account_password account_comment
  if ! getent passwd "$name" >/dev/null; then
    useradd --system --gid "$group" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$name"
  fi
  entry=$(getent passwd "$name")
  IFS=: read -r account_name account_password uid gid account_comment account_home account_shell <<<"$entry"
  [[ $account_name == "$name" && $uid =~ ^[1-9][0-9]*$ && $gid == "$(getent group "$group" | cut -d: -f3)" && $account_home == /nonexistent && $account_shell == /usr/sbin/nologin ]] || die "账户与专用身份不匹配：$name"
  groups=$(id -G "$name")
  [[ $groups == "$gid" ]] || die "账户存在其他组授权，停止接管：$name"
}
ensure_group nginxpanel
ensure_group nginxpanel-ipc
ensure_group nginxpanel-nginx
ensure_user nginxpanel nginxpanel
ensure_user nginxpanel-nginx nginxpanel-nginx
panel_uid=$(id -u nginxpanel)
[[ $panel_uid != "$(id -u nginxpanel-nginx)" ]] || die 'Web 与 Nginx worker 账户必须分离'
ensure_dir "$data" 755 root root
for dir in app bootstrap secrets staging; do ensure_dir "$data/$dir" 700 nginxpanel nginxpanel; done
ensure_dir "$data/run" 755 root root
ensure_dir "$data/run/agent" 2750 root nginxpanel-ipc
ensure_dir "$data/agent" 700 root root
ensure_dir "$data/acme" 700 root root
ensure_dir "$data/certificates" 700 root root
ensure_dir "$data/modules" 755 root root
ensure_dir "$data/bin" 755 root root
ensure_dir "$data/bin/components" 755 root root
ensure_dir "$data/nginx" 755 root root
ensure_dir "$data/logs" 755 root root

# Build the immutable release off to the side; partial copies never become live.
if [[ ! -e $release_dir && ! -L $release_dir ]]; then
  release_work=$(mktemp -d /opt/nginxpanel/releases/.install.XXXXXXXX)
  chmod 755 "$release_work"
  install -d -m 755 "$release_work/web"
  install -m 755 "$binary" "$release_work/nginxpanel"
  while IFS= read -r line; do
    relative=${line#*  }
    install -d -m 755 "$release_work/web/$(dirname "$relative")"
    install -m 644 "$web/$relative" "$release_work/web/$relative"
  done <"$manifest"
  install -m 444 "$manifest" "$release_work/web/.web.sha256"
  [[ $(sha256sum "$release_work/nginxpanel" | cut -d ' ' -f1) == "$binary_hash" ]] || die '程序复制期间发生变化'
  (cd "$release_work/web" && sha256sum --check --status .web.sha256) || die '前端复制期间发生变化'
  sync -f "$release_work"
  mv -T "$release_work" "$release_dir"
  release_work=
  sync -f /opt/nginxpanel/releases
fi
trusted_file "$release_dir/nginxpanel" $((192 * 1024 * 1024))
[[ $(sha256sum "$release_dir/nginxpanel" | cut -d ' ' -f1) == "$binary_hash" ]] || die '安装程序副本不匹配'
trusted_file "$release_dir/web/.web.sha256" $((1024 * 1024))
cmp -s "$manifest" "$release_dir/web/.web.sha256" || die '前端产物清单不匹配'
(cd "$release_dir/web" && sha256sum --check --status .web.sha256) || die '已安装前端产物变化'
if [[ -L /opt/nginxpanel/current ]]; then
  [[ $(readlink /opt/nginxpanel/current) == "releases/$release" ]] || die '程序指针已被外部修改'
elif [[ -e /opt/nginxpanel/current ]]; then die '程序指针不是符号链接'
else ln -s "releases/$release" /opt/nginxpanel/current; sync -f /opt/nginxpanel; fi

printf '{"version":1,"modules":[]}\n' >"$work/nginx-modules.json"
write_owned "$work/nginx-modules.json" /etc/nginxpanel/nginx-modules.json
runuser -u nginxpanel -- "$release_dir/nginxpanel" init --data-dir "$data"
if [[ $without_nginx == no ]]; then
  [[ $(sha256sum "$nginx" | cut -d ' ' -f1) == "$nginx_hash" ]] || die 'Nginx 程序已变化'
fi
"$release_dir/nginxpanel" component-bind --data-dir "$data" "${nginx_source[@]}" >"$work/nginx-binding.json"
if [[ $without_nginx == no && ! -f $state/ready ]]; then
  "$release_dir/nginxpanel" nginx-init --data-dir "$data" --nginx-binding --nginx-user nginxpanel-nginx --nginx-modules /etc/nginxpanel/nginx-modules.json
fi

cat >"$work/nginxpanel-nginx.service" <<EOF
[Unit]
Description=NginxPanel dedicated Nginx instance
After=network.target
Before=nginxpanel-agent.service

[Service]
Type=exec
User=root
Group=root
UMask=0027
ExecCondition=/opt/nginxpanel/current/nginxpanel nginx-runtime-status --data-dir $data
ExecStartPre=/opt/nginxpanel/current/nginxpanel nginx-runtime --data-dir $data --nginx-runtime-check
ExecStart=/opt/nginxpanel/current/nginxpanel nginx-runtime --data-dir $data
KillSignal=SIGQUIT
KillMode=mixed
TimeoutStartSec=180
TimeoutStopSec=65
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$data/nginx $data/logs $data/run
InaccessiblePaths=$data/app $data/bootstrap $data/secrets $data/staging $data/agent $data/acme
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
cat >"$work/nginxpanel-agent.service" <<EOF
[Unit]
Description=NginxPanel local privileged agent
After=nginxpanel-nginx.service
Before=nginxpanel.service

[Service]
Type=exec
User=root
Group=nginxpanel-ipc
UMask=0027
ExecStart=/opt/nginxpanel/current/nginxpanel agent --data-dir $data --allowed-uid $panel_uid --nginx-binding --nginx-user nginxpanel-nginx --nginx-modules /etc/nginxpanel/nginx-modules.json --metrics-scope host --component-scope host --maintenance-scope host
Restart=on-failure
RestartSec=3
TimeoutStartSec=180
TimeoutStopSec=45
RuntimeDirectory=nginxpanel-host
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$data/agent $data/acme $data/certificates $data/modules $data/nginx $data/logs $data/run /run/nginxpanel-host /opt/nginxpanel/prepared /opt/nginxpanel/release-downloads
InaccessiblePaths=$data/app $data/bootstrap $data/secrets $data/staging
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
cat >"$work/nginxpanel.service" <<EOF
[Unit]
Description=NginxPanel management API and Web
Wants=nginxpanel-agent.service
After=network.target nginxpanel-agent.service

[Service]
Type=exec
User=nginxpanel
Group=nginxpanel
SupplementaryGroups=nginxpanel-ipc
UMask=0077
WorkingDirectory=$data
ExecStart=/opt/nginxpanel/current/nginxpanel serve --data-dir $data --listen $listen --web-dir /opt/nginxpanel/current/web --nginx-modules /etc/nginxpanel/nginx-modules.json
Restart=on-failure
RestartSec=3
TimeoutStopSec=45
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectProc=invisible
ReadWritePaths=$data/app $data/bootstrap $data/secrets $data/staging
InaccessiblePaths=$data/agent $data/acme $data/certificates $data/modules $data/nginx $data/logs
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
cat >"$work/nginxpanel-install@.service" <<EOF
[Unit]
Description=NginxPanel first Nginx installation %i
After=network.target

[Service]
Type=exec
User=root
Group=nginxpanel-ipc
UMask=0027
ExecStart=/opt/nginxpanel/current/nginxpanel nginx-install-worker --data-dir $data --install-operation %i
RuntimeMaxSec=660
TimeoutStopSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$data/agent $data/acme $data/certificates $data/modules $data/nginx $data/logs $data/run $data/bin/components
InaccessiblePaths=$data/app $data/bootstrap $data/secrets $data/staging
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
EOF
root_chain /etc/systemd/system
for unit in nginxpanel-nginx.service nginxpanel-agent.service nginxpanel.service nginxpanel-install@.service; do
  write_owned "$work/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
printf 'native-install-v4\n' >"$work/ready"
write_owned "$work/ready" "$state/ready" 600
if [[ $start == yes ]]; then
  start_units=(nginxpanel.service)
  enabled_units=(nginxpanel-agent.service nginxpanel.service)
  if [[ $without_nginx == no ]]; then
    enabled_units+=(nginxpanel-nginx.service)
    start_units+=(nginxpanel-nginx.service)
  fi
  systemctl enable "${enabled_units[@]}"
  systemctl start "${start_units[@]}"
  for unit in "${enabled_units[@]}"; do
    systemctl is-active --quiet "$unit" || die "服务未进入 active：$unit；保留安装记录，请检查 systemd 日志"
  done
fi
printf '已准备原生部署：%s\n管理地址：https://%s\n' "$data" "$listen"
if [[ $without_nginx == yes ]]; then printf '%s\n' 'Nginx 未安装；配置导入可预检并准备可信资产，安装与运行接入仍须明确完成。'; fi
if [[ -f $data/bootstrap/token ]]; then printf '一次性引导文件：%s/bootstrap/token\n' "$data"; fi
