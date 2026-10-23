#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
root=$(cd -- "$(dirname -- "$0")" && pwd -P)
usage() {
  cat <<'EOF'
用法：sudo bash install.sh
交互配置原生/Docker 部署、Nginx 来源、管理端口及宿主机授权，确认后调用标准安装器。
先在构建机执行 bash scripts/build.sh，将生成的 tar 解压到部署目标。
不会在目标编译、安装 Docker、下载 Nginx 或接管已有系统 Nginx。

带参数时转交标准安装器，例如：
sudo bash install.sh --binary /可信目录/nginxpanel --web-dir /可信目录/web --without-nginx --start
完整参数：bash deploy/native/install.sh --help
EOF
}
if (($#)); then
  case "$1" in -h|--help) usage; exit 0 ;; esac
  exec /bin/bash "$root/deploy/native/install.sh" "$@"
fi
[[ $EUID == 0 ]] || die '请在实际部署目标使用 sudo bash install.sh'
[[ -t 0 && -t 1 ]] || die '引导安装需要交互终端；自动化安装请传入标准安装参数'
[[ -f $root/deploy/native/install.sh && -f $root/manage.sh ]] || die '安装材料不完整，缺少标准安装器或管理脚本'

ask() {
  local destination=$1 prompt=$2 default=$3 answer
  read -r -p "$prompt [$default]: " answer || die '输入已结束，安装取消'
  [[ -n $answer ]] || answer=$default
  printf -v "$destination" '%s' "$answer"
}
choose() {
  local destination=$1 prompt=$2 default=$3 answer i=0 entry
  shift 3
  local -a options=("$@")
  printf '\n%s\n' "$prompt"
  for entry in "${options[@]}"; do i=$((i + 1)); printf '  %s) %s\n' "$i" "${entry#*:}"; done
  while :; do
    read -r -p "请选择 [$default]: " answer || die '输入已结束，安装取消'
    [[ -n $answer ]] || answer=$default
    if [[ $answer =~ ^[1-9][0-9]?$ ]] && ((10#$answer <= ${#options[@]})); then
      entry=${options[10#$answer - 1]}
      printf -v "$destination" '%s' "${entry%%:*}"
      return
    fi
    printf '%s\n' '请输入列表中的编号'
  done
}
yes_no() {
  local answer
  while :; do
    read -r -p "$1 [y/N]: " answer || die '输入已结束，安装取消'
    case "$answer" in y|Y|yes|YES) return 0 ;; ''|n|N|no|NO) return 1 ;; *) printf '%s\n' '请输入 y 或 n' ;; esac
  done
}
root_chain() {
  local path=$1 mode
  while [[ $path != / ]]; do
    [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 ]] || die "非可信 root 目录：$path"
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || die "目录可被其他账户写入：$path"
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
confirm_install() {
  local answer
  read -r -p '输入 INSTALL 执行，其他输入取消: ' answer || die '输入已结束，安装取消'
  [[ $answer == INSTALL ]] || { printf '%s\n' '安装已取消'; exit 0; }
}
finish() {
  printf '\n管理入口：sudo bash /opt/nginxpanel/manage.sh\n'
  /bin/bash /opt/nginxpanel/manage.sh info
}
plan=/opt/nginxpanel/install-command.sh
if [[ -e $plan || -L $plan ]]; then
  trusted_file "$plan"
  [[ $(stat -c %s "$plan") -le 16384 ]] || die '原安装命令超出读取限制'
  printf '%s\n' '发现已保存的原安装命令。重复执行保留原参数和节点数据；版本更新请使用面板维护入口。'
  cat -- "$plan"
  confirm_install
  /bin/bash "$plan"
  finish
  exit 0
fi
[[ ! -e /etc/nginxpanel/install/intent && ! -L /etc/nginxpanel/install/intent ]] || die '已有标准安装记录但没有引导安装命令；请用原参数续装，日常管理可运行本目录的 manage.sh'

printf '%s\n' 'NginxPanel 引导安装' '安装将创建专用账户、目录及 systemd 服务。'
choose panel_mode '面板部署方式' 1 native:原生服务 docker:Docker容器
if [[ -f $root/nginxpanel ]]; then binary=$root/nginxpanel; web=$root/web; else binary=$root/bin/nginxpanel; web=$root/web/dist; fi
ask binary '面板程序路径' "$binary"
ask web '构建后的前端目录' "$web"
binary=$(readlink -e -- "$binary") || die '程序路径不存在；请先使用 Docker 构建并传输安装包'
web=$(readlink -e -- "$web") || die '前端目录不存在；请使用构建后的 web 目录'
[[ -f $binary && -x $binary && -d $web && -f $web/index.html ]] || die '程序不可执行或前端缺少 index.html'
[[ -z $(find "$web" -mindepth 1 ! -type d ! -type f -print -quit) ]] || die '前端目录只能包含普通文件和目录'
ask data '数据目录' /srv/nginxpanel
ask listen '回环管理地址' 127.0.0.1:9443
[[ $data =~ ^/(srv|var/lib)/[a-zA-Z0-9_-][a-zA-Z0-9_./-]*$ && $data != */ && $data != *//* && $data != */./* && $data != */../* && $data != */. && $data != */.. ]] || die '数据目录须为 /srv 或 /var/lib 下的规范路径'
[[ $listen =~ ^(127\.0\.0\.1|\[::1\]):([0-9]{2,5})$ ]] || die '管理地址仅允许回环 HTTPS'
port=${BASH_REMATCH[2]}
((10#$port >= 1024 && 10#$port <= 65535)) || die '端口须为 1024–65535'
root_chain "${data%/*}"
[[ ! -e $data && ! -L $data || -d $data && ! -L $data && -z $(find "$data" -mindepth 1 -maxdepth 1 -print -quit) ]] || die '数据目录非空，不能首次安装覆盖'

args=(--data-dir "$data" --listen "$listen" --panel-mode "$panel_mode")
nginx_kind= release_trust=/etc/nginxpanel/release-trust.json signed=no
if [[ $panel_mode == docker ]]; then
  command -v docker >/dev/null || die '需要已有 Docker；请先在目标配置 Docker'
  docker compose version >/dev/null
  ask panel_image '面板摘要镜像 repository@sha256:…' ''
  ask release_trust '发行信任文件' "$release_trust"
  ask release_manifest '签名发行清单' /opt/nginxpanel/offline/release-manifest.json
  ask release_signature '签名信封' /opt/nginxpanel/offline/release-manifest.sig
  args+=(--panel-image "$panel_image" --release-trust "$release_trust" --release-manifest "$release_manifest" --release-signature "$release_signature")
  signed=yes
  choose nginx_kind 'Nginx 运行方式（镜像须已在目标准备）' 1 image:配套容器 none:暂不安装 native:本机可信Nginx程序 component:已准备的签名Nginx组件
else
  choose nginx_kind 'Nginx 来源' 1 none:暂不安装，登录后通过组件安装 native:本机可信Nginx程序 component:已准备的签名Nginx组件
fi
case "$nginx_kind" in
  none) args+=(--without-nginx) ;;
  native)
    ask nginx '本机可信 Nginx 程序' /usr/sbin/nginx
    args+=(--nginx-binary "$nginx") ;;
  component)
    ask nginx_plan '签名准备计划 ID' ''
    ask nginx_asset 'Nginx 资产 ID' ''
    if [[ $panel_mode == native ]]; then ask release_trust '发行信任文件' "$release_trust"; args+=(--release-trust "$release_trust"); fi
    args+=(--nginx-plan "$nginx_plan" --nginx-asset "$nginx_asset")
    signed=yes ;;
  image)
    ask nginx_image 'Nginx 摘要镜像 repository@sha256:…' ''
    args+=(--nginx-image "$nginx_image") ;;
esac
if [[ $signed == yes ]] && yes_no '允许已签名的预发行版本？'; then args+=(--release-prerelease); fi
dns_owner=unconfirmed firewall_owner=unconfirmed firewall_ssh=unconfirmed log_owner=unconfirmed
if yes_no '配置主机 DNS、防火墙或日志轮转授权？'; then
  choose dns_owner '主机 DNS 的实际所有者' 1 unconfirmed:未确认，仅查看 regular-file:普通resolv.conf文件 networkmanager:NetworkManager networkd:systemd-networkd netplan:Netplan
  choose firewall_owner '主机防火墙的实际后端（本机规则登记另行完成）' 1 unconfirmed:未确认，仅查看 direct-nftables:直接nftables firewalld:firewalld ufw:UFW iptables-nft:iptables-nft iptables-legacy:iptables-legacy
  if [[ $firewall_owner != unconfirmed ]]; then
    choose firewall_ssh '目标 SSH 服务保护' 1 openssh:保护现有OpenSSH none:已确认没有SSH服务
    args+=(--firewall-owner "$firewall_owner" --firewall-ssh "$firewall_ssh")
  fi
  choose log_owner '本应用 Nginx 日志轮转的唯一所有者' 1 unconfirmed:未确认，仅查看 external:已有外部工具 agent:已排除外部轮转，由Agent管理
fi
args+=(--dns-owner "$dns_owner" --nginx-log-owner "$log_owner")
start=no
if yes_no '安装完成后启用并启动所选服务？Docker 模式同时启动容器'; then start=yes; args+=(--start); fi
printf '\n安装确认\n  部署：%s\n  程序：%s\n  前端：%s\n  数据：%s\n  管理：https://%s\n  Nginx：%s\n  DNS：%s\n  防火墙：%s / SSH：%s\n  日志轮转：%s\n  立即启动：%s\n' "$panel_mode" "$binary" "$web" "$data" "$listen" "$nginx_kind" "$dns_owner" "$firewall_owner" "$firewall_ssh" "$log_owner" "$start"
printf '%s\n' '请确认材料来源。将复制为本机 root 批准材料，调用标准安装器；不修改云安全组或接管其他 Nginx 服务。'
printf '安装参数：'; printf '%q ' "${args[@]}"; printf '\n'
confirm_install

root_chain /opt
if [[ ! -e /opt/nginxpanel && ! -L /opt/nginxpanel ]]; then install -d -m 0755 -o root -g root /opt/nginxpanel; fi
root_chain /opt/nginxpanel
if [[ -e /opt/nginxpanel/.wizard.lock || -L /opt/nginxpanel/.wizard.lock ]]; then trusted_file /opt/nginxpanel/.wizard.lock; fi
exec 8>/opt/nginxpanel/.wizard.lock
flock -n 8 || die '另一个安装向导正在执行'
[[ ! -e $plan && ! -L $plan && ! -e /etc/nginxpanel/install/intent && ! -L /etc/nginxpanel/install/intent ]] || die '安装状态已变化，请重新运行向导核对原安装命令'
stage=$(mktemp -d /opt/nginxpanel/installer-inputs.XXXXXXXX)
install -d -m 0755 "$stage/web" "$stage/deploy/native"
install -m 0555 "$binary" "$stage/nginxpanel"
install -m 0555 "$root/deploy/native/install.sh" "$stage/deploy/native/install.sh"
install -m 0555 "$root/manage.sh" "$stage/manage.sh"
cp -R -- "$web/." "$stage/web/"
chmod -R u=rwX,go=rX "$stage/web"
if [[ -e /opt/nginxpanel/manage.sh || -L /opt/nginxpanel/manage.sh ]]; then
  trusted_file /opt/nginxpanel/manage.sh
  cmp -s "$stage/manage.sh" /opt/nginxpanel/manage.sh || die '已有不同管理脚本，停止覆盖'
else
  install -m 0555 "$stage/manage.sh" /opt/nginxpanel/manage.sh
fi
pending=$(mktemp /opt/nginxpanel/.install-command.XXXXXXXX)
{
  printf '#!/bin/bash\nset -euo pipefail\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C\n'
  printf '%q ' /bin/bash "$stage/deploy/native/install.sh" --binary "$stage/nginxpanel" --web-dir "$stage/web" "${args[@]}"
  printf '\n'
  if [[ $panel_mode == docker && $start == yes ]]; then
    printf '%s\n' 'docker compose -f /etc/nginxpanel/docker/compose.yaml up -d --pull never'
  fi
} >"$pending"
chmod 0500 "$pending"
sync -f "$pending"
mv -T -- "$pending" "$plan"
sync -f /opt/nginxpanel
/bin/bash "$plan"
finish
