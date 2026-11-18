#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
export DOCKER_HOST=unix:///run/docker.sock
unset DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
root=$(cd -- "$(dirname -- "$0")" && pwd -P)
usage() {
  cat <<'EOF'
用法：sudo bash install.sh [--yes] [--advanced] [--port 端口] [--fresh | --uninstall [--keep-data | --purge]]
自动检测本机系统、架构、安装材料、Docker 和管理端口，确认推荐方案后安装面板。
源码目录自动使用 Docker 编译并接续安装，无需手动构建或解包。
--port 指定管理端口；不指定时自动选择随机空闲端口，默认允许外部访问。
--yes 直接确认所选操作（包括完全卸载的数据删除）；--advanced 才逐项调整安装配置。
--fresh 完全卸载旧安装后安装当前源码/安装包，永久删除原数据；适用于尚未使用的环境。
--uninstall 使用当前源码/安装包中的程序检查并卸载旧安装，默认保留数据，--purge 完全卸载。
不会安装宿主机编译工具、自动安装 Docker 或接管已有系统 Nginx。

带参数时转交标准安装器，例如：
sudo bash install.sh --binary /可信目录/nginxpanel --nginx-package /可信安装包 --start
  --protocol http|https     访问协议，默认 https
完整参数：bash deploy/native/install.sh --help
EOF
}
auto_confirm=no advanced=no requested_port= requested_protocol= fresh=no uninstall=no purge=no keep_data=no
while (($#)); do
  case "$1" in
    --yes) auto_confirm=yes; shift ;;
    --advanced) advanced=yes; shift ;;
    --fresh) fresh=yes; shift ;;
    --uninstall) uninstall=yes; shift ;;
    --purge) purge=yes; shift ;;
    --keep-data) keep_data=yes; shift ;;
    --protocol) (($# >= 2)) || die "--protocol 缺少协议"; requested_protocol=$2; [[ $2 == http || $2 == https ]] || die "管理协议须为 http 或 https"; shift 2 ;;
    --port) (($# >= 2)) && [[ -n $2 ]] || die '--port 缺少端口'; requested_port=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      [[ $auto_confirm == no && $advanced == no && -z $requested_port && -z $requested_protocol && $fresh == no && $uninstall == no && $purge == no && $keep_data == no ]] || die '引导入口选项不能与标准安装器参数混用'
      exec /bin/bash "$root/deploy/native/install.sh" "$@" ;;
  esac
done
[[ $fresh == no || $uninstall == no ]] || die '--fresh 和 --uninstall 不能混用'
[[ $purge == no || $uninstall == yes ]] || die '--purge 只能与 --uninstall 一起使用'
[[ $keep_data == no || $uninstall == yes && $purge == no ]] || die '--keep-data 只能与 --uninstall 一起使用，不能与 --purge 混用'
[[ $uninstall == no || $advanced == no && -z $requested_port && -z $requested_protocol ]] || die '卸载不接受 --advanced 或 --port'
if [[ -n $requested_port ]]; then
  [[ $requested_port =~ ^[1-9][0-9]{3,4}$ ]] && ((requested_port >= 1024 && requested_port <= 65535)) || die '端口须为 1024–65535'
fi
[[ $EUID == 0 ]] || die '请在实际部署目标使用 sudo bash install.sh'
if [[ $auto_confirm == no || $advanced == yes ]]; then
  [[ -t 0 && -t 1 ]] || die '交互安装需要终端；使用 --yes 按推荐配置直接安装'
fi
[[ -f $root/deploy/native/install.sh && -f $root/deploy/native/lifecycle.sh && -f $root/manage.sh ]] || die '安装材料不完整，缺少标准安装器或管理脚本'

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
  local answer default=${2:-no} hint='y/N'
  if [[ $default == yes ]]; then hint='Y/n'; fi
  while :; do
    read -r -p "$1 [$hint]: " answer || die '输入已结束，安装取消'
    answer=${answer:-$default}
    case "$answer" in y|Y|yes|YES) return 0 ;; n|N|no|NO) return 1 ;; *) printf '%s\n' '请输入 y 或 n' ;; esac
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
elf_arch() {
  local header low high
  header=$(od -An -tx1 -N6 -- "$1") || return 1
  [[ ${header//[[:space:]]/} == 7f454c460201 ]] || return 1
  read -r low high <<<"$(od -An -tu1 -j18 -N2 -- "$1")"
  [[ $high == 0 ]] || return 1
  case "$low" in 62) printf amd64 ;; 183) printf arm64 ;; *) return 1 ;; esac
}

empty_directory() {
  local entry
  [[ -d $1 && ! -L $1 ]] || return 1
  entry=$(find "$1" -mindepth 1 -maxdepth 1 -printf x -quit) || return 1
  [[ -z $entry ]]
}

install_from_source() {
  command -v docker >/dev/null || die '源码入口需要已有 Docker；无需编译时请使用 setup.sh 下载 Release'
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die '仅支持 amd64 或 arm64 安装目标' ;; esac
  build_work=$(mktemp -d /tmp/nginxpanel-build.XXXXXXXX)
  trap 'rm -rf -- "$build_work"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  /bin/bash "$root/scripts/build.sh" --output-dir "$build_work"
  install -d -m 0700 "$build_work/package"
  tar -xf "$build_work/nginxpanel-linux-$arch.tar" -C "$build_work/package"
  next_args=()
  if [[ $auto_confirm == yes ]]; then next_args+=(--yes); fi
  if [[ $advanced == yes ]]; then next_args+=(--advanced); fi
  if [[ -n $requested_port ]]; then next_args+=(--port "$requested_port"); fi
  if [[ -n $requested_protocol ]]; then next_args+=(--protocol "$requested_protocol"); fi
  if [[ $fresh == yes ]]; then next_args+=(--fresh); fi
  if [[ $uninstall == yes ]]; then next_args+=(--uninstall); fi
  if [[ $purge == yes ]]; then next_args+=(--purge); fi
  if [[ $keep_data == yes ]]; then next_args+=(--keep-data); fi
  /bin/bash "$build_work/package/install.sh" "${next_args[@]}"
  exit 0
}
source_tree=no
if [[ -f $root/scripts/build.sh && -f $root/go.mod && -f $root/web/package.json ]]; then source_tree=yes; fi
if [[ $fresh == yes || $uninstall == yes ]]; then
  [[ $(uname -s) == Linux && -d /run/systemd/system ]] || die '安装目标需要运行 systemd 的 Linux 主机'
  if [[ $uninstall == yes ]]; then
    [[ -e /etc/nginxpanel/install/intent || -L /etc/nginxpanel/install/intent ]] || die '未发现本系统安装记录，无需卸载'
  fi
  # Build/download the new tools before touching the old installation. Normal
  # installation still returns early for an already completed installation.
  if [[ $source_tree == yes ]]; then install_from_source; fi
  if [[ -e /etc/nginxpanel/install/intent || -L /etc/nginxpanel/install/intent ]]; then
    trusted_file /etc/nginxpanel/install/intent
    root_chain /opt
    installer_lifecycle_stage=$(mktemp -d /opt/.nginxpanel-lifecycle.XXXXXXXX)
    trap 'rm -rf -- "$installer_lifecycle_stage"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # A sibling directory survives full removal even when the input package was
    # unpacked under the application's program or data directory.
    cp -R -- "$root/." "$installer_lifecycle_stage/"
    chmod -R u=rwX,go= "$installer_lifecycle_stage"
    for control in install.sh manage.sh deploy/native/install.sh deploy/native/lifecycle.sh; do
      trusted_file "$installer_lifecycle_stage/$control"
    done
    candidate=$installer_lifecycle_stage/nginxpanel
    if [[ ! -f $candidate ]]; then candidate=$installer_lifecycle_stage/bin/nginxpanel; fi
    trusted_file "$candidate"
    [[ -x $candidate ]] || die '安装包缺少可执行程序'
    case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die '仅支持 amd64 或 arm64 安装目标' ;; esac
    [[ $(elf_arch "$candidate") == "$arch" ]] || die '安装包程序与本机架构不匹配'
    removal_args=(uninstall --checker-binary "$candidate")
    if [[ $fresh == yes || $purge == yes ]]; then removal_args+=(--purge); fi
    if [[ $auto_confirm == yes ]]; then removal_args+=(--yes); fi
    /bin/bash "$installer_lifecycle_stage/manage.sh" "${removal_args[@]}"
    if [[ $uninstall == yes ]]; then exit 0; fi
    next_args=()
    if [[ $auto_confirm == yes ]]; then next_args+=(--yes); fi
    if [[ $advanced == yes ]]; then next_args+=(--advanced); fi
    if [[ -n $requested_port ]]; then next_args+=(--port "$requested_port"); fi
  if [[ -n $requested_protocol ]]; then next_args+=(--protocol "$requested_protocol"); fi
    /bin/bash "$installer_lifecycle_stage/install.sh" "${next_args[@]}"
    exit 0
  elif [[ -e /opt/nginxpanel/install-command.sh || -L /opt/nginxpanel/install-command.sh ]]; then
    die '初次安装尚未建立可信安装记录，请先使用原命令完成安装；不能自动清理无绑定的安装材料'
  fi
fi
plan=/opt/nginxpanel/install-command.sh
if [[ -e /etc/nginxpanel/install/lifecycle || -L /etc/nginxpanel/install/lifecycle ]]; then
  trusted_file /etc/nginxpanel/install/lifecycle
  trusted_file /opt/nginxpanel/manage.sh
  [[ -z $requested_protocol ]] || die "已有安装记录；请使用 manage.sh set-protocol 修改协议"
  [[ -z $requested_port ]] || die '重装保留当前端口；重装后使用 manage.sh set-port 修改'
  printf '%s\n' '发现卸载记录，将恢复卸载前版本和配置；版本更新使用面板维护入口。'
  reinstall_args=(reinstall)
  if [[ $auto_confirm == yes ]]; then reinstall_args+=(--yes); fi
  exec /bin/bash /opt/nginxpanel/manage.sh "${reinstall_args[@]}"
fi
if [[ -e $plan || -L $plan ]]; then
  trusted_file "$plan"
  [[ $(stat -c %s "$plan") -le 16384 ]] || die '原安装命令超出读取限制'
  [[ -z $requested_protocol ]] || die "已有安装记录；请使用 manage.sh set-protocol 修改协议"
  [[ -z $requested_port ]] || die '已有安装计划；安装完成后使用 manage.sh set-port 修改端口'
  if [[ -e /opt/nginxpanel/install-complete || -L /opt/nginxpanel/install-complete ]]; then
    trusted_file /opt/nginxpanel/install-complete
    trusted_file /etc/nginxpanel/install/ready
    printf '%s\n' '已安装，未更新程序。保留数据升级使用面板维护入口；尚未使用且允许清空数据时，执行最新源码或安装包中的 install.sh --fresh。'
    finish
    exit 0
  fi
  printf '%s\n' '发现已保存的原安装命令。重复执行保留原参数和节点数据；版本更新请使用面板维护入口。'
  cat -- "$plan"
  confirm_install
  /bin/bash "$plan"
  finish
  exit 0
fi
[[ ! -e /etc/nginxpanel/install/intent && ! -L /etc/nginxpanel/install/intent ]] || die '已有标准安装记录但没有引导安装命令；请用原参数续装，日常管理可运行本目录的 manage.sh'

[[ $(uname -s) == Linux && -d /run/systemd/system ]] || die '安装目标需要运行 systemd 的 Linux 主机'
for tool in stat readlink od find sha256sum timeout systemctl tar mktemp; do
  command -v "$tool" >/dev/null || die "环境检测缺少系统工具：$tool"
done
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die '仅支持 amd64 或 arm64 安装目标' ;; esac
# 源码入口与发行包入口最终使用同一个安装器，构建产物不写回源码树。
if [[ $source_tree == yes ]]; then install_from_source; fi
os_name=Linux
if [[ -r /etc/os-release ]]; then
  while IFS='=' read -r key value; do
    if [[ $key == PRETTY_NAME ]]; then os_name=${value//\"/}; break; fi
  done </etc/os-release
fi
if [[ -f $root/nginxpanel ]]; then binary=$root/nginxpanel; else binary=$root/bin/nginxpanel; fi
docker_ready=no docker_state=未安装
if command -v docker >/dev/null; then
  docker_state='不可用（需要本机 rootful Docker 和 Compose）'
  if [[ -S /run/docker.sock && ! -L /run/docker.sock ]] && timeout 5 docker compose version >/dev/null 2>&1; then
    if docker_info=$(timeout 5 docker info --format '{{.OSType}}|{{.Swarm.LocalNodeState}}|{{json .SecurityOptions}}' 2>/dev/null); then
      if [[ $docker_info == 'linux|inactive|'* && $docker_info != *rootless* ]]; then docker_ready=yes; docker_state=可用; fi
    fi
  fi
fi
[[ $docker_ready == yes ]] || die '需要本机 rootful Docker 和 Compose；不会自动安装 Docker，请先准备 Docker 后重试'
[[ -f $root/containers.json && -f $root/container-images.tar ]] || die '安装包缺少运行镜像，请使用完整 Release 或在源码目录运行 install.sh 重新构建'
"$binary" container-package-info --manifest "$root/containers.json" >/dev/null || die '无法读取配套容器镜像'
data=/srv/nginxpanel data_ready=no
for candidate in /srv/nginxpanel /var/lib/nginxpanel; do
  if (root_chain "${candidate%/*}") 2>/dev/null && \
    { [[ ! -e $candidate && ! -L $candidate ]] || empty_directory "$candidate"; } && \
    { [[ ! -e $candidate ]] || (root_chain "$candidate") 2>/dev/null; }; then
    data=$candidate; data_ready=yes; break
  fi
done
listen_args=()
if [[ -n $requested_port ]]; then listen_args+=(--port "$requested_port"); fi
listen=
if [[ -f $binary && -x $binary && $(elf_arch "$binary") == "$arch" ]]; then
  listen=$("$binary" panel-listen-default "${listen_args[@]}") || die '无法选择管理地址或端口，请检查端口占用和网络配置'
fi
printf '\nNginxPanel 环境检测\n  系统：%s\n  架构：%s\n  Docker：%s\n  部署：宿主机服务\n  数据目录：%s\n  管理监听：%s\n' "$os_name" "$arch" "$docker_state" "$data" "${listen:-安装时自动选择}"
printf '%s\n' '默认自动识别主机网络环境并启用基础管理，安装完成后启动服务。'
custom=$advanced
if [[ ! -f $binary ]]; then
  [[ $custom == yes ]] || die '安装包缺少程序；请使用完整 Release 或在源码目录运行 install.sh'
elif [[ $data_ready == no ]]; then
  [[ $custom == yes ]] || die '默认数据目录均不可用；使用 --advanced 选择新的空目录'
fi
if [[ $custom == yes ]]; then
  ask data '数据目录' "$data"
fi
binary=$(readlink -e -- "$binary") || die '程序路径不存在；请先使用 Docker 构建并传输安装包'
[[ -f $binary && -x $binary ]] || die '程序不可执行'
[[ $(elf_arch "$binary") == "$arch" ]] || die "面板程序与目标 linux/$arch 架构不匹配，请传输正确的安装包"
if [[ -z $listen ]]; then
  listen=$("$binary" panel-listen-default "${listen_args[@]}") || die '无法选择空闲管理端口'
fi
if [[ $custom == yes ]]; then ask listen '管理监听 IP:端口（IPv6 使用 [地址]:端口）' "$listen"; fi
[[ $data =~ ^/(srv|var/lib)/[a-zA-Z0-9_-][a-zA-Z0-9_./-]*$ && $data != */ && $data != *//* && $data != */./* && $data != */../* && $data != */. && $data != */.. ]] || die '数据目录须为 /srv 或 /var/lib 下的规范路径'
[[ $listen =~ ^(\[[0-9a-f:]+\]|[0-9.]+):([0-9]{4,5})$ ]] || die '管理地址须为 IPv4:端口或 [IPv6]:端口'
port=${BASH_REMATCH[2]}
((10#$port >= 1024 && 10#$port <= 65535)) || die '端口须为 1024–65535'
"$binary" panel-listen-default --listen "$listen" >/dev/null || die '管理地址无效'
root_chain "${data%/*}"
[[ ! -e $data && ! -L $data ]] || empty_directory "$data" || die '数据目录不可用或非空，不能首次安装覆盖'

protocol=${requested_protocol:-https}
args=(--data-dir "$data" --listen "$listen" --protocol "$protocol")
dns_owner=auto firewall_owner=auto firewall_ssh=auto log_owner=agent
if [[ $custom == yes ]] && yes_no '手动调整主机网络管理或日志设置？'; then
  choose dns_owner '主机 DNS 的实际所有者' 1 auto:自动识别 unconfirmed:仅查看 regular-file:普通resolv.conf文件 networkmanager:NetworkManager networkd:systemd-networkd netplan:Netplan
  firewall_ssh=unconfirmed
  choose firewall_owner '防火墙管理方式' 1 auto:自动识别 unconfirmed:仅查看 direct-nftables:直接nftables firewalld:firewalld ufw:UFW iptables-nft:iptables-nft iptables-legacy:iptables-legacy
  if [[ $firewall_owner != unconfirmed && $firewall_owner != auto ]]; then
    choose firewall_ssh '目标 SSH 服务保护' 1 openssh:保护现有OpenSSH none:已确认没有SSH服务
  fi
  choose log_owner '网站日志轮转' 1 agent:由本系统管理 external:由已有外部工具管理 unconfirmed:仅查看
fi
if [[ $firewall_owner == auto ]]; then firewall_ssh=auto; fi
args+=(--dns-owner "$dns_owner" --nginx-log-owner "$log_owner" --firewall-owner "$firewall_owner" --firewall-ssh "$firewall_ssh")
start=yes
if [[ $custom == yes ]] && ! yes_no '安装完成后启动管理服务？' yes; then start=no; fi
if [[ $start == yes ]]; then args+=(--start); fi
printf '\n安装确认\n  部署：宿主机服务\n  程序：%s\n  数据：%s\n  管理：%s://%s\n  Nginx：在软件商店手动安装\n  DNS：%s\n  防火墙：%s / SSH：%s\n  日志轮转：%s\n  立即启动：%s\n' "$binary" "$data" "$protocol" "$listen" "$dns_owner" "$firewall_owner" "$firewall_ssh" "$log_owner" "$start"
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
install -d -m 0755 "$stage/deploy/native"
install -m 0555 "$binary" "$stage/nginxpanel"
install -m 0555 "$root/deploy/native/install.sh" "$stage/deploy/native/install.sh"
install -m 0555 "$root/deploy/native/lifecycle.sh" "$stage/deploy/native/lifecycle.sh"
install -m 0555 "$root/manage.sh" "$stage/manage.sh"
install -m 0444 "$root/containers.json" "$stage/containers.json"
install -m 0400 "$root/container-images.tar" "$stage/container-images.tar"
args+=(--nginx-package "$stage")
if [[ -e /opt/nginxpanel/manage.sh || -L /opt/nginxpanel/manage.sh ]]; then
  trusted_file /opt/nginxpanel/manage.sh
  cmp -s "$stage/manage.sh" /opt/nginxpanel/manage.sh || die '已有不同管理脚本，停止覆盖'
else
  install -m 0555 "$stage/manage.sh" /opt/nginxpanel/manage.sh
fi
if [[ -e /opt/nginxpanel/lifecycle.sh || -L /opt/nginxpanel/lifecycle.sh ]]; then
  trusted_file /opt/nginxpanel/lifecycle.sh
  cmp -s "$stage/deploy/native/lifecycle.sh" /opt/nginxpanel/lifecycle.sh || die '已有不同卸载管理脚本，停止覆盖'
else
  install -m 0555 "$stage/deploy/native/lifecycle.sh" /opt/nginxpanel/lifecycle.sh
fi
pending=$(mktemp /opt/nginxpanel/.install-command.XXXXXXXX)
{
  printf '#!/bin/bash\nset -euo pipefail\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DOCKER_HOST=unix:///run/docker.sock\nunset DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION\n'
  printf '%q ' /bin/bash "$stage/deploy/native/install.sh" --binary "$stage/nginxpanel" "${args[@]}"
  printf '\n'
  printf '%s\n' 'install -m 0400 /dev/null /opt/nginxpanel/install-complete' 'sync -f /opt/nginxpanel/install-complete' 'sync -f /opt/nginxpanel'
} >"$pending"
chmod 0500 "$pending"
sync -f "$pending"
mv -T -- "$pending" "$plan"
sync -f /opt/nginxpanel
/bin/bash "$plan"
finish
