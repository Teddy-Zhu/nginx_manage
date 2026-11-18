#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
用法：install.sh --binary /可信目录/nginxpanel --nginx-package /可信安装包 [--data-dir /srv/nginxpanel] [--listen IP:端口] [--protocol http|https] [--start]
管理界面与 Agent 由同一个宿主机服务运行；Nginx 使用预置 Docker 镜像。
推荐运行顶层 install.sh。面板启动后，从软件商店安装 Nginx。
显式预装可使用 --nginx-image 和 --container-manifest 或签名发行材料。

EOF
}
binary= nginx= nginx_plan= nginx_asset= release_trust=/etc/nginxpanel/release-trust.json release_manifest= release_signature= container_manifest= prerelease=no data=/srv/nginxpanel protocol=https listen= start=no nginx_image= nginx_package= dns_owner=auto firewall_owner=auto firewall_ssh=auto nginx_log_owner=agent
while (($#)); do
  case "$1" in
    --binary|--nginx-binary|--nginx-plan|--nginx-asset|--release-trust|--release-manifest|--release-signature|--container-manifest|--data-dir|--listen|--protocol|--nginx-image|--nginx-package|--dns-owner|--firewall-owner|--firewall-ssh|--nginx-log-owner)
      (($# >= 2)) || die "参数缺少值：$1"
      case "$1" in
        --binary) binary=$2 ;; --nginx-binary) nginx=$2 ;;
        --nginx-plan) nginx_plan=$2 ;; --nginx-asset) nginx_asset=$2 ;; --release-trust) release_trust=$2 ;;
        --data-dir) data=$2 ;; --listen) listen=$2 ;; --protocol) protocol=$2 ;;
        --nginx-image) nginx_image=$2 ;;
        --nginx-package) nginx_package=$2 ;;
        --container-manifest) container_manifest=$2 ;;
        --dns-owner) dns_owner=$2 ;;
        --firewall-owner) firewall_owner=$2 ;; --firewall-ssh) firewall_ssh=$2 ;;
        --nginx-log-owner) nginx_log_owner=$2 ;;
        --release-manifest) release_manifest=$2 ;; --release-signature) release_signature=$2 ;;
      esac
      shift 2 ;;
    --release-prerelease) prerelease=yes; shift ;;
    --start) start=yes; shift ;;
    --help) usage; exit 0 ;;
    *) usage; die "未知参数：$1" ;;
  esac
done
[[ $protocol == http || $protocol == https ]] || die "管理协议须为 http 或 https"
[[ $EUID == 0 ]] || die '安装需要本机 root'
[[ ! -e /etc/nginxpanel/install/lifecycle && ! -L /etc/nginxpanel/install/lifecycle ]] || die '已有卸载或重装记录，请使用 manage.sh reinstall 或续办完全卸载'
[[ -n $binary ]] || { usage; exit 1; }
[[ -z $nginx && -z $nginx_plan && -z $nginx_asset ]] || die '不支持宿主机 Nginx 安装，请使用配套 Nginx 镜像'
if [[ -n $nginx_package ]]; then
  [[ -z $nginx_image && -z $container_manifest && -z $release_manifest && -z $release_signature && $prerelease == no ]] || die '延后安装不能混用镜像预装参数'
else
  [[ $nginx_image =~ ^sha256:[0-9a-f]{64}$ || $nginx_image =~ ^[a-z0-9][a-z0-9._:/-]{0,240}@sha256:[0-9a-f]{64}$ ]] || die '须提供 --nginx-package 或 Nginx 固定内容摘要镜像'
  if [[ -n $container_manifest ]]; then
    [[ -z $release_manifest && -z $release_signature && $prerelease == no ]] || die '本地安装包不能混用远程发行材料'
  else
    [[ -n $release_manifest && -n $release_signature ]] || die '须提供完整安装包或签名发行材料'
  fi
fi
for tool in stat readlink install sha256sum cmp sync flock getent groupadd useradd systemctl systemd-tmpfiles mktemp find cut id uname dirname mv ln rm touch chmod od docker; do
  command -v "$tool" >/dev/null || die "缺少已有系统工具：$tool"
done
[[ -d /run/systemd/system ]] || die '仅支持实际运行 systemd 的宿主机'
docker compose version >/dev/null || die 'Nginx 容器管理需要 Docker Compose 插件'
machine=$(uname -m)
case "$machine" in x86_64|aarch64) ;; *) die '仅支持 linux/amd64 与 linux/arm64' ;; esac
[[ $data =~ ^/(srv|var/lib)/[a-zA-Z0-9_-][a-zA-Z0-9_./-]*$ ]] || die '数据目录须位于 /srv 或 /var/lib，且不含空格及控制符'
selinux_profile=disabled
if [[ -e /sys/fs/selinux/enforce ]]; then
  for tool in semodule restorecon matchpathcon; do
    command -v "$tool" >/dev/null || die "SELinux 部署缺少已有系统工具：$tool（policycoreutils）"
  done
  selinux_profile=native
fi

canonical() {
  [[ $1 == /* && $1 != */ && $1 != *//* && $1 != */./* && $1 != */../* && $1 != */. && $1 != */.. ]] || die "路径不是规范绝对路径：$1"
  [[ $1 =~ ^/[a-zA-Z0-9_./@-]+$ ]] || die "路径包含不支持的字符：$1"
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
selinux_context() {
  local path=$1 type=$2 context
  context=$(matchpathcon -n "$path" 9>&-) || die "无法确认 SELinux 默认标签：$path"
  [[ $context == "system_u:object_r:$type:s0" ]] || die "SELinux 标签规则冲突：$path；期望 $type，实际 $context"
}
selinux_install() {
  [[ $selinux_profile != disabled ]] || return 0
  local modules priority name language extra present=no policy=/etc/nginxpanel/selinux/nginxpanel_files.cil
  modules=$(semodule -lfull 9>&-) || die '无法读取 SELinux 模块登记'
  while read -r priority name language extra; do
    if [[ $name == nginxpanel_files ]]; then
      [[ $present == no && $priority == 400 && $language == cil && -z $extra ]] || die '已有冲突或已停用的 nginxpanel_files SELinux 模块'
      present=yes
    fi
  done <<<"$modules"
  if [[ $present == yes ]]; then
    trusted_file "$policy" $((64 * 1024))
    cmp -s "$work/nginxpanel_files.cil" "$policy" || die 'SELinux 模块来源与安装计划不一致'
    mkdir "$work/selinux-current"
    (cd "$work/selinux-current" && semodule -X 400 --cil --extract=nginxpanel_files 9>&-) || die '无法复核已安装的 SELinux 模块'
    cmp -s "$policy" "$work/selinux-current/nginxpanel_files.cil" || die '已安装的 SELinux 模块被外部修改'
  else
    ensure_dir /etc/nginxpanel/selinux 755 root root
    write_owned "$work/nginxpanel_files.cil" "$policy"
    semodule -X 400 --install="$policy" 9>&- || die 'SELinux 文件标签模块安装失败，保留安装记录'
  fi
  selinux_context /opt/nginxpanel usr_t
  selinux_context /etc/nginxpanel etc_t
  selinux_context /run/nginxpanel-host var_run_t
  selinux_context /run/nginxpanel-install var_run_t
  local type=var_lib_t dir unit
  if [[ $selinux_profile == docker ]]; then type=container_file_t; fi
  selinux_context "$data" "$type"
  for dir in app bootstrap secrets staging backups agent acme certificates modules nginx; do
    selinux_context "$data/$dir" "$type"
  done
  if [[ $selinux_profile == native ]]; then
    selinux_context "$data/logs" var_log_t
    selinux_context "$data/run" var_run_t
  else
    selinux_context "$data/logs" "$type"
    selinux_context "$data/run" "$type"
  fi
  if [[ $selinux_profile == native ]]; then type=usr_t; fi
  selinux_context "$data/runtime" "$type"
  selinux_context "$data/bin" "$type"
  for unit in "${reserved_units[@]}"; do
    selinux_context "/etc/systemd/system/$unit" systemd_unit_file_t
  done
  # File contexts persist across relabels; runtime/code descendants inherit an
  # executable type when later versions are published. Never traverse mounts.
  restorecon -RFx /opt/nginxpanel /etc/nginxpanel "$data" /run/nginxpanel-install 9>&- || die 'SELinux 文件标签应用失败'
}
canonical "$data"
binary=$(readlink -e "$binary")
canonical "$binary"
trusted_file "$binary" $((192 * 1024 * 1024))
[[ -x $binary ]] || die '指定面板程序不可执行'
native_elf "$binary"
# Resolve only on the installation host, using the same adapters as the Agent.
# Values are parsed as data; never evaluate detector output as shell code.
if [[ $dns_owner == auto || $firewall_owner == auto || $firewall_ssh == auto ]]; then
  detected=$("$binary" installation-defaults --data-dir "$data") || die '无法检测主机管理环境'
  detected_dns=unconfirmed detected_firewall=unconfirmed detected_ssh=unconfirmed
  while IFS='=' read -r key value; do
    case "$key:$value" in
      dns_owner:unconfirmed|dns_owner:regular-file|dns_owner:networkmanager|dns_owner:networkd|dns_owner:netplan) detected_dns=$value ;;
      firewall_owner:unconfirmed|firewall_owner:direct-nftables|firewall_owner:firewalld|firewall_owner:ufw|firewall_owner:iptables-nft|firewall_owner:iptables-legacy) detected_firewall=$value ;;
      firewall_ssh:unconfirmed|firewall_ssh:openssh|firewall_ssh:none) detected_ssh=$value ;;
      *) die '主机环境检测返回了无效结果' ;;
    esac
  done <<<"$detected"
  if [[ $dns_owner == auto ]]; then dns_owner=$detected_dns; fi
  if [[ $firewall_owner == auto ]]; then firewall_owner=$detected_firewall; fi
  if [[ $firewall_ssh == auto ]]; then
    if [[ $firewall_owner == unconfirmed ]]; then firewall_ssh=unconfirmed; else firewall_ssh=$detected_ssh; fi
  fi
fi
case "$nginx_log_owner" in
  unconfirmed|agent|external) ;;
  *) die 'nginx-log-owner 仅允许 agent、external 或 unconfirmed' ;;
esac
log_agent_flags=
if [[ $nginx_log_owner != unconfirmed ]]; then log_agent_flags="--nginx-log-owner $nginx_log_owner"; fi
dns_agent_flags= dns_write_paths=
case "$dns_owner" in
  unconfirmed) ;;
  regular-file)
    dns_agent_flags='--dns-scope host --dns-owner regular-file'
    # Atomic replacement of resolv.conf requires a writable parent directory.
    dns_write_paths=/etc ;;
  networkmanager) dns_agent_flags='--dns-scope host --dns-owner networkmanager' ;;
  networkd)
    dns_agent_flags='--dns-scope host --dns-owner networkd'
    dns_write_paths=-/etc/systemd/network ;;
  netplan)
    dns_agent_flags='--dns-scope host --dns-owner netplan'
    dns_write_paths='-/etc/netplan -/run/systemd/network -/run/NetworkManager/system-connections' ;;
  *) die 'dns-owner 仅允许 unconfirmed、regular-file、networkmanager、networkd 或 netplan' ;;
esac
firewall_agent_flags= firewall_write_paths= firewall_after=
case "$firewall_owner" in
  unconfirmed|direct-nftables|firewalld|ufw|iptables-nft|iptables-legacy) ;;
  *) die 'firewall-owner 仅允许 unconfirmed、direct-nftables、firewalld、ufw、iptables-nft 或 iptables-legacy' ;;
esac
case "$firewall_ssh" in
  unconfirmed|openssh|none) ;;
  *) die 'firewall-ssh 仅允许 unconfirmed、openssh 或 none' ;;
esac
if [[ $firewall_owner == unconfirmed ]]; then
  [[ $firewall_ssh == unconfirmed ]] || die 'firewall-ssh 须与明确的 firewall-owner 配套使用'
else
  [[ $firewall_ssh != unconfirmed ]] || die '选择 firewall-owner 时须明确 firewall-ssh 为 openssh 或 none'
  firewall_agent_flags="--firewall-scope host --firewall-owner $firewall_owner --firewall-ssh $firewall_ssh"
  case "$firewall_owner" in
    ufw) firewall_write_paths=-/etc/ufw; firewall_after=ufw.service ;;
    firewalld) firewall_after=firewalld.service ;;
  esac
fi
root_chain "${data%/*}"

image_source=()
if [[ -n $nginx_package ]]; then
  canonical "$nginx_package"
  [[ $nginx_package == /opt/nginxpanel/* ]] || die '配套 Nginx 安装包须保留在 /opt/nginxpanel 下'
  root_chain "$nginx_package"
  [[ $binary == "$nginx_package/nginxpanel" ]] || die '须使用安装包中的 nginxpanel 程序'
  trusted_file "$nginx_package/containers.json" $((2 * 1024 * 1024))
  trusted_file "$nginx_package/container-images.tar" $((512 * 1024 * 1024))
  "$binary" container-package-info --manifest "$nginx_package/containers.json" >/dev/null
  image_manifest_hash=$(sha256sum "$nginx_package/containers.json" | cut -d ' ' -f1)
elif [[ -n $container_manifest ]]; then
  canonical "$container_manifest"
  trusted_file "$container_manifest" $((2 * 1024 * 1024))
  image_manifest_hash=$(sha256sum "$container_manifest" | cut -d ' ' -f1)
  image_source=(--container-manifest "$container_manifest")
else
  canonical "$release_trust"; canonical "$release_manifest"; canonical "$release_signature"
  [[ $release_trust == /etc/nginxpanel/* ]] || die '镜像发行信任须位于 /etc/nginxpanel'
  trusted_file "$release_manifest" $((2 * 1024 * 1024))
  trusted_file "$release_signature" 4096
  image_manifest_hash=$(sha256sum "$release_manifest" | cut -d ' ' -f1)
  image_source=(--release-trust "$release_trust" --release-manifest "$release_manifest" --release-signature "$release_signature" --release-manifest-sha256 "$image_manifest_hash")
  if [[ $prerelease == yes ]]; then image_source+=(--release-prerelease); fi
fi
if [[ -n $nginx_image ]]; then
  "$binary" nginx-container-verify --data-dir "$data" --nginx-image "$nginx_image" --launcher-binary "$binary" "${image_source[@]}" >/dev/null
fi

ensure_dir /run/nginxpanel-install 700 root root
exec 9>/run/nginxpanel-install/lock
flock -n 9 || die '另一个安装操作正在执行'
# SELinux tools close this inherited descriptor before changing domains; the
# installer keeps the lock for the entire operation.
ensure_dir /opt/nginxpanel 755 root root
ensure_dir /opt/nginxpanel/releases 755 root root
ensure_dir /opt/nginxpanel/agent-releases 755 root root
ensure_dir /opt/nginxpanel/prepared 755 root root
ensure_dir /opt/nginxpanel/release-downloads 700 root root
ensure_dir /etc/nginxpanel 755 root root
ensure_dir /etc/modules-load.d 755 root root
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
    printf '%s\n' '安装未完成。处理上方错误后，可重新运行安装命令继续。' >&2
  fi
}
trap cleanup EXIT
printf '%s\n' '正在安装面板服务…'
reserved_units=(nginxpanel.service nginxpanel-core-update@.service nginxpanel-nginx-image@.service)
selinux_policy_hash=
if [[ $selinux_profile != disabled ]]; then
  data_pattern=${data//./\\.}
  data_type=var_lib_t code_type=usr_t
  # CentOS 9 resolves /run through the /var/run SELinux path substitution.
  # Cover both spellings of our dedicated runtime directories.
  cat >"$work/nginxpanel_files.cil" <<EOF
(filecon "/opt/nginxpanel(/.*)?" any (system_u object_r usr_t ((s0)(s0))))
(filecon "/etc/nginxpanel(/.*)?" any (system_u object_r etc_t ((s0)(s0))))
(filecon "/run/nginxpanel-host(/.*)?" any (system_u object_r var_run_t ((s0)(s0))))
(filecon "/run/nginxpanel-install(/.*)?" any (system_u object_r var_run_t ((s0)(s0))))
(filecon "/var/run/nginxpanel-host(/.*)?" any (system_u object_r var_run_t ((s0)(s0))))
(filecon "/var/run/nginxpanel-install(/.*)?" any (system_u object_r var_run_t ((s0)(s0))))
(filecon "$data_pattern(/.*)?" any (system_u object_r $data_type ((s0)(s0))))
(filecon "$data_pattern/runtime(/.*)?" any (system_u object_r $code_type ((s0)(s0))))
(filecon "$data_pattern/bin(/.*)?" any (system_u object_r $code_type ((s0)(s0))))
EOF
  if [[ $selinux_profile == native ]]; then
    printf '(filecon "%s/logs(/.*)?" any (system_u object_r var_log_t ((s0)(s0))))\n(filecon "%s/run(/.*)?" any (system_u object_r var_run_t ((s0)(s0))))\n' "$data_pattern" "$data_pattern" >>"$work/nginxpanel_files.cil"
  fi
  for unit in "${reserved_units[@]}"; do
    # CentOS policy aliases /etc/systemd/system to /usr/lib/systemd/system.
    # Keep both exact spellings so the policy lookup covers our own units.
    for unit_dir in /etc/systemd/system /usr/lib/systemd/system; do
      printf '(filecon "%s/%s" any (system_u object_r systemd_unit_file_t ((s0)(s0))))\n' "$unit_dir" "${unit//./\\.}" >>"$work/nginxpanel_files.cil"
    done
  done
  selinux_policy_hash=$(sha256sum "$work/nginxpanel_files.cil" | cut -d ' ' -f1)
fi
binary_hash=$(sha256sum "$binary" | cut -d ' ' -f1)
nginx_hash=
release=$binary_hash
release_dir=/opt/nginxpanel/releases/$release
if [[ -z $listen ]]; then
  if [[ -e $state/intent || -L $state/intent ]]; then
    trusted_file "$state/intent" 4096
    while IFS='=' read -r key value; do
      if [[ $key == listen ]]; then
        [[ -z $listen ]] || die '安装记录存在重复管理地址'
        listen=$value
      fi
    done <"$state/intent"
    [[ -n $listen ]] || die '原安装记录缺少管理地址'
  else
    listen=$("$binary" panel-listen-default) || die '无法选择空闲管理端口'
  fi
fi
[[ $listen =~ ^(\[[0-9a-f:]+\]|[0-9.]+):([0-9]{4,5})$ ]] || die '管理地址须为 IPv4:端口或 [IPv6]:端口'
port=${BASH_REMATCH[2]}
((10#$port >= 1024 && 10#$port <= 65535)) || die '管理端口须为 1024–65535'
"$binary" panel-listen-default --listen "$listen" >/dev/null || die '管理地址无效'
printf 'native-install-v16\npanel_mode=native\ndata=%s\nlisten=%s\nrelease=%s\nnginx_image=%s\nimage_manifest_sha256=%s\nnginx=%s\nnginx_sha256=%s\nnginx_plan=%s\nnginx_asset=%s\nrelease_trust=%s\nprerelease=%s\ndns_owner=%s\nnginx_log_owner=%s\nfirewall_owner=%s\nfirewall_ssh=%s\nselinux_profile=%s\nselinux_policy_sha256=%s\n' "$data" "$listen" "$release" "$nginx_image" "$image_manifest_hash" "$nginx" "$nginx_hash" "$nginx_plan" "$nginx_asset" "$release_trust" "$prerelease" "$dns_owner" "$nginx_log_owner" "$firewall_owner" "$firewall_ssh" "$selinux_profile" "$selinux_policy_hash" >"$work/intent"
if [[ -n $nginx_package ]]; then printf 'nginx_package=%s\n' "$nginx_package" >>"$work/intent"; fi
if [[ -e $state/intent || -L $state/intent ]]; then
  trusted_file "$state/intent" 4096
  cmp -s "$work/intent" "$state/intent" || die '已有不同安装计划；版本更新和路径迁移须走维护流程'
else
  [[ ! -e $data && ! -L $data || -d $data && ! -L $data && -z $(find "$data" -mindepth 1 -maxdepth 1 -print -quit) ]] || die '数据目录非空，禁止将首次安装覆盖到已有数据'
  for unit in "${reserved_units[@]}"; do
    # systemctl show requires an instance when querying a template unit.
    probe_unit=${unit/@.service/@install-check.service}
    load_state=$(systemctl show --property=LoadState --value "$probe_unit") || die "无法检查服务状态：$unit"
    [[ $load_state == not-found ]] || die "已有同名服务，停止接管：$unit"
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
ensure_group nginxpanel-nginx
ensure_user nginxpanel-nginx nginxpanel-nginx
[[ $(id -u nginxpanel-nginx) != 0 ]] || die 'Nginx worker 必须使用专用非 root 账户'
ensure_dir "$data" 755 root root
for dir in app bootstrap secrets staging backups; do ensure_dir "$data/$dir" 700 root root; done
ensure_dir "$data/run" 755 root root
ensure_dir "$data/run/readiness" 700 root root
ensure_dir "$data/run/agent" 700 root root
ensure_dir "$data/agent" 700 root root
ensure_dir "$data/acme" 700 root root
ensure_dir "$data/certificates" 700 root root
ensure_dir "$data/modules" 755 root root
ensure_dir "$data/bin" 755 root root
ensure_dir "$data/bin/components" 755 root root
ensure_dir "$data/nginx" 755 root root
ensure_dir "$data/logs" 755 root root
ensure_dir "$data/runtime" 755 root root
selinux_install

# Build the immutable release off to the side; partial copies never become live.
if [[ ! -e $release_dir && ! -L $release_dir ]]; then
  release_work=$(mktemp -d /opt/nginxpanel/releases/.install.XXXXXXXX)
  chmod 755 "$release_work"
  install -m 755 "$binary" "$release_work/nginxpanel"
  [[ $(sha256sum "$release_work/nginxpanel" | cut -d ' ' -f1) == "$binary_hash" ]] || die '程序复制期间发生变化'
  sync -f "$release_work"
  mv -T "$release_work" "$release_dir"
  release_work=
  sync -f /opt/nginxpanel/releases
fi
trusted_file "$release_dir/nginxpanel" $((192 * 1024 * 1024))
[[ $(sha256sum "$release_dir/nginxpanel" | cut -d ' ' -f1) == "$binary_hash" ]] || die '安装程序副本不匹配'
if [[ -L /opt/nginxpanel/current ]]; then
  [[ $(readlink /opt/nginxpanel/current) == "$data/runtime/current" ]] || die '程序指针已被外部修改'
elif [[ -e /opt/nginxpanel/current ]]; then die '程序指针不是符号链接'
else ln -s "$data/runtime/current" /opt/nginxpanel/current; sync -f /opt/nginxpanel; fi

printf '{"version":1,"modules":[]}\n' >"$work/nginx-modules.json"
write_owned "$work/nginx-modules.json" /etc/nginxpanel/nginx-modules.json
"$release_dir/nginxpanel" panel-native-bind --data-dir "$data" --panel-binary "$release_dir/nginxpanel" --listen "$listen" --protocol "$protocol" --allowed-uid 0 --panel-gid 0 --ipc-gid 0 >"$work/panel-runtime.json"
"$release_dir/nginxpanel" panel-writer-bind --data-dir "$data" --panel-gid 0
printf 'native-install-v16\n' >"$work/ready"
if [[ -e $state/ready || -L $state/ready ]]; then
  trusted_file "$state/ready" 64
  cmp -s "$work/ready" "$state/ready" || die '安装就绪记录不匹配'
else
  if ! "$data/runtime/current/nginxpanel" init --data-dir "$data" >"$work/init.log" 2>&1; then
    cat -- "$work/init.log" >&2
    die '面板初始化失败'
  fi
fi
nginx_agent_flag=--nginx-container
ensure_dir /etc/nginxpanel/docker 755 root root
if [[ -n $nginx_image ]]; then
  "$release_dir/nginxpanel" nginx-container-bind --data-dir "$data" --nginx-image "$nginx_image" --launcher-binary "$release_dir/nginxpanel" --nginx-user nginxpanel-nginx "${image_source[@]}" >"$work/nginx-binding.json"
  if [[ ! -f $state/ready ]]; then
    "$release_dir/nginxpanel" nginx-init --data-dir "$data" "$nginx_agent_flag" --nginx-user nginxpanel-nginx --nginx-modules /etc/nginxpanel/nginx-modules.json
  fi
  "$release_dir/nginxpanel" panel-runtime-compose --data-dir "$data" >"$work/compose.yaml"
  write_owned "$work/compose.yaml" /etc/nginxpanel/docker/compose.yaml 444
fi

# Root services must retain identity switching across systemd's SELinux/seccomp
# setup; NoNewPrivileges still applies to them and their children.
cat >"$work/nginxpanel.service" <<EOF
[Unit]
Description=NginxPanel management service
After=docker.service systemd-tmpfiles-setup.service $firewall_after
Wants=docker.service

[Service]
Type=exec
User=root
AmbientCapabilities=CAP_SETUID
Group=root
UMask=0027
ExecStart=/opt/nginxpanel/current/nginxpanel core --data-dir $data --allowed-uid 0 $nginx_agent_flag --nginx-user nginxpanel-nginx --nginx-modules /etc/nginxpanel/nginx-modules.json --metrics-scope host --component-scope host --maintenance-scope host${log_agent_flags:+ $log_agent_flags}${dns_agent_flags:+ $dns_agent_flags}${firewall_agent_flags:+ $firewall_agent_flags}
Restart=on-failure
RestartSec=3
TimeoutStartSec=180
TimeoutStopSec=45
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$data /run/nginxpanel-host /run/nginxpanel-install /run/ufw.lock /opt/nginxpanel /etc/nginxpanel/docker /etc/systemd/system /etc/modules-load.d -/etc/fail2ban/jail.d $dns_write_paths $firewall_write_paths
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
cat >"$work/nginxpanel-core-update@.service" <<EOF
[Unit]
Description=NginxPanel core update %i
After=network.target

[Service]
Type=exec
User=root
AmbientCapabilities=CAP_SETUID
Group=root
UMask=0077
ExecStart=/opt/nginxpanel/current/nginxpanel core-update-worker --data-dir $data --core-update %i
Restart=no
KillMode=mixed
RuntimeMaxSec=1500
TimeoutStopSec=660
RuntimeDirectory=nginxpanel-install
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$data /opt/nginxpanel /run/nginxpanel-install
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
EOF
cat >"$work/nginxpanel-nginx-image@.service" <<EOF
[Unit]
Description=NginxPanel independent Nginx image replacement %i
After=network.target

[Service]
Type=exec
User=root
AmbientCapabilities=CAP_SETUID
Group=root
UMask=0077
ExecStart=/opt/nginxpanel/current/nginxpanel nginx-image-worker --data-dir $data --nginx-image-operation %i
Restart=no
KillMode=mixed
RuntimeMaxSec=1500
TimeoutStopSec=660
RuntimeDirectory=nginxpanel-install
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$data/agent $data/bin/components $data/acme $data/runtime $data/nginx $data/run $data/logs /etc/nginxpanel/docker /run/nginxpanel-install
InaccessiblePaths=$data/backups
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
EOF
root_chain /etc/systemd/system
# tmpfiles creates the shared root lock directory on boot. Keeping it outside
# the Agent's RuntimeDirectory prevents an Agent restart from replacing locks
# still held by the independent upgrade worker or the installer.
ensure_dir /etc/tmpfiles.d 755 root root
# Even UFW status takes its official lock. Precreate one stable inode so the
# Agent can use the lock without granting write access to the whole /run tree.
if [[ -e /run/ufw.lock || -L /run/ufw.lock ]]; then trusted_file /run/ufw.lock 4096; fi
# Host locks must retain their directory while the Agent is stopped for root CLI operations.
printf 'd /run/nginxpanel-host 0700 root root -\nd /run/nginxpanel-install 0700 root root -\nf /run/ufw.lock 0600 root root -\n' >"$work/nginxpanel.conf"
write_owned "$work/nginxpanel.conf" /etc/tmpfiles.d/nginxpanel.conf
systemd-tmpfiles --create /etc/tmpfiles.d/nginxpanel.conf
install_units=(nginxpanel.service nginxpanel-core-update@.service nginxpanel-nginx-image@.service)
for unit in "${install_units[@]}"; do
  write_owned "$work/$unit" "/etc/systemd/system/$unit"
done
if [[ $selinux_profile != disabled ]]; then
  restorecon -RFx /opt/nginxpanel /etc/nginxpanel "$data" /run/nginxpanel-install 9>&- || die 'SELinux 最终文件标签应用失败'
  for unit in "${install_units[@]}"; do restorecon -F "/etc/systemd/system/$unit" 9>&-; done
fi
systemctl daemon-reload
# Root installation authorizes only our empty namespace; no traffic policy is
# installed and no system firewall manager is enabled or replaced here.
case "$firewall_owner" in
  direct-nftables) "$release_dir/nginxpanel" firewall-init --data-dir "$data" --firewall-scope host >"$work/firewall-registration.json" ;;
  firewalld) "$release_dir/nginxpanel" firewalld-init --data-dir "$data" --firewall-scope host >"$work/firewall-registration.json" ;;
  ufw) "$release_dir/nginxpanel" ufw-init --data-dir "$data" --firewall-scope host >"$work/firewall-registration.json" ;;
  iptables-nft|iptables-legacy) "$release_dir/nginxpanel" iptables-init --data-dir "$data" --firewall-scope host --firewall-backend "$firewall_owner" >"$work/firewall-registration.json" ;;
esac
write_owned "$work/ready" "$state/ready" 600
systemctl --quiet enable nginxpanel.service || die '无法设置面板开机启动'
if [[ $start == yes ]]; then
  printf '%s\n' '正在启动面板服务…'
  if [[ -n $nginx_image ]]; then docker compose -f /etc/nginxpanel/docker/compose.yaml up -d --pull never; fi
  if ! systemctl start nginxpanel.service || ! systemctl is-active --quiet nginxpanel.service; then
    die '面板启动失败。运行 journalctl -u nginxpanel.service -n 50 查看日志。'
  fi
fi
printf '\nNginxPanel 安装完成\n'
if [[ $start == no ]]; then
  printf '%s\n' '  启动面板：sudo systemctl start nginxpanel.service'
fi
if addresses=$("$data/runtime/current/nginxpanel" panel-access-urls --data-dir "$data") && [[ -n $addresses ]]; then
  printf '%s\n' '  面板地址：'
  while IFS= read -r address; do printf '    %s\n' "$address"; done <<<"$addresses"
else
  printf '  面板地址：使用服务器 IP 和端口 %s（%s）\n' "$port" "${protocol^^}"
fi
if [[ -f $data/bootstrap/token ]]; then
  printf '  初始令牌文件：%s/bootstrap/token\n' "$data"
fi
if [[ -x /opt/nginxpanel/manage.sh ]]; then
  printf '%s\n' '  管理命令：sudo bash /opt/nginxpanel/manage.sh'
fi
