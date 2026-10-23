#!/bin/bash
set -euo pipefail
export LC_ALL=C
umask 077

# 发布时写入仓库与标签，使下载后的脚本无需再填写来源。
default_repository=""
default_version="latest"
die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
用法：bash setup.sh [--source] [--repo owner/repo] [--yes] [--advanced] [--port 端口] [--fresh | --uninstall [--keep-data | --purge]]
默认下载 GitHub Release，自动匹配本机架构，校验 SHA-256 后安装。
--source          拉取源码，通过 Docker 编译并自动安装
--repo owner/repo 源码脚本未内置仓库时指定；本地仓库可自动读取 origin
--version v1.2.3  安装指定 Release，默认使用脚本所属发行版本
--ref 分支或标签  源码模式指定分支或标签，默认仓库默认分支
--yes             无需交互，确认所选操作（包括完全卸载的数据删除）
--advanced        安装时打开高级设置
--port 端口       指定管理端口，默认随机选择空闲端口并允许外部访问
--fresh           完全卸载旧安装并安装所选源码/Release，永久删除原数据
--uninstall       使用所选源码/Release 的新工具卸载旧安装，默认保留数据
--keep-data       明确保留数据卸载；--purge 完全卸载，仅与 --uninstall 一起使用
Release 安装不需要 Docker/Go/Node.js；源码安装需要 Git 和 Docker。
需要 root 权限时调用 sudo。私有 Release 可使用已认证的 GitHub CLI。
EOF
}
mode=release repository=$default_repository version=$default_version ref= version_override=no
fresh=no uninstall=no purge=no keep_data=no advanced=no requested_port=
install_args=()
while (($#)); do
  case "$1" in
    --source) mode=source; shift ;;
    --release) mode=release; shift ;;
    --repo|--version|--ref)
      (($# >= 2)) && [[ -n $2 ]] || die "参数缺少值：$1"
      case "$1" in --repo) repository=$2 ;; --version) version=$2; version_override=yes ;; --ref) ref=$2 ;; esac
      shift 2 ;;
    --port)
      (($# >= 2)) && [[ $2 =~ ^[1-9][0-9]{3,4}$ ]] && ((10#$2 >= 1024 && 10#$2 <= 65535)) || die '端口须为 1024–65535'
      requested_port=$2; install_args+=(--port "$2"); shift 2 ;;
    --fresh) fresh=yes; install_args+=(--fresh); shift ;;
    --uninstall) uninstall=yes; install_args+=(--uninstall); shift ;;
    --purge) purge=yes; install_args+=(--purge); shift ;;
    --keep-data) keep_data=yes; install_args+=(--keep-data); shift ;;
    --advanced) advanced=yes; install_args+=(--advanced); shift ;;
    --yes) install_args+=(--yes); shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "未知参数：$1" ;;
  esac
done
[[ $fresh == no || $uninstall == no ]] || die '--fresh 和 --uninstall 不能混用'
[[ $purge == no || $uninstall == yes ]] || die '--purge 只能与 --uninstall 一起使用'
[[ $keep_data == no || $uninstall == yes && $purge == no ]] || die '--keep-data 只能与 --uninstall 一起使用，不能与 --purge 混用'
[[ $uninstall == no || $advanced == no && -z $requested_port ]] || die '卸载不接受 --advanced 或 --port'
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || die '请在运行 systemd 的实际 Linux 部署目标执行'
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die '仅支持 amd64 或 arm64 安装目标' ;; esac
for tool in tar sha256sum mktemp stat; do command -v "$tool" >/dev/null || die "缺少系统工具：$tool"; done
if [[ $EUID != 0 ]]; then command -v sudo >/dev/null || die '需要 root 权限，请使用 sudo 或 root 账户执行'; fi
if [[ -z $repository ]] && command -v git >/dev/null && [[ -f ${BASH_SOURCE[0]} ]]; then
  script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  if origin=$(git -C "$script_root" config --get remote.origin.url); then
    case "$origin" in
      https://github.com/*) repository=${origin#https://github.com/} ;;
      git@github.com:*) repository=${origin#git@github.com:} ;;
      ssh://git@github.com/*) repository=${origin#ssh://git@github.com/} ;;
    esac
    repository=${repository%.git}
  fi
fi
[[ $repository =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die '未确定 GitHub 仓库；请使用 --repo owner/repo，或下载 Release 内置仓库的 setup.sh'
[[ $version == latest || $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+-]+)?$ ]] || die 'Release 版本须为 v 开头的版本号'
[[ $mode != source || $version_override == no ]] || die '源码版本使用 --ref 指定，不使用 --version'
if [[ -n $ref ]]; then
  [[ $mode == source && $ref =~ ^[A-Za-z0-9][A-Za-z0-9_./+-]*$ && $ref != *..* ]] || die '--ref 仅用于源码分支或标签'
fi

work=$(mktemp -d /tmp/nginxpanel-setup.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_installer() {
  if [[ $EUID == 0 ]]; then
    /bin/bash "$1/install.sh" "${install_args[@]}"
  else
    sudo /bin/bash "$1/install.sh" "${install_args[@]}"
  fi
}
download() {
  curl --fail --silent --show-error --location --max-redirs 5 \
    --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 \
    --retry 2 --max-filesize "$3" --output "$2" "$1"
}
if [[ $mode == source ]]; then
  command -v git >/dev/null || die '源码安装需要 Git'
  command -v docker >/dev/null || die '源码安装需要已有 Docker；可改用默认 Release 安装'
  clone_args=(--depth 1 --single-branch)
  if [[ -n $ref ]]; then clone_args+=(--branch "$ref"); fi
  printf '拉取源码：%s（%s）\n' "$repository" "${ref:-默认分支}"
  git clone "${clone_args[@]}" -- "https://github.com/$repository.git" "$work/source"
  [[ -f $work/source/install.sh && -f $work/source/scripts/build.sh ]] || die '源码缺少安装或 Docker 构建入口'
  run_installer "$work/source"
  exit 0
fi

# 先固定标签，程序与校验清单始终取自同一发行，避免 latest 切换时混用。
if command -v gh >/dev/null && { [[ -n ${GH_TOKEN:-} || -n ${GITHUB_TOKEN:-} ]] || gh auth status --hostname github.com >/dev/null 2>&1; }; then
  if [[ $version == latest ]]; then version=$(gh release view --repo "$repository" --json tagName --jq .tagName); fi
  transport=gh
else
  command -v curl >/dev/null || die 'Release 安装需要 curl 或 GitHub CLI'
  if [[ $version == latest ]]; then
    effective=$(curl --fail --silent --show-error --head --location --max-redirs 5 \
      --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 60 \
      --output /dev/null --write-out '%{url_effective}' "https://github.com/$repository/releases/latest")
    [[ ${effective,,} == "https://github.com/${repository,,}/releases/tag/"* ]] || die '无法解析最新 Release 标签'
    version=${effective##*/}
    version=${version//%2B/+}; version=${version//%2b/+}
  fi
  transport=curl
fi
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+-]+)?$ ]] || die '发行标签不是受支持的 v 前缀版本号'
asset=nginxpanel_${version#v}_linux_$arch.tar.gz
printf '下载发行：%s %s（linux/%s）\n' "$repository" "$version" "$arch"
if [[ $transport == gh ]]; then
  gh release download "$version" --repo "$repository" --pattern "$asset" --pattern checksums.txt --dir "$work"
else
  base=https://github.com/$repository/releases/download/$version
  download "$base/checksums.txt" "$work/checksums.txt" 16384
  download "$base/$asset" "$work/$asset" $((128 * 1024 * 1024))
fi
[[ -f $work/checksums.txt && $(stat -c %s "$work/checksums.txt") -le 16384 &&
   -f $work/$asset && $(stat -c %s "$work/$asset") -le $((128 * 1024 * 1024)) ]] || die '发行材料缺失或超过大小限制'
expected=
while read -r digest name extra; do
  [[ $name == "$asset" ]] || continue
  [[ -z $expected && -z $extra && $digest =~ ^[0-9a-f]{64}$ ]] || die '发行校验清单包含重复或无效记录'
  expected=$digest
done <"$work/checksums.txt"
[[ -n $expected ]] || die '发行校验清单缺少本机架构安装包'
actual=$(sha256sum -- "$work/$asset"); actual=${actual%% *}
[[ $actual == "$expected" ]] || die '安装包 SHA-256 不匹配，停止安装'

# 仅接收普通文件和目录；在解包前拒绝链接、特殊文件及目录穿越。
tar -tzf "$work/$asset" >"$work/paths"
while IFS= read -r entry; do
  entry=${entry%/}
  [[ $entry =~ ^[A-Za-z0-9_+.-][A-Za-z0-9_./+-]*$ && $entry != *//* &&
     /$entry/ != */../* && /$entry/ != */./* ]] || die '安装包包含非法路径'
done <"$work/paths"
tar -tvzf "$work/$asset" >"$work/types"
while read -r permissions rest; do
  [[ ${permissions:0:1} == - || ${permissions:0:1} == d ]] || die '安装包包含链接或特殊文件'
done <"$work/types"
mkdir -m 0700 "$work/package"
tar -xzf "$work/$asset" --no-same-owner --no-same-permissions -C "$work/package"
[[ -f $work/package/nginxpanel && -f $work/package/web/index.html &&
   -f $work/package/install.sh && -f $work/package/manage.sh &&
   -f $work/package/deploy/native/install.sh && -f $work/package/deploy/native/lifecycle.sh ]] || die 'Release 缺少完整安装入口；请使用包含一键安装脚本的新发行或使用源码安装'
printf '%s\n' '安装包校验完成'
run_installer "$work/package"
