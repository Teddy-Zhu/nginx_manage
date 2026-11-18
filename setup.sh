#!/bin/bash
set -euo pipefail
export LC_ALL=C
umask 077

# 发布时固定发行标签；源码入口默认使用官方仓库。
default_repository="Teddy-Zhu/nginx_manage"
default_version="latest"
die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
用法：bash setup.sh [--source | --dev] [--repo owner/repo] [--yes] [--advanced] [--port 端口] [--fresh | --uninstall [--keep-data | --purge]]
默认下载 GitHub Release，自动匹配本机架构，校验 SHA-256 后安装。
--source          拉取源码，通过 Docker 编译并自动安装
--dev             选择最近 100 条发行中适合本机架构的最新 -dev 预发布版
--repo owner/repo 指定其他发行仓库，默认 Teddy-Zhu/nginx_manage
--version 标签    安装指定 Release，支持 v1.2.3 和 v1.2.4-dev
--ref 分支或标签  源码模式指定分支或标签，默认仓库默认分支
--yes             无需交互，确认所选操作（包括完全卸载的数据删除）
--advanced        安装时打开高级设置
--port 端口       指定管理端口，默认随机选择空闲端口并允许外部访问
--fresh           完全卸载旧安装并安装所选源码/Release，永久删除原数据
--uninstall       使用所选源码或 Release 卸载旧安装，默认保留数据，可交互选择清理
--keep-data       明确保留数据卸载；--purge 完全卸载，仅与 --uninstall 一起使用
两种安装方式均需要 Docker 和 Compose；源码方式另需 Git，无需本机 Go 或 Node.js。
需要 root 权限时调用 sudo。私有 Release 可使用已认证的 GitHub CLI。
自动查找 dev 版需要已认证的 GitHub CLI，或 curl 与 jq。
EOF
}
mode=release repository=$default_repository version=$default_version ref= version_override=no dev=no
fresh=no uninstall=no purge=no keep_data=no advanced=no requested_port=
install_args=()
while (($#)); do
  case "$1" in
    --source) mode=source; shift ;;
    --release) mode=release; shift ;;
    --dev) dev=yes; shift ;;
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
dev_tag='^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?-dev$'
if [[ $dev == yes ]]; then
  [[ $mode == release ]] || die '--dev 仅用于 Release 安装；源码安装使用 --ref'
  if [[ $version_override == no ]]; then version=latest; fi
  [[ $version == latest || $version =~ $dev_tag ]] || die '--dev 与 --version 一起使用时须指定 -dev 标签'
fi
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
  command -v docker >/dev/null || die '需要已有 Docker 和 Compose；不会使用宿主机应用部署'
  clone_args=(--depth 1 --single-branch)
  if [[ -n $ref ]]; then clone_args+=(--branch "$ref"); fi
  printf '正在下载源码 %s（%s）…\n' "$repository" "${ref:-默认分支}"
  git clone --quiet "${clone_args[@]}" -- "https://github.com/$repository.git" "$work/source"
  [[ -f $work/source/install.sh && -f $work/source/scripts/build.sh ]] || die '源码缺少安装或 Docker 构建入口'
  run_installer "$work/source"
  exit 0
fi

if command -v gh >/dev/null && { [[ -n ${GH_TOKEN:-} || -n ${GITHUB_TOKEN:-} ]] || gh auth status --hostname github.com >/dev/null 2>&1; }; then
  transport=gh
else
  command -v curl >/dev/null || die 'Release 安装需要 curl 或 GitHub CLI'
  transport=curl
fi

# 固定标签后再下载，确保安装包和校验清单来自同一个发行。
if [[ $version == latest ]]; then
  if [[ $dev == yes ]]; then
    endpoint="repos/$repository/releases?per_page=100"
    filter='map(select(.draft == false and .prerelease == true and (.published_at | type == "string"))
      | select(.tag_name | test("'"$dev_tag"'"))
      | . as $release
      | [.assets[] | select(.state == "uploaded") | .name] as $names
      | select(($names | index("checksums.txt")) != null
          and ($names | index("nginxpanel_" + ($release.tag_name | ltrimstr("v")) + "_linux_'"$arch"'.tar.gz")) != null))
      | max_by(.published_at) | .tag_name // empty'
    if [[ $transport == gh ]]; then
      version=$(gh api "$endpoint" --jq "$filter") || die '无法查询 GitHub dev 发行列表'
    else
      command -v jq >/dev/null || die '自动查找 dev 版需要 jq，也可用 --version 指定标签'
      download "https://api.github.com/$endpoint" "$work/releases.json" $((4 * 1024 * 1024)) || die '无法查询 GitHub dev 发行列表'
      version=$(jq -r "$filter" "$work/releases.json") || die '无法解析 GitHub dev 发行列表'
    fi
    [[ $version =~ $dev_tag ]] || die "近期未找到适用于 Linux/$arch 的 dev 核心发行；可使用 --version 指定标签"
  elif [[ $transport == gh ]]; then
    version=$(gh release view --repo "$repository" --json tagName --jq .tagName) || die '找不到稳定版发行；可使用 --dev 安装开发版或 --source 从源码安装'
  else
    effective=$(curl --fail --silent --show-error --head --location --max-redirs 5 \
      --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 60 \
      --output /dev/null --write-out '%{url_effective}' "https://github.com/$repository/releases/latest") || die '找不到稳定版发行；可使用 --dev 安装开发版或 --source 从源码安装'
    [[ ${effective,,} == "https://github.com/${repository,,}/releases/tag/"* ]] || die '无法解析最新 Release 标签'
    version=${effective##*/}
    version=${version//%2B/+}; version=${version//%2b/+}
  fi
fi
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+-]+)?$ ]] || die '发行标签不是受支持的 v 前缀版本号'
asset=nginxpanel_${version#v}_linux_$arch.tar.gz
printf '正在下载安装包 %s %s（linux/%s）…\n' "$repository" "$version" "$arch"
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
[[ -f $work/package/nginxpanel &&
   -f $work/package/install.sh && -f $work/package/manage.sh &&
   -f $work/package/deploy/native/install.sh && -f $work/package/deploy/native/lifecycle.sh &&
   -f $work/package/containers.json && -f $work/package/container-images.tar ]] || die 'Release 缺少完整安装入口；请使用包含一键安装脚本的新发行或使用源码安装'
printf '%s\n' '安装包校验通过'
run_installer "$work/package"
