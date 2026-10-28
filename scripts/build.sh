#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法：bash scripts/build.sh [--arch amd64|arm64] [--output-dir 目录] [--version 版本] [--release-tool]
默认自动检测构建机架构，通过 Docker 构建 Linux 安装包，输出 dist/nginxpanel-linux-<架构>.tar。
只有为其他架构机器构建时才需使用 --arch；Docker 须已具备该架构的执行能力。
安装包包含面板和预置常用模块的 Nginx 运行镜像，全部编译在容器内完成。
--release-tool 仅构建发行工具，默认输出 bin/nginxpanel-release。
不调用宿主机 Go、Node.js 或 pnpm，不安装宿主机软件。
EOF
}
die() { printf '%s\n' "$*" >&2; exit 1; }
root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
arch= output= version= target=bundle
while (($#)); do
  case "$1" in
    --arch|--output-dir|--version)
      (($# >= 2)) && [[ -n $2 ]] || die "参数缺少值：$1"
      case "$1" in --arch) arch=$2 ;; --output-dir) output=$2 ;; --version) version=$2 ;; esac
      shift 2 ;;
    --release-tool) target=release-tool; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "未知参数：$1" ;;
  esac
done
if [[ -z $arch ]]; then
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die '请通过 --arch 指定 amd64 或 arm64' ;; esac
fi
case "$arch" in amd64|arm64) ;; *) die '仅支持 amd64 或 arm64' ;; esac
if [[ -z $version ]]; then
  version=$(sed -n 's/^var version = "\([^"]*\)"$/\1/p' "$root/cmd/nginxpanel/main.go")
fi
[[ $version =~ ^[a-zA-Z0-9][a-zA-Z0-9.+-]{0,63}$ ]] || die '版本仅允许字母、数字、点、加号和连字符，最长 64 字符'
command -v docker >/dev/null || die '需要已有 Docker；脚本不会自动安装'
go_version=$(sed -n 's/^toolchain go\([0-9.]*\)$/\1/p' "$root/go.mod")
node_version=$(sed -n 's/^[[:space:]]*"node": "\([0-9]*\)\.x".*/\1/p' "$root/web/package.json")
pnpm_version=$(sed -n 's/^[[:space:]]*"packageManager": "pnpm@\([0-9.]*\)".*/\1/p' "$root/web/package.json")
[[ $go_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && $node_version =~ ^[0-9]+$ && $pnpm_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die '无法读取项目固定工具版本'
if [[ -z $output ]]; then
  if [[ $target == release-tool ]]; then output=$root/bin; else output=$root/dist; fi
fi
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd -P)
[[ $output != *,* && $output != *$'\n'* && $output != *$'\r'* ]] || die '输出路径不能包含逗号或换行'
if [[ $target == release-tool ]]; then
  destination=$output/nginxpanel-release
  exporter=type=local,dest=$output
else
  destination=$output/nginxpanel-linux-$arch.tar
  work=$(mktemp -d)
  trap 'chmod -R u+w -- "$work"; rm -rf -- "$work"' EXIT
  exporter=type=tar,dest=$work/program.tar
fi
printf 'Docker 构建：linux/%s；Go %s；Node %s；pnpm %s\n' "$arch" "$go_version" "$node_version" "$pnpm_version"
docker build --file "$root/deploy/build.Dockerfile" --target "$target" \
  --platform "linux/$arch" \
  --build-arg "GO_VERSION=$go_version" \
  --build-arg "NODE_VERSION=$node_version" \
  --build-arg "PNPM_VERSION=$pnpm_version" \
  --build-arg "BUILD_VERSION=$version" \
  --output "$exporter" "$root"
if [[ $target == bundle ]]; then
  mkdir -p "$work/package"
  tar -xf "$work/program.tar" --no-same-owner --no-same-permissions -C "$work/package"
  bash "$root/scripts/package-containers.sh" "$work/package" "$arch"
  tar -C "$work/package" -cf "$destination" .
fi
printf '构建完成：%s\n' "$destination"
