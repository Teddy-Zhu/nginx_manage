#!/bin/bash
set -euo pipefail

[[ $# == 2 ]] || { printf '%s\n' '用法：package-containers.sh 安装包目录 amd64|arm64' >&2; exit 1; }
root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
package=$(cd -- "$1" && pwd -P)
arch=$2
case "$arch" in amd64|arm64) ;; *) exit 1 ;; esac
[[ -f $package/nginxpanel && -f $package/web/index.html && -f $package/LICENSE ]]
[[ $package != *,* && $package != *$'\n'* ]]
[[ ! -e $package/containers.json && ! -e $package/container-images.tar ]]
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/.release/binaries/licenses-$arch" "$work/deploy/docker"
cp -- "$package/nginxpanel" "$work/.release/binaries/nginxpanel-$arch"
cp -- "$package/LICENSE" "$work/.release/binaries/licenses-$arch/"
if [[ -f $package/THIRD_PARTY_NOTICES.txt ]]; then
  cp -- "$package/THIRD_PARTY_NOTICES.txt" "$work/.release/binaries/licenses-$arch/"
fi
cp -- "$root/deploy/docker/nginx-capabilities.json" "$root/deploy/docker/check-nginx-image.sh" "$work/deploy/docker/"
launcher_hash=$(sha256sum -- "$package/nginxpanel"); launcher_hash=${launcher_hash%% *}
images=() tags=()
for component in panel nginx; do
  if [[ $component == panel ]]; then context=$work/.release/binaries; else context=$work; fi
  tag=nginxpanel-build-$component:$arch-$launcher_hash
  docker build --platform "linux/$arch" --load --file "$root/deploy/docker/$component.Dockerfile" \
    --label "org.nginxpanel.launcher.sha256=$launcher_hash" --tag "$tag" "$context"
  tags+=("$tag")
  images+=("$(docker image inspect --format '{{.Id}}' "$tag")")
done
docker run --rm --platform "linux/$arch" --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$package,target=/package" \
  --entrypoint /usr/local/bin/nginxpanel-launcher "${images[0]}" \
  container-package --package-dir /package --panel-image "${images[0]}" --nginx-image "${images[1]}"
docker image save --output "$package/container-images.tar" "${tags[@]}"
