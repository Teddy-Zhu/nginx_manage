# 部署指南

[文档首页](README.md) · [使用手册](user-guide.md) · [运维与故障处理](operations.md)

本文从准备安装材料开始，到首次登录并具备创建代理的条件。示例数据目录为 `/srv/nginxpanel`，管理地址为 `127.0.0.1:9443`。安装命令均在实际部署目标执行。

## 1. 选择部署方式

| 方式 | 运行组成 | 需要的材料 |
| --- | --- | --- |
| 原生 | systemd 管理 Web、宿主机 Agent 和可选专用 Nginx | 已批准的 Linux 程序、构建后的前端、安装脚本；选择安装 Nginx 时还需本机可信程序或签名组件 |
| Docker | 容器运行 Web，宿主机运行 Agent；Nginx 可选配套容器 | 同版程序与前端、安装脚本、签名发行清单和签名、本机信任配置、对应架构的摘要镜像 |
| 先装面板 | Web 与 Agent 就绪，Nginx 明确登记为未安装 | 原生或 Docker 面板材料；后续通过组件准备及安装流程补齐 Nginx |

Docker 模式仍会在目标宿主机创建账户、目录、Agent 服务及必要的授权记录。安装器生成专用 Compose；镜像中的 Nginx 模块在构建时准备齐全，运行和迁移时不编译、增装模块。

原生部署管理本应用的专用实例。服务器已有系统 Nginx 时，保留原服务，规划互不冲突的业务端口；需要业务切换时单独安排停机或流量切换。

## 2. 准备目标环境

- 使用受支持的 Linux、amd64 或 arm64 架构，具备 systemd、Bash、GNU coreutils 及 shadow 账户工具。已运行的系统组合见[运行矩阵](support-matrix.md)。
- 使用可通过 SSH 登录并执行 root 管理操作的账户。数据根使用 `/srv/` 或 `/var/lib/` 下的新目录，其父目录须存在并由 root 保护。后文 SSH 转发需本地 SSH 客户端，指纹示例需目标具备 OpenSSL 命令。
- 准备业务所需监听端口、域名与上游地址。云安全组、外部防火墙和域名解析由目标环境管理员配置。
- Docker 模式需要本机 rootful Docker、标准 `/run/docker.sock`、支持 API v1.47 的 Engine，以及 Docker Compose。实际接入仍以安装器的能力检查为准；rootless、Swarm 不提供同等写入能力。
- SELinux 启用时，目标需具备 `semodule`、`restorecon`、`matchpathcon` 及对应策略工具；Docker 模式还需容器策略。安装器登记本应用标签，保留现有防护状态。
- Go、Node.js、pnpm 只在构建环境使用。运行面板无需 Node.js 或独立数据库；启用 Fail2ban 时才需要受支持的宿主机 Python 等依赖。

## 3. 准备程序与前端

### 使用已有安装材料

从受信来源取得与目标架构一致的 `nginxpanel`、前端 `web/` 目录、`deploy/native/install.sh`。前端根目录须含 `index.html` 及配套资源。

签名发行还应取得原始 `release-manifest.json`、`release-manifest.sig` 和所需资产。发布者公钥通过独立渠道核对，按[发行信任说明](releases.md#信任与签名)放入目标 `/etc/nginxpanel/release-trust.json`。离线准备和在线获取均使用该信任。

### 从源码构建原生产物

项目固定工具版本见 `go.mod` 和 `web/package.json`：当前为 Go 1.27.2、Node.js 24、pnpm 10.33.0。以下示例在已有 Docker 的构建环境、项目根目录执行，工具只安装到临时构建容器。

构建前端：

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$(pwd)",dst=/src \
  -w /src -e npm_config_cache=/tmp/npm-cache \
  node:24-bookworm-slim sh -eu -c '
    npm install --prefix /tmp/nginxpanel-build-tools pnpm@10.33.0
    /tmp/nginxpanel-build-tools/node_modules/.bin/pnpm --dir web install --frozen-lockfile --store-dir /tmp/pnpm-store
    /tmp/nginxpanel-build-tools/node_modules/.bin/pnpm --dir web build
  '
```

构建目标 Linux 程序；arm64 目标将变量改为 `arm64`：

```sh
NGINXPANEL_ARCH=amd64
mkdir -p bin
docker run --rm --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$(pwd)",dst=/src \
  -w /src -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$NGINXPANEL_ARCH" \
  -e GOPATH=/tmp/gopath -e GOMODCACHE=/tmp/go-mod -e GOCACHE=/tmp/go-build \
  -e GOTOOLCHAIN=local \
  golang:1.27.2 go build -trimpath -o bin/nginxpanel ./cmd/nginxpanel
```

得到 `bin/nginxpanel` 与 `web/dist/`。将它们和安装脚本通过受信通道传送到目标主机。不同架构的产物分别保存，防止传错。上述本地构建流程用于原生安装；Docker 分支还需要下一节要求的签名镜像及其发行材料。

### 在目标主机批准安装材料

以下假定目标当前目录已具有 `bin/nginxpanel`、`web/dist/` 和 `deploy/native/install.sh`，且来源及传输完整性已经核对。首次创建批准目录：

```sh
sudo install -d -m 0755 /opt/approved/nginxpanel
sudo install -m 0555 bin/nginxpanel /opt/approved/nginxpanel/nginxpanel
sudo install -m 0555 deploy/native/install.sh /opt/approved/nginxpanel/install.sh
sudo cp -R web/dist /opt/approved/nginxpanel/web
sudo chown -R root:root /opt/approved/nginxpanel
sudo chmod -R go-w /opt/approved/nginxpanel
```

安装器要求批准目录及其父目录不可被普通账户写入，程序和前端材料满足文件类型、权限及大小限制。重复部署或更新时使用对应流程，保留原批准材料。

## 4. 安装前确定宿主机管理范围

下列是可选的首次安装参数。安装记录会固定选择，业务页面的功能开关不替代本机授权；安装器成功后使用相同参数续装，改变授权需按对应模块的本机流程处理。

| 参数 | 何时选择 | 默认行为 |
| --- | --- | --- |
| `--dns-owner regular-file` | 确认 DNS 来源为受支持的普通文件 | 未指定时 DNS 只读 |
| `--dns-owner networkmanager` / `networkd` / `netplan` | 确认目标实际由对应管理器管理 DNS | 不安装或切换网络管理器 |
| `--firewall-owner direct-nftables` / `firewalld` / `ufw` / `iptables-nft` / `iptables-legacy` | 明确目标后端，配合 `--firewall-ssh openssh`；确认无 SSH 服务时显式选 `none` | 未指定时只读；后端本机登记另行完成 |
| `--nginx-log-owner agent` | 本应用 Nginx 日志由 Agent 独占轮转，已排除外部规则竞争 | 未指定时轮转只读 |
| `--nginx-log-owner external` | 继续由现有日志工具轮转 | 本应用不修改外部规则 |

首次只使用代理功能时，可保留默认的主机管理范围。后续 DNS、防火墙及 Fail2ban 写入需要各自的所有权检查和授权，见[使用手册](user-guide.md)。

## 5A. 原生安装

目标已有经本机批准的 Nginx 程序时：

```sh
sudo bash /opt/approved/nginxpanel/install.sh \
  --binary /opt/approved/nginxpanel/nginxpanel \
  --web-dir /opt/approved/nginxpanel/web \
  --nginx-binary /usr/sbin/nginx \
  --data-dir /srv/nginxpanel \
  --listen 127.0.0.1:9443 \
  --start
```

`/usr/sbin/nginx` 须替换为目标实际可信程序路径。模块能力以该程序及批准清单为准；需要动态模块时按[原生模块接入](native-modules.md)配置。

目标尚无 Nginx 时，使用：

```sh
sudo bash /opt/approved/nginxpanel/install.sh \
  --binary /opt/approved/nginxpanel/nginxpanel \
  --web-dir /opt/approved/nginxpanel/web \
  --without-nginx \
  --data-dir /srv/nginxpanel \
  --listen 127.0.0.1:9443 \
  --start
```

登录后在“组件准备”取得受信 Nginx 资产，再在“组件安装”按预览确认首次安装；也可由配置迁移显式授权准备与安装。准备资产、安装、启动、开机启用和应用业务配置是分别记录的操作。

安装器创建专用账户、目录、不可变程序副本和 systemd 服务。`--start` 启用并启动所选宿主机服务；不带该参数只准备安装。常用状态查询：

```sh
sudo systemctl status nginxpanel.service nginxpanel-agent.service
```

已安装原生 Nginx 时另查 `nginxpanel-nginx.service`。只有面板的部署不要求 Nginx 服务运行。完整参数和服务说明见[原生安装参考](../deploy/native/README.md)。

## 5B. Docker 安装

先在目标准备同一签名发行的程序、前端、信任配置、原始清单/签名，以及对应架构的 panel 和 Nginx 镜像。镜像使用清单中的完整 `repository@sha256:…` 引用，并已在本机 Docker 中存在；安装器不隐式拉取。

联网获取可按[签名镜像下载](../deploy/docker/README.md#签名镜像下载)使用 `release-image-pull`；离线运输的镜像先由管理员加载，安装时继续验证精确来源与本地内容。镜像内 launcher 须与签名批准的初始程序匹配。

将下面两个镜像占位值替换为签名清单中的实际引用：

```sh
sudo bash /opt/approved/nginxpanel/install.sh \
  --binary /opt/approved/nginxpanel/nginxpanel \
  --web-dir /opt/approved/nginxpanel/web \
  --panel-mode docker \
  --panel-image '<面板镜像仓库>@sha256:<镜像摘要>' \
  --nginx-image '<Nginx镜像仓库>@sha256:<镜像摘要>' \
  --release-trust /etc/nginxpanel/release-trust.json \
  --release-manifest /opt/nginxpanel/offline/release-manifest.json \
  --release-signature /opt/nginxpanel/offline/release-manifest.sig \
  --data-dir /srv/nginxpanel \
  --listen 127.0.0.1:9443 \
  --start

sudo docker compose -f /etc/nginxpanel/docker/compose.yaml up -d
```

仅装容器面板时，以 `--without-nginx` 替换 `--nginx-image …`。也可按参考文档选择宿主机专用 Nginx。

Docker 模式的 `--start` 只启动宿主机服务，容器由生成的 Compose 启动。查询：

```sh
sudo systemctl status nginxpanel-agent.service
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml ps
```

生成配置使用 host network，业务端口直接属于宿主机网络。保留安装器生成的用户、权限、挂载和容器身份约束；运行镜像通过面板维护流程更换。详见[Docker 部署参考](../deploy/docker/README.md)。

## 6. 首次访问与管理员初始化

在自己的电脑建立 SSH 转发，将下例用户名和主机替换为实际值，保持该 SSH 会话：

```sh
ssh -N -L 9443:127.0.0.1:9443 admin@部署主机
```

浏览器访问 `https://127.0.0.1:9443`。本地端口已占用时，例如改成 `-L 19443:127.0.0.1:9443` 并访问 19443。

主入口初始使用本节点生成的自签名证书。通过已认证 SSH 在目标查看证书指纹，核对浏览器展示的同一证书后建立信任：

```sh
sudo openssl x509 \
  -in /srv/nginxpanel/secrets/node-tls/cert.pem \
  -noout -fingerprint -sha256
```

同样在目标读取一次性引导令牌：

```sh
sudo cat /srv/nginxpanel/bootstrap/token
```

在初始化页面填写令牌、管理员用户名和 12–256 字节密码，创建管理员并登录。系统使用单管理员，无默认密码。引导令牌仅用于初始化；私钥、主密钥和登录凭据均按敏感材料保管。

## 7. 配置管理入口

可持续使用 SSH 转发。需要直接远程管理时，在当前节点的“管理入口”：

1. 填写目标实际监听 IP、1024–65535 端口和允许来源 CIDR。
2. 选择沿用/生成独立管理证书，或上传匹配的证书与私钥。
3. 先处理云安全组和外部防火墙；有本应用防火墙策略时，先应用并确认对应允许规则。
4. 提交候选后，通过新地址建立新的 HTTPS 连接，核对证书、登录，并在页面期限内确认。
5. 保留 SSH 与回环入口用于恢复。候选未确认到期时自动恢复原配置。

来源限制使用实际 TCP 对端地址。经过反向代理时，面板看到的是代理来源，应另在代理上限制外部访问。详细确认与本机停用命令见[管理入口](management-listener.md)。

## 8. 开始使用

进入“概览”，核对当前节点、Agent、Nginx 状态及期望/已应用修订。面板能登录只说明管理服务可用；代理服务还需要创建业务配置并应用。

接着按[使用手册的第一个 HTTP 代理](user-guide.md#创建第一个-http-代理)操作。安装失败、Agent 不可用、端口冲突和服务恢复见[运维与故障处理](operations.md)。
