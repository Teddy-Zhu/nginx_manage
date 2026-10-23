# 部署指南

[文档首页](README.md) · [使用手册](user-guide.md) · [运维与故障处理](operations.md)

本文从准备安装材料开始，到首次登录并具备创建代理的条件。示例数据目录为 `/srv/nginxpanel`，管理地址为 `127.0.0.1:9443`；自动安装的实际选择以向导摘要及管理脚本 `info` 输出为准。安装命令均在实际部署目标执行。

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

从受信来源取得与目标架构一致的程序、前端和安装脚本。使用本项目的 Docker 构建包时，包内已包含 `nginxpanel`、`web/`、引导入口 `install.sh`、管理入口 `manage.sh` 和标准安装器；前端根目录含 `index.html` 及配套资源。

签名发行还应取得原始 `release-manifest.json`、`release-manifest.sig` 和所需资产。发布者公钥通过独立渠道核对，按[发行信任说明](releases.md#信任与签名)放入目标 `/etc/nginxpanel/release-trust.json`。离线准备和在线获取均使用该信任。

### 从源码构建原生产物

在已有 Docker、支持 BuildKit 输出的构建机，从项目根执行。脚本读取 `go.mod` 和 `web/package.json` 中的固定版本，Go、Node.js、pnpm 及依赖均在容器内使用；源码通过构建上下文复制，宿主机仅接收输出产物。

```sh
bash scripts/build.sh
```

`make build` 调用同一脚本，默认自动检测构建机架构，无需指定 `--arch`。只有构建机与部署目标架构不同，才使用 `bash scripts/build.sh --arch arm64` 或 `make build ARCH=arm64` 指定目标。跨架构编译在构建机原生容器内完成，无需在宿主机配置模拟器。

产物为 `dist/nginxpanel-linux-amd64.tar` 或 `dist/nginxpanel-linux-arm64.tar`。可使用 `--output-dir` 指定输出目录、`--version` 注入本机批准的版本标识；首次构建需要下载工具镜像和依赖，缓存由 Docker 管理。本地构建包用于本机批准的原生安装，属于源码构建材料；Docker 部署仍需同版签名发行、批准镜像及其信任材料。

### 启动安装向导

将生成的安装包传到目标主机并解压。以下假定传输目录只包含本次安装包：

```sh
mkdir -p ~/nginxpanel-install
tar -xf /传输目录/nginxpanel-linux-*.tar -C ~/nginxpanel-install
cd ~/nginxpanel-install
sudo bash install.sh
```

无需指定系统、架构、程序路径或部署参数。向导先检测本机环境，展示推荐方案；在“调整推荐配置或主机授权”处直接回车即可沿用。

| 检测项 | 默认推荐 |
| --- | --- |
| 系统与 CPU | 识别运行 systemd 的 Linux 和 amd64/arm64，并核对程序 ELF 架构；错架构包明确拒绝 |
| 安装材料 | 自动识别解压包的程序和前端目录 |
| 部署方式 | 本机 rootful Docker/Compose 可用、发现唯一匹配程序摘要的面板镜像且发行材料齐全时推荐 Docker；其余推荐原生 |
| Nginx | Docker 方案优先匹配的固定模块镜像，其次使用检测到的可信本机程序；没有可用来源时先装面板，登录后补齐组件 |
| 数据目录 | 优先 `/srv/nginxpanel`；不可用时尝试 `/var/lib/nginxpanel`，已有数据不覆盖 |
| 管理端口 | 优先 `127.0.0.1:9443`，已占用时从 9444–9463 选择空闲 TCP 端口 |
| 启动与主机授权 | 默认启用并启动服务；DNS、防火墙及日志轮转默认只读 |

需要自定义时进入高级设置，检测结果仍作为默认值；缺少或有多个候选的镜像引用需要明确选择。检测只发现材料和基本能力，最终签名、镜像内容及运行能力仍由标准安装器校验。只访问目标本机 Docker，不沿用指向其他主机的 Docker context。

最后核对摘要和实际参数，输入 `INSTALL` 执行。向导将所选材料复制到 root 保护目录，复用标准安装器的账户、路径、签名、架构及服务检查。Docker 所需镜像必须已准备到目标，不在目标编译或动态增装 Nginx 模块。

默认立即启动：原生启用并启动对应服务；Docker 在启用并启动宿主机服务后执行生成 Compose 的 `up -d --pull never`。高级设置可关闭立即启动，之后可用管理脚本执行 `start all`；它只启动服务，systemd 开机启用状态由管理员另行设置。完成后用 `sudo bash /opt/nginxpanel/manage.sh` 打开管理菜单，再按第 6 节首次登录。

原安装命令保存在 `/opt/nginxpanel/install-command.sh`。失败后保留材料，重新运行向导可核对并明确重试原命令；它沿用原参数，不能用于变更版本、数据目录或既定授权。已有非引导安装使用原参数续装。使用向导时，由向导完成材料批准和后续安装；下节说明手动参数安装方式。

### 在目标主机批准安装材料

以下假定当前目录为安装包解压目录，具有 `nginxpanel`、`web/` 和 `deploy/native/install.sh`，且来源及传输完整性已经核对。首次创建批准目录：

```sh
sudo install -d -m 0755 /opt/approved/nginxpanel
sudo install -m 0555 nginxpanel /opt/approved/nginxpanel/nginxpanel
sudo install -m 0555 deploy/native/install.sh /opt/approved/nginxpanel/install.sh
sudo cp -R web /opt/approved/nginxpanel/web
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

标准安装器 Docker 模式的 `--start` 只启动宿主机服务，手动安装再由生成的 Compose 启动容器；引导安装在选中立即启动后会完成这一步。查询：

```sh
sudo systemctl status nginxpanel-agent.service
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml ps
```

生成配置使用 host network，业务端口直接属于宿主机网络。保留安装器生成的用户、权限、挂载和容器身份约束；运行镜像通过面板维护流程更换。详见[Docker 部署参考](../deploy/docker/README.md)。

## 6. 首次访问与管理员初始化

引导安装先在目标执行 `sudo bash /opt/nginxpanel/manage.sh info`，取得实际 SSH 转发命令、令牌与证书路径。向导可能避让已占用端口或改用 `/var/lib/nginxpanel`，以下默认示例需按该输出替换。

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
