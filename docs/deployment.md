# 部署指南

[文档首页](README.md) · [使用手册](user-guide.md) · [运维与故障处理](operations.md)

常规部署直接使用[一键安装](#3-一键安装)，自动选择本机架构和默认配置；第 4、5 节是手动高级安装参考。示例数据目录为 `/srv/nginxpanel`，管理端口默认随机分配，允许通过机器公网或内网 IP 访问；实际选择以安装摘要及管理脚本 `info` 输出为准。安装命令均在实际部署目标执行。

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

## 3. 一键安装

以下 `OWNER/REPO` 为实际 GitHub 仓库。安装脚本不自动安装 Docker 或宿主机编译工具。

### 从源码安装

目标已有 Git、Docker 和支持 BuildKit 输出的构建能力时：

```sh
git clone https://github.com/OWNER/REPO.git nginxpanel
cd nginxpanel
sudo bash install.sh --yes
```

安装入口自动识别源码目录，在 Docker 内按本机架构构建前后端、解包并接续标准安装器。Go、Node.js、pnpm 版本读取项目配置，无需在宿主机安装；产物使用临时目录，失败即停止，不把编译结果写回源码树。

也可从下面的 Release 下载 `setup.sh` 后运行 `bash nginxpanel-setup.sh --source --yes`，自动拉取仓库默认分支后编译安装；需要指定分支或标签时加 `--ref`。首次发布前可从源码取得 `setup.sh`，使用 `bash setup.sh --source --repo OWNER/REPO --yes`。

### 从 GitHub Release 安装

目标不需要 Docker 或编译工具，只需 curl（或已认证的 GitHub CLI）、tar/gzip 和常规系统工具：

```sh
curl -fL https://github.com/OWNER/REPO/releases/latest/download/setup.sh -o nginxpanel-setup.sh && bash nginxpanel-setup.sh --yes
```

发布脚本自动把仓库与所属标签写入 `setup.sh`，无需重复填写。脚本自动选择 amd64/arm64，固定同一发行标签，下载 `nginxpanel_<版本>_linux_<架构>.tar.gz` 和 `checksums.txt`，核对 SHA-256、归档路径及类型，再解包安装。安装后清理临时下载文件。指定历史发行可加 `--version v1.2.3`；源码目录内执行 `bash setup.sh --yes` 会自动读取 GitHub origin 并取得最新稳定发行。

公开 Release 使用 HTTPS 下载。私有 Release 使用已认证的 `gh`，脚本自动识别现有登录或 `GH_TOKEN` / `GITHUB_TOKEN`，不把令牌写入项目或安装记录；可先用 `gh release download --repo OWNER/REPO --pattern setup.sh --dir .` 取得入口脚本，再运行 `bash setup.sh --yes`。

此入口用于首次安装，首次信任来自所选 GitHub 仓库与下载脚本；SHA-256 用于传输完整性核对。面板包里的安装器、管理脚本和程序同时进入原发行签名清单；需要独立公钥验签时使用[发行准备流程](releases.md#信任与签名)。后续组件与在线更新仍使用既有固定公钥及签名准入。尚未发布新版完整安装包时会明确失败，不使用旧包或转为源码编译。

### 默认配置与高级设置

`--port 23456` 可在源码或 Release 安装时指定管理端口（1024–65535）；省略时由操作系统选择随机空闲端口，首次保存后续装和重启保持。`--yes` 采用推荐配置并直接安装；去掉后仅需核对最终摘要。需要调整路径、部署方式或宿主机授权时使用 `--advanced`，例如 `sudo bash install.sh --advanced`。高级设置需要交互终端。

| 检测项 | 默认推荐 |
| --- | --- |
| 系统与 CPU | 识别运行 systemd 的 Linux 和 amd64/arm64，并核对程序 ELF 架构；错架构包明确拒绝 |
| 安装材料 | 自动识别解压包的程序和前端目录 |
| 部署方式 | 本机 rootful Docker/Compose 可用、发现唯一匹配程序摘要的面板镜像且发行材料齐全时推荐 Docker；其余推荐原生 |
| Nginx | Docker 方案优先匹配的固定模块镜像，其次使用检测到的可信本机程序；没有可用来源时先装面板，登录后补齐组件 |
| 数据目录 | 优先 `/srv/nginxpanel`；不可用时尝试 `/var/lib/nginxpanel`，已有数据不覆盖 |
| 管理入口 | 默认 `[::]:随机空闲端口`，支持 IPv4/IPv6；内核不支持 IPv6 时使用 `0.0.0.0:随机空闲端口`，允许外部访问 |
| 启动与主机授权 | 默认启用并启动服务；DNS、防火墙及日志轮转默认只读 |

高级设置沿用检测结果作为默认值；缺少或有多个候选的镜像引用需要明确选择。检测只发现材料和基本能力，最终签名、镜像内容及运行能力仍由标准安装器校验。只访问目标本机 Docker，不沿用指向其他主机的 Docker context。没有可用 Nginx 时先装面板，代理流量须待 Nginx 组件安装并应用配置后才可用。

交互模式最后输入 `INSTALL` 执行；`--yes` 跳过该确认。安装器将材料复制到 root 保护目录，复用标准安装器的账户、路径、签名、架构及服务检查。Docker 所需镜像必须已准备到目标，运行和部署时不动态编译或增装 Nginx 模块。

默认立即启动：原生启用并启动对应服务；Docker 在启用并启动宿主机服务后执行生成 Compose 的 `up -d --pull never`。高级设置可关闭立即启动，之后可用管理脚本执行 `start all`；它只启动服务，systemd 开机启用状态由管理员另行设置。完成后用 `sudo bash /opt/nginxpanel/manage.sh` 打开管理菜单，再按第 6 节首次登录。

原安装命令保存在 `/opt/nginxpanel/install-command.sh`。失败后保留材料，重新运行向导可核对并明确重试原命令；它沿用原参数，不能用于变更版本、数据目录或既定授权。安装及容器启动步骤完成后记录 `/opt/nginxpanel/install-complete`，再次执行引导入口只显示当前信息，保留后来修改的端口和配置。已有非引导安装使用原参数续装。使用向导时，由向导完成材料批准和后续安装；下节说明手动参数安装方式。

管理菜单支持保留数据卸载、完全卸载和重新安装，命令分别为 `manage.sh uninstall --keep-data`、`manage.sh uninstall --purge`、`manage.sh reinstall`。保留数据卸载后，安装入口会识别卸载记录并恢复原版本、配置和服务状态；完全卸载后可全新安装。清理范围、前置处理及中断续办见[运维说明](operations.md#卸载与重新安装)。

### 旧版本卸载与未使用环境更新

源码目录的更新只更新源码，已安装程序仍由运行绑定选择；重复运行普通 `install.sh` 不更新程序。尚未使用、允许删除原数据时，在部署机同步最新源码后执行：

```sh
git pull --ff-only
sudo bash install.sh --fresh
```

`--fresh` 先在 Docker 中编译当前源码，再以新工具检查旧安装、完全卸载并安装新版本。旧账号、配置、密钥、证书和备份全部删除，重新生成初始化信息及随机管理端口；指定端口可加 `--port 23456`。交互时先确认完全卸载，再核对新安装摘要；`--yes` 明确确认整个过程。已有业务数据时使用面板及 Agent 的[维护更新流程](operations.md#组件准备与更新)。

旧程序缺少 `installation-removal-check` 时，也可只卸载：

```sh
sudo bash install.sh --uninstall --keep-data
# 或完全卸载
sudo bash install.sh --uninstall --purge
```

以上命令从最新源码或完整安装包执行，使用包内新程序做检查；源码入口自动用 Docker 编译，安装包无需编译。保留数据卸载仍保存旧版本的重装材料，`reinstall` 恢复原版本。任务、主机规则、绑定或权限不满足时明确停止，保留具体错误。

使用已发布的新 Release 时，对新版 `setup.sh` 执行 `bash setup.sh --version latest --fresh`，或 `bash setup.sh --version latest --uninstall --purge`。也可加 `--source` 拉取默认分支后容器编译；该模式用 `--ref` 选择源码版本，不与 `--version` 混用。发行尚未包含这些入口时使用最新源码。

### 离线构建与手动安装材料

仅需构建、不在构建机安装时，运行 `bash scripts/build.sh` 或 `make build`。Docker 在构建机架构上交叉编译，无需模拟器；构建机与部署目标架构不同才需指定 `--arch arm64`。

将生成的 `dist/nginxpanel-linux-<架构>.tar` 传到目标并解包，运行包内的 `sudo bash install.sh --yes` 即可。包内包含程序、前端、引导入口和管理脚本。手动签名准备还需原始清单、签名及独立核对公钥的本机信任配置，详见[发行信任说明](releases.md#信任与签名)。

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

在目标执行：

```sh
sudo bash /opt/nginxpanel/manage.sh info
```

手动参数安装时，可在可信安装包目录运行 `sudo bash manage.sh info`。输出当前生效的监听地址、机器实际 IP 对应的 HTTPS 地址、可选 SSH 转发命令及令牌/证书路径。浏览器直接打开其中管理电脑可达的公网或内网地址；IPv6 使用 `https://[机器IPv6]:端口`。`0.0.0.0` 和 `::` 表示全部网卡，不能作为浏览器目标地址。公网 IP 在 NAT 网关上时，使用其公网 IP 与映射端口。

云安全组、主机或外部防火墙需允许该 TCP 端口。安装器不会自动改写已有防火墙策略；不能直接访问时，可使用 `info` 输出的 SSH 转发命令。数据目录可能选择 `/var/lib/nginxpanel`，以实际输出为准。

安装后修改主入口端口：

```sh
sudo bash /opt/nginxpanel/manage.sh set-port 23456
# 非交互执行：
sudo bash /opt/nginxpanel/manage.sh set-port 23456 --yes
```

也可在管理菜单选择“修改主入口端口”。先确保新端口已允许访问；脚本检查端口范围与实际绑定占用，持久保存运行绑定，只重启原本正在运行的面板，停止状态保持。存在维护任务、持久停机或恢复屏障时拒绝修改；端口绑定失败保留原配置，其他写入或启动错误按提示核对当前配置并处理。后续 `info` 显示新端口。

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

主入口默认已支持外部访问。“管理入口”页面管理额外的独立监听，其允许来源与证书仅作用于附加入口，不限制主入口。需要只通过受控入口远程访问时，首次安装用 `--advanced` 将主入口绑定 `127.0.0.1:端口` 或 `[::1]:端口`，保留 SSH 转发，再配置附加入口：

1. 填写目标实际监听 IP、1024–65535 端口和允许来源 CIDR。
2. 选择沿用/生成独立管理证书，或上传匹配的证书与私钥。
3. 先处理云安全组和外部防火墙；有本应用防火墙策略时，先应用并确认对应允许规则。
4. 提交候选后，通过新地址建立新的 HTTPS 连接，核对证书、登录，并在页面期限内确认。
5. 保留 SSH 与主入口用于恢复。候选未确认到期时自动恢复原配置。

来源限制使用实际 TCP 对端地址。经过反向代理时，面板看到的是代理来源，应另在代理上限制外部访问。详细确认与本机停用命令见[管理入口](management-listener.md)。

## 8. 开始使用

进入“概览”，核对当前节点、Agent、Nginx 状态及期望/已应用修订。面板能登录只说明管理服务可用；代理服务还需要创建业务配置并应用。

接着按[使用手册的第一个 HTTP 代理](user-guide.md#创建第一个-http-代理)操作。安装失败、Agent 不可用、端口冲突和服务恢复见[运维与故障处理](operations.md)。
