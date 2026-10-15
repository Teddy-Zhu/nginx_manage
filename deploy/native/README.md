# 原生 systemd 安装

此入口为 Debian/Ubuntu 等使用 systemd、GNU coreutils 和 shadow 账户工具的 Linux 宿主机准备首次安装，支持 amd64/arm64。安装器及生成的服务尚未执行，语法、权限、实际系统及故障恢复验证统一留到 P5；目前不作为已验收发行包。

将配套后端二进制、构建后的前端和本机批准的 Nginx 放在 root 所有、上层目录不可被普通账户写入的目录。源文件必须是无硬链接的普通文件；Nginx 程序可通过系统路径的符号链接指定，安装时解析并固定实际路径。安装器检查 ELF 架构并对复制内容计算/复核散列。它只接收本机批准的产物，不下载、编译或自动安装系统包；面板产物自身仍须本机批准；签名 Nginx 可直接通过下述计划/资产入口安装，散列本身不证明发布者身份。

已签名资产可先通过 [离线发行准备](../../docs/releases.md) 验证本机固定公钥、依赖闭包及归档，再将准备目录里的 panel 程序和 web 目录作为本安装入口的输入。验证工具本身仍需本机批准，不能先执行未知下载程序来建立其自身信任；在线检查/准备见同一发行文档，运行中组件升级与面板更新继续实施。

```sh
sudo bash deploy/native/install.sh \
  --binary /opt/approved/nginxpanel/nginxpanel \
  --web-dir /opt/approved/nginxpanel/web \
  --nginx-binary /usr/sbin/nginx \
  --data-dir /srv/nginxpanel \
  --listen 127.0.0.1:9443
```

数据目录只接受 `/srv/` 或 `/var/lib/` 下的规范路径，父目录须已存在且受 root 保护。已有非空目录、同名外部服务、不同安装计划或权限冲突会停止安装。安装入口不是旧数据接管器，也不用于升级或更换数据根。

后端及前端按内容散列存入 `/opt/nginxpanel/releases/<digest>`，复制完整并复核后在同一文件系统中发布，通过 root 所有的 `current` 指针接入。前端拒绝链接、设备和不规范路径，最多 4096 项、12 层、每文件 8 MiB、合计 64 MiB。程序、清单、unit 和本机安装记录均由 root 持有。

## 身份和目录

| 范围 | 所有者与权限 |
| --- | --- |
| 数据根 | root，0755；业务用户不能替换其子目录 |
| app、bootstrap、secrets、staging | nginxpanel，0700；SQLite、主密钥、管理 TLS、引导令牌由 Web 身份初始化 |
| agent、acme、certificates | root，0700；执行日志、恢复记录、HTTP-01 租约及发布证书材料 |
| modules、nginx、logs、run | root；Nginx 临时目录另由执行器授予独立 worker |
| run/agent | root:nginxpanel-ipc，2750；Agent socket 为 0660，Web 通过服务的补充组访问 |

创建 `nginxpanel` 和 `nginxpanel-nginx` 两个不同的无登录账户，以及独立 IPC 组。安装器拒绝复用不匹配的账户、带额外授权的身份或已有外部成员的组。不会递归 chown 数据根，也不会把 root 执行目录授予 Web。

`nginx-init` 仅准备无站点基线，固定 worker、prefix 与配置入口；不会接管发行版 `nginx.service`。业务端口在后续保存并应用站点时才启用。动态模块默认批准清单为空；已有系统实例按本机 root 的受信清单接入，参见 [模块接入](../../docs/native-modules.md)。Docker 仍使用构建时预置模块策略。

## 服务与启动

安装生成 `nginxpanel-nginx.service`、`nginxpanel-agent.service` 和 `nginxpanel.service`。Nginx 独立前台运行，由 systemd 跟踪 master；退出使用 QUIT 和有限宽限期。面板、Agent 或其更新不会因服务依赖而停止正在代理流量的 Nginx。应用发布及运行确认仍由 Agent 完成。

Web 无 Linux capabilities，只能写四个业务目录；root Agent 可写固定执行目录，无法读取业务主密钥目录。三个服务使用只读系统挂载与独立临时目录，Web 保持回环 HTTPS，Agent 仅开放本地 Unix socket 并核对 Web UID。初始化输出 TLS 指纹和引导令牌文件位置，不输出令牌内容。

默认只准备文件并执行 `daemon-reload`。本机管理员可在安装命令中加 `--start` 启用并启动三个服务，或在检查配置后执行：

```sh
sudo systemctl enable nginxpanel-nginx.service nginxpanel-agent.service nginxpanel.service
sudo systemctl start nginxpanel.service
sudo systemctl status nginxpanel.service nginxpanel-agent.service nginxpanel-nginx.service
```

服务进入 active 只说明进程受 systemd 管理，不能代替 API、权限、Nginx 应用和故障恢复验收。首次管理员配置使用 `<DATA_DIR>/bootstrap/token`。远程访问仍通过已有 SSH/VPN/受保护代理，当前入口不开放公网监听。

主机指标来源显式为 host；DNS 接管和日志轮转所有者默认 unconfirmed。启用主机 DNS 写入还须本机确认实际所有者、宿主机范围并调整 Agent unit 的固定写入目录，不能只在业务页面绕过系统沙箱。networkd 写入及其完整恢复仍待实现；其 `RevertDNS` 会清除其他 DNS 运行时覆盖，不能将回写服务器地址视为完整回滚，见 [systemd 源码](https://github.com/systemd/systemd/blob/v257/src/network/networkd-link-bus.c)。

安装意图和完成标记保存在 `/etc/nginxpanel/install/`。失败保留账户、节点数据和记录，使用相同产物及参数重试；成功复制前不切换程序，配置文件通过同目录暂存和 rename 发布，不覆盖不同的现存内容。源产物变化、外部修改或服务启动失败须先检查原因，不能删除意图文件伪装成新安装。更新、卸载清理、签名发布、可信组件自动准备及完整 Docker 接入仍在后续范围内。

组件准备由原生 Agent 的 `--component-scope host` 启用，发行信任须由本机 root 配置，见 [发行准备](../../docs/releases.md)。安装器预建 `/opt/nginxpanel/prepared`（0755）及 `/opt/nginxpanel/release-downloads`（0700），并仅向 Agent unit 开放这两个额外写目录。缺少有效信任时页面报告不可用，不创建默认发布者。原生首次安装通过下述绑定接入，Web 安装和运行中版本切换仍待后续流程。

## 使用签名 Nginx 组件首次安装

先通过 `release-fetch` 或离线 `release-prepare` 准备 Nginx 资产，记录返回的 plan ID 和明确的 Nginx asset ID。安装器将 `--nginx-binary` 替换为二者，信任默认取 `/etc/nginxpanel/release-trust.json`；其他信任文件也须位于 `/etc/nginxpanel/`。预发布组件须额外传 `--release-prerelease`。安装入口只接受单一 Nginx 资产，不隐式安装 Fail2ban 或系统依赖。

```sh
sudo bash deploy/native/install.sh \
  --binary /opt/approved/nginxpanel/nginxpanel \
  --web-dir /opt/approved/nginxpanel/web \
  --nginx-plan '<已准备的64位计划ID>' \
  --nginx-asset '<清单中的Nginx资产ID>' \
  --data-dir /srv/nginxpanel
```

`component-path` 在写入前核验签名/平台/完整回执/系统运行文件并读取实际 Nginx 版本；安装器不执行归档中的脚本。`component-bind` 将确定的程序、内容散列、版本及签名计划以 root 只读记录写入 `<DATA_DIR>/bin/components/nginx.json`；已有不同绑定直接停止，只允许同一计划续装。本机批准的现有 Nginx 同样登记固定内容散列，服务隔离的用户目录不能作为程序来源。

Nginx 的两个 unit 入口改用 `nginx-runtime`，校验配置后通过 exec 进入 Nginx，保持 systemd 跟踪的 master PID；Agent 使用 `--nginx-binding` 解析同一记录。签名组件每次启动都在无网络、无缓存写入的路径重新核验产物及运行依赖；当前公钥仍须信任签名，文件改动/缺失/运行文件漂移会拒绝启动，不回退系统程序。清单过期限制新安装，已批准安装按本机批准时间复核；新增无关公钥不破坏既有有效回执，撤销签名公钥或修改仓库则阻止后续启动。

安装、启动及运行确认仍分开：默认不启用服务，`--start` 才启动；组件页面展示已登记来源、版本、散列及实际运行确认。首次安装不会切换正在运行的实例；在线升级、维护锁和失败恢复仍须后续流程。此入口及服务沙箱尚未实际运行，待 P5 集中验证。
