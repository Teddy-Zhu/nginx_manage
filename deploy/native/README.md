# 原生 systemd 安装

此入口为 Debian/Ubuntu 等使用 systemd、GNU coreutils 和 shadow 账户工具的 Linux 宿主机准备首次安装，支持 amd64/arm64。安装器及生成的服务尚未执行，语法、权限、实际系统及故障恢复验证统一留到 P5；目前不作为已验收发行包。

将配套后端二进制、构建后的前端，以及选择同时安装时所需的本机批准 Nginx 放在 root 所有、上层目录不可被普通账户写入的目录。源文件必须是无硬链接的普通文件；Nginx 程序可通过系统路径的符号链接指定，安装时解析并固定实际路径。安装器检查 ELF 架构并对复制内容计算/复核散列。它只接收本机批准的产物，不下载、编译或自动安装系统包；面板产物自身仍须本机批准；签名 Nginx 可直接通过下述计划/资产入口安装，散列本身不证明发布者身份。

已签名资产可先通过 [离线发行准备](../../docs/releases.md) 验证本机固定公钥、依赖闭包及归档，再将准备目录里的 panel 程序和 web 目录作为本安装入口的输入。验证工具本身仍需本机批准，不能先执行未知下载程序来建立其自身信任；在线检查/准备见同一发行文档，运行中组件升级与面板更新继续实施。

```sh
sudo bash deploy/native/install.sh \
  --binary /opt/approved/nginxpanel/nginxpanel \
  --web-dir /opt/approved/nginxpanel/web \
  --nginx-binary /usr/sbin/nginx \
  --data-dir /srv/nginxpanel \
  --listen 127.0.0.1:9443
```

也可显式选择仅安装面板和 Agent，用于先部署目标节点再导入配置及准备组件：

```sh
sudo bash deploy/native/install.sh \
  --binary /opt/approved/nginxpanel/nginxpanel \
  --web-dir /opt/approved/nginxpanel/web \
  --without-nginx \
  --data-dir /srv/nginxpanel \
  --start
```

`--without-nginx` 与本机程序、签名资产和预发布选择互斥；不填写选择会拒绝安装。此模式登记 root 所有的明确未安装状态，不创建 Nginx 基线、不启用或启动其服务；Web 和 Agent 可提供目标预检及可信组件准备。实际安装、运行接入和迁移应用仍须分别完成，在线安装流程继续实施。重新运行首次安装器不能改换已登记选择。

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

选择安装 Nginx 时，`nginx-init` 仅准备无站点基线，固定 worker、prefix 与配置入口；不会接管发行版 `nginx.service`。业务端口在后续保存并应用站点时才启用。动态模块默认批准清单为空；已有系统实例按本机 root 的受信清单接入，参见 [模块接入](../../docs/native-modules.md)。Docker 仍使用构建时预置模块策略。

## 服务与启动

安装注册 `nginxpanel-nginx.service`、`nginxpanel-agent.service` 和 `nginxpanel.service`；是否安装组件、是否启用服务及实际运行状态分别核对。Agent 不依赖启动 Nginx，重启 Agent 不会顺带拉起已停止的代理实例。Nginx 独立前台运行，由 systemd 跟踪 master；退出使用 QUIT 和有限宽限期。面板、Agent 或其更新不会因服务依赖而停止正在代理流量的 Nginx。应用发布及运行确认仍由 Agent 完成。

Web 无 Linux capabilities，只能写四个业务目录；root Agent 可写固定执行目录，无法读取业务主密钥目录。三个服务使用只读系统挂载与独立临时目录，Web 保持回环 HTTPS，Agent 仅开放本地 Unix socket 并核对 Web UID。初始化输出 TLS 指纹和引导令牌文件位置，不输出令牌内容。

默认只准备文件并执行 `daemon-reload`。本机管理员可在安装命令中加 `--start`：仅面板模式只启用并启动 Web 与 Agent；选择 Nginx 时同时启用并启动其专用服务。已选择 Nginx 的部署也可在检查配置后执行：

```sh
sudo systemctl enable nginxpanel-nginx.service nginxpanel-agent.service nginxpanel.service
sudo systemctl start nginxpanel.service
sudo systemctl status nginxpanel.service nginxpanel-agent.service nginxpanel-nginx.service
```

仅面板部署手动启用时只选择 `nginxpanel-agent.service nginxpanel.service`。Nginx unit 的 `ExecCondition` 读取同一安装记录：明确未安装时跳过，记录缺失、损坏或已装文件校验失败时报告 unit 失败；不会把损坏状态当作未安装。退出状态遵循 [systemd 官方条件启动语义](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)。

服务进入 active 只说明进程受 systemd 管理，不能代替 API、权限、Nginx 应用和故障恢复验收。首次管理员配置使用 `<DATA_DIR>/bootstrap/token`。远程访问仍通过已有 SSH/VPN/受保护代理，当前入口不开放公网监听。

主机指标来源显式为 host；DNS 接管和日志轮转所有者默认 unconfirmed。启用主机 DNS 写入还须本机确认实际所有者、宿主机范围并调整 Agent unit 的固定写入目录，不能只在业务页面绕过系统沙箱。networkd 写入及其完整恢复仍待实现；其 `RevertDNS` 会清除其他 DNS 运行时覆盖，不能将回写服务器地址视为完整回滚，见 [systemd 源码](https://github.com/systemd/systemd/blob/v257/src/network/networkd-link-bus.c)。

安装意图和完成标记保存在 `/etc/nginxpanel/install/`。失败保留账户、节点数据和记录，使用相同产物及参数重试；成功复制前不切换程序，配置文件通过同目录暂存和 rename 发布，不覆盖不同的现存内容。源产物变化、外部修改或服务启动失败须先检查原因，不能删除意图文件伪装成新安装。更新、卸载清理、可信组件在线安装/运行接入及完整 Docker 接入仍在后续范围内。

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

安装的 Agent 同时以 `--maintenance-scope host` 确认配置维护范围。面板“配置维护”关闭新写入、等待既有任务结束并取得独立 root 锁；手动进入维护后须显式恢复写入，Web 或 Agent 重启不会把锁当作已释放。状态不可核实时保持写入关闭。此入口尚不执行组件切换或完整备份。

仅面板安装使用 `component-bind --nginx-uninstalled` 保存同一 root 只读记录，其中所有运行文件和签名字段必须为空。Agent 的 `--nginx-binding` 接受这一明确状态并报告执行能力缺失；记录不存在或既有资产丢失仍拒绝启动。`nginx-init` 和 `nginx-runtime` 要求真正的安装绑定，未安装登记不能绕过此检查。`nginx-runtime-status` 是 systemd 的只读条件入口，不执行 Nginx、下载或初始化。该部署方式尚未运行安装器、语法/构建检查、服务或测试，待 P5 集中验证。
