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

`--without-nginx` 与本机程序、签名资产和预发布选择互斥；不填写选择会拒绝安装。此模式登记 root 所有的明确未安装状态，不创建 Nginx 基线、不启用或启动其服务；Web 和 Agent 可提供目标预检及可信组件准备。准备后可在维护期间使用“组件安装”页面或下述独立首次安装命令，也可在迁移中显式授权自动维护及首次安装，见[迁移说明](../../docs/migration.md)。重新运行首次安装器不能改换已登记选择。

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

安装意图 v9 在业务初始化前由 root 登记 `run/panel-writer.lock`，文件为 root 持有、面板专用组可读写的 0660 常规文件，上层目录不可被面板账户替换。正式 `init/serve` 共用此锁，恢复启动标记存在时保持关闭；开发模式使用独立写锁。systemd 仅额外开放该锁文件的写权限。

原生面板的初始程序及前端也复制到 root 持有的 `DATA/runtime/releases/<内容散列>`，运行绑定固定原生模式、身份和监听，`runtime/current` 选择完整版本。systemd 通过固定 `panel-native-serve` 入口启动所选程序；`/opt/nginxpanel/current` 继续用于宿主机 Agent 和安装工具。正式启动在写锁内核对实际程序与前端，初始安装重放保留当前选择，指针丢失时不会重置为旧代码。root 版本选择入口及尚未完成的更新编排见 [发行说明](../../docs/releases.md#面板程序版本选择)。

选择安装 Nginx 时，`nginx-init` 仅准备无站点基线，固定 worker、prefix 与配置入口；不会接管发行版 `nginx.service`。业务端口在后续保存并应用站点时才启用。动态模块默认批准清单为空；已有系统实例按本机 root 的受信清单接入，参见 [模块接入](../../docs/native-modules.md)。Docker 仍使用构建时预置模块策略。

## 服务与启动

安装注册 `nginxpanel-nginx.service`、`nginxpanel-agent.service` 和 `nginxpanel.service`；是否安装组件、是否启用服务及实际运行状态分别核对。Agent 不依赖启动 Nginx，重启 Agent 不会顺带拉起已停止的代理实例。Nginx 独立前台运行，由 systemd 跟踪 master；退出使用 QUIT 和有限宽限期。面板、Agent 或其更新不会因服务依赖而停止正在代理流量的 Nginx。应用发布及运行确认仍由 Agent 完成。

Web 无 Linux capabilities，只能写四个业务目录；root Agent 可写固定执行目录，无法读取业务主密钥目录。各服务使用只读系统挂载与独立临时目录，Web 保持主回环 HTTPS；可选[受控远程监听](../../docs/management-listener.md)由 Agent 持有 TCP 描述符、Web 完成 TLS，独立执行确认期限与恢复。Agent 管理命令仍仅通过本地 Unix Socket 并核对 Web UID。初始化输出 TLS 指纹和引导令牌文件位置，不输出令牌内容。

默认只准备文件并执行 `daemon-reload`。本机管理员可在安装命令中加 `--start`：仅面板模式只启用并启动 Web 与 Agent；选择 Nginx 时同时启用并启动其专用服务。已选择 Nginx 的部署也可在检查配置后执行：

```sh
sudo systemctl enable nginxpanel-nginx.service nginxpanel-agent.service nginxpanel.service
sudo systemctl start nginxpanel.service
sudo systemctl status nginxpanel.service nginxpanel-agent.service nginxpanel-nginx.service
```

仅面板部署手动启用时只选择 `nginxpanel-agent.service nginxpanel.service`。Nginx unit 的 `ExecCondition` 读取同一安装记录：明确未安装时跳过，记录缺失、损坏或已装文件校验失败时报告 unit 失败；不会把损坏状态当作未安装。退出状态遵循 [systemd 官方条件启动语义](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)。

服务进入 active 只说明进程受 systemd 管理，不能代替 API、权限、Nginx 应用和故障恢复验收。首次管理员配置使用 `<DATA_DIR>/bootstrap/token` 并通过 SSH 访问回环入口。之后可显式启用受控远程监听，或继续使用已有 VPN/受保护代理。

主机指标来源显式为 host；DNS 接管和日志轮转所有者默认 unconfirmed。启用主机 DNS 写入还须本机确认实际所有者、宿主机范围并调整 Agent unit 的固定写入目录，不能只在业务页面绕过系统沙箱。networkd 写入及其完整恢复仍待实现；其 `RevertDNS` 会清除其他 DNS 运行时覆盖，不能将回写服务器地址视为完整回滚，见 [systemd 源码](https://github.com/systemd/systemd/blob/v257/src/network/networkd-link-bus.c)。

安装意图和完成标记保存在 `/etc/nginxpanel/install/`。失败保留账户、节点数据和记录，使用相同产物及参数重试；成功复制前不切换程序，配置文件通过同目录暂存和 rename 发布，不覆盖不同的现存内容。源产物变化、外部修改或服务启动失败须先检查原因，不能删除意图文件伪装成新安装。更新、卸载清理及完整 Docker 接入仍在后续范围内。

组件准备由原生 Agent 的 `--component-scope host` 启用，发行信任须由本机 root 配置，见 [发行准备](../../docs/releases.md)。安装器预建 `/opt/nginxpanel/prepared`（0755）及 `/opt/nginxpanel/release-downloads`（0700），并仅向 Agent unit 开放这两个额外写目录。缺少有效信任时页面报告不可用，不创建默认发布者。原生首次安装通过下述绑定接入，Web 首次安装见下节，运行中版本切换仍待后续流程。

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

安装、启动及运行确认仍分开：默认不启用服务，`--start` 才启动；组件页面展示已登记来源、版本、散列及实际运行确认。首次安装不会切换正在运行的实例；运行中切换与恢复使用独立组件切换流程。此入口及服务沙箱尚未实际运行，待 P5 集中验证。

安装的 Agent 同时以 `--maintenance-scope host` 确认配置维护范围。面板“配置维护”关闭新写入、等待既有任务结束并取得独立 root 锁；手动进入维护后须显式恢复写入，Web 或 Agent 重启不会把锁当作已释放。状态不可核实时保持写入关闭。组件切换和备份使用各自的独立任务，复用此维护准入。

仅面板安装使用 `component-bind --nginx-uninstalled` 保存同一 root 只读记录，其中所有运行文件和签名字段必须为空。Agent 的 `--nginx-binding` 接受这一明确状态并报告执行能力缺失；记录不存在或既有资产丢失仍拒绝启动。`nginx-init` 和 `nginx-runtime` 要求真正的安装绑定，未安装登记不能绕过此检查。`nginx-runtime-status` 是 systemd 的只读条件入口，不执行 Nginx、下载或初始化。该部署方式尚未运行安装器、语法/构建检查、服务或测试，待 P5 集中验证。

## 为已部署的面板首次安装 Nginx

仅适用于原生 `--without-nginx` 节点，且 Web/Agent 已启动、Nginx 签名资产已准备。先从“配置维护”进入维护，等待 Web 与独立 Agent 均为 `held`。从 `GET /api/v1/maintenance` 的统一响应 `data.agent.id`、`data.agent.epoch` 取得当前维护标识和 epoch；安装期间保留该维护会话。

在目标宿主机使用已登记的面板程序执行，安装操作 UUID 须预先生成并留存：

```sh
sudo /opt/nginxpanel/current/nginxpanel component-install \
  --data-dir /srv/nginxpanel \
  --install-operation '<本次安装UUID>' \
  --maintenance-id '<当前维护UUID>' \
  --maintenance-epoch '<当前Agent epoch>' \
  --release-plan '<已准备的64位计划ID>' \
  --release-select '<单一Nginx资产ID>' \
  --install-enable \
  --install-start
```

`--install-enable` 仅设置专用服务开机启用，`--install-start` 才立即启动；均省略时只安装并接入 Agent；未请求启动不等于执行停止，运行状态按实际观测返回。信任文件默认 `/etc/nginxpanel/release-trust.json`，使用其他固定信任或预发布资产时须填写相应 `--release-trust`、`--release-prerelease`。模块批准清单固定为 `/etc/nginxpanel/nginx-modules.json`，不下载、编译或安装模块和系统包。

独立 root 进程先保存 `<DATA_DIR>/agent/operations/<安装UUID>.json`，核对原生服务、原未安装登记和签名资产，再初始化受管空基线并检查配置、原子发布安装绑定，按显式选项控制专用 Nginx，并重启 Agent。最后以 Web 身份通过原有 IPC 权限核对 Agent 的安装来源、基线完整性及所请求的运行状态。安装不会接管已有实例或应用迁移业务配置；结果从标准输出返回独立 JSON 记录，失败同时返回非零退出状态。

中断或失败保留原记录并阻止释放维护锁。核对记录阶段及 systemd 日志后，等待原维护会话再次为 `held`，以**相同安装 UUID、维护 UUID、资产和全部原选项**，更新当前 epoch 并增加 `--resume-install` 续办；不能换新操作或资产掩盖未完成安装。绑定尚未发布时，也可保留上述全部原选项并增加 `--abort-install` 显式取消，已生成的受管空基线和审计记录保留。绑定发布后仅允许续办确认，不按未安装状态取消。成功或有效取消后，再从面板显式结束维护。

Web/API 启动见下节。迁移已支持显式授权的自动维护及首次安装；运行中版本切换见下文；命令、服务操作和故障恢复均未实际执行，待 P5 集中验证。

## 页面与 API 首次安装

当前原生安装器另登记 `nginxpanel-install@.service` 模板，不设置开机启用。每次 API 安装使用原操作 UUID 对应的固定实例启动独立 root worker，与 Agent 生命周期分开；Web 无需 root 权限或服务管理权限。模板参数与非阻塞启动遵循 [systemd 模板规范](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml) 和 [systemctl 启动规范](https://github.com/systemd/systemd/blob/main/man/systemctl.xml)，受理启动不等于安装完成。

在“组件准备”完成签名资产准备，进入“配置维护”并等待确认后，打开“组件安装”，选择准备结果与单一 Nginx 资产。开机启动和立即启动分别勾选；安装只创建空基线，业务配置仍通过导入和应用流程发布。未结束的安装任务同时阻止 Web 和 root 释放原维护锁。

对应 API 均返回统一外壳，写入要求 `components.manage`、`system.write`，浏览器还需近期认证；查询另需 `read`。准备结果须属于当前调用者，管理员可按原授权读取；维护会话也须由当前调用者拥有或具备管理员权限。请求使用 `Idempotency-Key`：

- `POST /api/v1/components/installations`：JSON 为 `maintenance_id`、`prepare_task_id`、`asset_id`、`start`、`enable`，后二者必须显式填写。服务器从已完成的准备任务固定计划、清单和信任散列。
- `GET /api/v1/components/installations` 及 `GET /api/v1/components/installations/{id}`：读取原任务及独立执行结果。
- `POST /api/v1/components/installations/{id}/resume`：重新授权十分钟，只续办原资产和原选项。
- `POST /api/v1/components/installations/{id}/cancel`：仅在确认执行器停止且尚未发布安装登记时取消；已有基线和审计记录保留。

初次授权同样为十分钟，续办/取消最多 31 次；每次控制序号递增，迟到请求不能覆盖较新授权。不确定提交只查询原操作，记录缺失不重建；已请求启动的任务以真实运行确认作为成功条件。API/服务重启后核对同一记录，不按等待超时假定工作停止。控制请求若未执行而原安装已终结，任务展示原安装实际结果。普通 CLI 安装仍按上一节原命令续办，API 安装使用其原任务控制端点。

尚未执行接口、构建、类型检查、lint、安装器、服务或故障恢复验证，统一留到 P5。迁移父任务的显式安装选项、任务关联及恢复边界见[迁移说明](../../docs/migration.md)。


## 面板容器模式

首次安装可增加 `--panel-mode docker --panel-image <镜像@sha256:摘要> --release-manifest <清单绝对路径> --release-signature <签名绝对路径>`，由相同宿主机安装器初始化持久应用版本、UID/GID 和 Agent Socket 权限，生成固定 Compose，且不登记原生 Web unit。信任根由 root 独立配置在 `/etc/nginxpanel`。写入安装意图前核对签名、当前架构、实际镜像启动器、本机程序及全部前端文件，绑定时再次检查并保存只读批准记录；镜像须事先准备到本机，不自动拉取。`--start` 只启动宿主机服务，面板容器另行使用生成的 Compose 启动。已登记的模式、镜像或版本不能通过重跑首次安装器改换。运行、固定控制接口及真实遗留范围见 [Docker 部署](../docker/README.md)。

配合 `--nginx-image <已在本机准备的镜像@sha256:摘要>` 可同时接入预置模块 Nginx 容器，使用同一镜像发行清单验签；与原生程序、签名组件和 `--without-nginx` 选择互斥。此分支只登记宿主机 Agent，生成双服务 Compose；不登记原生 Nginx、原生首次安装或组件切换 unit。Docker Socket 仅由宿主机 root Agent 访问，不挂入容器。首次安装意图为 v7，首版发布前不保留旧意图兼容路径。

运行中的原生 Nginx 可通过独立 root 命令在已持有维护会话中切换至签名准备组件，支持原记录续办、补偿和只读查询；要求明确允许停机，保留当前发布及原组件。详见 [组件维护切换](../../docs/releases.md#原生-nginx-运行组件维护切换)。网页“组件切换”和 `/components/switches` API 使用同一切换核心，由安装器登记的 `nginxpanel-switch@.service` 独立执行。每次五分钟启动授权只领取一次，失败后须在原任务显式续办或恢复原组件；源环境恢复任务不自动重放。此入口及服务尚未执行验证，待 P5 集中验证。


## 宿主机 Agent 升级

安装器同时登记独立的 `nginxpanel-agent-upgrade@.service`。Agent 和 `/opt/nginxpanel/current` 中的宿主机工具使用[独立 Agent 升级](../../docs/releases.md#独立-agent-与宿主机工具升级)，要求已准备签名产物、同协议/数据库/launcher 合同及已排空维护会话；不通过重复首次安装覆盖版本。独立 worker 保留原程序，停止 Agent 后切换、启动并确认，失败补偿；原维护会话在事务确认前不能释放。此入口适用于原生与 Docker 面板的宿主机 Agent，容器 launcher 仍通过受信镜像替换。实现待 P5 隔离集中验证，未在开发主机执行安装或升级。

Agent 升级支持网页「Agent 升级」及 `/api/v1/agent/upgrades` 持久任务入口，绑定已准备签名产物和原维护会话，断连只查询，停止事务须显式重新授权；API 创建的任务不能通过本机 resume 绕过原授权。安装器登记 tmpfiles 配置及必要目录写权限，适用于重启后的宿主机 Agent。详见上述升级文档。
