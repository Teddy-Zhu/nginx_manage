# P5 集中验证记录

2026-10-20。当前完成软件构建、接口迁移、双节点 HTTPS 迁移与授权、amd64 预置 Nginx 镜像运行与原生静态构建，以及 Debian 12/amd64 原生安装、Nginx 应用、完整备份/克隆恢复、受控管理监听、direct nftables 指定中断恢复及普通文件、Debian 13 networkd/resolved、NetworkManager/resolved 及两种 netplan renderer 静态 DNS 的双栈解析与独立恢复验证，以及 CentOS Stream 10/amd64 Enforcing 和 Debian 13/amd64 的 v14 原生安装、重放与重启持久化，以及 CentOS 受管 Nginx 的 HTTP 应用、回滚和重启恢复验证，P5 尚未完成。以下结果仅覆盖列出的组合及行为，全部目标系统、内核操作和业务功能仍须分别验收。

## 隔离环境

所有程序生成、编译、类型检查、lint 和业务测试均在 Docker 容器中执行。常规构建和接口验证使用普通用户、只读根文件系统、移除全部 capabilities、禁止提权。Nginx 运行验收使用独立网络、只读根文件系统及私有 `/srv` tmpfs；root 测试进程仅用于准备目录所有权、启动和回收子进程，实际 Nginx 使用 UID/GID 1000。启动器验收使用独立数据卷及与运行绑定一致的只读/可写挂载；启动后核对 PID 1 的身份和 capabilities。全部容器不映射宿主机端口、管理 Socket、系统目录或主机网络。工作目录用于源码及生成文件，依赖和测试数据库放在容器卷或私有 tmpfs 中，验证产物保存在工作区及专用卷中。未安装宿主机软件或修改宿主机服务、网络、防火墙及 Docker 配置。

固定镜像：

- Go：`golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`。
- 前端：`node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5`，pnpm `10.33.0`，按锁文件安装。
- Nginx：`nginx:1.30.6-alpine-slim@sha256:3028fc1419f99b95c1c69f844bbaf49dc1b881750c51b497fc721ac4f02a14e6`，由实际 `deploy/docker/nginx.Dockerfile` 构建本地 amd64 验证镜像；使用实际静态面板程序、MIT 及 Go 依赖许可，未作为签名发行产物发布。

## 已执行范围

| 范围 | 入口与结果 |
| --- | --- |
| 合同生成 | oapi-codegen `v2.8.0`、sqlc `v1.31.1`、`pnpm generate:api`、`pnpm generate:routes` 成功；生成文件已纳入本次改动 |
| 后端 | `go test -p 2 ./... -timeout 120s` 通过；主程序和发行工具通过 `go build -p 2 -trimpath` 编译 |
| 前端 | `pnpm typecheck` 通过，包含 vue-tsc 与锁定 TypeScript 包的 `tsc6`；Vite 生产构建通过 |
| 静态检查 | ESLint 全项目 0 错误、5321 条样式警告；后续修改的 Vite 配置和 API 客户端单独检查通过，未批量改写样式 |
| 发布规格 | 在独立受保护临时目录运行发行工具的 `spec`，确认两种架构的 panel 及 web 资产均声明 `MIT`，并保留 LICENSE、第三方声明文件；仅使用本地验证仓库标识，未签名或发布 |
| Nginx 镜像 | 实际 Dockerfile 构建通过；全部静态能力声明与 `nginx -V` 匹配；配置服务生成的 HTTP/Stream/WAF/ACL 经 Agent 渲染后，由真实 Nginx 校验和运行通过 |
| 固定启动器 | 实际镜像入口拒绝缺失登记及两种程序哈希错误；正常启动后 PID 1 的全部 UID/GID 为 1000，inheritable/permitted/effective/bounding/ambient 均仅有 `NET_BIND_SERVICE`，且禁止提权；容器私有端口阈值为 1024 时成功服务 80 端口 |

接口集成测试使用两个独立数据目录，执行真实数据库初始化、只读开发 Agent、HTTP 服务和会话存储，覆盖：

- 管理员初始化、登录、会话持久化、CSRF 与来源校验、未认证和不存在接口的统一响应，以及 UUID 参数错误。
- 受管 HTTP 站点创建、可移植配置导出、目标依赖预检；目标缺少受管 Nginx 时阻止保存生效配置，允许导入草稿。
- 草稿内容及停用状态保留、目标当前配置不被草稿覆盖、执行幂等重试，以及归档内容篡改拒绝。
- 加密迁移包不暴露源站点明文、错误口令拒绝和正确口令预检。
- 会话加载、提交故障注入；错误仍返回单份 `code/message/data/request_id/node_id` JSON，不附加原成功响应或成功会话 Cookie。

这轮验证发现并修复了生成合同与调用不一致、编译错误、远程节点与配对路由冲突、近期认证时间序列化失败和会话失败响应拼接。远程资源前缀统一调整为 `/api/v1/nodes/connections/{connection}/…`，合同、后端白名单与前端调用同步更新。多数包目前没有独立测试用例，`go test ./...` 通过不能代替下列系统验收。

### 双节点 HTTPS 迁移与授权

`internal/app` 的 `TestAPIRemoteMigrationAndAuthorization` 在隔离 Docker 容器内启动两个真实应用、独立 SQLite/只读开发 Agent 及各自 HTTPS 网关。`go test -p 2 ./internal/app -run '^TestAPIRemoteMigrationAndAuthorization$' -v -timeout 90s` 通过，场景耗时 12.42 秒，覆盖：

- 加密 HTTPS 拉取及监听映射；草稿保留源启用元数据，目标缺少受管 Nginx 时阻止保存及应用，草稿不改变目标当前配置。
- 源配置改变后的同键重试返回原快照，不重复导出；同键改变输入返回冲突。
- 异步推送预览和草稿的完整父子任务执行、固定目标身份、目标依赖结果与父任务幂等重放。
- 错误证书指纹、错误永久身份、导出权限不足及已撤销 Key 均拒绝迁入；实际 307 响应不被跟随。
- 节点登记、永久身份去重及受控配置读写；响应保留目标节点身份和统一外壳，目标只读 Key 拒绝配置写入且源版本不变。
- 撤销 Key 后已有缓存连接立即收到未认证响应并标记授权失败，后续转发被阻止。删除已失效连接报告撤销待核对；删除有效只读连接收到匹配撤销回执，目标随后拒绝该 Key。
- 两端数据目录未发现三份 API Key 的明文，公开推送摘要未包含目标 Key。

该结果仅覆盖容器内 HTTPS 网关与应用链路，不包含真实跨主机网络、自动安装、一次性配对、SSE 或中断恢复。

### Nginx 镜像运行范围

`internal/agent` 的 `TestPrebuiltNginxRuntime` 使用真实 SQLite、配置修订服务和 Agent 运行配置渲染器。编译出的静态测试程序在上述实际镜像内执行，设置 `NGINXPANEL_TEST_NGINX=/usr/sbin/nginx`；普通后端测试未提供该环境时明确跳过。Nginx 主进程以 UID/GID 1000 运行，`nginx -t` 和以下流量校验通过：

- HTTP 反代返回实际上游响应，TCP 和 UDP 均完成实际双向载荷转发。
- WAF 路径拒绝 403、方法拒绝 405、请求体上限 413、速率与并发限制 429，以及豁免路径、ACL 拒绝。
- HTTP 与两种 Stream 访问日志为有效 JSON，具备实际地址和状态；查询参数、Authorization 值及 Stream 载荷不出现在访问日志中。

首次真实运行发现 UUID 命名的防护变量无法装入 Nginx 默认变量哈希桶，已在 HTTP 运行配置提供 `variables_hash_bucket_size 128`。原生临时目录修复后，使用更新的测试程序在相同镜像内复验上述范围通过（0.20 秒）。构建上下文通过 Dockerfile 专用忽略文件限制为所需配方、模块声明、二进制及许可文件。

`internal/nginxcontainer` 的 `TestPrepareNginxLauncherFixture` 仅在显式环境变量下准备 root 所有的隔离登记夹具，随后直接运行镜像的实际入口。分别验证正常降权/低端口监听、无登记、启动器哈希不匹配及 Nginx 哈希不匹配。端口阈值只设置在 `--network none` 容器的网络命名空间中；未修改宿主机 sysctl。登记夹具的签名来源字段是合成数据，这组结果不能证明发行签名、Registry 来源或宿主机安装器准入已通过。验证容器和对应夹具卷已回收。

### 原生 Nginx 静态构建

在独立 Debian 构建容器内复用发布构建器的源码下载、解包及 UAPI 头文件准备函数，按当前 `nginx-source-lock.json` 的完整配置参数编译 amd64 Nginx。四份源码的长度和 SHA-256 全部匹配锁定值；产物实际执行 `nginx -V`，确认 Nginx 1.30.6 与 OpenSSL 3.5.9。ELF 无动态解释器及共享库依赖，36 个必需模块符号全部存在，二进制 SHA-256 为 `1e168f3239c9f650651d68797b97f986c7c21769c8a9db8ca0caa2fdf6b46f08`。

首次编译暴露 OpenSSL 的 `linux/mman.h` 搜索路径缺失，现由构建器单独复制目标架构 Linux UAPI 头文件，配方显式供 OpenSSL 使用；CI 明确安装 `linux-libc-dev`。实际运行库证据收集也已通过，涵盖 musl-dev 1.2.3-1、libgcc-12-dev 12.2.0-14+deb12u1 的三个静态运行库及其真实许可文本。该本地构建未伪造 GitHub 工作流来源，不替代正式 CI、签名、发布或 arm64 验收。

### Debian 原生安装与重启

在上述 Go 镜像内安装 QEMU `7.2.22`、ISO 工具，随后以 UID/GID 1000、只读根文件系统、移除全部 capabilities、禁止提权及 `--network none` 运行 QEMU TCG。虚拟机使用独立内核、命名卷中的磁盘和只读安装介质；QEMU 内部 DHCP 不连接宿主机网络，未使用 KVM、主机设备、端口映射或 binfmt 注册。安装器对账户、目录和 systemd 的实际修改均发生在虚拟机中。

Debian 官方 `debian-12-genericcloud-amd64.qcow2` 已与同源 [SHA512SUMS](https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS) 核对，SHA-512 为 `dc0d7b526a3a9a9265142fe8e903984c03f8d605ac4ba6f14d15d27988a69581fb05fc06cd2a6d79f6eaf68ba9725f2eb38b5ddd64ad166faadad279af776c9e`。通过 [NoCloud 安装介质](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html#source-2-drive-with-labeled-filesystem) 输入实际面板程序、锁定依赖构建的前端和当前原生安装器，由虚拟机 root 批准文件，分别执行 `--without-nginx --start` 和 `--nginx-binary /opt/p5-approved/nginx --start`。

| 系统/架构 | 内核 / systemd | 部署组合 | 验收结果 |
| --- | --- | --- | --- |
| Debian 12 / amd64 | `6.1.0-54-cloud-amd64` / `252.39-1~deb12u2` | 原生面板 + 宿主 Agent，Nginx 未安装 | 以下范围通过 |
| Debian 12 / amd64 | 同上 | 原生面板 + 宿主 Agent + 本地批准的静态 Nginx | 以下范围通过 |

`--without-nginx` 组合完成：

- 首次安装实际创建专用账户、受保护目录、程序及前端运行绑定，并启用和启动 Web/Agent；Nginx 服务保持未启用、未运行。
- Web 进程的四项 UID 均为专用账户，`CapEff=0`、`NoNewPrivs=1`；数据根为 root:0755，秘密目录为 Web:0700，写锁为 root:nginxpanel:0660。Web 用户无法读取 Agent 目录，Agent 挂载命名空间内不可见业务主密钥。
- 使用实际本机证书并验证 TLS，完成管理员初始化、登录、CSRF 请求、未认证拒绝、配置创建及统一响应身份核对。
- 在 Web 运行时以相同参数重放安装成功；重启 Web/Agent 后原会话、永久节点编号、配置版本和修订均保留。
- 真实系统重启后再次核对服务、权限及相同会话、节点和配置，最终输出 `P5_NATIVE_ALL_PASS` 后关机。

`--nginx-binary` 使用上一节的本地静态 Nginx，完成：

- 实际启用并运行 Nginx、Agent 和 Web。Nginx worker 使用专用账户且 `CapEff=0`，Nginx 挂载命名空间内不可见业务主密钥；Web 与 Agent 的上述隔离检查同样通过。
- 经 HTTPS API 创建、应用 HTTP 代理资源，任务最终为 `succeeded/runtime_confirmed`，80 端口返回预期上游内容。
- 额外候选端口被独立上游夹具占用后，应用任务最终为 `rolled_back/rollback_confirmed`；原运行修订及物理部署编号不变，轮询期间原站点请求成功。
- 再次提交相同候选，观察配置指针切换后向 Agent 发送 SIGKILL；systemd 重启 Agent 后确认回滚，原修订及部署保持。删除冲突资源后再次应用新修订成功。
- 运行中重放安装器、重启 Web/Agent 及整机后，原会话、永久节点编号、配置版本/修订、物理部署编号和 HTTP 转发均保持，最终输出 `P5_NATIVE_NGINX_ALL_PASS` 后关机。

这些验收修复了首次安装直接查询 systemd 模板导致误报冲突、运行中重放重复初始化触发写锁、重放校验拒绝模板文件名 `@`，以及原生 Nginx 默认临时目录写入只读数据根的启动缺陷。临时目录现按实际编译模块生成并归入受管可写子目录，未放宽 systemd 写入范围。两组分别在修正夹具依赖环、上游目录权限后，沿用原安装磁盘分段完成。当前结果不覆盖生产签名资产、其他危险操作补偿或其他发行版/架构，也未执行 UI 自动化。

### Debian 完整备份与克隆恢复

在上述 Debian 12/amd64 全内核虚拟机中，以当前原生安装器、本地批准的面板和静态 Nginx 完成加密完整备份及 `clone` 恢复。面板二进制 SHA-256 为 `34c6bd9323811808b8413c6fdd2310a6f311ce476d92c84bffbb37e80f730e6b`，安装器 SHA-256 为 `aee28b0f098931e639f4aed90d1fccbed501b26dc60d317a666dbcf089e55a11`；这是本地开发产物，不代表正式签名发行。

- 在实际 Nginx 转发和非空 SQLite WAL 存在时捕获备份，经 HTTPS 单次票据下载并核对归档散列及长度；重复票据和离线错误口令被拒绝，正确口令检查通过。
- 备份后修改目标管理员密码并新增代理配置；取得原维护、持久停机和目标回退快照后，完成隔离准备、root 材料接入、恢复计划及文件安装，并核对目标入口 TLS/主密钥散列保持。
- 文件安装后 systemd 因持久标记跳过启动，直接以面板账户运行程序也被恢复写锁拒绝。真实系统重启后保持无面板进程，以新 Agent epoch 和原操作标识续办；修改业务主密钥字节时运行批准被拒绝，恢复原字节后继续成功。
- 完成受管 Nginx 运行确认、数据库对账、完整外部结果清单复核及激活，父事务最终为 `succeeded/committed`。复核场景只有源任务，未模拟真实外部处置。
- 激活后旧会话失效、归档中的旧密码被拒绝、目标修改后的密码可登录，新节点编号生效。再次重启后完整核对以上结果，并确认仅保留备份内代理资源，配置修订及物理部署均为原恢复计划，80 端口转发正常，备份后新增的 18090 监听消失，维护已开放，捕获时未完成的备份任务为 `cancelled/restore_abandoned`，原已完成 Agent 记录的散列保持。

验收修复了独立 Agent 被错误要求运行面板 inode、Agent 沙箱内访问业务私有文件、激活新增维护任务触发离线事件队列变化，以及持久停机后重启仍反复尝试启动面板的问题。root 协调器负责运行批准前后核对业务文件；激活事务暂停事件投递并恢复，继续保留逐表、日志及序列核对；原生服务以持久标记作为启动条件。相关 Agent 现有 Go 测试复用缓存通过，主程序构建和安装器语法检查通过；backup/panelrecovery 包没有现成单元测试，行为结论来自上述虚拟机验收。

记录保留在 `.validation/native-vm/backup-round5.log` 和 `backup-resume5.log`，磁盘为同一命名卷内的 `backup-5.qcow2`。激活后的字段检查夹具由错误的顶层 `domains` 修正为合同中的 `fields.domains.values`，沿用已恢复磁盘完成剩余核对，最终输出 `P5_FULL_BACKUP_RESTORE_ALL_PASS`；恢复操作为 `d1f4288f-3ed1-4dc2-94c8-147c8f8ca1ba`，源/新节点分别为 `c661aa8a-94cd-4b20-bed8-8400d522a8c9`、`2ea4b323-acfa-4579-8599-11bb597e7a8a`。本轮在同一隔离目标恢复较早归档，未覆盖不同宿主密钥、保留源节点身份的灾备、完整恢复补偿或跨发行版恢复。

### Debian 双节点管理监听与 direct nftables

在同一隔离 Docker 容器内启动两台独立内核 QEMU/TCG 虚拟机，分别运行原生面板/Agent 和外部 API/流量客户端；复用前述已核验的 Debian 12 云镜像、面板程序、原生静态 Nginx 和当前安装器。工具镜像为 `sha256:f82caa7871569c91c8d4d08a09d063bb0ce43270c044373b74ff8c8da733e27d`，仅在镜像内下载离线依赖，目标虚拟机内安装 nftables `1.0.6-2+deb12u2`、iptables `1.8.9-2`。容器无外部网络和宿主端口映射；两台虚拟机通过 QEMU socket 网卡连接，使用 `192.0.2.10/11` 和 `fd42:5::10/11`，未借用宿主内核执行防火墙操作。

目标通过实际原生安装器部署，由本机 root 登记空受管表，再为独立 Agent 明确授权 `--firewall-scope host --firewall-owner direct-nftables --firewall-ssh openssh`。外部客户端逐连接核对独立管理 TLS 证书 SHA-256，使用实际会话、CSRF 和统一 JSON API，检查响应请求编号/节点编号；恢复阶段查询原操作，并通过新的 TCP/UDP socket 检查实际流量。通过范围：

- 双栈受控监听的外部登录、IPv4 新连接确认，以及回环入口伪造 `X-Forwarded-For` 无法确认监听或防火墙操作。
- 两个版本的策略实际改变 IPv4/IPv6 TCP 放行/丢弃及 UDP 放行/拒绝；覆盖指定网卡、业务规则试图阻止 SSH 和当前管理端口时的保护规则。两族 SSH 均能建立连接，规则经 IPv4 管理入口独立确认。
- 第三方表变化使旧内核基线的应用计划被拒绝，重新规划后可应用；应用、确认、各次回滚及规则移除期间，第三方表的完整 JSON 对象哈希保持原值。
- 已确认策略阻止将管理监听改到被拒绝端口，原监听继续可用。
- 候选策略尚未确认时，分别停止 Web、对 Agent 执行 `SIGKILL`、等待 120 秒确认超时、调用本机 root 救援，以及执行 `systemctl reboot`。各阶段均查询到原操作 `rolled_back`、原已确认版本，并核对实际双栈流量已恢复；整机重启后也能通过原证书及受控监听访问。
- 在存在更新期望草稿时，仍按原已确认版本生成移除计划，独立确认移除后以对应操作编号停用模块；实际端口恢复放行，第三方规则保持完整。

记录为 `.validation/native-vm/firewall-round2.log`、`firewall-target-2.log`、`firewall-client-2.log`；磁盘保留在命名卷 `nginxpanel-p5-native-vm-20261019` 的 `firewall-target-2.qcow2` 和 `firewall-client-2.qcow2`。最终输出 `P5_FIREWALL_ALL_PASS` 和 `P5_FIREWALL_TWO_VM_ALL_PASS`，两台虚拟机已关机，验证容器已退出。首轮在 IPv6 登录前遗漏 CSRF 初始化而终止，修正验收夹具后完成本轮；未修改产品代码或重复执行已通过的 Go/前端检查。

本轮仅证明原生面板和直接 nftables 的上述范围；整机重启为正常系统重启，未覆盖强制掉电。第三方表在重启后由其自己的夹具服务重建，不计为面板持久化第三方规则。旧 TCP 连接拒绝、证书轮换、其他监听来源/地址组合及其他防火墙所有者仍待验收。

### Debian 双节点普通文件 DNS 与独立恢复

复用上述 Debian 12/amd64 云镜像和 QEMU 工具镜像，在无外部网络、无宿主端口映射的容器内运行两台独立内核虚拟机。目标使用当前原生安装器及 `--without-nginx --dns-owner regular-file --start`；客户端同时提供两个不同答案的真实 UDP/TCP DNS 服务，绑定 `192.0.2.11/12`、`fd42:5::11/12`，通过双栈受控 HTTPS 管理入口执行实际会话、CSRF 和统一 API。逐连接核对管理证书指纹，使用目标系统的 `getaddrinfo` 检查解析答案。

目标云镜像原有 `/etc/netplan/50-cloud-init.yaml` 时，Agent 正确报告 netplan 所有者并保持只读；验收夹具将该源备存于虚拟机 root 私有目录，关闭该虚拟机的自动网络渲染和相关网络服务，以独立 LAN 服务建立真正无上游管理器的普通文件场景。安装器自身不启停、切换或接管网络管理器。开发宿主机的包、服务、网络及 Docker 配置未修改。

本轮修复原生 Agent 的 DNS 写入授权和 netplan 固定文件写入准入。安装意图升级为 v13，冻结明确选择的所有者，并同步所有原生安装记录读取入口；未确认所有者时不开放额外路径。程序 SHA-256 为 `0cdb19ade730ce087ae84c4a83844721fa2de3bfbe4ee03fcef842b262ab88eb`，安装器为 `87ceddd41663898b0f6648fd635780b1a5ea9eebdc201180ca0ab165252b9718`。

集中验证通过 Agent 现有测试、主程序构建和安装脚本语法检查。另以只读根文件系统、无网络、无额外 capabilities 的 root 容器，在三个私有 tmpfs DNS 目录中执行 `TestNetplanDNSSourceReplacement`：原生 YAML、networkd 和 NetworkManager 生成配置均可原子替换并保留 UID/GID、权限和扩展属性；越界路径及过期快照被拒绝。记录为 `.validation/native-vm/dns-go-round2.log`、`dns-files-round1.log`。此检查只证明固定文件写入，不代表 netplan 后端已完成实际系统验收。

真实双节点通过范围：

- 过期源计划、符号链接、硬链接、生成标记及不安全权限均拒绝写入；重复提交同一应用请求返回原任务。未确认配置不进入期望配置，活动 DNS 事务阻止管理监听变更。
- 不同 DNS 服务实际改变系统解析答案；分别确认双栈服务器和仅 IPv6 的服务器配置。应用和恢复保留原有注释、非 DNS 选项、UID/GID、权限及 `user.p5-dns` 扩展属性。
- 解析失败、确认超时、停止 Web、SIGKILL Agent 后，原任务均进入 `rolled_back`，恢复已确认的 IPv6 DNS 配置、完整文件属性及实际解析，双栈管理入口保持可访问。
- 未确认配置期间通过 QMP `system_reset` 强制重置目标虚拟机；新 boot 下查询相同原操作编号，原配置、期望配置和实际解析恢复。该操作没有执行 guest 正常关机，不等同于宿主掉电或虚拟磁盘缓存丢失。
- 外部修改期间保持文件原样、进入 `recovery_required` 并阻止新计划；本机处理源文件后，显式续办同一事务，最终恢复精确基线、完整属性及实际解析。

主要记录为 `.validation/native-vm/dns-round5.log`、`dns-target-5.log`、`dns-client-5.log`。第 5 轮完成上述解析与中断恢复，输出 `P5_DNS_HARD_RESET_RESTORED`；最后一项夹具将异步恢复尚未更新的状态过早判为失败。修正等待后，以 `dns-target-5.qcow2` 为只读基底创建目标克隆，仅补验外部修改恢复，不重跑已通过范围。补验记录为 `dns-round6.log`、`dns-target-6.log`、`dns-client-6.log`，原任务 `e7d1cd05-ccbd-4cd7-aa6d-8ccceddb3f8a` 已对账为 `rolled_back`；新事务同操作恢复后输出 `P5_DNS_EXTERNAL_CHANGE_PRESERVED_AND_ORIGINAL_OPERATION_RECOVERED` 和 `P5_DNS_TWO_VM_EXTERNAL_RECOVERY_ALL_PASS`。磁盘及记录保留，两台虚拟机已关机，验证容器已退出。

本轮未验证 NetworkManager、networkd/resolved 或 netplan 的完整 DNS 事务、不同接口/DHCP/RA 组合及跨发行版行为；这些范围继续按能力门禁保持只读或等待独立验收。

### Debian 13 networkd/resolved 与 netplan/networkd DNS

2026-10-20，复用两台独立内核虚拟机和受控双栈 HTTPS 客户端，将目标升级为官方 Debian 13/amd64 云镜像。镜像来源为 `https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2`，已按同目录 `SHA512SUMS` 核对完整 SHA-512：`ec584ccabfef7120b4c4f7482adf0e615894d9292cedec446b64194b951ebe5dd97c336b5dcbae458333764b0edd516334506017f33c4f2020ef8d38b569ffe3`。实际内核为 `6.12.113+deb13-cloud-amd64`，systemd/resolved 为 `257.13-1~deb13u1`，netplan.io 为 `1.1.2-7`。目标分别使用原生安装器的 `--dns-owner networkd` 和 `--dns-owner netplan`，不含 Nginx；安装器仍为上述 v13 和相同散列。

修复 resolved 标准运行文件由服务账户持有时被 root-only 读取规则误拒绝的问题。仅两个固定 resolved 运行路径从本机系统总线查询唯一服务拥有者的 UID，并在读取后复核拥有者；所有持久配置及写入快照继续只接受 root。现有 Agent 测试及主程序构建通过，记录为 `.validation/native-vm/dns-managed-go-round1.log`，程序 SHA-256 为 `f0413fb9132c9cc08a8c683259cbce8d4d7d705907675a2ee390f9dd47ad7d05`。

每台虚拟机使用独立管理链路和另一块真实虚拟网卡；客户端分别提供两组主 DNS 答案与独立分域 DNS。夹具明确关闭云初始化网络重写，静态配置和管理器由夹具在目标虚拟机内准备；安装器不接管网络管理器。所有解析均经目标系统 `getaddrinfo`，不以 API 投影代替实际结果。通过范围：

- resolved 非 root 服务账户的安全运行文件可被观测；将持久源或运行文件改为无关 UID 65534 后拒绝写入，恢复原拥有者后恢复准入。过期源散列拒绝应用，重复请求返回原任务。
- 临时应用实际改变解析答案，确认前不改变持久源和期望配置；确认双栈及仅 IPv6 DNS 后，原注释、非 DNS 设置、UID/GID、权限及扩展属性保留。重启 networkd 和 resolved 后，确认配置和实际解析保持。
- 独立网卡的分域 DNS 仍返回原独立答案；各事务前后复核其 DNSEx/Domains，以及所选和独立网卡的地址、路由、MAC/MTU。此场景不是实际 VPN 隧道验收。
- 解析失败、确认超时、停止 Web、SIGKILL Agent 和 QMP 强制 `system_reset` 后，均恢复精确源文件与属性、已确认期望及实际 IPv6 DNS 解析，双栈管理入口保持可访问。强制重置后查询相同 root 操作编号，未另建恢复事务；不等同于宿主掉电或磁盘缓存丢失。
- 外部源修改被保留，进入 `recovery_required` 并阻止新计划；本机处理冲突后显式续办原操作，恢复精确基线、分域解析及网络参数。netplan 同时核对上游 YAML、实际生成的 `.network` 和运行状态。

networkd 第 9 轮和 netplan 第 10 轮均输出 `P5_DNS_MANAGED_TWO_VM_ALL_PASS`。记录分别为 `.validation/native-vm/dns-managed-round9.log`、`dns-target-9.log`、`dns-client-9.log` 及 `dns-managed-round10.log`、`dns-target-10.log`、`dns-client-10.log`。强制重置恢复的任务/root 操作分别为 `91dffbdd-d882-4c87-a7ee-4cbc83a211aa` / `fbca5139-2afb-4b48-adc9-9a69eee121df` 和 `2ec325a8-8cb8-48c2-a47a-89be314bcdc6` / `aaa4e441-fe02-40c0-857e-a6dc8d4d50f0`。第 7 轮的 dummy 分域夹具缺少独立 DNS 传输链路，已改用上述真实第二网卡；第 8 轮因夹具诊断命令路径错误停止，第 9 轮从其磁盘克隆，仅更新夹具后完成事务，不修改产品安装或业务数据库。相关磁盘及失败记录保留，两台虚拟机已关机，验证容器已退出，开发宿主机包、服务、网络和 Docker 配置未修改。

NetworkManager 及 netplan/NetworkManager 的验证见下节；动态 DHCP/RA、多发行版/架构和真实 VPN 隧道继续等待独立验收。

### Debian 13 NetworkManager/resolved 与 netplan/NetworkManager DNS

2026-10-20，在上述官方 Debian 13/amd64 镜像的隔离虚拟机内准备 NetworkManager `1.52.1-1`，systemd/resolved、netplan 和内核版本不变。分别验证原生安装器的 `--dns-owner networkmanager` 和 `--dns-owner netplan`，使用直接以太网静态双栈配置及 systemd-resolved 入口；后者由真实 netplan `renderer: NetworkManager` 生成运行 keyfile。仍使用 v13 安装器，不安装 Nginx；开发宿主机环境未修改。

实际 NetworkManager 拒绝了原实现的 Reapply 和回滚：godbus `Call.Store` 递归展开配置映射的 Variant，导致 IPv6 `addresses` 从 `a(ayuay)` 变为 `aav`。修复直接保留回复中的 Variant，并将旧式 IPv6 地址、路由元组恢复为可按原签名编码的具体结构；无法保持类型的复合属性禁止写入。新增实际 D-Bus 编解码回归用例覆盖非空/空元组、现代地址/路由属性及 DNS 修改后的非 DNS 保持。Agent 测试及主程序构建通过，记录为 `.validation/native-vm/dns-nm-go-round1.log`，程序 SHA-256 为 `bfcf4bcf02118015ea6bd16cca7e3845633e8c58813ed84b5b449f3732eb4be2`。

两种后端均通过以下范围：

- 持久源及 resolved 运行文件的拥有者保护、过期源散列拒绝和请求幂等；实际双栈 DNS 临时应用改变解析答案，确认前不改变持久配置或已确认期望，确认双栈和仅 IPv6 DNS 后持久生效。
- 重启 NetworkManager 与 resolved 后，已确认配置和目标系统实际 `getaddrinfo` 解析保持。独立第二网卡的分域 DNS 答案保持；所选和独立连接的非 DNS 设置（排除连接更新时间戳）、地址、路由、MAC/MTU 逐次复核。
- 解析失败、确认超时、Web 停止、Agent SIGKILL 和 QMP 强制 `system_reset` 后，恢复已确认 IPv6 DNS、持久源及期望，双栈管理入口可访问；强制重置后 boot ID 改变并沿用原 root 操作编号。此结果不等同于宿主掉电或磁盘缓存丢失。
- 外部修改原生 keyfile DNS 或 netplan 上游 YAML 后，保留修改并进入 `recovery_required`，阻止新计划；本机处理冲突后显式续办同一操作，恢复基线和分域解析。原生 keyfile 按规范化键值核对并仅排除 NetworkManager 更新时间戳，不宣称保留其原注释/字节；netplan 上游 YAML 按原字节核对，权限、UID/GID、链接数及预置扩展属性保留，同时核对实际生成源与运行状态。

第 15/16 轮完成安装、保护、应用确认、管理器重启及解析失败回滚后，因夹具函数名被循环变量覆盖中断；第 17/18 轮从对应保留磁盘克隆，仅更新夹具，完成原解析失败任务的恢复核对及其余故障场景，不重装程序或修改业务数据库。第 17/18 轮均输出 `P5_DNS_MANAGED_TWO_VM_ALL_PASS`。证据为 `.validation/native-vm/dns-managed-round15.log` 至 `dns-managed-round18.log` 及对应 `dns-target-*.log`、`dns-client-*.log`；种子清单和程序散列同时保留。强制重置任务/root 操作分别为 `a89ab07e-4bbe-4ef2-b82b-6cd4a16f5903` / `d6f4cb33-2202-4622-956a-8e47feb293aa` 和 `1200afd1-3afb-4de7-9401-d39b24bd78f6` / `12e622d9-8521-44bc-bd24-7bb13ddc632c`。

第 11 轮保留原程序的真实序列化失败及离线 journal；第 13/14 轮因夹具误取旧程序，不能评价本次修复，第 12 轮仅准备未启动。已纠正种子程序路径并强制校验上述 SHA-256，失败记录及磁盘均保留。验证虚拟机已关机，验证容器已退出。本轮不覆盖动态 DHCP/RA、Wi-Fi、NetworkManager 的 default 文件入口、实际 VPN 隧道、其他发行版/架构或 Docker 面板组合。

### SELinux 文件标签与 v14 原生安装

在无外部网络、无宿主端口映射的 Docker 容器中运行独立内核 QEMU/TCG 虚拟机，使用本地批准的面板与前端产物执行 `--without-nginx --data-dir /srv/nginxpanel.selinux --start`。CentOS 官方 [Stream 10 GenericCloud 镜像](https://composes.stream.centos.org/stream-10/production/latest-CentOS-Stream/compose/BaseOS/x86_64/images/CentOS-Stream-GenericCloud-10-20261019.0.x86_64.qcow2) 已与同源 SHA256SUM 核对，SHA-256 为 `61a925943be6f1352c5841d6d79e87f9864d265bb062495034408a83ea544b30`。目标保持 Enforcing，内核为 `6.12.0-277.el10.x86_64`，策略为 `selinux-policy-targeted-42.1.27-2.el10`，policycoreutils 为 `3.11-1.el10`，systemd 为 `257-34.el10`；未安装目标软件包或修改开发宿主机配置。

已通过以下实际行为：

- 原生 Web/Agent 首次启动、HTTPS 引导/登录、统一响应、配置保存及安装重放；节点身份、配置版本/修订和原会话保持。
- 核对关键目录、程序和服务单元的 `security.selinux` 扩展属性及 `matchpathcon -V`；含点的数据路径不会匹配相邻的相似目录。安装意图绑定的规则散列一致，模块来源只包含文件上下文声明。
- 修改策略存储中的同名模块、添加冲突的本地标签规则均使安装器明确拒绝；恢复规则后，同参数重放再次成功。
- 新建程序目录及复制文件从父目录继承 `usr_t`，无需单独重标即可由专用非 root 账户在 `NoNewPrivileges=yes`、空 capabilities 下实际执行。
- 整机重启后，原会话经正常密码重新认证，节点身份、配置版本/修订和安装意图保持；文件标签及 Enforcing 状态经重标和安装重放后再次核对，输出 `P5_NATIVE_SELINUX ALL_PASS enforcing` 并关机。

首次 CentOS 安装因系统策略将 `/etc/systemd/system` 等价到 `/usr/lib/systemd/system`，服务单元仍匹配默认 Nginx 标签而被安装器拒绝；补齐两个位置的保留单元规则后，新虚拟机完成上述检查。第二轮重启后的配置读取被五分钟重新认证要求阻止，属于夹具遗漏正常密码重新认证；首次续验又抢在修正脚本载入前执行。沿用原安装磁盘，仅补正常重新认证并通过 [systemd 夹具启动延迟](https://www.freedesktop.org/software/systemd/man/257/systemd-debug-generator.html) 避免时序冲突，完成剩余重启检查；未改动产品认证规则，也未重跑已通过的策略故障检查。失败记录及原磁盘均保留。

复用前述 Debian 13/amd64 镜像，内核 `6.12.113+deb13-cloud-amd64`，在 SELinux 未启用的原生组合中完成 v14 初装、实际 API、安装重放、整机重启及节点/配置/会话持久化，最终输出 `P5_NATIVE_SELINUX ALL_PASS no-selinux`。安装器之后仅补齐 SELinux 启用分支的服务单元等价路径，未重复执行这个组合。

程序 SHA-256 为 `974f19a301475efbd6e005063668d5c4f32b26794811f545ef7969458a961795`；最终安装器为 `79f1a05310a505a099822c4b36a0a23928165e185d34b1dd1b362b35b917fe6d`，Debian 及 CentOS 首轮安装器为 `677a23ccdf1ce37c346efe5d397c11ae2fab70fdf63b36b87ad30b5da513ea9c`。集中检查通过安装脚本语法、Agent 现有测试（缓存结果）和主程序构建，日志为 `.validation/native-vm/selinux-go-round1.log`。VM 记录以 `.validation/native-vm/centos-native-v14-1/2`、`debian-native-v14-1` 及 `centos-native-v14-resume-2-1/2` 为前缀。成功续验输出 `P5_NATIVE_SELINUX_VM_RESUME_ALL_PASS`；两台虚拟机均已关机，验证容器退出。磁盘和种子介质保留在命名卷 `nginxpanel-p5-native-vm-20261019`。

上述 `--without-nginx` 轮次不覆盖受管 Nginx，后续验证见下节；文件标签模块沿用系统既有进程域，不代表新增专用 SELinux 进程隔离。

### CentOS 原生 Nginx 与身份切换

沿用上节 CentOS Stream 10/amd64 官方镜像、Enforcing 策略及面板程序，在无外网、无宿主端口映射的 Docker/QEMU 独立内核虚拟机中接入本地批准的静态 Nginx 1.30.6，SHA-256 为 `1e168f3239c9f650651d68797b97f986c7c21769c8a9db8ca0caa2fdf6b46f08`。未安装目标软件包或修改开发宿主机配置。

首轮 Nginx master 活跃，但 worker 日志记录 `setuid(991) failed (1: Operation not permitted)` 并全部退出。实际进程缺少 `CAP_SETUID`；定点 systemd 单元重现显式 `User=root`、禁止提权及过滤设置下的能力丢失，添加 `AmbientCapabilities=CAP_SETUID` 后正常切换 UID，与 [systemd v257 执行器的能力处理](https://github.com/systemd/systemd/blob/v257/src/core/exec-invoke.c) 一致。安装器所有 root 服务模板显式保留这项身份切换能力，非 root Web 仍使用空 capabilities。审计还发现 SELinux 工具继承安装锁描述符产生拒绝记录；调用这些工具时关闭子进程的 FD 9，父安装器继续持有安装锁。

已通过以下实际行为：

- Web 专用 UID、空有效 capabilities、禁止提权和目录权限；Agent/Nginx 挂载命名空间不可见主密钥。Nginx worker 使用专用账户，`CapEff`、`CapPrm`、`CapAmb` 均为零。
- 实际 HTTPS 引导、登录、正常密码重新认证和统一响应/请求头；创建 HTTP 反代后，通过本机 80 端口取得上游响应 `P5_NATIVE_UPSTREAM`。
- 候选配置绑定已占用端口时，原任务进入 `rolled_back`，旧修订、发布记录与流量保持；候选切换后 SIGKILL Agent，原操作恢复并确认回滚。删除失败候选后再次应用成功。
- 安装器同参数重放、Web/Agent 重启和整机真实重启后，原会话、节点身份、配置版本 3、修订、发布记录和业务流量保持；重新核对 worker 身份和 capabilities。
- 初始业务检查及重启后均核对 Enforcing、安装意图与规则散列、关键路径扩展属性及 `matchpathcon -V`，当前启动期间未发现相关 AVC。三个主服务实际沿用 `unconfined_service_t`。

关闭描述符的安装器 `4905cf1437f2d030871322610f5483bd6827fb5ac92f7ac23558a5dacced4f9f` 已完成文件标签模块移除后的重装；最终安装器 `75c8da170d3f4c8706ebca4a3126c4efdbcf238ac8afda284c7be2ecb77b750c` 在派生安装盘归档旧单元后重新生成服务，完成上述重放和运行验收。脚本语法及差异检查通过；面板 Go 程序未改动，复用上节产物。

首次续验夹具误将 `/proc` 文件长度作为就绪条件，后续修正等待条件并通过虚拟机内部 SSH 读取实际进程和 Nginx 文件日志定位身份切换问题。失败记录、原盘及派生盘均保留。主要记录为 `.validation/native-vm/centos-native-nginx-1.log`、`centos-native-nginx-resume-1-console.log`、`centos-native-nginx-fixed-1-console.log`、`centos-native-nginx-live-repair-1.log` 和 `centos-native-nginx-live-1-console.log`；最终驱动记录 `centos-native-nginx-live-1-run.log` 输出 `P5_CENTOS_NATIVE_NGINX_VM_LIVE_ALL_PASS`，虚拟机已关机，验证容器退出。磁盘位于既有命名卷，最终盘为 `centos-native-nginx-live-1.qcow2`。

本轮覆盖原生 Nginx 到本机上游的 HTTP 反代，不替代 TLS/Stream 业务、SELinux 下的 Docker 面板、防火墙、其他系统/架构及升级事务验收。

### Debian 13 默认 Docker 部署

使用前述 Debian 13/amd64 官方云镜像及独立内核 `6.12.113+deb13-cloud-amd64`，在隔离虚拟机内安装 Docker Engine 29.9.1、containerd 2.4.2、runc 1.5.2 和 Compose v2.40.3。采用默认 containerd 镜像存储、标准 Docker 网络、`docker-default` AppArmor 和内置 seccomp；宿主网络低端口阈值保持 1024。实际部署为宿主机 Agent 加面板/Nginx 容器，使用项目 Dockerfile 构建的 amd64 镜像，Nginx 模块在镜像中预置。准备阶段仅在虚拟机安装依赖；运行阶段关闭外网且不映射开发主机端口，未修改开发主机软件、服务或系统配置。

首轮实际来源校验发现 Docker 返回的镜像 ID 为签名引用的索引摘要，原实现错误地要求它等于平台 config 摘要；这与 [Moby containerd 镜像检查实现](https://github.com/moby/moby/blob/master/daemon/containerd/image_inspect.go) 一致。准入现在只接受签名 config 或签名引用目标的身份，并继续核对精确仓库引用、平台及启动器内容；运行绑定保存实际 ID，已冻结的运行、替换和恢复检查仍须精确匹配。第二轮发现直接以非 root 用户执行的 `nginx -t` 缺少低端口绑定能力。普通配置校验及独立候选容器改为复用固定启动器，执行 Nginx 前降权且仅保留 NET_BIND_SERVICE；原 exec 回执增加启动器命令身份，恢复同时约束降权前后的程序、身份、权限及命名空间。

已通过以下实际行为：

- 本机明确信任的签名包安装准入，篡改清单及未受信任 Key 的拒绝；v14 默认 Docker 安装、生成的 Compose 启动和同参数安装重放。
- 面板 UID 999、空有效/许可/ambient capabilities，Nginx master UID 995、允许范围内的 NET_BIND_SERVICE；两者禁止提权、只读根、独立 PID/挂载空间且不挂载 Docker Socket。Agent 挂载空间和 Nginx 容器均不可见主密钥。
- HTTPS 引导、登录、正常密码重新认证及统一响应/请求头；80 端口真实 HTTP 反代取得 `P5_NATIVE_UPSTREAM`。占用 18089 的候选进入 `rolled_back`；候选切换后 SIGKILL Agent，原操作恢复并确认回滚，旧流量保持。删除失败候选后再次应用成功。
- 在实际 Docker exec 启动器仍为 root 时将其 SIGSTOP，杀死诊断控制程序，再由独立调用沿原回执核对并通过 pidfd 终止该启动器；回执清理，原 Nginx master PID 和流量保持。独立候选校验容器在标准低端口策略下完成固定 `nginx -t` 并正常清理。
- 强制重建两个容器，确认容器 ID 均改变；安装重放、Agent 重启和整机真实重启后，原会话、节点身份、配置版本 3、修订 `5afcd2ca-1c53-44d2-9e15-b9df1c699571`、发布记录及业务流量保持。重启后再次核对身份、权限与主密钥隔离。

程序 SHA-256 为 `591ac1484b498d1abfa56a26e636573cd239a64e04c116f879a1e28d959b175d`，安装器沿用上节的 `75c8da170d3f4c8706ebca4a3126c4efdbcf238ac8afda284c7be2ecb77b750c`。新增的镜像身份准入用例接受经典 config 和 containerd 索引 ID，拒绝其他/空 ID；相关 releases、nginxcontainer、Agent 现有测试及完整程序构建通过。记录为 `.validation/native-vm/docker/image-identity-go-checks.log`、`diagnostic-launch-go-checks.log`、镜像构建日志及 `runtime-environment-3.json`。

验证期间另修正夹具的启动等待条件、上游脚本读取权限和逐服务就绪检查；沿用已安装磁盘续验未完成的业务流程，未改动产品断言或重跑已通过的安装。原始失败记录、两轮原盘及最终盘均保留。主要记录为同目录的 `runtime-initial-1/2/3.log`、`runtime-resume-2/3.log`、`debian13-docker-runtime-3-console.log` 和 `debian13-docker-runtime-3-run.log`；重启后输出 `P5_DOCKER_RUNTIME_ALL_PASS`，驱动退出码为 0。虚拟机均已关机，验证容器退出；最终磁盘 `debian13-docker-runtime-3.qcow2` 保留在既有命名卷 `nginxpanel-p5-native-vm-20261019`。

签名材料由隔离测试发行者产生，amd64 索引、配置及层来自实际镜像；未使用的 arm64 目录条目为明确标记的测试数据，不是可执行发行资产。本轮覆盖本机信任准入与默认部署，不替代正式发布工作流、多架构 OCI 证据、镜像升级事务、其他系统/架构和 SELinux 下 Docker 的验收。

## 尚待验收

- 其他系统/架构及 Docker 面板组合的账户与 systemd、其他 DNS 所有者、其他防火墙后端、Fail2ban、管理监听的其余场景，以及其他危险操作在重启/断电/中断后的恢复，仍需独立 Linux 系统验收；已完成范围限于上文列明的组合及场景。
- 两种架构的正式原生资产、arm64 预置模块镜像、正式发布链的签名镜像来源与多架构证据、升级/回滚和其他备份恢复故障注入，仍需完成产物构建及运行验收；上文本机信任准入、amd64 运行绑定及克隆恢复结果不替代这些检查。
- 真实域名的 ACME/DNS、通知接收端及跨主机 API 一键迁移，尚未进行外部集成验收；容器内双节点迁移与授权结果见上节。
- 正式 GitHub 仓库及发布凭据尚未配置，未运行真实发布 CI、推送或发布。项目 MIT 许可证已补齐，第三方组件保留各自许可。
- UI 由用户人工验收，未创建或执行 UI 自动化测试。
