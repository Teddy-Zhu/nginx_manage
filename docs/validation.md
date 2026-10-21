# P5 集中验证记录

2026-10-21。P5 进行中：原生安装/重启矩阵已完成 14/14，Docker 部署完成 2/14；构建、接口、迁移、Nginx、备份恢复、防火墙、DNS、监控与 Fail2ban 的结果分别按以下证据范围记录。其他 Docker 组合、完整 Docker 转发事务、未覆盖故障点和功能组合、正式签名来源及外部集成仍需验收。

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

### Debian 13 Docker 签名升级运行路径

沿用上节 Debian 13/amd64、默认 Docker/containerd 和无外网的独立内核虚拟机，使用同一隔离测试发行者签发本地包与实际 amd64 镜像。前七轮安装器沿用上节；第八轮增加就绪运行目录及原生 Web 写权限，安装登记仍为 v14。开发主机配置未修改。首次真实升级发现并修正以下运行阻塞：

- Agent 的 UMask 0027 会产生 0750 的公共暂存目录；接受并规范化该安全权限，仍拒绝组可写和符号链接。原 `recovery_required` 准备操作启动时沿原签名缓存重新对账，不重建回执或重新下载。
- 受限 systemd 服务中的 `openat2` 返回 ENOSYS，与 [RestrictSUIDSGID 的系统调用限制](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RestrictSUIDSGID=) 一致。改用逐级固定目录 FD 的只读 `openat`，全路径拒绝链接，保留原文件身份、权限、大小与散列检查，以及该服务隔离设置。
- v14 Agent 入口的尾部空白、systemd 实例服务自动生成的模板 slice，分别使原固定入口及直接控制组假设拒绝正常升级。现在规范化入口首尾空白，并同时绑定实际单元 ControlGroup 与 MainPID，三个独立 worker 共用此校验。
- 应用更新遗漏子进程控制的 launcher 协议绑定；现在复用独立进程控制的现有校验。Web 与 Agent 两层维护准入分别补齐 Nginx 镜像创建/续办及两种镜像替换固定接口，普通配置写入仍被关闭。

第五轮从干净 Docker 系统盘安装已修正的基线 `3bd8940f50a04d432bf785a0e95af566a92f68a9e5f4fea15b915dd195281658`，使用同源码不同版本标签的目标 `0.1.5-dev`（程序 `b6ad90d59ab65cdcc17177bf0b9716f400060b1504c98710ef0c3f3c8bdd6e2e`）。签名准备、独立 Agent 升级及普通应用更新均提交成功；Agent 升级只更换 Agent 进程，应用更新不重建容器或重启 Nginx master。真实快照、schema 37、节点、配置版本/修订、发布记录及 HTTP 反代流量均核对。应用更新任务为 `d9005733-767a-49f4-8a93-1071db4037fb`，root 操作为 `5056b1d8-6132-4edf-a20e-13850895a811`。

应用更新完成后自动释放维护会话，夹具最初错误地继续沿用会话；修正为正常重新进入维护后，面板镜像任务在 Agent 准入处被拒绝，尚未发布 root 镜像操作。原失败任务 `8770a7ef-d117-4fe6-b106-103bac3fca54` 及磁盘保留；未删除任务或修改业务数据库。更早轮次的未确认准备、应用更新及升级失败盘同样保留，不将其计作成功升级。

第六轮已完成新 Agent 升级，但面板镜像预检遭 15 秒 IPC 客户端/服务端时限中断，未留下 root 操作；原任务 `7e25caeb-fd0d-4e48-a568-2333dec715e9`、磁盘及日志保留。禁止发布 root 回执的预检诊断耗时 50.5 秒并完成意图校验，定位到普通 IPC 时限不足；诊断跳过执行器自身路径校验，不计作真实服务升级通过。镜像提交改用任务、客户端与响应一致的两分钟上限，服务端预检预留五秒失败响应时间，其余 IPC 时限保持。证据为 `docker-upgrade-v6/diagnose/result.log`、诊断源码及原请求日志。

第七轮新时限下完成 Agent/应用更新，镜像预检在约 46 秒后明确拒绝：Agent 的挂载命名空间隐藏 `app`，无法连接其中的就绪 Socket。原失败任务 `e58063d8-1519-41d4-ac47-3c6b9ba1ce38`、原盘与拒绝证据保留。就绪 Socket 改放在面板账户独占的 `run/readiness`，启动时原子发布同目录的公开 TLS 证书；连接仍核对 root 对端和实际程序/PID，证书继续核对权限、身份、链接数及实际 HTTPS。数据库、私钥和主密钥保持隐藏，原生 Web 仅增加该运行目录写权限，Docker 固定挂载定义不变。

第八轮从干净 Docker 系统盘安装修正后的基线，Agent、应用及面板镜像升级均提交成功。面板镜像任务 `4fb0b4bc-13f6-400e-94eb-7382fb9fdc66` 选择实际签名索引 `sha256:b10b39af9faab557e531ae0b619942f1706c93838347fe00c267d7ef477b1d17`；只有面板容器发生重建，Agent、Nginx 容器和 master PID 保持，原配置与流量核对通过。记录为 `docker-upgrade-v8/agent.log`、`application.log`、`panel.log`。

随后 Nginx 候选校验在切换前退出 1，原运行实例保持。沿同一签名目标和配置定点复现，日志显示新启动器误读旧运行绑定，报“镜像程序与宿主机登记不一致”；诊断容器确认清理。候选校验现在只读覆盖本次批准的绑定，核对文件内容和固定挂载，旧运行选择保持；仅在确认校验容器不存在后清理临时绑定，绑定缺失不冒充容器不存在。原失败操作 `8df726a0-c881-4de3-9c72-9b3d13e42217`、原盘及 `docker-upgrade-v8/diagnose/result.log` 保留。

第九轮在原节点通过签名接口部署候选绑定修复，Agent、应用更新提交成功，Nginx 候选完整配置校验通过。独立 worker 随后初始化 HTTP-01 存储时发现单元缺少 ACME 目录写权限；原操作 `2e69b8f2-a4d5-41aa-9530-01367ab9c856` 保留 `recovery_required`，目标容器尚未创建。模板补齐专用 ACME 目录；原冻结模板与回执不改写，原盘关机保留，修正后的安装模板另建独立盘验收。夹具曾指向旧版本目录，导致 Agent 正确拒绝重复升级；修正夹具后继续，失败任务和日志保留，未修改业务数据库。记录为 `docker-upgrade-v9/fixture-path-failure/`、`agent.log`、`application.log`、`final-state.log`。

第十轮在修正模板上通过安装和签名 Agent 升级，Nginx 校验通过后又发现运行存储发布锁缺少写权限。模板同时补齐运行目录；原操作 `bf7d1854-3446-4790-8b00-339fb93050b4`、磁盘和 `docker-upgrade-v10/final-state.log` 保留，不改写已冻结单元。后续沿源码一致的基线及原签名目标另建安装盘，仅续验 Nginx 及持久化，复用前述有效的 Agent、应用、面板镜像升级结果。

第十一轮使用源码一致的 `0.1.9-dev` 基线与已签发的 `0.1.10-dev` 目标，在最终模板的独立安装盘完成 Nginx 升级。任务 `7d1c08e2-8b55-42e5-b523-79ed0036c937`、root 操作 `ec20c1cc-bb18-4159-8330-ba3dfc4e8b60` 先通过完整配置校验并启动目标镜像，在 `confirming_agent` 阶段实际 SIGKILL 独立 worker，再通过原 API 续办；任务和操作 UUID 保持、授权序号增至 2，最终 `succeeded/committed`，维护会话正常释放。实际签名索引为 `sha256:27b283df118408899f9e9b1cf3a6457f07817faf83394a7e5645d12bd55711fb`，程序 SHA-256 为 `fb62094e4a63c20878ac4bfb6218b17ecce84c642e37931402d844fbf6a8b9b2`，清单为 `20fdee461d4ece1ba42a562f0699a0a0169fd45a18ac695f973d311b78514242`；未重复已通过的应用和面板镜像升级。

随后强制重建两个容器，确认各容器 ID 改变；整机重启确认内核 boot ID 改变。两次均核对原节点、配置版本/修订、发布记录、两种镜像选择及实际 HTTP 反代流量。重启后核对就绪目录、Socket 和证书的专用身份/权限，公开证书指纹与原管理证书一致；Agent 命名空间仍不可见业务数据库和私密证书目录，可读取公开证书，临时候选绑定已清理。最终安装器 SHA-256 为 `32ee9d61f9afb122dc521af1ead9c955b776e99e98608d5df4430e48cadd6ec7`。记录为 `.validation/native-vm/docker-upgrade-v11/verify-chain.log`、`nginx.log`、`persistence.log`；分别输出 `P5_NGINX_UPGRADE_REMAINING_ALL_PASS` 和 `P5_UPGRADE_REBOOT_PERSISTENCE_PASS`。相关虚拟机均关机，验证容器退出，原盘与最终 `debian13-docker-upgrade-11.qcow2` 保留在既有命名卷；未修改开发主机配置。

安全路径回归覆盖祖先/最终链接、路径穿越、写入/创建标志拒绝，以及目录路径被替换后仍沿已固定 FD 读取；`internal/secure` 测试通过。实际 CLI 已核对 UMask 0027/0077 暂存成功、不安全目录拒绝，以及原准备 UUID 恢复。记录为 `.validation/native-vm/docker-upgrade/openpath-go-checks.log`、`permissions.log`、`reconcile.log`。Agent 现有测试（缓存结果）、app 现有测试、panelready 包编译、安装脚本语法及两种版本标签的完整程序构建通过，记录为 `.validation/native-vm/docker-upgrade-v8/go-checks.log`；imageupdates 包编译结果见第七轮日志；候选绑定修复后的 Agent、nginxcontainer 现有测试及完整程序构建通过，记录为 `docker-upgrade-v9/go-checks.log`、`final-build.log`。最终模板的安装器语法和完整程序构建通过，记录为 `docker-upgrade-v11/build.log`。第五轮业务记录为 `docker-upgrade-v5/agent.log`、`application.log` 及原失败日志。

### Debian 13 Fail2ban 官方代码与受管服务

2026-10-20：从干净提交 `397b65ef5687be1e03016963b4145f332d587217` 按锁定来源组装 Fail2ban 1.1.1 官方代码包，保留其 GPL、MIT 和 Async 许可；不打包解释器或发行版 site-packages。实际发布工具通过来源、文件清单和 SPDX 检查，并生成本地测试签名。归档包含 234 个文件，338816 字节，SHA-256 为 `f1a7f7208aa212bf609e6bafb5bb5b036e50cd85dd90a13775fe6a9e1a5c3f8b`；清单为 `92d2e88e04accd903866574f75ffe0fdb1c575cf1905681ccfa125491ac3c3cd`。规格使用 `p5-validation/nginxpanel`、`0.2.0-dev` 及本地测试 workflow 标识，不代表真实 CI、正式发布账户或生产信任根。组装和签名记录为 `.validation/native-vm/fail2ban/assembly.log`、`bundle.log`。

实际 Debian 13/amd64 独立内核虚拟机使用发行版 Python 3.13.5。验收定位并修正：不存在的 Socket 单元不提供服务专属 MainPID，须用其实际单元状态确认缺席；开机启用/停用需要同步 systemd 加载状态并核对结果；Agent 须能在 `/etc/systemd/system` 原子创建、删除固定的独立服务单元；官方过滤器须放在私有配置目录的 `filter.d` 下；客户端拒绝集合的 UUID/IP 组合键要求至少 128 字节哈希桶，该设置须置于所有 `map` 前，并保留更大的显式设置；单 jail 冷读取串联两段采样，Agent/API、前端和节点转发的外层时限须覆盖它们。手动操作前的 12 项固定只读查询复用同一官方客户端进程，避免重复启动解释器耗尽原 12 秒外层时限，仍逐项核对参数、动作和封禁时间。原生 Nginx 日志目录显式恢复预期的遍历权限，避免 Agent 的私有 UMask 阻止降权工作进程在轮转时重新打开日志，文件仍为 0640。未伪造 PID、跳过实例冲突保护或扩大正则及采样工作进程预算。

CLI 实际验收覆盖已存在 Socket 的拒绝、默认不启动及不启用、原安装 UUID 重试、显式启动/启用、停用及重新启用，最后 `NeedDaemonReload=no`。另一个新环境实际通过 API 默认安装、启动、启用、停用及重新启用，任务最终成功，实例版本 1.1.1、服务状态和加载状态一致。该范围记录为 `.validation/native-vm/fail2ban/enable-failure/managed.log`、`managed.log` 和 `.validation/native-vm/fail2ban-api/lifecycle-retry.log`、`confirm.log`；后者输出 `P5_FAIL2BAN_API_INSTALL_SERVICE_FINAL_PASS`。首轮测试夹具存在 stdin、HTTP 状态断言及保存 Cookie 变量错误；原失败记录保留，确认脚本只核对最终任务和实例，没有重放已成功操作。

受管 `nginx-http-401` jail 使用 `nginx-client` 动作，可信本地代理分别传入 IPv4 `198.51.100.77` 和 IPv6 `2001:db8::77`：实际 401 日志达到阈值后，官方引擎出现封禁且 HTTP 返回 403；API 手动解封任务成功，官方封禁移除且 HTTP 恢复 200。该范围在 `0.2.7-dev` 程序上完成，SHA-256 为 `5b731ab6588f508cb30143dd16048bcdb15e2f7524755be5262e757aea1191b2`，记录为 `.validation/native-vm/fail2ban-acceptance/jails.log`；这是日志中的双栈来源地址验证。

`0.2.8-dev` 程序修正原生目录权限后，实际重命名日志并对已确认的 Nginx 主进程发送 USR1，核对主进程及全部工作进程均打开新 inode；新文件中的 401 日志触发封禁且 HTTP 返回 403。随后 API 手动封禁另一地址，记录其原到期时间、节点身份和配置修订。程序 SHA-256 为 `62ccf9da0c6622c27b6adddbe6a3970c33c2e0afca89e3c52b73c6351a517868`，安装器为 `35dc58a87acd263f8b88257fe5ccc7c47b7c2a94c1c6ceeeea88a97f22c3b052`；记录为 `.validation/native-vm/fail2ban-rotation/persistence-before.log`。

实际系统重启后 boot ID 已变化，节点身份、配置版本/修订和 jail 集合保持一致；官方引擎恢复原封禁，实际 HTTP 继续返回 403，API 解封后恢复 200。原到期读数 `1792496353`，恢复后为 `1792496354`：官方数据库以 `int(round(ticket.getTime()))` 保存起点，而 CLI 丢弃微秒，符合项目既有 ±1 秒核对约定，未按重启时间重新计满 900 秒。记录为 `.validation/native-vm/fail2ban-rotation/reboot.log`、`persistence-after.log`。初始夹具要求整秒完全相同，失败记录保存在 `persistence-after-exact-second-failure.log`；按上述既有契约修正夹具后，仅续验重启后的观察及尚未执行的解封，没有重启或重放已成功操作。

故障定位记录保留：`.validation/native-vm/fail2ban-final/diagnosis-map.log` 确认默认哈希桶不足，`fail2ban-deny/diagnosis-nginx.log` 确认指令必须早于首个 map；`fail2ban-verified/diagnosis-address-time.log` 记录原读取在 12.06 秒取消，同环境 `diagnosis-client-batch.log` 的 12 项官方查询耗时 0.748 秒；`fail2ban-acceptance/diagnosis-rotation.log`、`diagnosis-reopen.log` 和 `diagnosis-log-permissions.log` 证明新文件为空、请求仍写入旧文件且工作进程因目录权限无法重开。双栈结果保留有效，目录修正后的新环境仅补验轮转与重启。

相关现有 Agent、transport 测试和完整程序构建通过，节点转发包编译通过（无测试文件）；记录为 `.validation/native-vm/fail2ban/deny-build.log`、`callers-build.log` 和 `fail2ban-rotation/build.log`。前端单 jail 请求设置已接入，UI 仍由用户人工验收。以上操作均在隔离 Docker 工具容器和独立内核虚拟机中执行，未调整开发主机的系统环境；磁盘、原始失败记录及本地测试密钥均保留。最终虚拟机已正常关机，归档记录为 `fail2ban-rotation/final-state.log` 和 `vm-run.log`。


### 2026-10-20 独立面板 Fail2ban 宿主机动作（P5）

- 范围：Debian 13/amd64、Python 3.13.5、nftables 1.1.3、官方 Fail2ban 1.1.1 源码及前节隔离签名资产。Docker 外层断网，虚拟机两核、2 GiB，使用原生安装器 `--without-nginx`；Nginx 程序未安装且其服务未运行。沿用已签名 Debian trixie 包安装最小 nftables 依赖，仅修改虚拟机。最终主程序 `0.2.11-dev` 由 Go 1.27.2、`CGO_ENABLED=0` 构建，SHA-256 为 `76ee40d874486874b4374f035aea22e12b8b27780b43a1b2f58d4c8701dfc714`。现有 Agent、transport 测试及静态构建通过；fail2ban 包无单元用例。Node 24 前端构建（含应用类型检查）通过，后续仅修改 Go 预览调度，未重复前端构建。
- 实际行为：API 默认安装、启动及启用受管引擎；root 明确登记空表、管理来源、受管封禁来源及持续同步。冷预览通过，唯一的面板登录 jail 成功应用。虚拟机内独立网络命名空间通过 veth 以真实 IPv4、IPv6 地址各发起三次失败登录；日志只记录实际对端，伪造的转发头未改变来源，也未记录密码。官方引擎确认封禁后，已核对的宿主机对象阻断新 TCP 连接；通过官方 API 解封任务后，封禁集合归零且 HTTPS 访问恢复。IPv6 封禁期间 `SIGKILL` Agent，MainPID 从 3138 变为 4422，原同步会话重新采样达到 current，真实 TCP 仍被阻断，随后 API 解封恢复访问。
- 失败与修正：首轮缺少 nft 工具时完整管理器检查拒绝同步；补齐目标依赖后原批准继续有效。旧采集/并发方式在两核 TCG 冷预览中超时并拒绝应用，保留各轮环境与日志；修复复用官方客户端、移除重复探测并限制预览并发。第 3 轮验证构建遗漏静态链接选项，被安装器拒绝，未进入业务验收，动态产物和失败盘保留。最终第 5 轮夹具误将 CLI 的 runtime 嵌套字段当作顶层字段，首次 IPv4 封禁后中止；修正字段读取后从原封禁状态续验，没有重复失败登录或重新批准。
- 证据：`.validation/native-vm/fail2ban-host-input-v5/` 的 `build.log`、`host-prepare.log`、`flow.log`、`flow-resume.log`、`final-host-state.json`、`final-host-preview.json` 和 `final-runtime.json`；有效前端构建日志在 `fail2ban-host-input-v3/web-build.log`。此前 `fail2ban-host-input`、`-v2`、`-v3`、`-v4` 的源脚本、日志、原生安装及批准记录、二进制、密钥和虚拟磁盘均保留。没有创建或执行 UI 自动化测试。此轮未验收宿主机动作的整机重启恢复，不以 Agent 重启替代；其他后端、平台及外部场景仍按下节处理。

### 2026-10-20 Fail2ban 同机整机重启与显式停用（P5）

- 沿用上一节 `0.2.11-dev` 静态主程序及 Debian 13/amd64 原磁盘，复用两核、2 GiB、外层断网的隔离虚拟机；没有源码变更，未重复构建、类型检查或单元测试。连续三个新内核启动身份均实际变化，原节点 ID、策略版本和管理 TLS 指纹保持一致；原生程序、批准、密钥和磁盘继续保留。
- 原盘首次重新启动，在明确的 `recover_on_boot` 批准下重建新授权范围，空封禁集恢复 current，双栈访问正常。随后通过 API 新增一个 900 秒封禁，核对官方记录、current、内核对象及真实 TCP 超时；停用 Web 的开机启动并整机重启。Web 仍停用、Nginx 未安装，Agent 和官方引擎运行；新持续会话重新达到 current，已核对内核对象包含当前封禁，真实 TCP 继续被阻断。恢复 Web 开机启动及服务后，官方封禁的绝对到期时间差为 0，原保护、来源及同步事件文件散列全部保持不变；API 解封任务完成后内核封禁数归零，IPv4/IPv6 访问正常。
- 明确停用当前持续会话，规则清除完成后核对空表及无 INPUT 链，再次整机重启。Agent、官方引擎、Web 均运行，当前停用事件 ID 保持不变、`enabled=false`、`recover_on_boot=false`；完整内核视图证明目标表不存在。通知执行器并等待 35 秒覆盖后台轮询后，目标仍缺失，恢复事件清单及散列未变，未自动重建或重新授权；双栈 HTTPS 访问正常。
- 证据保存在 `.validation/native-vm/fail2ban-host-reboot/`：`setup-network-setup.log`、`persistence-before.log`、`reboot.log`、`web-stopped.log`、`after.log`、`stop-before.log`、`stop-reboot.log`、`stop-after.log`、`agent-journal.log` 及 `artifacts/` 内各阶段原始状态。Web 开机开关已恢复，目标持续会话按显式停止意图保持停用，虚拟机正常关机。没有修改开发宿主机环境或创建 UI 自动化测试。身份/实例变化、准备及发布点中断、创建未知结果、恢复期间再次重启、维护和取消仍待验收；此节不证明这些场景完成。

### 2026-10-20 Ubuntu 24.04 原生部署及探测 Socket 恢复（P5）

- 使用 Ubuntu 官方 Noble 云镜像，下载时核对官方 SHA256SUMS 及完整镜像散列；原盘系统为 Ubuntu 24.04.5 LTS/amd64、内核 6.8.0-147-generic。沿用两核、2 GiB、外层断网的独立内核虚拟机，原生主程序为上一轮 `0.2.11-dev`，静态 Nginx 及前端复用已批准资产。AppArmor 实际启用并加载 117 个系统配置；Web、Agent、Nginx 的实际标签为 `unconfined`，不将其记为产品专用 AppArmor 策略约束。
- v14 原生安装、独立用户/权限/密钥隔离、Web 和 Nginx worker 降权及零有效能力通过；严格核对统一 API 封装。端口 80 的 HTTP 代理实际返回固定上游内容；占用 18089 导致的应用按原修订及部署身份回滚。另一次候选指针切换后，以 pidfd 仅向 Agent MainPID 发送 SIGKILL，原任务 `426e3d07-9735-4ea6-bd44-c89dca39e684` 自动恢复为 `rolled_back/rollback_confirmed`，原业务流量持续可用。
- 初次中断脚本使用 systemd 全单元 kill，在主进程已被杀死后因辅助进程返回错误；原控制器退出失败，退出处理使虚拟机正常关机。原盘重新启动后暴露真实问题：固定探测 Socket 遗留在文件系统、内核已无引用，Nginx 因地址占用而无法启动，原任务停留在 `recovery_required`。相关失败日志、原盘和批准材料保留。启动入口现仅在同初始网络命名空间、root 保护目录及归属正确、完整内核表无引用、连接明确拒绝且 inode/ctime/模式复核未变时删除固定 Socket；校验模式不清理，活动、已绑定未监听及异常路径均拒绝清理。
- 9 个真实 Unix Socket/root 定点回归全部通过，没有跳过；`0.2.12-dev` 静态候选构建通过，SHA-256 为 `bfb7f90b2f4e7520e3b23899fdc6e9628d466e4a7884b38bcc0a11197bd473cc`。原失败现场通过 root 显式批准的候选启动器和临时独立服务验证：校验模式保留原 inode 262605，实际启动替换为 262552 并恢复真实 HTTP；再次启动拒绝清理已有内核引用的 Socket，原服务流量保持正常。停止临时服务后恢复原正式单元，原任务 `e723a67e-d987-43c8-a04c-30505384fb72` 在同一 UUID 下自动对账为回滚确认，原修订及部署身份保持不变。已安装的不可变程序及选择仍为 `0.2.11-dev`，此项不替代新候选正式升级后的开机恢复验收。
- 清理脚本曾误判两个测试资源 ID，删除了正常测试站点，随后应用被正确回滚。通过实际监听与域名字段识别资源，使用正常 CRUD 重建测试站点并移除占用端口站点；修正后的应用任务 `903b8533-ec1b-4351-b977-60bfefefef10` 成功，业务恢复到单站点、期望版本 5。错误清理任务 `6689cdbe-25a6-4a8f-8113-4bd917270375` 的原失败和回滚记录保留。
- 安装重放、Agent/Web 服务重启及后续计划内整机重启通过；使用单独保存的本次重启前 boot ID 核对新启动身份，原始 boot ID 继续保留。最终节点、期望版本 5、修订和部署身份保持一致，HTTP 实际流量正常；管理 TLS 指纹仍为 `26f9d9971d99deb5b0235f7afe8e25c1bc8bb3897064a2dcbf3b26677f837407`。首次失败任务、中断任务和错误清理任务均保持原 UUID 及回滚确认历史，最终成功任务保持成功。重启前后的账户隔离、worker 零能力和 AppArmor 观测均通过。
- 证据位于 `.validation/native-vm/ubuntu24-native/`，包含原始 `initial.log`、`inspection.log`、Socket 诊断、`build.log`、`build-final.log`、`rescue.log`、`continue-api-cleanup-failure.log`、`cleanup-api.log`、`finish-resumed.log`、`finish-flow.log`、`final-api.log` 和 `artifacts/`；镜像来源与完整散列核对另见 `.validation/native-vm/ubuntu24-native/range-image.json` 和下载记录。没有修改开发宿主机环境，没有创建或执行 UI 自动化测试。虚拟机正常关机。新候选经正式服务升级后的异常退出及开机恢复见下一项；Ubuntu 的 Docker 面板组合、其他架构及其他故障矩阵仍待独立验收。

### 2026-10-20 Ubuntu 24.04 原生协调升级及异常重启（P5）

- 沿用上述 Ubuntu 原盘、密钥、节点及已发布配置，以独立测试签发者为现有 `0.2.12-dev` 候选和实际前端生成单个 amd64 签名离线包。本机 root 首次安装该测试仓库的独立信任，通过离线上传、检查和准备 API 暂存；上传脚本过于频繁地重新认证触发限流，修正后从原上传记录的已接收偏移继续，原失败日志保留。候选程序及既有 9 项回归结果沿用，没有重复构建或运行。
- 首个协调任务 `2a857638-3749-4145-a0e3-881eed911761` 因更新 worker 沙箱未开放 `/opt/nginxpanel` 写入，无法创建 Agent 临时选择指针，自动回滚并完成释放及清理。修正安装器的独立面板更新模板；在虚拟机由 root 安装从源码提取、仅展开数据路径的完整新模板，先核对原模板仅相差该写目录，再核对加载后的 `ProtectSystem=strict` 与写入范围。安装器 SHA-256 为 `748af915a49d7fb47a3d6031923b60c921a5c77e16d49d3aa2aabaadf77c6ee3`，隔离容器中的脚本语法检查通过；此轮未重放首次安装。
- 新任务 `230b423a-0a65-4510-8352-fc11c70aa806` 使用已准备候选、独立维护会话及明确停机授权，完成 Agent 与 Web 协调升级，最终 `succeeded/committed`、已确认释放且清理完成。维护期间并发应用返回 `MAINTENANCE_ACTIVE`；升级前后 Nginx 主进程和活动发布指针保持一致，节点、期望版本 5、修订、部署身份、主密钥及节点 TLS 材料散列保持一致，真实 HTTP 代理正常。
- 对正式 Nginx 服务以 pidfd 停住主进程并杀死同控制组的主进程及两个 worker，确认全部退出、固定 Socket 仍存在且内核表已无引用。systemd 自动重启通过已选择的新程序完成清理，Nginx 主进程代次改变并恢复真实流量，无人工删除 Socket 或临时启动服务。
- 在探测 Socket 仍有内核引用时保存并同步材料，以虚拟机内 `/proc/sysrq-trigger` 的 `b` 立即重启内核，未先停止 Nginx。启动标识从 `d7494550-51d8-4a3b-8dd0-8ece2657ecf0` 变为 `dee0c7c3-53e2-48bb-a422-03e08fb89641`；正式单元自动启动、固定 Socket 身份更新、原配置及实际流量恢复。API 报告原生 `0.2.12-dev`，实际 Web/Agent 程序散列匹配上述候选，Nginx 程序散列保持原值。此前六个应用任务与本轮回滚、成功升级的终态均保持，维护窗口开放，密钥材料未变。AppArmor 保持启用，三个进程仍为 `unconfined`。
- 证据位于 `.validation/native-vm/ubuntu24-upgrade/`，包含原始限流与升级回滚日志、修正后的升级日志、异常退出及突然重启记录、重启前后 journal、源模板和 `artifacts/final-proof.json`。突然重启遗留的测试 SSH 连接在新启动验收通过后按精确进程身份关闭；测试自启动单元已停用，虚拟机正常关机，原盘和全部审计保留。未修改开发宿主机配置，未创建或执行 UI 自动化测试。本次测试签发声明自动回滚；当时正式发布工具拒绝该声明，后续按版本策略修复见下一项，此项不替代正式发布链和其他系统组合验收。

### 2026-10-20 发布策略与自动回滚声明（P5）

- 正式发布工具改为读取独立批准的版本策略，`spec` 和 `bundle` 均要求 `--policy-file`；构建生成声明，签名从批准源码重新读取并核对。策略必须包含确切版本和显式布尔值，拒绝未知/重复字段、大小写别名、null、错误类型及超过 4 KiB 的输入；路径沿用发布账户归属与受保护上层检查，并须位于归档、镜像输入及输出树之外。CI 两个阶段及发布文档已接入同一版本策略，接收端的自动回滚准入保持原有语义。
- Docker 隔离集中验证通过新增 14 项策略检查及发布工具构建。首次容器未接收 stdin，未执行检查；随后测试目录的缓存卷上层为 1777，被发布路径保护正确拒绝。测试改用发布账户的受保护临时目录后，所有策略用例通过，无跳过；原始失败日志保留，没有放宽生产路径校验。
- 复用此前从干净提交 `397b65ef5687be1e03016963b4145f332d587217` 组装的官方 Fail2ban 1.1.1 材料，以实际发布 CLI 分别生成 `automatic_rollback=false/true` 规格并打包签名。两者均通过现有锁定源码、来源、许可和 SPDX 检查，234 文件归档的 SHA-256 保持为 `f1a7f7208aa212bf609e6bafb5bb5b036e50cd85dd90a13775fe6a9e1a5c3f8b`；相应清单 SHA-256 分别为 `7f39d6fb5b950edf681a0264bd87cd0a180a6e2b2ffedfd404baed3c1ad3ffeb`、`82dad5d1ec0d956df951c15f003b8cc013876beae8dfc7b7afcc1ef36bdeeb34`。
- OpenSSL 独立验证两份 Ed25519 签名，修改回滚声明后验签失败；两种方向的策略不匹配、构建树内策略、版本不符及缺少策略参数均拒绝生成发行目录。测试 seed 仅位于容器 tmpfs，导出公开验证材料；未使用生产信任或发布凭据。
- 证据位于 `.validation/release-rollback-policy/` 的 `go.log`、`publisher.log`、`proof.json`、`signed-false/` 和 `signed-true/`，输出 `P5_RELEASE_POLICY_ALL_PASS`。本轮验证签名工具的策略与真实组件打包，不代表新生成了完整面板、多架构镜像或跑通真实 GitHub CI；正式标签仍须在批准提交中提供本版说明及策略，仓库、发布凭据和其余 P5 门禁仍待完成。未修改开发宿主机配置，未创建或执行 UI 自动化测试。

### 2026-10-20 Ubuntu 24.04 原生 Agent 的 UFW 状态锁（P5）

- 从既有 Ubuntu 24.04/amd64 原生部署创建独立叠加磁盘，以另一台 Debian 12 虚拟机提供真实双栈客户端。首轮 iptables-nft 计划因无法排除其他管理器而拒绝；定点诊断确认宿主机 `ufw status` 成功，Agent 挂载命名空间内则因 `/run/ufw.lock` 只读失败。UFW 即使查询停用状态也会获取官方锁，不能将该失败视为管理器未运行。
- 安装器新增 `systemd-tmpfiles` 前置检查，验证已有锁文件并在安装及启动时预建 root 专用 `0600` 文件，Agent 的严格沙箱只新增该文件的写入范围。安装器 SHA-256 为 `4833f0ce8c395b2515f1a1f4dcb67624ea288e3d21276e6d81500d0eda6382e7`，隔离容器中 `bash -n` 通过。第二轮磁盘由 root 应用从该源码提取的写路径和 tmpfiles 内容，核对原单元仅增加此锁文件；此轮未重放完整首次安装。
- 第二轮确认官方 UFW 查询保持锁 inode；iptables-nft 本机空命名空间授权核对通过，真实 IPv4/IPv6 HTTPS 新连接确认及基线 TCP/UDP、SSH 访问通过。随后第一个业务计划返回 `409 CONFLICT`，提示计划期间工具、后端或完整规则变化；原因尚待定位。终态规则导出仅有测试第三方链，未安装业务规则，应用、确认、移除和故障恢复场景均未进入。节点密钥、活动 Nginx 指针及三个正式进程的程序散列保持一致，两台虚拟机正常关机；不得将这轮记为完整 iptables 验收通过。
- 对第二轮磁盘单独重启后，API 确认 UFW 已安装且未运行、管理器为 `direct-candidate`；宿主机与 Agent 挂载命名空间内的官方状态命令均成功，锁的设备号、inode、root 归属、`0600` 权限及单硬链接一致，查询未替换 inode。启动标识从 `e4609476-d40c-4bc7-8c4c-362d0f9973d0` 变为 `2f1dd446-e52f-47ee-8c03-cbbd9a35fb02`，输出 `P5_UFW_SANDBOX_REBOOT_PROBE_PASS`，随后正常关机。
- 首轮失败与定点诊断位于 `.validation/native-vm/iptables-ubuntu24/`；修正后的完整尝试、前后证据、准确源码策略、重启诊断及控制台位于 `.validation/native-vm/iptables-ubuntu24-v2/`。保留两轮磁盘及失败记录；未修改开发宿主机环境，未创建或执行 UI 自动化测试。UFW 业务规则管理和其他后端组合仍待独立验收。

### 2026-10-21 iptables 检查时限与首次规则应用（P5）

- 上轮 `409` 的定点诊断确认，计划后的完整环境核对耗尽了原 10 秒执行时限；当时并未证明工具或规则实际发生变化。现在将核对失败返回为不可用，仅在完整读取成功且散列不同的情况下报告冲突。iptables 就绪读取改为 20 秒、计划及应用为 45 秒；对应 IPC、Web 响应和浏览器等待分别预留至 50、55、60 秒，保留完整管理器、工具与双栈规则核对。
- 第三轮及第二次定点诊断仍在约 15 秒遇到旧 Web 的 IPC 限制。验证脚本仅替换了 `panel-native-serve` 启动入口，原生入口随后仍执行已批准的旧运行版本；即时进程检查捕获了短暂启动状态，最终前后证明文件中的 Web 散列仍为旧值。这两轮不算新 Web 的运行验证，失败磁盘与日志保留。
- 第四轮改用现有离线签名及协调升级流程，测试签发候选 `0.2.13-dev`，在升级回执成功后核对 Agent 与实际 Web 的程序散列均为 `19cba34a26c8d03ab2e4351d1526e2f858fdce155255c89bd2661244b5c74fb3`。这是隔离测试签发，包含当时未提交的修复，不替代正式发布工具、干净源码或真实 GitHub CI 验收。
- 双栈管理入口确认、规则计划生成和过期计划拒绝已通过。首次正式应用中，IPv4 restore 子进程退出码为 0，但随后官方 go-iptables 回读失败，IPv6 尚未提交；自动恢复也被回读失败阻断，原操作进入 `recovery_required/restore_unproven`。尚未完成策略确认、故障恢复和移除验收，不得标记该后端通过。失败盘正常关机并保留，继续使用独立叠加盘定位。
- 在独立诊断盘中用原候选输入重建 IPv4 受管链后，旧只读 helper 于 0.74 秒退出 125，直接官方链读取均成功；这次失败不是 8 秒 helper 时限耗尽。代码核对发现固定入口和代际指针复用了 UFW 的终端目标白名单，必然拒绝面板自有链跳转。回读改为逐项比较已认证原生快照中的固定跳转，业务代际规则保留原有语义核对；新增六个双栈子用例通过，覆盖 host/Docker 指针及目标、归属、条件和入口位置篡改。原始诊断及重放材料位于 `.validation/native-vm/iptables-library-diagnostic-v3/`；此重放不计作业务恢复验收。
- 第五轮签名候选 `0.2.14-dev`（程序 SHA-256 `e92cf563589d4abcc46acd44233e8891de6e087c6b7bd46cd7fe829a31784d98`）已完成双栈首次应用、跨新连接确认及第三方规则保留；原操作为 `succeeded/confirmed`。后续 B 策略被 Web 的 `MAINTENANCE_ACTIVE` 阻断，故障恢复与移除未执行，两台虚拟机正常退出，证据保留于 `.validation/native-vm/iptables-ubuntu24-v5/`。代码发现维护状态查询等待后台防火墙核对所持的互斥锁，可能超过其 3 秒查询时限；仅在写入准入开放时改为锁被占用即保守报告忙，既有维护租约和其他调用继续精确核对，保留 held/零在途契约。对应非阻塞回归用例通过；完整内核验收见后续记录。
- 第六轮控制器未指定镜像运行用户，SSH 因 UID 1000 无用户记录持续失败，未进入业务验收；控制器超时后结束 QEMU，不作为正常关机或恢复证据。已在虚拟机准备阶段补齐上述维护租约边界并构建签发 `0.2.16-dev`（程序 SHA-256 `4c399f3679455d02465551788e974b494278472b47ca9ba13948831d0a105ae1`、清单 SHA-256 `9565f70a22727c622c6c27039d81581e45c67b0df7df686728c1c34b524c6857`）；后续第七轮显式使用容器内 root，复用确切程序与签名包。原盘、未使用产物和失败日志保留于 `.validation/native-vm/iptables-ubuntu24-v6/`。
- 第七轮已核对实际 Web/Agent 均运行上述 `0.2.16-dev` 程序，双栈首次应用和确认、第三方规则保留通过；管理入口变更严格返回已确认防火墙规则的 `409/CONFLICT`，B 策略应用不再被维护查询误阻断。停止 Web 后夹具固定等待 4 秒即检查流量，观察到尚未完成恢复；原记录已是 `compensating/restoring_previous`，采集时 IPv4 为 A、IPv6 仍为 B，不能据此判定最终恢复失败或通过。Web 当时仍停止，故后续“三个进程均在运行”的检查也未满足；两台虚拟机正常退出，全部证据保留于 `.validation/native-vm/iptables-ubuntu24-v7/`。续验复用该盘的独立叠加盘，先核对原 B 操作完成回滚及程序/密钥/Nginx 配置未变，再执行尚未通过的恢复和移除场景；Web 停止场景使用 120 秒有界流量等待，双栈恢复前保持 Web 停止，并继续要求原操作 `rolled_back`。
- 第八轮复用第七轮磁盘启动，在原 B 操作恢复准入处超时，未进入后续故障矩阵。采集时原操作仍为 `compensating/restoring_previous`，原确认 A 的修复记录为 `recovery_required`，双栈内核均只有第三方规则、尚未恢复 A；实际三个程序、密钥摘要及 Nginx 活动配置均与第七轮基线一致。保留 `.validation/native-vm/iptables-ubuntu24-v8/` 的失败归档和独立磁盘；目标正常关机，未进入验收的客户端由控制器终止，不作为双机恢复通过证据。
- 对第八轮独立叠加盘停用 Agent/Web 后，专项诊断直接调用同一恢复执行器，仍使用已冻结的 `0.2.16-dev` 原工具绑定。30 秒预算在约 30.77 秒以 `context deadline exceeded` 失败，150 秒预算在约 94.76 秒完成并发布原 B 操作 `rolled_back/confirmed_restored`；双栈原规则由原恢复材料重建。此结果用于确认完整恢复预算不足，不计为 Agent 自动恢复通过；诊断二进制、源码、输出、规则归档和正常关机磁盘保留于 `.validation/native-vm/iptables-recovery-diagnostic-1/`。生产实现将启动、后台原操作补偿和已确认规则重建统一限制为 150 秒，保留交互回滚的 30 秒预算、单个库读取的 8 秒预算及 120 秒确认窗口；状态读取争用时保持不可用，原操作查询返回统一的能力不可用错误，避免排队超过请求时限，修复记录保留本次完整观测错误。
- 新增争用读取回归与静态主程序构建通过，前端沿用本轮已通过的构建；未重复执行原固定跳转和维护锁测试。第九轮使用新候选 `0.2.17-dev`（程序 SHA-256 `bbf6e012d138cb0a57cb441506e7eec22933f90358c4716b93ffd39e7417e181`、清单 SHA-256 `8f500c27232ada399d7e599d94bd2260c5c5bd6843f5839911a1328e7d19f3a4`）重新进行独立双机验收。停止 Web 的双栈等待上限为 180 秒，原操作终态等待上限为 300 秒，分别包含完整恢复预算及自动确认超时；仍要求 Web 启动前流量恢复、原操作确实回滚、重启前后第三方规则一致，不放宽终态或流量断言。
- 第九轮签名协调更新及实际程序核对通过，完成双栈首次应用确认、旧计划拒绝、严格管理入口保护，以及 Web 停止期间恢复 A、原 B 操作 `rolled_back` 和第三方规则保持。随后 Agent SIGKILL 场景的原操作查询收到结构化 `504/TIMEOUT`，夹具仅重试 `503/CAPABILITY_UNAVAILABLE`，因而提前退出；采集时该操作仍在补偿，不能据此宣布 Agent 中断恢复通过。程序、密钥和 Nginx 配置不变，两台虚拟机正常关机，证据保留于 `.validation/native-vm/iptables-ubuntu24-v9/`。
- 第十轮复用第九轮独立叠加盘和新客户端，只读等待识别确切的 `503/CAPABILITY_UNAVAILABLE` 与 `504/TIMEOUT`，其他错误仍失败，写入不自动重试。启动后原未确认操作自动回滚、确认 A 的双栈流量、Agent SIGKILL 及确认超时恢复通过；程序、密钥与 Nginx 配置不变。本机救援的原操作 `308592b6-6033-7f19-3fe7-3b7678d0e3ae` 未在 300 秒内完成，采集时仍补偿且 IPv4 为 A、IPv6 为 B，尚未执行后续重启和移除；保留 `.validation/native-vm/iptables-ubuntu24-v10/` 归档及正常关机的双机磁盘。代码核对发现救援入口仍用 30 秒交互回滚，失败后不断刷新重试时间，阻止较长的后台补偿；将此后台入口也统一为 150 秒，并限制无活动操作时的救援核对预算。
- 第十一轮构建新候选 `0.2.18-dev`（程序 SHA-256 `28f4dcd714d94db8aff9c9c70f772d1e7ca78e04785ca713b653a3d81034a21e`、清单 SHA-256 `2387d2c98e4a9934fb34ef048377fe990b3f352ad3594025c4adb467089b7f6a`）。第十轮失败盘的独立叠加盘仍运行旧 `0.2.17-dev`，恢复准入 180 秒超时，原救援操作仍在补偿，新候选尚未部署，不计为新修复验证结果；失败归档与磁盘保留于 `.validation/native-vm/iptables-ubuntu24-v11/`。
- 第十二轮的第九轮基线恢复准入、签名检查和候选准备通过，但协调更新 `d9d1f63b-17b5-460f-b0aa-f05b697c08ad` 在 `preflight_rejected` 正确拒绝夹具修改后的 Agent systemd 启动参数，候选仍未部署。配置与失败归档保留于 `.validation/native-vm/iptables-ubuntu24-v12/`，两台虚拟机正常退出。第十一轮同样两台虚拟机退出码为 0。
- 第十三轮从原始已登记安装基线先完成签名协调更新，再配置 iptables 夹具并建立确认 A。实际 Web/Agent 均为上述 `0.2.18-dev` 程序，本机救援和整机重启均完成原操作回滚、双栈 A 流量及第三方规则核对。后续移除应用的 HTTPS 回执出现 `DECRYPTION_FAILED_OR_BAD_RECORD_MAC`，归档显示原移除 `9d172c21-07c6-3451-f44d-f606f726129d` 已在 `waiting_confirmation/awaiting_new_connection`，尚未确认或停用模块；两台虚拟机正常退出，证据保留于 `.validation/native-vm/iptables-ubuntu24-v13/`。
- 代码核对发现移除需依次查询原操作、读取当前确认状态及调用 Agent，原 Web 55 秒写入时限只覆盖单个控制调用，早于组合路径完成。现将整次 API 调用限制为 75 秒，HTTP 写入为 80 秒，浏览器等待为 85 秒，并让防火墙模块停用复用同一预算；Agent 单步控制预算保持不变。静态主程序与前端重新构建通过，候选为 `0.2.19-dev`（程序 SHA-256 `7c2c5e881610f159b1d8d1ce475a59d0c801ba1f00aa403b4d2546564a633050`、清单 SHA-256 `5afd1822b7e53b9cc990fac04226a9ee7ed81b36f3079e3ea5cb9ecac6d49a52`）；第十四轮仅复验移除确认和停用，以新基线先升级再建立 A，并在停用前读取原移除的完整确认状态，写入仍不自动重试。
- 第十四轮签名协调更新及实际进程核对通过，Web/Agent 均运行上述 `0.2.19-dev`；确认 A 后，独立移除原确认版本并通过新连接确认，读取当前移除回执后停用模块成功。双栈 TCP/UDP 流量恢复、SSH 可达及第三方规则保持通过；控制器完成程序、密钥和 Nginx 活动配置不变的前后核对，输出 `P5_IPTABLES_UBUNTU24_TWO_VM_ALL_PASS`。两台虚拟机正常关机，退出码均为 0；证据保留于 `.validation/native-vm/iptables-ubuntu24-v14/`。
- 本阶段 native 内核结果限于 Ubuntu 24.04/amd64 的 iptables-nft，覆盖首次确认、管理入口保护、过期计划拒绝、Web 停止、Agent SIGKILL、确认超时、本机救援、正常整机重启以及确认移除/模块停用。有效结果分布于上述候选与独立磁盘，未重复未受后续修改影响的场景；其他平台/后端、Docker 路径及硬断电等未据此声明通过。
- 静态主程序及前端构建通过；早期对相关 Go 包的指定测试筛选没有匹配用例，仅证明包可编译，未记作防火墙单元测试通过。未创建或执行 UI 自动化测试，未修改开发宿主机环境。定点诊断、第三和第四轮证据分别位于 `.validation/native-vm/iptables-diagnostic/`、`iptables-diagnostic-v2/`、`iptables-ubuntu24-v3/` 和 `iptables-ubuntu24-v4/`。

## 2026-10-21 原生 Agent 已配置所有者的协调升级

- 上一阶段的 iptables 第十二轮曾拒绝手工追加防火墙参数的服务入口；代码核对确认同一固定比较也会拒绝安装器 `--dns-owner` 生成的合法 DNS 参数。本次只开放固定入口后的五个 DNS/防火墙键值选项及既定枚举，拒绝重复或未知选项；完整 root 服务文件散列、原参数顺序、实际 `/proc` 参数及 systemd 身份核对继续保留。
- 集中验证的 `TestAgentUpgradeConfiguredEntry` 通过（0.007 秒），覆盖 native/container Nginx 入口、四种 DNS 所有者、五种防火墙所有者、撤销授权值和组合参数，以及 UID/路径/维护范围变更、重复/未知选项和 systemd 变量等拒绝边界，共 44 个参数变体。两份静态 amd64 主程序构建通过；前端未改动，测试包逐文件核对复用上一阶段已验证的前端构建，未重复构建或执行 UI 测试。
- 隔离签名候选为 `0.2.20-dev`（程序 SHA-256 `1239f087525f9e73675eb124e2bf7db0faa6bec3a90950ef59b0fa7039928305`、清单 `e70db9abd4383923ff7cae4a91934327bbd75d1e6f1dae471e0e11970fb4c7e6`）与 `0.2.21-dev`（程序 `19d9cbafb42d566074b517ec94beb64e5d6b260a0ec03bc761e30cc5b0feb137`、清单 `a37642bc2cb18ab345e74ecef489e9f82501361001bfffa9051dfb7bde87843f`）。两者包含同一本次未提交实现，仅版本标记不同；仍用既有本机测试公钥签发，不作为正式发布或干净 CI 构建证据。
- 在上一阶段 Ubuntu 24.04/amd64 成功磁盘的独立克隆中，先临时使用安装器默认 Agent 入口，通过正常签名协调更新引入 `0.2.20-dev` 修复；随后由目标机 root 恢复 iptables-nft/openssh 参数，并添加安装器对应的 networkd DNS 参数与固定写权限。配置后的 `0.2.20-dev` → `0.2.21-dev` 签名检查、准备、维护排空、快照、协调切换和提交成功，Web/Agent 实际进程 SHA-256 均匹配目标。完整 Agent 单元及实际启动参数保持；原已确认移除的 iptables 状态仍 available/can_plan，双栈第三方链/规则、密钥、Nginx 活动指针与进程程序散列保持。此轮未变更 DNS，保留活动过滤策略的升级验收见下节；其余枚举的实机升级组合仍未覆盖。
- 首轮夹具的证据路径拼接和第三方链过滤名称存在错误，在业务步骤前主动中止，原磁盘和 `.validation/native-vm/agent-config-upgrade-v1/` 保留；修正夹具后沿用同一产物，第二轮证据位于 `.validation/native-vm/agent-config-upgrade-v2/`。第二轮输出 `P5_CONFIGURED_AGENT_SIGNED_UPGRADE_ALL_PASS`，完成证据归档并正常关机，退出码为 0。未修改开发宿主机环境，其他 P5 门禁继续推进。

## 2026-10-21 活动 iptables 策略下的协调升级与独立恢复

- 沿用上轮已配置 networkd DNS 与 iptables-nft/openssh 的 Ubuntu 24.04/amd64 成功盘，创建独立目标克隆；客户端使用独立 Debian 12/amd64 内核。仍通过无外部网络、无宿主端口映射的 QEMU socket LAN 执行双栈流量与受控 HTTPS API 验收，开发宿主机环境未修改。
- 本轮无业务代码变更，使用提交 `843a09c` 的实现，仅将版本标记设为 `0.2.22-dev` 以触发真实程序切换；静态构建通过，未重复未受影响的参数回归或前端构建。签名候选程序 SHA-256 为 `86ec2bb80de006f6426ca409600cb6eeb180e71cbae210a1136d574853e1eb6b`，清单 SHA-256 为 `c252fa893d805b7cf22f7d0167a5c4a374eb3255c90e9b3031393af0048a392c`。沿用已批准的本机测试公钥和已验证前端，逐文件比对前端散列；测试签发仍不代表正式发布 CI。
- 先以真实客户端应用并通过新连接确认策略 A，核对管理 HTTPS/SSH 来源保护、IPv4/IPv6 TCP/UDP 允许和阻断、双栈第三方规则保持；原登记接续及新计划/应用可用。随后在 A 活动时执行 `0.2.21-dev` → `0.2.22-dev` 的签名协调升级。客户端在升级运行期间完成 44 轮实际流量检查，A 的允许/阻断和 SSH 可达保持；升级后 Web/Agent 实际进程均匹配目标程序，已确认操作 ID、版本、策略散列和后端不变，原确认回执仍为 succeeded。完整 Agent 单元、密钥、Nginx 活动指针和主进程 PID/程序散列保持。
- 在升级后的 Agent 上应用未确认策略 B，验证其实际双栈流量后停止 Web。Web 仍 inactive 时，独立 Agent 已恢复 A 的真实 TCP/UDP 流量和 SSH；恢复 Web 后，查询原 B 操作得到 rolled_back，运行状态指向原 A 操作/版本且 available/can_plan，双栈第三方链和规则保持。对应客户端标记为 `ACTIVE_POLICY_PRESERVED_DURING_UPGRADE_SAMPLES_44`、`UPGRADED_AGENT_RESTORED_A_WITH_WEB_STOPPED`、`ORIGINAL_RECEIPT_AND_CONFIRMED_A_RESTORED` 及 `ALL_PASS`。
- 证据与独立磁盘保留于 `.validation/native-vm/active-firewall-upgrade-v1/` 及既有虚拟机卷。控制器完成前后证据比对，输出 `P5_ACTIVE_FIREWALL_UPGRADE_TWO_VM_ALL_PASS`；两台虚拟机正常关机，退出码均为 0。本次范围为原生 Ubuntu 24.04/amd64 的 iptables-nft，不替代其他后端、架构/发行版、Docker 面板或升级过程本身发生中断的验收。

## 2026-10-21 原生 iptables-legacy 应用与恢复

- 首轮在 Ubuntu 24.04/amd64 初始化时被完整后端视图检查拒绝。失败盘的独立诊断克隆确认：官方 iptables 1.8.10 的两种 nft-save 均退出 0、导出空 nft 视图，但在 stderr 精确提示对应 legacy 表存在；legacy 双栈导出及 nft JSON 均正常。现在只允许这两条按命令、动作和地址族精确匹配的提示；独立五份内核视图、退出状态、输出预算和其他诊断拒绝条件保持，未知或不兼容表提示不放行。
- 定点回归 `TestFirewallLegacyPresenceWarning` 通过（0.006 秒），覆盖两条真实提示及错误地址族、动作/工具不符、额外/重复诊断、不兼容表和缺失换行等 14 个边界；静态 amd64 主程序构建通过。前两次验证容器分别因缓存路径权限与 tmpfs 不可执行而未能启动用例，日志保留，未计作测试通过；修正验证环境后才取得上述结果。未改前端，候选逐文件核对复用已验证前端，未重复构建或执行 UI 测试。
- 隔离候选为 `0.2.23-dev`，程序 SHA-256 `1b9a20e50c62c6019d89f9390e10503cfadb2b4aad4d5e40d8b210ce0db0f114`、清单 SHA-256 `4dcb5655f1e86628a6302183acb40b872f4efb611b471dca35ccab074396fdb2`。候选包含本次未提交的诊断识别修复，沿用本机测试公钥，不代表正式发布或干净 CI 产物。第二轮已通过签名协调部署、Web/Agent 实际程序核对、legacy 空命名空间授权和双栈管理入口确认；首次规则应用因保护来源变化返回 409，尚未安装业务规则。
- 第二轮夹具在采证 SSH 退出前启动业务计划，存在 SSH 保护来源变化窗口；第三轮改为先完成基线采证、关闭采证连接，再启动业务夹具，并断言计划不包含采证 SSH 来源。首轮、诊断克隆与第二轮的磁盘和证据分别保留于既有虚拟机卷及 `.validation/native-vm/iptables-legacy-ubuntu24-v1/`、`iptables-legacy-diagnostic-v1/`、`iptables-legacy-ubuntu24-v2/`；第三轮继续复用同一候选，未重复未受影响的回归或构建。
- 第三轮使用全新原始安装基线克隆的 Ubuntu 24.04/amd64 目标和独立 Debian 12/amd64 客户端，目标内核为 `6.8.0-147-generic`。真实双栈应用并新连接确认 A、HTTPS/SSH 来源保护、TCP/UDP 允许和阻断通过。应用未确认 B 后停止 Web，Web 仍 inactive 时 A 的实际流量已恢复；重启 Web 后，原 B 回执为 rolled_back，运行状态保持原 A ID/版本且 available/can_plan。随后再次应用未确认 B 并正常整机重启，原 B 回执回滚、原 A ID/版本、双栈流量及第三方规则均核对通过。最后确认移除原 A 并停用模块，双栈业务流量恢复、SSH 可达。
- 控制器前后比对确认 boot ID 改变，双栈第三方 legacy 链/规则、密钥、Nginx 活动指针及三项原生服务程序散列保持；未选择的 nft 视图始终为空且保持，不据此声明保护非空 nft 规则的覆盖。客户端输出 `RESTORED_A_BEFORE_WEB_START`、`WEB_STOP_RESTORED_CONFIRMED_A`、`REBOOT_RESTORED_CONFIRMED_A`、`CONFIRMED_REMOVE_AND_MODULE_DISABLED` 和 `ALL_PASS`，控制器输出 `P5_IPTABLES_LEGACY_UBUNTU24_TWO_VM_ALL_PASS`；两台虚拟机正常关机，退出码均为 0。证据保留于 `.validation/native-vm/iptables-legacy-ubuntu24-v3/` 和既有虚拟机卷。
- 本次原生 legacy 范围限于上述 Ubuntu 24.04/amd64 组合及场景，不替代其他系统/架构、Docker、Agent SIGKILL、本机救援、硬断电或活动 legacy 策略下的升级中断验收。容器无外部网络及宿主端口映射，目标机执行真实规则修改；未修改开发宿主机环境，整体 P5 继续推进。

## P5 Ubuntu 24.04 原生 UFW 生命周期（2026-10-21）

- 补齐原生安装器的 `--firewall-owner` / `--firewall-ssh` 配套参数，默认仍为未确认的只读范围。明确选择 UFW 时生成宿主机所有者参数、`After=ufw.service` 和 `-/etc/ufw` 写路径，允许确认阶段原子保存用户规则；明确选择 firewalld 时仅增加对应启动顺序。安装器不安装、启停或切换管理器，不代办本机授权。脚本语法和 17 项参数/权限边界检查在隔离容器通过，涵盖五种所有者与两种 SSH 方式、默认无授权、无效或缺失配套参数。安装器源文件 SHA-256 为 `feaa470ef7fb4f631ff655c036a4a2126eb7159be4034e244160cc7f0484035c`。
- 实际环境为 Ubuntu 24.04/amd64 目标（内核 `6.8.0-147-generic`、UFW `0.36.2-6`、iptables `1.8.10-3ubuntu2`、nftables `1.0.9-1ubuntu0.1`）与独立 Debian 12 客户端。沿用已验证的签名候选 `0.2.23-dev`，程序 SHA-256 `1b9a20e50c62c6019d89f9390e10503cfadb2b4aad4d5e40d8b210ce0db0f114`、清单 SHA-256 `4dcb5655f1e86628a6302183acb40b872f4efb611b471dca35ccab074396fdb2`；未重复构建 Go 或前端。目标经正常签名协调升级后，使用当前安装器模板生成的完整 Agent 服务配置和持久 UFW 锁完成本机授权登记；本轮未对已有数据目录重跑首次安装。
- 第一轮在基线采证阶段因夹具把 IPv6 链误写为 IPv4 的 `ufw-user-input` 而中止，未进入业务规则应用；修正为 `ufw6-user-input` 后使用新原始安装克隆。第二轮已完成双栈管理入口确认、官方后台准备（16 条预演、32 条重载链、保留 4 条外部规则）、A 的实际双栈 TCP/UDP 允许/阻断、HTTPS/SSH 保护及新连接确认。随后直接准备 B 返回 503，未应用 B；原 A 及失败证据保留，不能据此宣布整轮通过。
- 第三轮从第二轮已确认 A 的磁盘建立独立写时复制克隆，核对原 A 操作 `529f1158-8390-7235-396c-3243e4c6fe26`、版本 1 及启动后实际双栈流量。夹具停止在每次控制查询中调用官方 UFW 状态命令，避免额外争用管理器锁，并在新计划前读取运行状态；冷启动核对期间记录不可用原因，恢复 `available/can_plan` 后才提交一次计划，不重试写请求。沿同一准备 ID 查询固定动作、版本、期限和进度，原计划进入 ready 后才应用。
- 第三轮应用未确认 B 后停止 Web，Web 仍 inactive 时 A 的实际流量已恢复；重新启动 Web 后，原 B 回执 rolled_back，原 A ID/版本及可计划状态保持。再次应用未确认 B 并正常整机重启后，原 B 回执回滚、原 A ID/版本、双栈流量及第三方规则均通过。最后对原 A 版本准备并确认移除，再停用模块，双栈业务流量恢复，UFW 仍 active 且开机 enabled。B 的替换准备执行 32 条官方预演，移除准备执行 16 条，全部保留双栈入口保护及受控来源核对。
- 控制器前后比对确认 boot ID 改变；双栈第三方 UFW 原生 tuple 块及相对顺序、对应内核规则、其他 UFW 配置散列、密钥、Nginx 活动指针及三项服务程序散列保持。未选择的两个 legacy 导出均为空且保持，不据此声明保护非空 legacy 规则的覆盖。客户端输出 `PRESERVED_CONFIRMED_A_PERSISTED_AFTER_BOOT`、`RESTORED_A_BEFORE_WEB_START`、`WEB_STOP_RESTORED_CONFIRMED_A`、`REBOOT_RESTORED_CONFIRMED_A`、`CONFIRMED_REMOVE_AND_MODULE_DISABLED` 和 `ALL_PASS`；控制器输出 `P5_UFW_UBUNTU24_TWO_VM_ALL_PASS`。两台虚拟机均有正常 Power down 记录、退出码为 0。
- 三轮磁盘、源模板配置及证据分别保留于既有虚拟机卷和 `.validation/native-vm/ufw-ubuntu24-v1/`、`ufw-ubuntu24-v2/`、`ufw-ubuntu24-v3/`。额外诊断克隆因源磁盘仍被运行中的第三轮占用而未启动，日志保留于 `ufw-diagnostic-v1/`，不计作运行验收。本轮范围限于上述 UFW/nftables 组合；不替代 UFW/legacy、其他系统/架构、Docker、Agent SIGKILL、本机救援、硬断电或活动 UFW 策略下升级中断验收。未执行 UI 测试，未修改开发宿主机环境，整体 P5 继续推进。

## CentOS Stream 10/amd64 firewalld 原生生命周期（2026-10-21）

- 使用官方 `CentOS-Stream-GenericCloud-10-20261019.0.x86_64.qcow2` 的独立写时复制磁盘和 Debian 12 客户端，两台 QEMU/TCG 虚拟机经专用以太网通信。目标保持 SELinux Enforcing，实际管理器为 firewalld `2.4.3-4.el10`、nftables `1.1.5-6.el10`，systemd `257-34.el10`。仅在目标虚拟机安装管理器软件；Nginx 沿用预编译静态程序。第三轮从空白系统执行当前原生安装器，明确指定 `--firewall-owner firewalld --firewall-ssh openssh --start`，未修改开发宿主机的软件、服务或防火墙。安装器 SHA-256 为 `0ffa1daa33d2dbe7b1c5dd79e29dbaf4541ad5f396d8b5740377911ac63debdf`。
- 首轮因系统未安装显式 xtables 工具而被完整视图门禁拒绝，尚未创建自有 policy。核对完整 nftables 视图及当前网络命名空间的 legacy 表登记后，新增保守的空后端证明；现存表、残缺或损坏的工具和读取异常仍拒绝。Docker 隔离环境中的缺失证明定点测试和程序构建通过；第三轮程序为本机 root 批准的 `0.2.24-dev` 原生资产，SHA-256 `dd8e4c110d3cfb1242493752291e3896cf59f40a3b294102a2a62e7817069f3e`，前端沿用已核对清单的 v23 资产，不将本轮程序声明为正式签名发布包。
- 第二轮空 policy 的 root 初始化、人工审核 reload 和 recover 已通过，但随后 Agent 首次启动报 `233/RUNTIME_DIRECTORY`，三秒后自动重启成功。安装器现通过 tmpfiles 维护共享宿主锁目录，不随 Agent 停启删除；脚本语法检查通过。第三轮完整安装及停止 Agent 后的 root 登记、重新启动均通过，锁目录前后均为同一设备/inode、root:root、0700。登记原操作为 `9f2d3c75-3212-4c60-942c-ef10174422b2`。
- 第三轮实际完成双栈受控 HTTPS 监听确认、A 的 TCP/UDP 允许与阻断、SSH/HTTPS 入口保护、回环伪造确认拒绝和外部新连接确认；确认后 runtime/permanent rich rules 相同。firewalld 重启后原 A 及流量保持。未确认 B 在 Web 停止且尚未启动时恢复 A；再次应用未确认 B 并整机重启后，原 B 回执回滚，原 A ID、版本和流量保持。随后原 A 版本的移除经外部连接确认，模块停用返回成功，双栈业务流量恢复，firewalld 仍 active/enabled。
- 原客户端和控制器在最后把官方空行输出解析为 `['']`，误判为空规则检查失败，原日志没有整轮 `ALL_PASS`。保留原始输出并修正夹具解析后，对冻结的前后证据集中复核通过：runtime/permanent 无 rich rules，永久 XML 仅有固定空 policy 设置，自有内核链只有指向空子链的跳转，移除 `df2d9e7e-f200-8033-b8ac-04f69f7bc367` 的 root 回执为 succeeded/rules_removed。boot ID 改变，第三方 zone/policy/XML、密钥、Nginx 指针及三项服务程序散列保持；全启动周期 AVC 查询无匹配，两台虚拟机均正常 Power down、退出码 0。补充结果标记为 `P5_FIREWALLD_CAPTURED_FINAL_EVIDENCE_PASS`，未重写原控制器失败状态，也未重复已完成的业务场景。
- 三轮磁盘、夹具和日志保留于虚拟机卷及 `.validation/native-vm/firewalld-centos10-v1/`、`firewalld-centos10-v2/`、`firewalld-centos10-v3/`；修正后的采集夹具和独立证据复核报告位于 `firewalld-centos10-v3-review/`。本轮不覆盖 firewalld 的其他系统/架构、Docker、Agent SIGKILL、本机救援、硬断电或活动策略下升级中断。未执行 UI 测试，其余 P5 验收继续推进。

## 尚待验收

- 其他系统/架构及 Docker 面板组合的账户与 systemd、其他 DNS 所有者、其他防火墙后端、Fail2ban 的其余实例/动作/升级及跨节点查询场景、管理监听的其余场景，以及其他危险操作在重启/断电/中断后的恢复，仍需独立 Linux 系统验收；已完成范围限于上文列明的组合及场景。
- 两种架构的正式原生资产、正式发布链的签名镜像来源与多架构证据、其他升级/回滚和备份恢复故障注入，仍需完成构建及运行验收。arm64 预置模块镜像已完成下文列明的构建和程序执行核对，托管部署仍待验收；上文本机信任准入、amd64 运行绑定及克隆恢复结果不替代这些检查。
- 真实域名的 ACME/DNS、通知接收端及跨主机 API 一键迁移，尚未进行外部集成验收；容器内双节点迁移与授权结果见上节。
- 正式 GitHub 仓库及发布凭据尚未配置，未运行真实发布 CI、推送或发布。项目 MIT 许可证已补齐，第三方组件保留各自许可。
- UI 由用户人工验收，未创建或执行 UI 自动化测试。

### Ubuntu 22.04/amd64 原生部署（2026-10-21）

- 使用 Ubuntu 官方 Jammy 20261020 云镜像，核对官方 SHA256SUMS、范围响应与 ETag，最终镜像 SHA-256 为 `2099e63da0b822ef8e05e3d596c1b402eaaae658fc08ab919cb8495bfcdc488b`。实际系统为 Ubuntu 22.04.5 LTS/amd64、内核 5.15.0-198-generic；在外层断网、无宿主端口、无特权及 host network 的 Docker 控制器内以 QEMU TCG 运行独立内核，2 核、2 GiB 内存。
- 复用已构建的 `0.2.24-dev` 静态程序（SHA-256 `dd8e4c110d3cfb1242493752291e3896cf59f40a3b294102a2a62e7817069f3e`）、已批准的静态 Nginx 1.30.6/OpenSSL 3.5.9 与前端资产。当前安装器 SHA-256 为 `0ffa1daa33d2dbe7b1c5dd79e29dbaf4541ad5f396d8b5740377911ac63debdf`；逐项核对种子内资产及前端包清单，不将本机 root 批准的原始程序视为正式签名发行。
- v1 首次原生安装完成，三个正式服务均启用并启动；随后即时权限断言返回 1，未进入 API 引导及代理应用。原脚本未记录具体断言，失败原因尚未确定，不据后续成功将该次启动门禁改记为通过。原盘与失败日志保留，虚拟机正常关机。
- v2 使用 v1 安装后磁盘的独立覆盖盘续办，增加 shell 追踪，保持原权限断言不变。Web 独立用户、零有效能力与 NoNewPrivileges、数据/密钥/写锁归属、Web 不可读 Agent 数据、Agent/Nginx 挂载视图不可见面板主密钥、Nginx worker 独立用户及零有效能力全部通过。没有修改产品代码或放宽权限检查。
- v3 从同一官方镜像新建空白覆盖盘，仅定点执行首次安装及原权限断言，增加具体失败命令/行号和失败进程快照；未添加就绪轮询或延时，未重跑 v2 已通过的代理、回滚和重启业务。全部首次权限断言通过，控制器记录 `P5_FRESH_STARTUP_DIAGNOSTIC_PASS`，QEMU 退出 0 且正常关机。证据位于 `.validation/native-vm/ubuntu22-startup-v3/`。未复现首轮失败，没有据此声明原失败已定位或已修复。
- HTTPS 实际证书校验与统一 API 封装检查通过；端口 80 的代理真实返回预置上游内容。占用 18089 的配置应用自动回滚；候选指针切换后中断 Agent，原任务 `cc065307-8e47-442a-a4f2-e81b8001ab83` 恢复为 `rolled_back/rollback_confirmed`，原流量及部署身份保持。后续正常应用任务 `9f1e57eb-ea14-4914-84a7-e0ee11504598` 成功。
- 安装重放、Agent/Web 服务重启及正常整机重启通过。节点 `96053d26-b15e-46ec-9320-bf5cd9c2ca83`、期望版本 3、修订及部署身份保持，重启后真实代理流量与全部权限断言通过。控制器核对 boot ID 确已变化，主密钥/TLS 文件散列、Nginx 活动指针及三个正式进程程序散列保持。AppArmor 实际启用并加载 37 个系统配置；三个正式服务实际标签为 `unconfined`，不声明专用 AppArmor 策略约束。
- 控制器记录 `P5_UBUNTU22_NATIVE_ACCEPTANCE_PASS`，随后虚拟机正常关机、QEMU 退出 0，无强制终止。证据位于 `.validation/native-vm/ubuntu22-native-v1/` 与 `ubuntu22-native-v2/`，包括下载校验、原始失败、带追踪的续办、重启后日志及前后 JSON 证明；两轮原盘及种子保留。未重复既有程序/前端构建或无关测试，没有修改开发宿主机系统配置，没有执行 UI 自动化。首次即时权限断言失败未复现、具体原因仍未确定；Ubuntu 22.04 的 Docker 组合仍未验收；arm64 后续不含 Nginx 的部署验收见下一项。

### Ubuntu 22.04/arm64 原生 Web/Agent 部署（2026-10-21）

- 使用 [Ubuntu 官方 Jammy 镜像](https://cloud-images.ubuntu.com/jammy/current/) 20261020 的实际 arm64 镜像，核对官方 SHA256SUMS、完整范围响应及 ETag；SHA-256 为 `e720ae083f93baae47ac9b76a096243fe1027f60998cf1127a47a74c880f64ed`。实际系统为 Ubuntu 22.04.5 LTS/arm64、内核 5.15.0-198-generic；QEMU 7.2.22、QEMU_EFI.fd、virt/GICv3、TCG、2 核、2 GiB，运行独立 ARM 内核。外层控制器断网、删除全部 capabilities 后仅授予 DAC_OVERRIDE，不使用特权、KVM、host network 或开发主机端口发布，未注册宿主机 binfmt。
- 在隔离 Go 1.27.2 容器中构建 `0.2.24-dev`：`CGO_ENABLED=0`、`GOARCH=arm64`、`GOARM64=v8.0`，源码提交为 `874eb00ff59d910c742306013390829ee7081a6e` 且构建时工作树干净。程序为真实 AArch64 ELF、无动态解释器，SHA-256 为 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`。实际 ARM 执行返回预期版本、Agent 协议 122、数据库 37 和 launcher 2；前端逐文件核对后复用既有资产，没有重复前端构建。
- v1 以当前安装器执行 `--without-nginx --start`，原生安装及 Web/Agent 启动通过。Web 独立用户、零有效能力、NoNewPrivileges、数据/密钥/写锁归属、Web 不可读 Agent 数据、Agent 挂载空间不可见主密钥全部通过；Nginx 未启用且未运行。HTTPS 严格证书验证、引导/登录、统一响应及请求/节点头核对通过，实际 Agent 报告 Ubuntu 22.04/arm64，缺失 Nginx 明确报告不可用及原因，未伪造运行成功。
- 随后 AppArmor 采证误将本次未安装的 Nginx 纳入 MainPID 检查，原脚本及控制器失败，未执行计划重启；原盘、日志、采证与原始退出状态保留，虚拟机正常关机。v2 从已安装盘的独立覆盖盘续办，仅修正采证的服务集合为 Web/Agent，不重装或重复已通过的首次 API 引导。AppArmor 启用、服务 active、实际加载 37 个系统配置的检查保持；两服务标签均为 `unconfined`，不声明专用策略约束。
- 安装重放、Agent/Web 服务重启及正常整机重启通过；重启后再次核对全部权限、Nginx 未启用/未运行、HTTPS 会话及统一 API。节点 `a10cd7d0-a183-4de0-a396-cb10aa02b55d`、空配置版本 0 和空修订身份保持；计划重启前后的 boot ID 确已变化，主密钥/TLS 文件及两正式进程程序散列保持一致。控制器记录 `P5_ARM64_NATIVE_WITHOUT_NGINX_ACCEPTANCE_PASS`，QEMU 退出 0 且正常关机，无强制终止。
- 证据位于 `.validation/native-vm/arm64-bootstrap-v1/` 与 `arm64-native-v2/`，包括工具镜像构建、镜像校验、程序构建与 ELF/Go 信息、首轮失败、续办/重启日志、AppArmor/能力/散列 JSON 和来宾采证归档；原盘与种子保留。只完成此架构的原生 Web/Agent 基础部署；arm64 原生 Nginx、预置模块镜像、Docker 组合及其他发行版仍待验收。原始批准程序不替代正式签名发行包。本轮没有修改产品代码、开发宿主机系统配置或运行 UI 自动化，没有重跑无关 Go 测试或前端构建。

### 双架构镜像产物与 ARM 执行（2026-10-21）

- 使用当前 `deploy/docker/panel.Dockerfile` 和 `nginx.Dockerfile` 构建实际 `0.2.24-dev` 镜像。复用已验证的静态程序：amd64 SHA-256 为 `dd8e4c110d3cfb1242493752291e3896cf59f40a3b294102a2a62e7817069f3e`，arm64 为 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`。未重复 Go 或前端构建；前端沿用逐文件核对的 v23 包。MIT 许可及第三方声明随镜像和两个实际架构的面板包收录。
- 面板镜像构建阶段不执行 ARM 程序；Nginx 镜像的构建与执行核对位于独立 Ubuntu 22.04.5/arm64、5.15.0-198-generic 虚拟机。来宾安装 Docker 29.9.1、Compose 2.40.3 和 Buildx 0.36.1，工具取自官方 AArch64 资产，插件核对官方校验和。开发宿主机未安装工具、修改 Docker 配置或注册 binfmt。
- Nginx 直接使用固定上游索引 `nginx:1.30.6-alpine-slim@sha256:3028fc1419f99b95c1c69f844bbaf49dc1b881750c51b497fc721ac4f02a14e6`，构建阶段核对所需模块及程序摘要，不在部署时编译或安装模块。ARM 实际执行返回 Nginx 1.30.6，构建 OpenSSL 3.5.8、运行 OpenSSL 3.5.9；能力声明为 `image-only`，运行时模块安装及编译均关闭。
- 两个真实 ARM 容器均以只读根文件系统、无网络、删除全部 capabilities 和 NoNewPrivileges 执行程序版本命令；均返回 `0.2.24-dev`、Agent 协议 122、数据库 37、launcher 2。Nginx 与 launcher 的镜像内散列核对通过。导出镜像跨控制器传输后的 SHA-256 再次匹配，控制器输出 `P5_ARM64_DOCKER_BUILD_ARTIFACT_PASS`，随后虚拟机正常关机、QEMU 退出 0。程序执行不代表托管容器部署、代理或重启已通过。
- 本地隔离签发器使用两种实际程序、四个实际镜像配置和完整层生成双架构 OCI 索引，逐层验证 diff ID，并逐镜像核对 launcher 实际内容；两个平台均有真实清单及配置证据。测试清单 SHA-256 为 `995634fd807065257a436eff5a6100fe4194e3bb99fcd76efbd3c5dfff4a5eb6`；面板索引为 `sha256:6c7ae80842a25412b1aba314d69b8843982ba5ce535cdb3058a19181684e5fb1`，Nginx 索引为 `sha256:a69461c9ba249b0796b292ba92a40b20a66ca9be1bebab7a92e0ec61406df23d`。本轮目录不使用旧夹具的不可执行 ARM 占位项；没有据此改写旧记录或宣称正式 CI 已运行。
- 产物和证据位于 `.validation/native-vm/arm64-images-v1/`、`arm64-docker-build-v1/`、`dualarch-images-v1/` 及既有虚拟机卷；签名密钥仅用于隔离验证，没有推送或发布。托管 ARM Docker 安装、回滚及重启验收另行记录，arm64 原生静态 Nginx 构建继续。没有运行 UI 自动化或重复无关回归，完整 P5 继续推进。

### Ubuntu 26.04/amd64 原生部署（2026-10-21）

- [Ubuntu 官方云镜像](https://cloud-images.ubuntu.com/releases/resolute/release/ubuntu-26.04-server-cloudimg-amd64.img)以官方 SHA256SUMS 和分段 ETag 完整校验，859,090,944 字节，SHA-256 `5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5`。Docker 内独立 QEMU/TCG 来宾实际为 Ubuntu 26.04.1 LTS、`7.0.0-38-generic`；复用已批准的 `0.2.24-dev` amd64 程序、前端及静态 Nginx，不计作正式发行包。
- 当前原生安装器完成首次安装；原即时 UID、能力、权限和密钥隔离断言通过。HTTPS 引导及统一 API、真实代理、占用端口回滚和切换候选后 Agent SIGKILL 回滚通过；安装重放和服务重启后原会话、节点及配置保持。配置版本为 3，节点 `fb3a525a-fcfa-4be6-9d1b-f74ede8a5b5c`。
- 整机重启后再次完成身份、实际代理、API 和 AppArmor 检查。AppArmor 启用且加载 179 个配置，三个实际服务标签均为 `unconfined`；不声明专用进程策略。前后启动 ID 不同，主密钥、TLS 文件、活动 Nginx 指针和三个实际进程散列相同；Web/Agent 为 `dd8e4c110d3cfb1242493752291e3896cf59f40a3b294102a2a62e7817069f3e`，Nginx 为 `1e168f3239c9f650651d68797b97f986c7c21769c8a9db8ca0caa2fdf6b46f08`。
- 来宾已输出全部业务通过标记后，控制器首次读取完成文件的 SSH 连接返回 255。随后异常收尾采集成功取得原始完成文件、状态、前后 JSON 及完整归档，虚拟机正常关机、QEMU 退出 0；未伪改控制器退出结果，也未重跑已通过的业务。独立复核原始证据后记录 `P5_UBUNTU26_NATIVE_EVIDENCE_REVIEW_PASS`，原连接失败及复核散列均保留。隔离网络下的 networkd 等待失败不计作 DNS 功能验收。
- 证据位于 `.validation/native-vm/ubuntu26-native-v1/`，包括下载校验、初次及重启输出、来宾归档、前后进程/密钥证明和 `evidence-review.json`；原盘和种子保留。此结果仅覆盖该系统/架构的原生组合，Docker 和其他功能组合仍待验收；没有执行 UI 自动化或修改开发宿主机环境。

### Ubuntu 22.04/arm64 Docker 托管部署（2026-10-21）

- 使用上述实际 Ubuntu 22.04.5/arm64、5.15.0-198-generic 镜像、Docker 29.9.1、Compose 2.40.3 和真实双架构 OCI 验证包。首次 v1 的来宾 Docker 启动超过夹具默认 90 秒期限，未进入产品安装；v2 仅将来宾 Docker 服务启动期限设为 300 秒，不调整产品期限，实际镜像导入、选择 ARM 平台、篡改清单/未信任签名拒绝和托管首次安装通过。
- v2 的身份和初次配置应用通过，首次代理请求返回 502；原始日志确认测试上游文件为 root:600，服务用户 `nobody` 无法读取。v3 从保留原盘新建覆盖盘，继续同一次安装，仅将上游夹具改为 644、逐个核对服务状态；保留 v1/v2 原始失败，不将它们标为通过，也未重跑首次安装。
- v3 的真实代理、占用端口回滚、候选切换后 Agent SIGKILL 回滚、恢复应用、Compose 强制重建、安装重放、Agent 重启和整机重启全部通过。容器重建实际更换容器 ID，原 HTTPS 会话、节点和配置保持；节点为 `ca2a872c-716b-4e23-8d42-f79345348d52`，配置版本 3，活动部署 `9f315758-0eda-4573-a779-f308e440c2c4`。
- 两个容器实际以独立非 root 身份运行；Web 零有效能力，Nginx 仅保留绑定端口能力，NoNewPrivileges 和受限挂载/密钥隔离检查通过。容器 AppArmor 标签为 `docker-default (enforce)`，宿主 Agent 为 `unconfined`。前后启动 ID 不同，主密钥、TLS 文件、活动 Nginx 指针和实际进程散列相同；Agent/Web 为 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`，镜像内 Nginx 为 `933fa45f91eb5da9e3029817d725aa5c29872d6104eb59a311e6dcfc749db7a8`。
- 控制器记录 `P5_ARM64_DOCKER_ACCEPTANCE_PASS`、正常关机及 QEMU 退出 0。完整证据在 `.validation/native-vm/arm64-docker-native-v1/`、`arm64-docker-native-v2/`、`arm64-docker-native-v3/`，包括原始失败、首次安装、续办与重启输出、容器实际状态、前后进程/密钥证明和来宾归档；原盘及种子保留。本组合通过不代表 Docker 发布端口的防火墙转发路径、其他操作系统或正式签名发行已验收。开发宿主机环境未修改，没有执行 UI 自动化。

### arm64 原生静态 Nginx 构建（2026-10-21）

- 首次真实 ARM 构建在 `libgcc.a(lse-init.o)` 引用未解析的 `__getauxval` 时失败。原始构建日志和正常关机原盘保留于 `.validation/native-vm/arm64-nginx-build-v1/`。在锁定配方中增加按架构选择的 C 编译选项：arm64 将 `-mno-outline-atomics` 同时用于 Nginx 和 OpenSSL，amd64 保持空值；Python 构建器和 Go 发布证据校验从同一配方生成实际参数。该选项的 ARMv8.0 原子指令行为见 [GCC AArch64 文档](https://gcc.gnu.org/onlinedocs/gcc/AArch64-Options.html)。
- v2 复用已核对源归档及来宾工具链，在新的工作目录完整解包、配置和编译，未复用失败目标文件。实际 Ubuntu 22.04.5/arm64、5.15.0-198、GCC 11.4.0/musl 1.2.2 来宾完成静态 Nginx 1.30.6、OpenSSL 3.5.9 构建；实际编译命令和回执均包含两个项目所需的架构参数。ELF 为 AArch64，缺少解释器及动态依赖，36 项必需模块符号、实际版本和依赖归档/许可证明通过。
- 二进制为 13,088,112 字节，SHA-256 `c04c861d413d27772c7103dc872c11e82dbc29d879ff81a71d99ef63eb663c27`；锁定配方 SHA-256 `b91578fd9cabe375b3f20fe18107a0d353d40c7d0248523154ac22a0c93d03bd`。控制器记录 `P5_ARM64_NATIVE_NGINX_BUILD_ARTIFACT_PASS`，虚拟机正常关机、QEMU 退出 0。发布模块现有 Go 测试在隔离 SDK 容器内通过，未扩大到无关回归或 UI 测试。
- 完整证据和原生产物位于 `.validation/native-vm/arm64-nginx-build-v2/`。构建回执明确记录本地验证用途、基础提交 `fb11dd3`、实际工作区补丁及构建器散列，未冒充正式 CI 或正式签名发行；Cortex-A53 基线 CPU 上的原生安装、故障恢复和重启结果见下一项。
- 余下 7 个待验收系统/架构组合的官方基础镜像已完成散列校验，记录位于 `.validation/native-vm/remaining-images-v1/` 和 `remaining-images-debian-v2/`；各组合安装及内核行为验收继续。

### Ubuntu 22.04/arm64 原生静态 Nginx 部署（2026-10-21）

- 使用已核对的 Ubuntu 22.04.5/arm64 官方镜像、5.15.0-198-generic 内核及新的独立覆盖盘。QEMU 明确选择 Cortex-A53、2 核、2 GiB；实际 `/proc/cpuinfo` 两核均无 `atomics`，覆盖不提供 LSE 的 ARMv8.0 基线。外层控制器断网、无特权及宿主端口，没有注册开发宿主机 binfmt。
- 当前原生安装器在空白系统安装已批准的 `0.2.24-dev` ARM 程序、现有前端和上述静态 Nginx；未安装或编译运行时模块。原即时 Web/worker UID、零有效能力、NoNewPrivileges、目录权限、Agent/Nginx 主密钥不可见断言通过。HTTPS 引导、统一 API、真实代理、端口占用回滚、候选切换后 Agent SIGKILL 回滚、恢复应用、安装重放和服务重启通过。
- 正常整机重启后再次核对身份、权限、HTTPS 会话及代理；节点 `3e916394-5acb-41ac-9ceb-ca4c1adc9246`、配置版本 3、修订 `ec71accc-168e-4cfe-8938-de6fd8e30480` 和部署 `839f76c2-edfc-4975-8a5b-b70dbd7e45f2` 保持。前后 boot ID 不同，主密钥/TLS 文件、活动指针及实际进程散列相同：Web/Agent 为 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`，Nginx 为 `c04c861d413d27772c7103dc872c11e82dbc29d879ff81a71d99ef63eb663c27`。
- AppArmor 启用且加载 37 个配置，三个服务实际标签均为 `unconfined`，不声明专用进程策略。控制器记录 `P5_ARM64_NATIVE_NGINX_ACCEPTANCE_PASS`，正常关机、QEMU 退出 0，无强制终止。证据位于 `.validation/native-vm/arm64-nginx-native-v1/`，包含 CPU 特征、初次及重启日志、来宾归档和前后证明；未重跑已通过的发布模块测试或 UI 自动化，没有修改开发宿主机环境。

### Debian 12/arm64 原生静态 Nginx 部署（2026-10-21）

- 使用 [Debian 官方 Bookworm arm64 云镜像](https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.qcow2)，完整传输后核对同源 SHA512SUMS；镜像 SHA-256 为 `c11b0165ca40653616dbbdfc14e24024b3cc8a3941cd67dceac9d93703730e2a`，341,245,952 字节。实际内核为 `6.1.0-54-cloud-arm64`，QEMU/TCG 2 核、2 GiB、独立新盘，外层控制器断网、无特权及宿主端口，没有注册宿主机 binfmt。
- 当前安装器在空白系统安装同一已批准 `0.2.24-dev` ARM 程序、现有前端及静态 Nginx。即时身份/权限及主密钥隔离、HTTPS 引导与统一 API、真实 HTTP 代理、端口冲突和候选切换后 Agent SIGKILL 回滚、恢复应用、安装重放、服务及整机重启全部通过。
- 节点为 `815ee55a-6518-4cf6-a24e-ecefe9854e42`、配置版本 3、修订 `64b0063c-74ef-4fca-81b9-13de7e9356c1`、部署 `48a8614e-1aca-44f6-abf9-f7805e540cfe`；重启前后身份及代理保持，boot ID 不同，主密钥/TLS 文件、活动指针及实际程序散列一致。Web/Agent 为 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`，Nginx 为 `c04c861d413d27772c7103dc872c11e82dbc29d879ff81a71d99ef63eb663c27`。
- AppArmor 实际启用、服务 active、11 个配置已加载，三个服务进程均为 `unconfined`。控制器记录 `P5_DEBIAN12_ARM64_NATIVE_NGINX_ACCEPTANCE_PASS`，正常关机、QEMU 退出 0，无强制终止。证据位于 `.validation/native-vm/debian12-arm64-native-v1/`，包括官方镜像信息、初次及重启输出、LSM/能力/进程证明和来宾归档。此结果只覆盖原生组合，Docker 仍待验收；没有改产品代码、重复无关测试或修改开发宿主机环境。

### Debian 13/arm64 原生静态 Nginx 部署（2026-10-21）

- 使用 [Debian 官方 Trixie arm64 云镜像](https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2)，完整传输后按同源 SHA512SUMS 校验；镜像 SHA-256 为 `9631b921171ce9b4bb4c2743f07f757e9996a0f2fc5f1fd5c9c486688d51856c`，336,592,896 字节。实际系统为 Debian 13.7、内核 `6.12.113+deb13-cloud-arm64`；QEMU/TCG Cortex-A53、2 核、2 GiB、独立新盘，外层控制器断网、无特权及宿主端口。
- 当前安装器在空白系统安装同一已批准的 `0.2.24-dev` ARM 程序、现有前端及静态 Nginx。即时 Web/worker 身份与权限、主密钥隔离、HTTPS 引导和统一 API、真实代理、端口冲突及候选切换后 Agent SIGKILL 回滚、恢复应用、安装重放、服务及整机重启全部通过。
- 原节点 `3da37803-b4a0-402f-9d17-dfaeba675fd8`、配置版本 3、修订 `71bd35a2-ac2c-4cd5-8975-a397cb29d912`、部署 `d34dad5d-0a83-439d-b2d9-d25bf5236a3c` 及 HTTPS 会话保持。前后 boot ID 不同，主密钥/TLS 文件、活动指针及实际程序散列一致；Web/Agent 为 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`，Nginx 为 `c04c861d413d27772c7103dc872c11e82dbc29d879ff81a71d99ef63eb663c27`。
- AppArmor 启用、服务 active、106 个配置已加载，三个服务进程实际均为 `unconfined`。控制器记录 `P5_DEBIAN13_ARM64_NATIVE_NGINX_ACCEPTANCE_PASS`，正常关机、QEMU 退出 0，无强制终止。证据保留于 `.validation/native-vm/debian13-arm64-native-v1/`；Docker 尚未验收，没有改产品代码、重复无关验证或修改开发宿主机环境。

### Ubuntu 26.04/arm64 原生部署（2026-10-21）

- [Ubuntu 官方云镜像](https://cloud-images.ubuntu.com/releases/resolute/release/ubuntu-26.04-server-cloudimg-arm64.img)经官方 SHA256SUMS 校验，940,373,504 字节，SHA-256 `8eb876c2ccc4b6ff89e4a65d511815923b285e04503ba465809bf587f763da24`。Docker 内独立 QEMU/TCG、Cortex-A53、2 核 2 GiB 来宾实际为 Ubuntu 26.04.1 LTS、`7.0.0-38-generic`，两个虚拟 CPU 均不暴露 LSE atomics。复用已批准的 ARM64 `0.2.24-dev` 程序、前端及静态 Nginx 1.30.6，不计作正式发行包。
- 程序散列 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`，Nginx 散列 `c04c861d413d27772c7103dc872c11e82dbc29d879ff81a71d99ef63eb663c27`。首次真实安装、Web 非 root/零有效能力/NoNewPrivileges、worker 身份与零能力、目录权限及 Agent/Nginx 对主密钥的挂载隔离检查通过；验收脚本先等待实际 Nginx 可执行文件和子进程，再执行原有身份与权限断言。
- 严格 HTTPS API、实际代理、端口占用失败回滚、切换后 Agent SIGKILL 回滚、恢复后再次应用、安装重放、服务重启和整机重启恢复通过。节点 `f48a61b0-9083-4944-8150-91319bb6ed03`，配置版本 `3`，修订 `3161d893-dbca-4b29-acdc-54358a796dc1`，部署 `020ff41c-57e8-4fd6-a784-127e6232ceae`。
- boot ID 从 `d1b2e697-7c95-4ec2-9613-6b44d6d3a24d` 变为 `c7eee2a2-0669-4485-aedd-17e3f7095328`；节点、配置、主密钥、节点 TLS、active 指针及三个实际进程的可执行文件散列保持。AppArmor 在两个启动阶段均启用并加载 179 个 profile；Web、Agent、Nginx 实际标签均为 `unconfined`，不据此宣称应用受到 profile 约束。
- 离线来宾首次启动的 networkd wait-online 超时后正常完成 cloud-init；应用验收在 SSH 和启动日志检查通过后开始。控制器 `nginxpanel-p5-ubuntu26-arm64-native-1` 退出 `0`，记录 `P5_UBUNTU26_ARM64_NATIVE_NGINX_ACCEPTANCE_PASS`、QEMU 退出 `0` 和正常关机。证据保留于 `.validation/native-vm/ubuntu26-arm64-native-v1/`；Docker 部署仍待验收，开发宿主机环境未修改。

### Docker 默认策略路由识别（2026-10-21）

- Ubuntu 22.04/arm64、`5.15.0-198-generic` 独立内核来宾中，Docker 发布端口的 IPv4/IPv6、TCP/UDP 八条基础流量通过；绑定实际容器及网络后，计划被默认策略路由识别拒绝，尚未执行策略应用。失败现场保留于 `.validation/native-vm/docker-forward-iptables-nft-v3/`。该环境使用直接 iptables-nft；此前已确认停用且无用户规则的 UFW 仅在来宾中卸载，并核对完整双栈内核规则保持，不据此放宽管理器排除保护。
- 在独立续盘只读采集原始 GETRULE：五条默认规则均含 `FRA_SUPPRESS_PREFIXLEN=0xffffffff`。该值表示禁用抑制，Linux 会在默认规则转储中发送它，见 [Linux 5.15 实现](https://github.com/torvalds/linux/blob/v5.15/net/core/fib_rules.c#L932)。原始报文及正常关机证据位于 `.validation/native-vm/docker-forward-route-diagnostic-v4/`；控制器记录采集通过、正常关机、QEMU 退出 0。
- 解析器仅接受四字节的禁用值，仍拒绝有限抑制值、畸形长度和其他未支持条件。基于上述五条实际内核报文及有限/畸形抑制值的定点 Go 回归通过；隔离 Go 1.27.2 容器完成 `0.2.25-dev` 静态 ARM 候选构建，摘要为 `abe5fe8e1c711ab61156c730df181a488ffb409bf4a614f87041276cf82047d7`。本地源码、补丁、构建及测试证据位于 `.validation/native-vm/docker-forward-route-fix-v1/`。发布端口规则应用、RETURN 语义及中断/重启恢复继续验收，暂不标记支持矩阵通过；没有运行 UI 测试或修改开发宿主机配置。


## 监控边界与 Stream 双栈权重（2026-10-21）

修复同一分钟内采样中断后恢复时未立即标记历史空档的问题：采样时间差超过两个间隔加 5 秒时，该分钟保持空档标记。现有计数器连续性约束不变。真实 SQLite 验证通过：进行中与已持久化分钟不重复计数，重启读取保持结果，缺失分钟和 null 不补零，真实零参与统计，下采样保留空档；中断不能满足告警持续时间，缺失指标不能清除告警或计入恢复窗口；32 MiB 载荷配额淘汰最旧数据并保留最新数据，缩短至 1 小时保留期限后清除过期记录。

Linux 指标边界使用 Docker 内独立 chroot 的普通 `/proc`、`/sys` 夹具文件运行实际采集器，不改真实内核计数器。首样本、CPU/网络计数器重置、接口同名重建、boot ID 变化、采样间断、CPU 热插拔、缺失/非法来源和 128 核维度上限通过；CPU guest 不重复累计，网络按 bit/s 计算，内存使用 MemAvailable，未配置 Swap 保持 null，挂载容量调用真实 statfs 并去重，容器标识阻止冒充宿主采集。该夹具不能替代原生/容器 Web 读取同一真实宿主 Agent 的对照验收。

使用已有预置模块镜像 `nginxpanel-p5-nginx:20261021-dualarch-v1-amd64`，镜像 ID 为 `sha256:513bd336f4aee8c27cfaa97bedb045dd65eb84ccb507d65f6884ed81251f798b`。真实配置创建和常用字段修改经 Agent 渲染、实际 `nginx -t` 与降权进程启动；TCP/UDP 的 IPv4/IPv6 四种客户端各进行 12 次请求/响应，IPv4 与 IPv6 上游分别收到 3/9 次，符合 1:3 权重。普通 TCP 与独占外部 UDP 监听冲突产生实际 EADDRINUSE，候选进程退出后旧代理仍正常响应。未覆盖其他发行包、arm64 权重或 UDP 端口复用组合；UDP 发送未被当作健康证明。

源码与集中验收证据保存在 `.validation/p5-metrics-stream-v1/` 至 `v4/`。v1 因临时目录 noexec 未能执行测试；调整容器参数后，v2 的监控与 Linux 来源检查通过，Stream 被公共可写 `/srv` 的安全检查拒绝；v3 收紧目录权限后四种权重检查通过，原冲突夹具误将 Nginx UDP 的 SO_REUSEADDR 共享当作独占冲突；v4 改用独占外部 UDP 监听，仅重新编译并复验受影响的冲突用例，通过，未重复已通过的监控和权重检查。最终源码散列及结果范围见 v4/result.json。使用锁定 Go 1.27.2 SDK、离线依赖缓存、无网络和受限容器能力；未运行 UI 测试或修改开发宿主机配置。


### CentOS Stream 9/amd64 原生部署与 SELinux 续验（2026-10-21）

隔离 QEMU 的官方 CentOS Stream 9 镜像、实际 `5.14.0-758.el9.x86_64` 内核已完成原生 Web/Agent 与静态 Nginx 1.30.6 验收。首次安装、HTTPS 代理、监听冲突回滚、切换后 Agent 中断回滚及恢复应用的原始证据保留在本地 `centos9-amd64-native-v3`；从其后续覆盖盘完成安装重放、服务重启和整机重启，`centos9-amd64-native-v5` 控制器退出 0，虚拟机正常关机。前后 boot ID 不同，密钥与活动 Nginx 证明保持一致；两次 SELinux 均为 Enforcing。

安装器补充 `/var/run/nginxpanel-host`、`/var/run/nginxpanel-install` 的 CIL 路径声明，与 `/run` 别名一致，解决该系统的等价路径冲突。实际受管目录保持 `system_u` 和预期类型，`matchpathcon -V` 验证通过。外部已批准程序保留系统允许的 `unconfined_u:object_r:usr_t:s0`，没有改写其标签或关闭 Enforcing；原夹具把其 SELinux user 强制等同于受管目录，已修正该断言。一次续验误重放已完成的幂等请求得到正确的 409，后续仅续办待验收步骤；全部失败日志保留。

本轮安装器 SHA-256 为 `334d1fa1bcd817ef1510b34e8f5ed82cd53597d1d76df35f15b8e30579690d23`；运行程序为原批准的 amd64 `v0.2.24-dev`（SHA-256 `dd8e4c110d3cfb1242493752291e3896cf59f40a3b294102a2a62e7817069f3e`）。该记录只更新此原生系统组合，不表示后续监听检查代码、Docker 或其他功能已重跑。

Ubuntu 24.04/arm64 的 `ubuntu24-arm64-native-v8` 在 QEMU 7.2.22/TCG、Cortex-A53、单核下再次于 SSH 就绪前出现 6.8 内核软锁死，未进入应用验收。已停止失败覆盖盘，保留控制台与停止原因，不再重复同参数运行；该组合等待能稳定执行该内核的 ARM 隔离环境。开发宿主机的包、服务、网络、SELinux 及 binfmt 配置均未修改。


### Nginx 监听冲突、IPv6 归属与端口复用（2026-10-21）

配置渲染按协议和实际地址覆盖范围检查重叠，拒绝 HTTP/Stream、通配/具体地址和跨地址族双栈冲突，保留同端口 TCP/UDP、IPv6-only 与 IPv4 分离以及 HTTP 同族虚拟主机合并。应用和受管恢复在切换前检查外部端口占用；运行确认同时检查受管套接字、外部共享 UDP 和实际 IPv6-only 模式，避免仅凭相同地址/端口宣告成功。管理 HTTPS 就绪检查同步使用带上下文的 TCP 读取。

只读 `SOCK_DIAG` 读取替代 `/proc/net` 的地址字符串判断，包含已连接 UDP 的本地端点，单次最多 2 秒、2 MiB、8192 项；内核响应缺失、截断、重复关键属性、预算超限或无法确认 IPv6 模式均明确失败。未提供降级到不完整观察后继续发布的路径。

本地 `p5-listener-ownership-v2` 至 `v5` 保存检查结果及失败夹具。最终通过 7 项实际渲染地址组合、IPv6 双栈/仅 IPv6 的真实内核读取、管理监听归属、已连接 UDP、外部 `SO_REUSEADDR` 抢占检测，以及两工作进程 TCP/UDP 双栈 `reuseport`（每端点两个受管套接字和真实代理流量）。HTTP 通配/具体 IP 合并后的归属和实际响应也通过；TCP/UDP 双栈 1:3 权重仍各为 3/9。已通过且未受后续夹具调整影响的结果复用，没有重跑无关检查。配置用例补齐受信任运行目录，复用用例改用实际配置渲染；原失败日志保留，属性尾部截断接收已修正并复验。

运行镜像为预置模块 amd64 镜像 `sha256:513bd336f4aee8c27cfaa97bedb045dd65eb84ccb507d65f6884ed81251f798b`，使用私有 PID/网络、只读根文件系统和私有 `/srv` tmpfs，无宿主 PID/端口或 Docker socket；套接字诊断模块在检查前已存在，未修改开发宿主机配置。程序与测试散列、结果复用映射见本地 `p5-listener-ownership-v5/result.json`。该记录不替代完整原生发布事务、其他内核/架构或其他发行包的验收，未执行 UI 自动化。

### CentOS Stream 9/10/arm64 原生部署（2026-10-21）

官方 CentOS Stream 9、10 的独立 Cortex-A53 来宾分别运行 `5.14.0-758.el9.aarch64`、`6.12.0-277.el10.aarch64`。首次安装、身份/权限与密钥隔离、HTTPS 代理、端口冲突及 Agent 中断回滚、恢复应用、安装重放、服务重启和整机重启均通过；两阶段 SELinux 均为 Enforcing，受管标签及 `matchpathcon -V` 检查通过。重启前后 boot ID 不同，密钥、活动 Nginx 与实际程序散列保持。原生安装/重启矩阵现覆盖 13/14 个系统架构组合，仍不表示各组合的全部功能已验收。

证据位于本地 `centos9-arm64-native-v2`、`centos10-arm64-native-v2`。来宾的 postboot 单元已成功退出并写入完成文件，但输出未出现在控制器捕获的串口，控制器停留在标记等待；中断等待后，其 finally 阶段完成采证和正常关机，保留 KeyboardInterrupt 原日志。另行核对原始 journal 的通过标记、前后证明及 Enforcing，结果和证据散列写入 `acceptance-result.json`，未重跑已通过的业务步骤，也未将控制器退出宣称为成功。

两轮使用已批准的 arm64 `v0.2.24-dev`（SHA-256 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`）、静态 Nginx `c04c861d413d27772c7103dc872c11e82dbc29d879ff81a71d99ef63eb663c27` 和安装器 `334d1fa1bcd817ef1510b34e8f5ed82cd53597d1d76df35f15b8e30579690d23`。不据此覆盖后续监听检查代码、Docker 或其他功能；开发宿主机环境未修改。

### Ubuntu 24.04/arm64 原生部署续验（2026-10-21）

官方镜像中的 Ubuntu 24.04.5、6.8.0-147-generic，Cortex-A53 单核、2 GiB 内存，在隔离 Docker 内以 QEMU 8.2.2/TCG 运行。程序为冻结的 `0.2.24-dev` ARMv8.0 静态资产，SHA-256 `591740c0df09e9cbedf6a661a16e7164deabe59310ab89709f7cf6f3a061154f`；预置 36 项模块的静态 Nginx 1.30.6 为 `c04c861d413d27772c7103dc872c11e82dbc29d879ff81a71d99ef63eb663c27`。

首次安装、身份权限、真实 HTTPS 代理及端口冲突回滚由前序 v6 执行。首次中断驱动误将辅助进程也纳入 kill，v7 又在续办前读取不存在的 cookie 文件；两轮原始失败保留。v8 的旧版 QEMU 在 SSH 就绪前出现内核 soft lockup；升级工具仅在 Docker 中进行，v9 因缺少可选 PXE ROM 在内核启动前退出。v10 明确关闭网卡 PXE ROM，沿用正常关机的 v7 基盘，仅续办未完成阶段，没有使用未正常关机的 v8 磁盘。

v10 核对原 Agent 主进程中断任务已回滚，恢复后真实代理应用通过；安装器幂等重放、服务重启、整机重启及重启后权限、API、代理和配置核对通过。重启前后 boot ID 不同，Web、Agent、Nginx 的实际可执行文件散列、密钥和活动配置保持。AppArmor 启用并加载 117 项配置，三个应用进程实际标签为 `unconfined`；此记录不声明已有专用 AppArmor 策略。控制器和原始 journal 均有完成标记，虚拟机正常关机，容器退出 0。期间一次 SSH 诊断超时，未据此改写原始记录或重跑已经通过的业务。

证据位于 `.validation/native-vm/ubuntu24-arm64-native-v6` 至 `v10`；v10 的 `acceptance-result.json` 记录最终证明与原始日志、前后权限和配置证明的散列。本轮仅完成该原生组合，不覆盖 Docker 部署、防火墙后端、其他 Nginx ABI 或正式发行资产。

### Fail2ban 体积与轮询资源首组实测（2026-10-21）

冻结的官方 Fail2ban 1.1.1 组件包 SHA-256 为 `f1a7f7208aa212bf609e6bafb5bb5b036e50cd85dd90a13775fe6a9e1a5c3f8b`。逐文件核对清单后，压缩包 338,816 字节，234 个普通文件合计 1,151,987 字节；实际解包在本次工作区文件系统占用 1,794,048 字节（包含目录块，不代表所有目标文件系统的分配量）。基础面板固定启动器镜像的 Docker `Size`：amd64 为 37,732,174 字节（`160857bc3972…`），arm64 为 34,029,390 字节（`ddfb7f4ff692…`）。此镜像大小不包含另行挂载的活动应用发行包和数据，也不是注册表压缩传输大小。原始完整镜像 ID、检查输出及资产来源散列记录在 `.validation/p5-fail2ban-resources-v1/`。

官方引擎资源测量使用已锁定的 amd64 Docker 工具镜像、Python 3.11.2、单核 CPU 配额和 128 MiB 内存上限，无网络、只读根文件系统、非 root、无附加 capability。单个 jail 使用 polling、关闭 DNS、INFO 日志和空动作；输入目标为每秒 100 行，实际负载及轮转阶段各写入并识别 2,000 行。每个阶段采样约 20 秒，轮转前先确认旧文件已读完；不覆盖并发 rename/truncate 竞争。

| 场景 | 引擎 CPU 时间 | 单核平均 CPU 占比 | RSS 最大值（MiB） |
| --- | --- | --- | --- |
| 空闲 | 0.02 秒 | 0.100% | 23.984 |
| 轮询匹配输入 | 0.21 秒 | 1.046% | 24.414 |
| 有序文件轮转后继续输入 | 0.21 秒 | 1.046% | 24.426 |

CPU 由该引擎进程 `/proc` 计数差计算，RSS 为实际进程采样；不含测量驱动、Agent、封禁动作、宿主防火墙或其他架构开销。基线已安装 Python，前后完整 dpkg 清单一致，没有新增依赖包；这不能替代缺少 Python 的安装场景或完整运行时增量依赖核算。结果是该锁定场景的数据，不构成通用负载或资源上限保证。

首轮测量因 client 未指定配置目录而未能就绪，v2 定点诊断确认其尝试读取不存在的 `/etc/fail2ban`；失败保留。v3 给 client 与 server 指定同一配置目录，全部 4,000 行匹配及有序轮转通过，正常停止，容器退出 0、无 OOM。`runtime-resources.json`、完整包清单、配置、原始日志及 `measurement-result.json` 位于 `.validation/p5-fail2ban-resources-v3/`。未安装主机依赖、未发送网络请求或修改开发宿主环境。

## 同一宿主 Agent 的 Web 进程隔离指标对照（2026-10-21）

Ubuntu 22.04/arm64、实际内核 `5.15.0-198-generic` 的隔离虚拟机中，保留同一原生部署绑定、程序、数据和非特权 UID 997，依次运行原生 Web、容器内 Web，再恢复原生 Web。冻结程序为 `0.2.29-dev`，SHA-256 `d00b4f0515559ffcc23daa5785bb5ebf17f311d3fe5c94354f31086618342b63`。Host Agent 全程保持原进程，宿主采集授权有效。

容器使用已准备的 arm64 固定启动器基础镜像，覆盖入口执行同一批准程序；只读根文件系统、移除全部 capabilities、禁止提权、独立 PID/网络命名空间，CPU 限额 0.5 核、内存 512 MiB。容器网络仅有 `lo`，未挂入宿主 `/proc` 或 `/sys`。通过真实 HTTPS API 取得三个新样本，均在各阶段开始后采集、未过期，来源为 `host-agent`：

| 检查项 | 原生 Web / 容器 Web / 恢复原生 Web |
| --- | --- |
| Host Agent | 同一进程，PID 669 |
| boot ID | `28774724-d42a-47d6-b31b-bc8aa11f1c21` |
| CPU 维度 | 三组均含 `cpu0`、`cpu1`，使用率可用 |
| 内存总量 | 三组均为实际宿主的 4,097,085,440 字节 |
| 网络维度 | 三组均含完整宿主网卡，包括 `p5-in`、`p5-docker`，而非只含容器的 `lo` |
| 样本时间 | 依次递增，排除复用容器启动前缓存 |

本组保持 `--panel-runtime native` 及其运行绑定，只验证 Web 执行隔离切换后的宿主指标来源；正式 Docker 安装、固定启动器入口及部署模式迁移仍按各自门禁验收，Docker 部署矩阵维持 2/14。

首轮夹具误用基础镜像未提供的 `/bin/sh`，在容器指标读取前失败；记录保留。v2 改由来宾宿主只读检查容器根目录中的环境标记及 cgroup 文件，确认 `memory.max=536870912`、`cpu.max=50000 100000`，未向镜像增加工具。对照通过后容器正常停止、原生 Web 恢复；虚拟机正常关机，外层容器退出 0、无 OOM。证据、源码散列和验收结果位于 `.validation/native-vm/host-metrics-native-container-v2/`。未改变开发主机环境，未执行 UI 自动化。

## Docker FORWARD 实际内核准入续验（2026-10-21）

Ubuntu 22.04/arm64、Linux 5.15 隔离虚拟机发现并修复三项准入问题：合并 local/main FIB 的 IPv4 本地路由须以精确 local 清单核对；不同出入接口的 IPv6 转发源证明须扣除内核已禁止的 link-local 范围，以识别 Docker 默认 DNAT 排除条件；iptables-nft 合成的空 ACCEPT INPUT 须在实际创建前计入 nft 对象和字节预算。保留路由歧义、非永久选中路由、未知 DNAT 路径、同接口转发及矛盾规则视图的拒绝边界。

相关定点用例通过，证据位于 `docker-forward-routing-fix-v3/v4/v5/v7/`。冻结的 `0.2.30-dev` ARM 程序在 `docker-forward-iptables-nft-v19/` 中通过安装、登记、八条 TCP/UDP IPv4/IPv6 基线流量及显式计划准入；实际 nft 回读确认两族 INPUT 创建。应用请求返回 504，未计为事务通过。保留原盘及后续诊断；`docker-forward-recovery-wait-v23/` 等到原任务 `rolled_back/confirmed_restored`，但运行态核对仍报 `context deadline exceeded`。完整确认、Agent 中断、重启及第三方规则保留流程尚未通过，本组不增加 Docker 部署矩阵。上述目录均位于 `.validation/native-vm/`，虚拟机正常关机；产品超时和严格核对边界未改动，开发宿主环境未修改。
