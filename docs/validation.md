# P5 集中验证记录

2026-10-19。当前完成软件构建、接口迁移、双节点 HTTPS 迁移与授权、amd64 预置 Nginx 镜像运行与原生静态构建，以及 Debian 12/amd64 原生安装、Nginx 应用和指定中断恢复验证，P5 尚未完成。以下结果仅覆盖列出的组合及行为，全部目标系统、内核操作和业务功能仍须分别验收。

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

## 尚待验收

- 其他系统/架构及 Docker 面板组合的账户与 systemd、各 DNS/防火墙所有者、Fail2ban、管理监听，以及其他危险操作在重启/断电/中断后的恢复，仍需独立 Linux 系统验收；本轮结果仅证明表内组合与列明的 Nginx 故障场景。
- 两种架构的正式原生资产、arm64 预置模块镜像、签名镜像来源准入、不可变镜像绑定、升级/回滚和其他备份恢复故障注入，仍需完成产物构建及运行验收；本轮 amd64 模块运行、固定启动器及上述克隆恢复结果不替代这些检查。
- 真实域名的 ACME/DNS、通知接收端及跨主机 API 一键迁移，尚未进行外部集成验收；容器内双节点迁移与授权结果见上节。
- 正式 GitHub 仓库及发布凭据尚未配置，未运行真实发布 CI、推送或发布。项目 MIT 许可证已补齐，第三方组件保留各自许可。
- UI 由用户人工验收，未创建或执行 UI 自动化测试。
