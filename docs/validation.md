# P5 集中验证记录

2026-10-19。当前完成软件构建、接口迁移、双节点 HTTPS 迁移与授权及 amd64 预置 Nginx 镜像运行验证，P5 尚未完成。以下结果不代表宿主机部署、内核操作或全部业务功能已验收。

## 隔离环境

所有程序生成、编译、类型检查、lint 和业务测试均在 Docker 容器中执行。常规构建和接口验证使用普通用户、只读根文件系统、移除全部 capabilities、禁止提权。Nginx 运行验收使用独立网络、只读根文件系统及私有 `/srv` tmpfs；root 测试进程仅用于准备目录所有权、启动和回收子进程，实际 Nginx 使用 UID/GID 1000。启动器验收使用独立数据卷及与运行绑定一致的只读/可写挂载；启动后核对 PID 1 的身份和 capabilities。全部容器不映射宿主机端口、管理 Socket、系统目录或主机网络。工作目录用于源码及生成文件，依赖、测试数据库和构建产物放在容器卷中。未安装宿主机软件或修改宿主机服务、网络、防火墙及 Docker 配置。

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

首次真实运行发现 UUID 命名的防护变量无法装入 Nginx 默认变量哈希桶，已在 HTTP 运行配置提供 `variables_hash_bucket_size 128`，相同范围复验通过（0.17 秒）。构建上下文通过 Dockerfile 专用忽略文件限制为所需配方、模块声明、二进制及许可文件。

`internal/nginxcontainer` 的 `TestPrepareNginxLauncherFixture` 仅在显式环境变量下准备 root 所有的隔离登记夹具，随后直接运行镜像的实际入口。分别验证正常降权/低端口监听、无登记、启动器哈希不匹配及 Nginx 哈希不匹配。端口阈值只设置在 `--network none` 容器的网络命名空间中；未修改宿主机 sysctl。登记夹具的签名来源字段是合成数据，这组结果不能证明发行签名、Registry 来源或宿主机安装器准入已通过。验证容器和对应夹具卷已回收。

## 尚待验收

- 原生安装、目标账户与 systemd、各 DNS/防火墙所有者、Fail2ban、管理监听、Nginx 实际应用及重启/断电/中断后的恢复，需要独立 Linux 系统环境；不在开发宿主机执行。
- 两种架构的正式原生资产、arm64 预置模块镜像、签名镜像来源准入、不可变镜像绑定、升级/回滚和备份恢复故障注入，仍需完成产物构建及运行验收；本轮 amd64 模块运行与固定启动器结果不替代这些检查。
- 真实域名的 ACME/DNS、通知接收端及跨主机 API 一键迁移，尚未进行外部集成验收；容器内双节点迁移与授权结果见上节。
- 正式 GitHub 仓库及发布凭据尚未配置，未运行真实发布 CI、推送或发布。项目 MIT 许可证已补齐，第三方组件保留各自许可。
- UI 由用户人工验收，未创建或执行 UI 自动化测试。
