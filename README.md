# NginxPanel

基于 Go、Vue 和 SQLite 的轻量 Linux Nginx 管理面板，提供代理与 HTTPS、配置发布回滚、主机管理、节点连接、迁移备份及签名更新。

## 部署与使用

首次使用从[部署指南](docs/deployment.md)开始，安装后按[使用手册](docs/user-guide.md)创建第一个代理。

默认仓库为 `Teddy-Zhu/nginx_manage`。在部署目标选择一种方式：

**源码安装**（需要 Git、Docker 和 Compose，编译工具全部在容器内）：

```sh
bash setup.sh --source --yes
```

仓库发布包含安装脚本和本机架构安装包的正式版本后，可使用 Release 安装：

```sh
curl -fL https://github.com/Teddy-Zhu/nginx_manage/releases/latest/download/setup.sh \
  -o nginxpanel-setup.sh
bash nginxpanel-setup.sh --yes
```

两种方式都会检测环境、安装并启动服务，最后输出首次访问地址。省略 `--yes` 可先核对安装摘要；加 `--advanced` 才进入自定义设置。也可对下载的引导脚本加 `--source`，拉取源码、容器编译并安装。仓库公开访问和正式 Release 是否可用仍待确认，本文不表示 GitHub 已有可用公开发行。默认监听全部网卡并随机选择空闲管理端口，保存后重启不变；安装后可通过机器公网或内网 IP 访问。首次指定端口可加 `--port 23456`。安装后使用 `sudo systemctl restart nginxpanel.service` 重启核心服务，或用 `sudo bash /opt/nginxpanel/manage.sh set-port 23456` 修改端口。

核心程序将 Agent、管理 API 和前端页面合并为一个二进制，由宿主机 `nginxpanel.service` 以 root 运行。Nginx 使用 Docker 容器，配置、数据库、证书和日志保存在外部数据目录。源码安装由 Docker 容器编译；安装包包含核心程序和 Nginx 镜像，不再提供独立 `web/` 目录或面板运行镜像。Fail2ban、[FRP 服务端](docs/frps.md)和第三方应用默认不安装，需要时再手动安装。Nginx 常用模块已预置在镜像中。

| 文档 | 内容 |
| --- | --- |
| [完整文档导航](docs/README.md) | 从安装到日常使用的阅读顺序及专题索引 |
| [部署指南](docs/deployment.md) | 环境检测、源码或 Release 安装、首次登录、服务管理 |
| [使用手册](docs/user-guide.md) | 代理、证书、主机功能、API、节点、迁移与备份 |
| [运维与故障处理](docs/operations.md) | 服务管理、更新、恢复、常见问题与停用边界 |

管理脚本支持 `uninstall --keep-data` 保留数据卸载、`uninstall --purge` 完全卸载和 `reinstall` 恢复原版本；也可从菜单操作。详细范围见[卸载与重新安装](docs/operations.md#卸载与重新安装)。

旧程序缺少卸载命令时，在最新源码或安装包中执行 `sudo bash install.sh --uninstall`；需要完全卸载加 `--purge`。尚未使用且允许清空旧数据时，`sudo bash install.sh --fresh` 会先准备新程序，再完全卸载并安装当前版本。重复普通安装和 `reinstall` 均不更新版本，详见[旧版本处理](docs/deployment.md#旧版本卸载与未使用环境更新)。

当前实现状态及暂缓验收项见[进度清单](docs/progress.md)，已执行的系统组合见[运行矩阵](docs/support-matrix.md)。设计背景和阶段历史分别见[设计文档](Linux_Nginx_Manager_Design.md)、[实施记录](docs/implementation.md)。

## 功能概览

当前实现：单管理员引导、SCS 会话、CSRF、Argon2id、限定权限机器凭据；统一 JSON 响应与 Axios 请求层；HTTP/Stream 代理 CRUD、常用字段/原文双向映射、可复用黑白名单与基础 WAF 策略、手动证书版本与 HTTPS 绑定/跳转/HSTS、不可变修订、原文差异、外部快照/草稿捕获/受管恢复、并发保护和独立草稿；核心服务身份校验、预置 Nginx 模块、不可变发布/运行确认/回滚、持久任务及审计；自动扫描页面路由的管理界面。

ACME、主机 DNS、防火墙、Fail2ban、多节点、加密备份与跨环境迁移、宿主核心服务和 Docker 应用管理及签名更新均已接入，实际运行能力须按目标系统验收；保存与校验不会显示为已生效。

## 开发

开发阶段不得修改当前主机的软件包、系统服务、网络、防火墙或 Docker 配置。运行验证使用隔离的 Docker/虚拟机环境；安装器仅在实际部署目标执行，并须正确配置目标宿主机。

开发需要 Go 1.27.2（`go.mod` 自动选择）、Node.js 24、pnpm 10.33.0。面板核心运行不需要 Node 或独立数据库；Docker 部署需要目标 Docker Engine，启用 Fail2ban 需要受支持的目标 Python 环境。

```sh
pnpm --dir web install --frozen-lockfile
go run ./cmd/nginxpanel dev
```

另一个终端运行前端：

```sh
pnpm --dir web dev
```

访问 `http://127.0.0.1:5173`。API 默认 `127.0.0.1:8080`，Vite 同源代理 `/api`。首次启动生成 `.local/bootstrap/token`，从本机读取该文件，在初始化页面设置管理员；没有默认密码。数据目录不纳入 Git。

开发模式使用回环地址，不作为生产部署方案。开发时由 Go 提供 API、Vite 提供热更新页面；生产中前端随核心二进制提供。实际执行及部署验收须在隔离虚拟机完成，见[运行矩阵](docs/support-matrix.md)。

签名发行检查与准备见[发行资产合同](docs/releases.md)。系统更新只有一个入口，更新核心二进制并在启动时自动完成数据迁移；Nginx 及其他应用镜像按各自流程更新，不随核心程序更新。

项目采用 [MIT 许可](LICENSE)。[发布工具与 GitHub 工作流](docs/publishing.md)包含安装包、实际许可文件、依赖 SBOM、构建来源及 Ed25519 签名流程。正式仓库公开发行和签名配置尚未完成验证。

生成代码：`make generate`。构建：`make build`，调用 Docker 构建并输出安装包；`make release-tool` 同样通过 Docker 构建发行工具。构建入口不调用本机 Go、Node.js 或 pnpm。验证：`make verify`，仅在业务实现和集成稳定后的集中验证阶段执行；不包含 UI 自动化。开发验证须在隔离环境执行，已执行范围及待验收项见 [验证记录](docs/validation.md)。

## 接口与约束

普通 JSON 成功/失败均为：

```json
{
  "code": "OK",
  "message": "操作成功",
  "data": {},
  "request_id": "request-uuid",
  "node_id": "node-uuid"
}
```

HTTP 状态码保留语义；失败使用明确业务码，空数据为 `null`。异步操作返回 `202`，任务标识在 `data.task_id`。前端只通过 `src/api/client.ts` 解包和处理错误，不保存会话令牌或远程节点凭据。

页面由 `vue-router/vite` 自动扫描 `web/src/pages`，菜单由页面元信息派生；集中路由文件仅负责创建 Router、鉴权与热更新。API 合同位于 `api/openapi.yaml`，生成 Go 服务接口及 TypeScript 类型。首版发布前直接修改唯一合同，不增加旧版本兼容分支。

配置原文与投影均加密保存；完整原文需要 `config.secrets`，浏览器须近期重新认证。配置 `base_version` 指向当前有效期望修订；写操作携带 `Idempotency-Key`。安全策略、保真边界及资源预算见 [工程合同](docs/contracts.md)。
