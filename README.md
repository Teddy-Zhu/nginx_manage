# NginxPanel

基于 Go、Vue 和 SQLite 的轻量 Linux Nginx 管理面板，提供代理与 HTTPS、配置发布回滚、主机管理、节点连接、迁移备份及签名更新。

## 部署与使用

首次使用从[部署指南](docs/deployment.md)开始，安装后按[使用手册](docs/user-guide.md)创建第一个代理。

| 文档 | 内容 |
| --- | --- |
| [完整文档导航](docs/README.md) | 从安装到日常使用的阅读顺序及专题索引 |
| [部署指南](docs/deployment.md) | 材料准备、源码构建、原生/Docker 安装、首次登录、管理入口 |
| [使用手册](docs/user-guide.md) | 代理、证书、主机功能、API、节点、迁移与备份 |
| [运维与故障处理](docs/operations.md) | 服务管理、更新、恢复、常见问题与停用边界 |

当前实现状态及暂缓验收项见[进度清单](docs/progress.md)，已执行的系统组合见[运行矩阵](docs/support-matrix.md)。设计背景和阶段历史分别见[设计文档](Linux_Nginx_Manager_Design.md)、[实施记录](docs/implementation.md)。

## 功能概览

当前实现：单管理员引导、SCS 会话、CSRF、Argon2id、限定权限机器凭据；统一 JSON 响应与 Axios 请求层；HTTP/Stream 代理 CRUD、常用字段/原文双向映射、可复用黑白名单与基础 WAF 策略、手动证书版本与 HTTPS 绑定/跳转/HSTS、不可变修订、原文差异、外部快照/草稿捕获/受管恢复、并发保护和独立草稿；Unix Socket Agent 身份校验、Nginx 编译/受信动态模块能力、不可变发布/运行确认/回滚、持久任务及审计；自动扫描页面路由的管理界面。

ACME、主机 DNS、防火墙、Fail2ban、多节点、加密备份与跨环境迁移、原生与 Docker 部署及签名更新均已接入，实际运行能力须按目标系统验收；保存与校验不会显示为已生效。

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

需要 Agent 宿主机只读诊断时，在同一普通用户下另开终端：

```sh
go run ./cmd/nginxpanel agent --dev --data-dir=.local
```

实际执行入口由本机 root 显式指定 `--nginx-binary` 和 `--nginx-user`，要求可信程序及独立 worker 账户。`nginx-init` 创建无站点基线；服务须以对应数据根为 prefix，并从 `nginx/active/nginx.conf` 启动。动态模块由本机 root 清单批准，通过 `--nginx-modules` 向 Web/Agent 提供同一选择范围，详见 [模块接入](docs/native-modules.md)。[原生安装入口](deploy/native/README.md) 已接入账户/目录分区、不可变产物及三个 systemd 服务，支持 `--without-nginx` 仅安装 Web/Agent，显式 `--start` 才按所选组件启用启动；不接管已有系统 Nginx。实际安装与服务的验收范围见[运行验收矩阵](docs/support-matrix.md)。开发 Agent 不开放实际执行。

未连接 Agent 时保持预览模式，不提供虚假的系统操作成功结果。开发模式只允许回环 HTTP，不作为生产部署方案；生产保留回环 HTTPS 救援入口，远程管理通过受控监听开放。部署方式见 [原生安装](deploy/native/README.md) 和 [Docker 部署](deploy/docker/README.md)。

本机 `release-verify/release-prepare` 与 `release-check/release-fetch` 已接入固定发布公钥、离线签名清单、固定 GitHub 仓库的受限下载和有界资产准备，见 [发行资产合同](docs/releases.md)。准备好的 panel 可交给原生安装器；组件激活、在线更新及迁移依赖安装通过各自的维护流程执行。

项目采用 [MIT 许可](LICENSE)。面板/web 的 [发布工具与 GitHub 工作流](docs/publishing.md) 已接入打包、实际许可文件、依赖 SBOM、构建来源及 Ed25519 签名，先上传完整草稿再公开。正式发布仍需配置仓库和发布密钥。

生成代码：`make generate`。构建：`make build`。验证：`make verify`，仅在业务实现和集成稳定后的集中验证阶段执行；不包含 UI 自动化。开发验证须在隔离环境执行，已执行范围及待验收项见 [验证记录](docs/validation.md)。

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
