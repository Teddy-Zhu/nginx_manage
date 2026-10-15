# NginxPanel

基于 Go、Vue 和 SQLite 的 Linux Nginx 管理面板。完整范围与实施顺序见 [设计文档](Linux_Nginx_Manager_Design.md) 和 [实施进度](docs/implementation.md)。当前处于基础工程实施阶段，尚未发布，不声明系统兼容性验收通过。

当前实现：单管理员引导、SCS 会话、CSRF、Argon2id、限定权限机器凭据；统一 JSON 响应与 Axios 请求层；HTTP/Stream 代理 CRUD、常用字段/原文双向映射、可复用黑白名单与基础 WAF 策略、手动证书版本与 HTTPS 绑定/跳转/HSTS、不可变修订、原文差异、外部快照/草稿捕获/受管恢复、并发保护和独立草稿；Unix Socket Agent 身份校验、Nginx 编译/受信动态模块能力、不可变发布/运行确认/回滚、持久任务及审计；自动扫描页面路由的管理界面。

安全发布流程代码已接入，尚未集中验证。ACME 已接入独立测试/正式账户、DNS 凭据、DNS-01 签发及持久订单恢复；HTTP-01、自动续期、完整代理能力、安全/主机管理、多节点、备份和发布更新继续实施；保存与校验不会显示为已生效。

## 开发

需要 Go 1.27.2（`go.mod` 自动选择）、Node.js 24、pnpm 10.33.0。生产运行不需要 Node、独立数据库、Python 或 Docker。

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

实际执行入口由本机 root 显式指定 `--nginx-binary` 和 `--nginx-user`，要求可信程序及独立 worker 账户。`nginx-init` 创建无站点基线；服务须以对应数据根为 prefix，并从 `nginx/active/nginx.conf` 启动。动态模块由本机 root 清单批准，通过 `--nginx-modules` 向 Web/Agent 提供同一选择范围，详见 [模块接入](docs/native-modules.md)。[原生安装入口](deploy/native/README.md) 已接入账户/目录分区、不可变产物及三个 systemd 服务，显式 `--start` 才启用启动；不接管已有系统 Nginx。安装与实际服务尚未验证。开发 Agent 不开放实际执行。

未连接 Agent 时保持预览模式，不提供虚假的系统操作成功结果。开发模式只允许回环 HTTP，不作为生产部署方案；当前生产入口仅允许回环 HTTPS。P4 原生首次安装已开始接入，签名发布、可信组件自动准备及完整 Docker 持久运行继续实施。

本机 `release-verify/release-prepare` 已接入固定发布公钥、离线签名清单和有界资产准备，见 [发行资产合同](docs/releases.md)。准备好的 panel 可交给原生安装器；此入口不启动组件或切换当前版本，在线更新及迁移自动准备继续实施，尚未运行验证。

生成代码：`make generate`。构建：`make build`。验证：`make verify`，仅在业务实现和集成稳定后的集中验证阶段执行；不包含 UI 自动化。当前实现尚未执行构建、类型检查或业务验证。

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
