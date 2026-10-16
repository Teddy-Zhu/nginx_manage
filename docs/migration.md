# 跨环境配置迁移

“配置迁移”页面由 `src/pages/migrations.vue` 自动扫描接入。当前实现加密配置包、API 拉取及源端推送，均使用同一目标预检、修订保存及 Nginx 执行器。尚未运行构建、类型检查、测试、镜像构建或真实迁移，等待 P5 集中验收。

## 迁移内容

始终包含当前期望 Nginx 原生配置树，连同 HTTP/Stream、ACL、WAF 与相互引用。导入明确替换 Nginx 业务配置范围，不覆盖目标节点身份、管理员、API Key、管理入口、TLS 信任、主机 DNS、监控设置、功能开关或 Agent 信任/救援记录。

可显式选择证书与私钥、DNS 提供商凭据、ACME 账户及签发配置、通知渠道及其凭据。证书包括最新版本及当前配置引用版本；资源和证书版本在目标重新分配 ID，逻辑文件 ID 重新生成，证书引用按参数位置重绑定。业务配置树内部的站点/策略标识随同一树保留。秘密由源主密钥解密后放入 age 加密归档，目标再以自己的主密钥加密；不复制源密文或主密钥。

ACME 迁移须同时选择证书和 DNS 凭据，并先完成注册、签发及恢复。仅恢复现有注册记录，不发起新 CA 操作；同环境、相同账户密钥且 CA 地址一致的目标已注册账户可复用。签发配置自动续期/部署均关闭，HTTP-01 公网确认清除，订单与挑战租约不复制。通知渠道新增后始终停用，不复制旧投递队列或重放告警。

完整数据库的加密捕获、下载及离线检查已独立接入，见[完整备份](backups.md)，安装恢复事务仍待补齐。普通可移植无秘密归档、监控设置迁移、主机 DNS/防火墙映射，以及可信组件自动安装仍待后续实施。当前包与计划明确展示范围及目标缺失项，不将这些能力视为已经交付。

## 文件导出与导入

在源节点使用 16–256 字节口令导出 `.tar.age`，在目标节点上传并输入口令。完整原文可能含秘密，所有导出均要求 `backup.export/backup.secrets/config.secrets` 及浏览器近期认证；包和口令需分别保管。

预检解析当前唯一 schema、固定 JSON 文件清单及 SHA-256，检测目标模块、原生指令、证书引用/有效性、资源容量、运行接入及未应用修订，并列出监听、域名和上游供核对。映射仅能替换识别出的指令参数，不执行包内脚本，不读取源机器绝对路径。缺失或未知镜像能力只能保留草稿；换用匹配镜像后重新预检，不能运行时增装模块。真实监听/目录/ABI 与配置检查沿用 Agent 的应用前检查及 `nginx -t`。

计划有效期 30 分钟，执行支持 `draft`、`save`、`apply`；草稿不代表配置生效。保存和应用均要求精确基础版本，目标配置模块停用时须明确授权启用。导入需要 `backup.restore/backup.secrets/config.write/config.secrets/security.write`；恢复通知渠道另需 `notifications.write`，启用配置模块另需 `system.write`。

依赖资源、修订、任务、审计和幂等响应同事务保存。应用期间拦截其他 Nginx 修改/执行和模块开关。成功以原有 root 执行器确认运行结果为准；失败先核对原运行修订，再恢复原期望指针和本次启用的模块。配置头使用递增代次使旧客户端失效，不改写历史修订。不能证明运行恢复或遇到外部冲突时保留 `recovery_required`，不覆盖外部变化。导入的不可变修订、证书、凭据及停用的自动化配置保留，便于审计与重试；这些保留项不是已经启用的业务。

## API 一键迁入

在目标调用 `POST /api/v1/migrations/pull`，提供源节点 HTTPS API 和 Key；本地还需 `nodes.manage`。源 Key 需导出权限及来源网络授权。源节点可通过[受控管理监听](management-listener.md)、现有受保护网络、VPN 或管理员配置的代理提供 HTTPS API；迁移本身不改变管理入口或建立隧道。

```json
{
  "remote": {
    "url": "https://source.example.com:9443/api/v1",
    "api_key": "源节点导出 Key",
    "fingerprint": "",
    "node_id": "",
    "selection": {
      "certificates": true,
      "dns_credentials": true,
      "automation": true,
      "notifications": false
    }
  },
  "base_version": 0,
  "mappings": {"192.168.1.10:80": "0.0.0.0:80"},
  "mode": "apply",
  "enable_nginx": false
}
```

`base_version` 从目标 `GET /nginx/config-tree` 取得；请求同时提供 `Idempotency-Key`。`mode=preview` 只拉取与预检，其余模式继续执行同一计划。响应统一为 `code/message/data/request_id/node_id`；`data.state=applying` 表示异步执行，继续读取 `GET /migrations/{id}`，直到 `succeeded/rolled_back/recovery_required`。

默认使用系统 CA；自签名证书须填写独立核对的叶证书 SHA-256。可用 `node_id` 固定预期源身份。连接禁止重定向和环境代理，目标解析及响应有界；不接受 link-local、组播、未指定地址或常见元数据地址。API Key 仅用于本次固定导出接口，不持久保存或写日志；源节点校验通过后，计划以源稳定 ID 绑定。此入口是专用一次性迁移，不提供任意 API 转发。

其他入口：`POST /migrations/export`、`POST /migrations/plan`、`POST /migrations/{id}/execute`、`GET /migrations`。执行请求幂等；拉取请求在计划提交时持久关联幂等键，响应丢失后使用原请求和原键核对，避免重复迁入。

## 资源边界

加密包与解密归档各不超过 8 MiB，不使用压缩，不向磁盘解包。只接收固定六个普通文件，拒绝目录、链接、设备、重复名称、PAX、未知文件和非零尾随内容；全部 age 内容认证完成后才解析。scrypt 工作因子上限 18，每节点串行处理包。原文仍受 128 文件/2 MiB 配置树限制，证书材料合计 1 MiB；其他资源沿用各模块配额。

最多 8 个待执行计划、128 条保留记录及 128 MiB 迁移材料；状态摘要单独加密且不超过 256 KiB，列表不解密原始归档。预检展示最多 128 项，超限明确提示，所有项目仍参与准入判断。API 请求上限 12 MiB，远程响应与超时均有界；实际容量冲突会阻止事务提交。

迁移计划可通过 `POST /migrations/{id}/dependencies` 按次授权准备缺失的可信 Nginx 资产，输入 `tag` 和 `prerelease`，要求导入权限及 `components.manage`、浏览器近期认证和幂等键。目标仅使用本机已确认的发行信任；已有 Nginx 不替换，已有安装绑定需要恢复时不准备替代资产，Docker 缺少模块能力仍需换用匹配镜像。父任务授权最多 30 分钟且不超过原计划有效期；检查及准备子任务与父关联同事务提交，断连或重启不新建相同子任务。准备绑定检查过的资产、清单、信任及所需模块能力，缺少系统运行依赖或能力时停止；不安装系统包、不编译或增装 Nginx 模块。

## 源端推送式一键迁出

源节点调用 `POST /api/v1/migrations/push` 并提供 `Idempotency-Key`，或使用自动扫描的“迁出到节点”页面。输入格式沿用 `remote.url/api_key/fingerprint/node_id/selection`，但 remote 指向目标；另有 `mappings`、`mode=preview|draft|save|apply`、`enable_nginx`、可选 `base_version` 和可选 `dependencies: {tag, prerelease, install?: {start, enable}}`。未提供基础版本时，首次受信连接读取并固定目标当前配置版本，后续不自动改用新版本。首次响应为 HTTP 202 的父任务；`GET /migrations/push` 列表及 `GET /migrations/push/{id}` 查询同一任务和目标逐项结果。preview/draft/save 的完成只表示对应步骤完成，apply 须等目标执行器确认生效才报告应用成功。

源端要求 backup.export、backup.secrets、config.secrets 和 nodes.manage，浏览器需近期认证。目标 Key 需 backup.restore、backup.secrets、config.write、config.secrets、security.write；迁入通知另需 notifications.write，启用配置模块另需 system.write，授权准备组件另需 components.manage，授权首次安装另需 system.write。目标通过 `GET /migrations/receiver` 提供当前版本和本 Key 权限，身份在首次连接后持久绑定；每个响应核对同一节点。目标接收使用 `PUT /migrations/receive/{id}`，固定 ID、配置包散列、映射及基础版本的回执和计划同事务保存；重复 ID 的不同内容会被拒绝。执行沿用 `/migrations/{id}/execute` 和原幂等键，不另建导入执行器。

源端只导出一次并冻结包，在自己主密钥保护下暂存包、随机口令及本次目标授权；Key、口令和包正文不出现在任务响应、通用任务及审计中。授权一小时、单轮请求 35 秒、每次授权最多 128 轮，网络失败有限退避并遵守 Retry-After；串行 worker 在重启后先查询原目标计划。已确认计划缺失、身份变化、目标补偿不明或结果不符时停止新提交，不因超时判定目标停止。授权到期清除活动 Key：未提交者失败；可能已提交者保留加密恢复材料和待恢复状态。终态任务清除活动包及授权，保留加密摘要与审计；不宣称 SQLite 历史页已物理擦除。

预检未通过、权限不足或目标待恢复时可处理逐项结果，再调用 `POST /migrations/push/{id}/resume`，提供新的 `api_key` 和幂等键。此操作续授一小时，只继续原包、原节点、原模式和原阶段；更换目标 Key 后仍须有原计划所有者权限或 auth.manage，不绕过目标权限。映射、目标或基础版本需要改变时须创建新的迁移。依赖准备/安装和完整快照尚待接入；Docker 所需模块仍必须来自预置镜像。

推送最多保留 64 条父任务，列表覆盖全部保留任务；推送暂存与导入计划共享 128 MiB，单条暂存最多 12 MiB、父任务摘要 264 KiB（目标结果及父任务元数据），目标响应最多 256 KiB。创建请求最多 2 MiB。未执行真实网络迁移、构建或测试，待 P5 集中验证。

目标 `Plan.dependencies` 展示父任务、检查/准备/维护/首次安装子任务及结果；GET 读取摘要，不解密整个迁移包。`install` 未提供时，`prepared` 只表示签名资产准备好。显式提供 `install: {start: true, enable: false}` 时，额外要求 system.write，且两个选项均须明确指定；仅支持已登记为未安装的原生目标，不接管已有实例。父任务自动进入维护、等待其他在途任务结束、提交原首次安装执行器、跟随同一安装结果、等待独立维护释放确认，然后用原包、映射、基础版本及资源 ID 重新预检。源端推送跟随同一父任务，再进入原配置执行器；文件导入仍由用户确认应用。`installed` 不表示迁移配置已应用；未启动、缺少依赖或存在配置冲突时，原预检继续阻塞。

环境修复后可在有效期内调用 `POST /migrations/{id}/preflight` 或页面“重新预检”，沿用原包、映射、基础版本和资源 ID 更新预检结果；不会延长计划或替换配置。过期计划或基础版本变化需要重新创建预检。准备失败的父任务保留审计及子任务关联，重新准备需要新迁移计划，不能借恢复授权切换原准备选项。尚未执行构建、测试、真实下载或迁移，待 P5 集中验证。

新的原生目标节点可通过 [仅面板安装](../deploy/native/README.md) 的 `--without-nginx` 方式部署 Web/Agent，随后导入预检并按次授权准备及首次安装，或从源节点推送时设置上述选项。维护仅排除原子关联的协调父任务；其他任务和迁移仍须排空。同一目标一次只接收一个未结束的迁移依赖父任务。首次安装子任务和父关联同事务提交，安装授权不超过父授权期限且最多 10 分钟；断连或重启只核对原操作，不自动重建或续装。结果待恢复时保留维护，并通过“组件安装”页面/API 显式恢复或取消原任务。原任务终结后父任务继续核对并释放维护；授权到期停止新提交，已接收操作仍须核对真实结果。安装已完成但计划过期或目标版本变化时，不继续写入配置，需要新建迁移预检。Docker 仍使用预置模块镜像，不进入原生首次安装。自动协调尚未执行构建、测试、真实下载、安装或迁移，统一留待 P5。
