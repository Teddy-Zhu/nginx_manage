# 跨环境配置迁移

“配置迁移”页面由 `src/pages/migrations.vue` 自动扫描接入。当前实现加密配置包与 API 拉取，两者使用同一目标预检、修订保存及 Nginx 执行器。尚未运行构建、类型检查、测试、镜像构建或真实迁移，等待 P5 集中验收。

## 迁移内容

始终包含当前期望 Nginx 原生配置树，连同 HTTP/Stream、ACL、WAF 与相互引用。导入明确替换 Nginx 业务配置范围，不覆盖目标节点身份、管理员、API Key、管理入口、TLS 信任、主机 DNS、监控设置、功能开关或 Agent 信任/救援记录。

可显式选择证书与私钥、DNS 提供商凭据、ACME 账户及签发配置、通知渠道及其凭据。证书包括最新版本及当前配置引用版本；资源和证书版本在目标重新分配 ID，逻辑文件 ID 重新生成，证书引用按参数位置重绑定。业务配置树内部的站点/策略标识随同一树保留。秘密由源主密钥解密后放入 age 加密归档，目标再以自己的主密钥加密；不复制源密文或主密钥。

ACME 迁移须同时选择证书和 DNS 凭据，并先完成注册、签发及恢复。仅恢复现有注册记录，不发起新 CA 操作；同环境、相同账户密钥且 CA 地址一致的目标已注册账户可复用。签发配置自动续期/部署均关闭，HTTP-01 公网确认清除，订单与挑战租约不复制。通知渠道新增后始终停用，不复制旧投递队列或重放告警。

普通可移植无秘密归档、完整数据库灾备、监控设置迁移、主机 DNS/防火墙映射，以及可信组件自动安装仍待后续实施。当前包与计划会明确展示范围及目标缺失项，不将这些能力视为已经交付。

## 文件导出与导入

在源节点使用 16–256 字节口令导出 `.tar.age`，在目标节点上传并输入口令。完整原文可能含秘密，所有导出均要求 `backup.export/backup.secrets/config.secrets` 及浏览器近期认证；包和口令需分别保管。

预检解析当前唯一 schema、固定 JSON 文件清单及 SHA-256，检测目标模块、原生指令、证书引用/有效性、资源容量、运行接入及未应用修订，并列出监听、域名和上游供核对。映射仅能替换识别出的指令参数，不执行包内脚本，不读取源机器绝对路径。缺失或未知镜像能力只能保留草稿；换用匹配镜像后重新预检，不能运行时增装模块。真实监听/目录/ABI 与配置检查沿用 Agent 的应用前检查及 `nginx -t`。

计划有效期 30 分钟，执行支持 `draft`、`save`、`apply`；草稿不代表配置生效。保存和应用均要求精确基础版本，目标配置模块停用时须明确授权启用。导入需要 `backup.restore/backup.secrets/config.write/config.secrets/security.write`；恢复通知渠道另需 `notifications.write`，启用配置模块另需 `system.write`。

依赖资源、修订、任务、审计和幂等响应同事务保存。应用期间拦截其他 Nginx 修改/执行和模块开关。成功以原有 root 执行器确认运行结果为准；失败先核对原运行修订，再恢复原期望指针和本次启用的模块。配置头使用递增代次使旧客户端失效，不改写历史修订。不能证明运行恢复或遇到外部冲突时保留 `recovery_required`，不覆盖外部变化。导入的不可变修订、证书、凭据及停用的自动化配置保留，便于审计与重试；这些保留项不是已经启用的业务。

## API 一键迁入

在目标调用 `POST /api/v1/migrations/pull`，提供源节点 HTTPS API 和 Key；本地还需 `nodes.manage`。源 Key 需导出权限及来源网络授权。源节点须经现有受保护网络、VPN 或管理员配置的代理可达；本实现不开放新的公网管理监听，也不建立隧道。

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

迁移计划报告原生组件缺失时，具有 `components.manage` 权限的用户可从计划进入 `/components` 检查并准备受信预编译资产。准备完成不解除实例未运行、完整性或模块能力阻塞；安装与运行接入尚待后续流程，完成后须重新生成迁移计划。Docker 缺少 Nginx 能力仍需更换预置模块的镜像。
