# 实时状态订阅

每个浏览器页面共用一个 `GET /api/v1/events` WebSocket，包括本机页面、远程服务器页面和操作侧栏。订阅在连接内动态替换，添加、移除页面订阅不重建浏览器连接。不使用 URL 查询参数订阅。

客户端发送完整订阅集合；`connection` 为空字符串表示本机，否则为已登记的服务器连接编号。每次发送使用递增的安全整数 `revision`，空集合释放所有订阅。

```json
{"type":"subscribe","revision":1,"subscriptions":[{"connection":"","topics":["tasks","version"]},{"connection":"远程连接编号","topics":["monitoring"]}]}
```

推送沿用统一返回格式，携带连接范围及当前订阅序号，防止切换页面后处理已过期消息：

```json
{"code":"OK","message":"状态已更新","data":{"connection":"","topics":["tasks"],"revision":1},"request_id":"请求标识","node_id":"该资源所属服务器编号"}
```

首次订阅、重连及订阅类型改变时发送同步通知，此后仅在状态变化时推送。通知标记已变化的资源，页面通过已有业务 API 按需读取所需数据，不进行定时 HTTP 查询。写入保留原有 HTTP 接口及权限、幂等和确认约束，日志跟随继续使用 SSE。客户端按服务器合并同类订阅，并将消息分发给订阅该资源的页面。

| 类型 | 状态范围 | 所需权限 |
| --- | --- | --- |
| tasks | 后台任务；阶段日志落盘后再次通知 | read |
| monitoring | 最新监控样本及告警状态 | read |
| notifications | 通知健康、事件与投递状态 | read |
| maintenance | 维护状态 | read、system.write |
| backups | 备份文件与备份策略 | read、backup.export |
| firewall | 防火墙运行状态、准备进度及确认结果 | read、security.write |
| listener | 管理入口状态及确认结果 | read、system.write |
| version | 前端资源更新 | read |

| dns | DNS 当前设置、变更及管理开关 | read |

远程订阅由服务端复用已有证书校验、目标身份和单跳授权，使用机器身份连接目标 `/events?topics=...` 数据源；浏览器不直接连接远端，不接触凭据。目标中断返回该订阅的 `REMOTE_STREAM_INTERRUPTED`，本机及其他订阅继续工作；客户端延迟重试失败订阅。备份、防火墙执行及管理入口仅支持本机订阅。

Cookie 握手严格校验同源，会话和权限在连接期间持续复核；失效时返回 `UNAUTHENTICATED` 并关闭连接。每个服务最多 32 条实时连接，单个浏览器连接最多订阅 16 个服务器范围。服务端每 15 秒发送 Ping，45 秒内无响应则断开。

前端统一处理重连与消息分发。页面销毁、服务器切换、退出登录时释放对应订阅；最后一个订阅释放时关闭连接并清理重连定时器。关闭中的连接结束前不会创建下一条连接。断开后服务端取消所有观察和远程连接；后台状态比较任务仅在有订阅时运行，每个进程共用一份、每 2 秒比较已订阅状态。消息不包含配置、凭据或日志正文。
