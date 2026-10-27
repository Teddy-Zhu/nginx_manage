# 实时状态与日志

浏览器通过同源 `GET /api/v1/events` 建立唯一 WebSocket。登录后，页面状态的首次读取和持续更新均通过此连接完成，不通过主题通知重新发送 HTTP 请求。登录、保存、安装等操作接口及手动日志查询、文件下载继续使用 HTTP。

订阅按服务器连接分组，在连接中提交当前页面所需主题和资源；分页与筛选参数保留在资源地址中。页面关闭、服务器切换、退出登录时释放订阅，断线重连后重新发送当前订阅并同步完整数据。

```json
{"type":"subscribe","revision":1,"subscriptions":[{"connection":"","topics":["monitoring"],"resources":["/monitoring/latest","/monitoring/history?kind=cpu&id=total&value=usage_percent&window=3600&points=180"]}]}
```

服务端首次发送完整快照，随后推送发生变化的主题对应资源。每个资源保留统一响应格式和状态码；前端先更新同一帧内的全部快照，再通知页面使用数据。监控数值及采样时间包含在 `/monitoring/latest` 的响应中。

```json
{"code":"OK","message":"状态已更新","data":{"connection":"","topics":["monitoring"],"revision":1,"values":{"/monitoring/latest":{"status":200,"response":{"code":"OK","message":"操作成功","data":{"enabled":true,"stale":false,"sample":{"at":1793060000,"source":"host-agent","metrics":[{"kind":"cpu","id":"total","values":{"usage_percent":13.5}}]}},"request_id":"...","node_id":"..."}}}},"request_id":"...","node_id":"..."}
```

资源与主题由前后端共用的 `api/realtime-resources.json` 定义。只允许列明的读取资源，服务端在进程内复用现有读取逻辑、参数校验、权限校验和错误响应。不会通过 HTTP 再次请求本机 API。`refresh: true` 可重新同步现有订阅；保存操作会触发状态同步。

| 主题 | 数据 | 权限 |
| --- | --- | --- |
| monitoring | 最新监控、趋势、监控设置 | read |
| tasks | 任务、软件操作、证书及其他相关状态 | read；各资源另行校验权限 |
| notifications | 通知状态、事件、投递记录 | read |
| maintenance | 维护状态 | read、system.write |
| backups | 备份记录与策略 | read、backup.export |
| firewall | 防火墙状态及已有准备任务的进度 | read、security.write |
| listener | 管理入口及确认结果 | read、system.write |
| version | 页面更新信息 | read |
| dns | DNS 状态与管理开关 | read |
| fail2ban | 登录防护状态 | read |
| nginx | 网站配置与 Nginx 运行状态 | read；各资源另行校验权限 |
| nodes | 服务器连接与连接申请状态 | read、nodes.manage |
| logs | 日志来源、策略和实时日志 | read；敏感日志另行校验权限 |

监控历史资源支持 `window=秒数`，最大 24 小时，由服务端滚动计算起止时间。防火墙准备查询使用 `/firewall/plan?input=JSON`，只允许读取已有 `preparation_id`；创建或取消准备仍使用操作接口。

实时日志通过 `/logs/live?query=JSON` 订阅，查询须为最近模式、无结束时间且不携带游标。服务端维护并释放游标，推送增量日志；`reset: true` 表示订阅首次同步或游标恢复，应替换已有日志。前端不再建立 EventSource 或额外实时连接。

远端资源通过现有证书校验、目标身份与单跳授权连接目标 `/events?topics=...&resources=...`，完整转发资源数据。资源还需满足远端 HTTP 读取白名单，浏览器不接触远端凭据。远端中断只影响对应订阅，本机及其他连接继续工作。备份、防火墙执行及管理入口仅支持本机订阅。

Cookie 握手严格校验同源，会话与授权在连接期间持续复核。失效时发送 `UNAUTHENTICATED` 并关闭连接。每个服务最多 32 条实时连接；一个浏览器最多订阅 16 个服务器范围，每个范围最多 64 个资源、合计最多 128 个资源。命令最大 64 KiB，消息最大 8 MiB。服务端每 15 秒 Ping，45 秒内无响应断开。观察器仅在有订阅时运行，每 2 秒检查已订阅主题；监控仍按用户配置的采样间隔产生新样本，默认 15 秒。
