# 实时状态与日志

浏览器通过同源 `GET /api/v1/events` 建立唯一 WebSocket，接收实时数据和操作进度。登录、保存、安装、软件清单、登录防护容器状态、手动日志查询及文件下载使用 HTTP。软件清单在进入页面、手动刷新或软件操作结束时读取，版本列表在打开版本选择时读取。

订阅按服务器连接分组，在连接中提交当前页面所需主题和资源；分页与筛选参数保留在资源地址中。页面关闭、服务器切换、退出登录时释放订阅，断线重连后重新发送当前订阅并同步完整数据。

```json
{"type":"subscribe","revision":1,"subscriptions":[{"connection":"","topics":["monitoring"],"resources":["/monitoring/latest","/monitoring/history?kind=cpu&id=total&value=usage_percent&window=3600"]}]}
```

服务端首次逐项发送订阅资源的数据，随后只推送内容变化的资源。每条消息统一采用单层 `code`、`message`、`data`；`data` 直接承载业务数据，不再嵌套 HTTP 响应。成功时 `message` 为空，失败时包含明确原因并额外携带 `status`，保留各页面现有错误处理。

```json
{"code":"OK","message":"","data":{"enabled":true,"stale":false,"sample":{"at":1793060000,"source":"host-agent","metrics":[{"kind":"cpu","id":"total","values":{"usage_percent":13.5}}]}},"resource":"/monitoring/latest","revision":1}
```

```json
{"code":"FORBIDDEN","message":"权限不足","data":null,"status":403,"resource":"/credentials","revision":1}
```

`resource` 用于匹配订阅；`revision` 是订阅序号，用于丢弃仍在传输的旧订阅消息。仅远端消息携带 `connection`；仅日志首次同步或恢复携带 `reset: true`。不再重复发送主题、请求 ID、节点 ID、成功状态码及内嵌响应包装。节点身份仍通过已有登录和远端握手校验确认，权限校验保持在服务端。

资源与主题由前后端共用的 `api/realtime-resources.json` 定义。服务端在进程内复用列出的读取接口及权限校验。需要重新同步时，在对应服务器的订阅项中设置 `refresh: true`。页面已读取某个主题的数据时，客户端优先使用这些资源更新状态。

| 主题 | 数据 | 权限 |
| --- | --- | --- |
| monitoring | 最新监控、趋势、监控设置 | read |
| tasks | 任务、软件操作、证书及其他相关状态 | read；各资源另行校验权限 |
| notifications | 通知状态、事件、投递记录 | read |
| backups | 备份记录与策略 | read、backup.export |
| firewall | 防火墙状态及已有准备任务的进度 | read、security.write |
| listener | 管理入口及确认结果 | read、system.write |
| version | 页面更新信息 | read |
| dns | DNS 状态与管理开关 | read |
| fail2ban | 登录防护配置 | read |
| nginx | 网站配置与 Nginx 运行状态，按订阅及操作同步 | read，各资源另行校验权限 |
| nodes | 服务器连接与连接申请状态 | read、nodes.manage |
| logs | 日志来源、策略和实时日志 | read；敏感日志另行校验权限 |

监控历史资源支持 `window=秒数`，最大 24 小时，由服务端滚动计算起止时间。防火墙准备查询使用 `/firewall/plan?input=JSON`，只允许读取已有 `preparation_id`；创建或取消准备仍使用操作接口。

实时日志通过 `/logs/live?query=JSON` 订阅，查询须为最近模式、无结束时间且不携带游标。服务端维护并释放游标，推送增量日志；`reset: true` 表示订阅首次同步或游标恢复，应替换已有日志。前端不再建立 EventSource 或额外实时连接。

远端资源通过现有证书校验、目标身份与单跳授权连接目标 `/events?topics=...&resources=...`，按同一精简格式转发资源数据。资源还需满足远端 HTTP 读取白名单，浏览器不接触远端凭据。远端中断只影响对应订阅，本机及其他连接继续工作。备份、防火墙执行及管理入口仅支持本机订阅。

Cookie 握手严格校验同源，会话与授权在连接期间持续复核。失效时发送 `UNAUTHENTICATED` 并关闭连接。每个服务最多 32 条实时连接；一个浏览器最多订阅 16 个服务器范围，每个范围最多 64 个资源、合计最多 128 个资源。命令最大 64 KiB，消息最大 8 MiB。服务端每 15 秒 Ping，45 秒内无响应断开。观察器仅在有订阅时运行，每 2 秒检查已订阅主题；监控仍按用户配置的采样间隔产生新样本，默认 15 秒。
