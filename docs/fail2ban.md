# Fail2ban 宿主机诊断与已有实例只读接入

`GET /fail2ban` 返回 `Fail2banObservation`，要求 `read` 权限，沿用统一 JSON 外壳。显式远程资源仅转发登记的读取；页面 `/fail2ban` 由 `src/pages` 自动扫描接入。模块默认停用且控制入口暂不可启用，诊断和已授权实例的只读观察不改变模块开关或 jail 所有权。

仅 root Agent 在本机以 `--metrics-scope=host` 确认宿主机范围后执行采集。开发、容器、范围未确认或无 Agent 时返回不可用原因，不在面板容器内探测或补装程序。诊断的 `available` 仅表示宿主机读取获准；实例和 jail 的 `available` 表示该次完整采样成功，采样时间明确返回。所有 `writable` 及已有 jail 的 `managed` 均为 false。

## 未接入时的固定读取

- 在 `/usr/bin`、`/usr/sbin`、`/bin`、`/sbin` 查找 Fail2ban 工具及诊断依赖。核对 root 保护的目录、usr-merge 链接、最终程序归属与权限，不使用调用方 PATH 或自定义程序路径。不存在和无法读取分别返回 false 和 null。
- 客户端只执行固定 `--version`。读取固定 systemd 服务/Socket 单元元数据及默认 Socket 文件，不连接。默认路径不存在不证明未安装或未运行，文件存在也不证明健康。
- 系统 Python 限固定系统解释器路径，以 `-I -S -B` 执行内置探针，检查固定标准库及 SQLite 内存事务，不导入用户 site、第三方 Fail2ban 包或磁盘数据库。dpkg-query/rpm 仅查询解释器的软件包归属与版本，未知时不推测来源。标准库可用不等于满足签名组件的解释器约束及完整启动条件。

元数据诊断同时只运行一份采集，最短采集间隔 30 秒，单次最多 6 秒；页面首次进入和手动刷新读取，不后台轮询。官方客户端 `--version` 的早退出和配置读取边界依据 [Fail2ban 1.1.1 参数处理](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2bancmdline.py)。

## 已有实例授权

在宿主机以 root 执行，服务须已由原所有者正常运行；以下命令不由 API 代执行：

```sh
nginxpanel fail2ban-bind --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-service fail2ban.service --fail2ban-socket /run/fail2ban/fail2ban.sock
nginxpanel fail2ban-binding --data-dir /srv/nginxpanel --fail2ban-scope host
nginxpanel fail2ban-unbind --data-dir /srv/nginxpanel --fail2ban-scope host
```

接入固定规范 `/run` Socket、systemd 服务及受信系统客户端；初次接入须完整核对版本和 jail 列表。客户端路径、解析路径、文件 SHA-256 与版本进入 root 私有批准记录。重复接入同一有效实例返回原登记；程序升级或路径变化后须重新明确接入，不自动接受漂移。系统程序仍归原包管理器管理，不另起第二个实例。

记录位于 `DATA/agent/fail2ban/current.json` 和 `bindings/<UUID>.json`，目录 0700、文件 0600。每次批准或撤销先保存独立记录，再原子发布当前指针，保留前序 ID 和历史文件；中断不允许凭未发布记录连接。撤销不要求服务健康，不停止服务、解除封禁或删除旧记录。每个读取请求与采集收尾重查当前批准，旧缓存不能绕过撤销。此机器专属授权不进入可移植配置，不随导入自动接管目标实例。

## 实例与 jail 读取

`GET /fail2ban/instance` 返回 `Fail2banInstance`；`GET /fail2ban/jails/{name}` 返回 `Fail2banJail`。二者要求 `read`，各有同路径的显式远程资源。未登记时仅返回未接入状态，不连接。jail 只允许读取当前完整列表中的名称；页面提供列表、归属、失败/封禁计数及引擎记录的封禁地址，不提供未接管 jail 的控制按钮。

采集前后通过固定 `systemctl show` 核对服务主进程、运行状态及 InvocationID；通过有界 `/proc/net/unix` 和主进程文件描述符核对 Socket 监听归属及身份。Socket 及其目录须受 root 保护。服务停止、身份变化、客户端漂移、输出不完整或超限均返回不可用原因和空记录，不伪造零计数或部分成功。

服务 `TriggeredBy` 必须为空；有 Socket/其他激活依赖的实例需后续单独的启动授权流程，当前不以只读接入触发启动。依据 [systemd v252 单元依赖合同](https://github.com/systemd/systemd/blob/v252/man/org.freedesktop.systemd1.xml)及 [Fail2ban 1.1.1 Socket 激活说明](https://github.com/fail2ban/fail2ban/releases/tag/1.1.1)。服务状态只用于核对既有运行实例，不调用 start/restart/reload。

实际连接仅由官方客户端执行固定 `version`、`status` 或 `status <已核对名称>`。显式设置全部早期配置参数，使用批准 Socket、固定 `/dev/null` PID/系统日志占位及 STDERR/ERROR 日志选项，避免客户端读取系统配置或创建日志文件。严格解析官方状态格式，不使用 eval 或 Python pickle 解码。格式依据 [官方客户端状态格式](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/beautifier.py)；超出可识别格式保持未知，不使用宽松文本子集。引擎记录封禁不代表已核对 action 或当前流量路径的实际阻断效果。

实例与 jail 各缓存 30 秒，相同目标只运行一份在途采集，共用最多 2 个在途采集及每个 30 秒预算窗口最多 16 份新采集；缓存各最多 65 项。单次采集最多 6 秒，单命令最多 2 秒，进程组超时终止。版本输出最多 4 KiB、单元元数据 8 KiB、状态输出 128 KiB、错误输出 4 KiB；Unix Socket 表 2 MiB、进程描述符最多 512 项。完整 jail 列表最多 64 项，单 jail 封禁最多 1024 项，数值 IP/CIDR 解析并去重。Web 共用最多 4 个 Fail2ban 读取请求，实例/jail 请求最多 14 秒，适配 Agent 15 秒传输期限。请求取消不重复启动同一采集；页面卸载或切换 jail 取消读取。

## 当前边界

公开 OpenAPI、Go/TypeScript 声明和显式远程资源同步更新；当前 Agent 协议为 37、数据库仍为 24，root 防火墙记录仍为 3，Fail2ban 接入记录为 1。首版不提供旧协议兼容。

已有实例当前只读接入。安装/启动与 Socket 激活授权、签名组件运行绑定、完整引擎自检、jail 持久配置与接管、模板/匹配测试、受控 action、ban/unban、历史日志及 CDN 来源处理仍在完整实施范围内。面板和 Nginx 镜像不增加 Python/Fail2ban，不增加运行时 Nginx 模块安装能力。

实现与集成源码审阅已完成，未运行生成器、构建、类型检查、lint、测试、浏览器、服务或真实宿主机探测/接入命令；发行版、Python、systemd、Fail2ban 与日志后端组合留待 P5 集中验证。
