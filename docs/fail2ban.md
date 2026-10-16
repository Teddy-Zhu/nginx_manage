# Fail2ban 宿主机诊断

`GET /fail2ban` 返回 `Fail2banObservation`，要求 `read` 权限，沿用统一 JSON 外壳。显式远程资源 `/nodes/{connection}/fail2ban` 仅转发此读取；页面 `/fail2ban` 由 `src/pages` 自动扫描接入。模块默认停用且暂不可启用，诊断不依赖模块开关。

仅 root Agent 在本机以 `--metrics-scope=host` 确认宿主机范围后执行采集。开发、容器、范围未确认或无 Agent 时返回不可用原因，不在面板容器内探测或补装程序。`available` 仅表示宿主机诊断获准，`writable` 始终为 false；文件存在、受信路径、版本、服务活动、实例健康及 jail 保护分别表达，不相互替代。

## 固定读取边界

- 在 `/usr/bin`、`/usr/sbin`、`/bin`、`/sbin` 查找 `fail2ban-client`、`fail2ban-server`、`fail2ban-regex` 及诊断依赖。核对 root 保护的目录、usr-merge 链接、最终程序归属与权限，不使用调用方 PATH 或自定义程序路径。不存在和无法读取分别返回 false 和 null。
- 客户端只执行固定 `--version`，接受完整版本格式。读取 systemd 中固定的 `fail2ban.service`、`nginxpanel-fail2ban.service`、`fail2ban.socket` 的加载、活动、开机及主进程元数据；不能完整解析时保持未知，不用部分输出推断状态。
- 默认 `/run/fail2ban/fail2ban.sock` 仅核对文件类型、归属和权限，不连接。已有实例可能使用其他路径，默认路径不存在不证明未安装或未运行；文件存在也不证明健康。
- 系统 Python 限固定系统解释器路径，以 `-I -S -B` 执行内置只读探针，检查固定标准库导入与 SQLite 内存事务，不读取用户 site、第三方 Fail2ban 包或磁盘数据库。dpkg-query/rpm 仅查询解释器的软件包归属与版本，未知时不推测来源。标准库可用不等于满足所选签名组件的解释器约束及完整启动条件。

不执行安装、启动、重启、Socket 连接、jail 状态命令、配置加载、封禁或防火墙操作。官方客户端的 `--version` 在配置及连接前退出，依据 [Fail2ban 1.1.1 客户端参数处理](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2bancmdline.py)。[官方 1.1.1 发布说明](https://github.com/fail2ban/fail2ban/releases/tag/1.1.1)包含 systemd Socket 激活支持，因此未授权接入实例时不以连接 Socket 作为诊断。

## 资源与合同

Agent 同时只运行一份采集，最短采集间隔 30 秒，请求取消不另起进程；单次采集最多 6 秒，单命令最多 2 秒，进程组超时终止。标准输出按命令限制为 4 或 16 KiB，错误输出最多 4 KiB，超限拒绝完整性判断，不将原始输出回传页面。Web 进程同时最多 4 个读取请求、每次最多 8 秒。页面首次进入和手动刷新读取，不后台轮询；卸载取消请求。

公开 OpenAPI、Go/TypeScript 声明、显式远程资源与 Agent 协议同步更新；当前 Agent 协议为 36、数据库仍为 24，root 防火墙记录仍为 3。首版不提供旧协议兼容。

## 未交付边界

本次仅交付依赖及实例元数据诊断。已有实例显式接入、签名组件准备后的运行绑定、完整引擎自检、jail 与模板管理、受控 action、ban/unban、日志和 CDN 来源处理仍在完整实施范围内；当前不返回虚构的 jail 数量或保护成功状态。Fail2ban 不增加 Nginx 镜像运行时模块安装能力。

实现与集成源码审阅已完成，未运行生成器、构建、类型检查、lint、测试、浏览器、服务或真实宿主机探测命令；发行版、Python、systemd 与 Fail2ban 组合留待 P5 集中验证。
