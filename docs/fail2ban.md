# Fail2ban 配置、诊断与实例接入

`GET /fail2ban` 返回 `Fail2banObservation`，要求 `read` 权限，沿用统一 JSON 外壳。显式远程资源仅转发登记操作；页面 `/fail2ban` 由 `src/pages` 自动扫描接入。模块默认停用，可显式启用管理入口；启用不安装或启动引擎，不自动停止现有保护。诊断和已授权实例的只读观察不改变模块开关或 jail 所有权。

仅 root Agent 在本机以 `--metrics-scope=host` 确认宿主机范围后执行采集。开发、容器、范围未确认或无 Agent 时返回不可用原因，不在面板容器内探测或补装程序。诊断的 `available` 仅表示宿主机读取获准；实例和 jail 的 `available` 表示该次完整采样成功，采样时间明确返回。单 jail 诊断保持 `writable=false`；明确登记且可读取的本应用 jail 返回 `managed=true`，手动写入须另行核对当前目标基准。

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

## 已有 SSH jail 接管预检

本机 root 可预览一个正在原实例中运行的 SSH jail，明确期望参数及固定来源。此命令只完成预检，不发布接管授权、不写入系统配置、不 reload；首次接管、释放、参数应用及操作取消见下文，网页/API 修改入口继续实施。

将以下 JSON 保存为 root 所有且不可被组或其他用户写入的 `/root/sshd-takeover.json`；端口须按升序明确列出，日志来源可选 `auth-log`、`secure-log` 或 `systemd`：

```json
{
  "profile": {
    "name": "sshd",
    "profile": "sshd-nftables-input",
    "log_source": "auth-log",
    "ports": [22]
  },
  "policy": {
    "enabled": true,
    "ban_time": 600,
    "find_time": 600,
    "max_retry": 5,
    "ignore_ips": ["127.0.0.0/8", "::1"]
  }
}
```

```sh
nginxpanel fail2ban-existing-jail-plan --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-existing-jail-file /root/sshd-takeover.json
```

当前只接纳已显式接入的官方 1.1.1 系统实例、固定 `/etc/fail2ban`、原版 `sshd/common` 过滤器与 `nftables/nftables-multiport` 动作数据，逐文件核对内置 SHA-256，不下载组件。SSH 使用 normal 模式、TCP 指定端口和 `usedns=no`；文件来源固定 `/var/log/auth.log` 或 `/var/log/secure`，后端限 auto/polling；journal 来源要求 systemd 后端。其他动作、自定义 Python action、可执行 ignorecommand、递增/随机时长及无法识别的参数明确拒绝，不自动改写为固定配置。

预检读取完整受 root 保护的配置树（最多 1024 项、总计 8 MiB、单文件 256 KiB，拒绝链接及特殊文件），同时核对所有文件和目录在宿主机与实际服务进程根目录中的身份，拒绝不同挂载或 chroot 视图。在私有临时目录生成参考和候选配置，通过官方客户端 `-d` 获取配置流，使用有界字面量解析器读取，不执行 Python 表达式。比较原 jail 与固定 profile 的关键配置，再比较原配置与候选的全部非调整参数，并核对目标参数没有被其他配置覆盖。候选覆盖路径为 `jail.d/zzzz-nginxpanel-existing-<name>.local`，同名文件存在时拒绝覆盖。

成功结果包含原参数、期望参数、完整 jail 名单、影响说明、目标摘要、实际过滤器/动作的 `native_proof` 及独立的 `ban_proof` 观察摘要。原生观察涵盖展开后的匹配表达式、实际日志来源及固定 CommandAction 属性，首次交接时重新核对。目标固定接入、单元、配置和服务代次；正常新增/到期的封禁不使配置接管基准失效。采集收尾复核配置、参数、完整名单、程序及实例身份。临时材料清理失败也报告失败。预检不证明内核实际阻断或授权接管；封禁日历时间的绝对换算使用下述独立运行证明，不重放历史封禁。网页/API 的已有 jail 修改仍未开放，迁移不能授予本机所有权。

配置流与单 jail reload 合同依据 [官方客户端](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2banclient.py)、[参数与 dump 输出](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2bancmdline.py)及 [action 配置转换](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/actionreader.py)。官方实例和发行版组合验收留待 P5。

## 已有 SSH jail 的本机所有权交接

首次接管要求文件中的 policy 与预检 `before` 完全一致，保持原 jail 启用。将原参数写入上述 JSON 后重新预检，再使用该次 `target` 明确授权。接管生成 root 所有、0600 的独立覆盖文件，核对真实配置流、原参数、动作、完整 jail 名单与实例身份后才发布所有权；不修改发行版配置或完整 `jail.local`。本阶段不发送 reload、stop、ban/unban，不以接管成功表示内核保护已验证。

```sh
nginxpanel fail2ban-existing-jail-adopt --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <NEW_UUID> --fail2ban-existing-jail-target <PREVIEW_TARGET> \
  --fail2ban-existing-jail-file /root/sshd-takeover.json
nginxpanel fail2ban-existing-jail-status --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <ORIGINAL_UUID>
nginxpanel fail2ban-existing-jail-release --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <NEW_UUID> --fail2ban-existing-jail-base <ADOPTION_UUID>
nginxpanel fail2ban-existing-jail-cancel --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <UNFINISHED_UUID>
```

操作 UUID 固定请求；同一请求重试沿用原快照与操作，不重新授予所有权。原配置快照先保存，再保存 journal，最后写系统覆盖文件及发布不可变所有权事件和当前指针。Agent 的独立 jail worker 在重启后继续原操作，维护排空期间可收尾；未完成记录阻止新的共享写入。实例代次、配置或文件漂移无法证明时保留 `recovery_required`，不覆盖外部变化。尚未发布的操作可由本机 root 显式取消；取消意图先落盘，只撤回本次等价文件变化。所有权已经发布时只能通过独立释放操作交还，不能回写原操作结果。

释放只移除本应用生成且内容一致的覆盖文件，核对原配置等价后发布独立释放事件；不会改写其他 jail。期间其他 jail 的配置变化可通过当前配置流与移除候选重新证明，不要求按接管的逆序释放。服务离线时，若全部配置仍与冻结快照一致，可仅凭已证明的等价配置交还所有权。仍存在接管的 jail 时，禁止变更/撤销实例接入；原样重复接入保留原身份。

快照、事件和指针位于 `DATA/agent/fail2ban/existing-jails/{captures,events,current}`，均为 root 私有运行材料，不进入配置迁移或业务恢复。单快照最多 16 MiB，接管快照及事件各最多 2048 项，名称指针最多 64 项，历史保留用于审计。当前公开读取及写入入口仍沿用既有边界，已有 jail 的网页/API 参数、启停和手动地址操作尚待接入；该本机交接不会自动赋予这些入口写权限。

## 已接管 SSH jail 的运行证明

本机 root 可读取当前有效接管的参数、实际过滤器/动作摘要、完整 jail 名单及封禁的绝对到期时间：

```sh
nginxpanel fail2ban-existing-jail-runtime --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-existing-jail-base <ADOPTION_UUID>
```

此入口只读，整体预算 90 秒，复用宿主机/实例锁及维护准入。目标必须仍由原接管授权管理，固定单元、当前已确认配置流/参数及实际过滤器/动作须一致；允许服务正常重启后核对当前实例。采集前后复核配置及进程根目录视图、服务身份、程序、实际参数、完整名单和时区材料。运行 `target` 绑定当前 `policy_id`、完整名单、配置与时钟依据，不包含会正常变化的封禁集合；返回的 `bans` 是采样时的引擎记录，不证明内核阻断。已停用时核对完整名单中目标不存在，不返回运行过滤器或时钟证明。

通过实际服务进程的初始 `TZ/TZDIR`、精确 UTC 启动时间及 root 保护的 TZif 文件识别时区，只支持固定 `/etc/localtime` 或 `/usr/share/zoneinfo` 数据；材料或系统程序/库在启动后变化、非标准目录、POSIX 时区表达式、夏令时重复/不存在的日历时间均拒绝换算。有限封禁须起止时间与时长一致，永久封禁保留 `duration=-1`。再使用实际固定系统 Python 的隔离进程按相同环境回算日历标签，核对可执行程序与库的映射设备、inode、进程根目录视图及启动前文件时间；结果不一致或读取不完整时返回失败，不默认按 UTC 处理。时钟证明、时区文件或原封禁不会进入迁移授权。

受管 jail 的实际表达式核对同样使用已认证官方库展开固定 `<HOST>` 模板，再与引擎返回值比较。依据 [官方过滤器 getter](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/filter.py)、[官方表达式展开](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/failregex.py)及 [systemd 时间格式](https://github.com/systemd/systemd/blob/v252/man/systemctl.xml)。本入口只读，应用参数使用下述独立操作；官方工具、时区及发行版运行验收仍待 P5。

## 已接管 SSH jail 的参数应用与停用

本机 root 可复用原 profile/policy JSON 修改 `enabled/ban_time/find_time/max_retry/ignore_ips`；profile、来源和端口必须保持原接管值。每次先计划，再引用计划摘要和新的操作 UUID 应用：

```sh
nginxpanel fail2ban-existing-jail-policy-plan --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-existing-jail-base <ADOPTION_UUID> --fail2ban-existing-jail-file /root/sshd-policy.json
nginxpanel fail2ban-existing-jail-policy-apply --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-existing-jail-base <ADOPTION_UUID> --fail2ban-existing-jail-file /root/sshd-policy.json \
  --fail2ban-operation <NEW_UUID> --fail2ban-existing-jail-target <POLICY_TARGET>
nginxpanel fail2ban-existing-jail-policy-status --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <ORIGINAL_UUID>
nginxpanel fail2ban-existing-jail-policy-cancel --data-dir /srv/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <UNFINISHED_UUID>
```

从启用改为停用时，应用命令须额外提供 `--fail2ban-confirm-jail-stop`。计划绑定采样封禁集合及数量，发送前集合变化则不停止，须取消并重新确认。停用将结束该 SSH jail 的现有保护；修改停用中的参数或重新启用也必须重新计划。普通调整不接受此停用确认，避免意图混淆。未发送计划五分钟后过期；已提交操作续办始终沿用原 UUID、文件与摘要。

预检核对当前已确认选择、实际参数及完整配置，并在私有目录比较候选、原 profile 和全部非调整参数。停用时也强制编译其启用副本，防止空配置流掩盖后端、过滤器或动作变化。`maxmatches` 须保持独立原值，或继续按原配置随 `maxretry` 派生；运行值须与对应配置一致。

执行只原子替换本应用的覆盖文件，先保存完整快照和 journal，再持久记录发送意图及当前封禁。通过实际系统 Python 的隔离入口调用原官方客户端，固定只读 root 私有候选并执行 `reload --if-exists <name>`，不加 `--all/--restart/--unban`。预检和执行均限制官方解析器的 include 读取范围，超出冻结候选目录即拒绝；不依赖源机器的绝对 include。官方客户端单 jail 配置流仍包含全局设置，因此入口将选取固定在原 jail，移除已知全局日志/数据库设置，遇到其他 jail 或未知命令即拒绝；不改变全局服务参数。配置流与 reload 行为依据 [官方配置组装](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/configurator.py)、[官方 reload 客户端](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2banclient.py)及 [官方服务分发](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/transmitter.py)。

收到完成回包后重新核对候选、实际参数、过滤器/动作及完整名单；继续启用时，原未到期封禁必须保留相同的时长及绝对到期时间。只在这些证明完整后发布不可变参数事件和当前选择。回包丢失或提交后中断不重发，也不抢先回写原文件；原服务进程尚可能执行时保留 `recovery_required`。原 boot/PID/启动身份已证明结束后，可以观察新实例是否满足原候选；不能核对则保留现场，不自动重放封禁。

未发送操作可取消，仅恢复本应用的覆盖文件。已发送请求只有原进程退出、原运行参数/名单和未到期封禁均重新证明后，才允许取消并撤回候选；已发布或已生效的候选须查询续办结果，再通过新计划恢复参数。解除接管前必须先以独立参数操作恢复首次接管的参数及启用状态。私有材料位于 `existing-jails/policy-{captures,events,current,configs}`；单配置树最多 8 MiB、单捕获最多 16 MiB，历史受 2048 项上限及共享 journal 配额约束，均不迁移。网页/API 修改入口继续实施，尚未运行官方工具或真实应用，待 P5 集中验收。

## 实例与 jail 读取

`GET /fail2ban/instance` 返回 `Fail2banInstance`；`GET /fail2ban/jails/{name}` 返回 `Fail2banJail`。二者要求 `read`，各有同路径的显式远程资源。未登记时仅返回未接入状态，不连接。jail 只允许读取当前完整列表中的名称；页面提供列表、归属、失败/封禁计数及引擎记录的封禁地址，不提供未接管 jail 的控制按钮。

采集前后通过固定 `systemctl show` 核对服务主进程、运行状态及 InvocationID；通过有界 `/proc/net/unix` 和主进程文件描述符核对 Socket 监听归属及身份。Socket 及其目录须受 root 保护。服务停止、身份变化、客户端漂移、输出不完整或超限均返回不可用原因和空记录，不伪造零计数或部分成功。

服务 `TriggeredBy` 必须为空；有 Socket/其他激活依赖的实例需后续单独的启动授权流程，当前不以只读接入触发启动。依据 [systemd v252 单元依赖合同](https://github.com/systemd/systemd/blob/v252/man/org.freedesktop.systemd1.xml)及 [Fail2ban 1.1.1 Socket 激活说明](https://github.com/fail2ban/fail2ban/releases/tag/1.1.1)。服务状态只用于核对既有运行实例，不调用 start/restart/reload。

实际连接仅由官方客户端执行固定 `version`、`status` 或 `status <已核对名称>`。显式设置全部早期配置参数，使用批准 Socket、固定 `/dev/null` PID/系统日志占位及 STDERR/ERROR 日志选项，避免客户端读取系统配置或创建日志文件。严格解析官方状态格式，不使用 eval 或 Python pickle 解码。格式依据 [官方客户端状态格式](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/beautifier.py)；超出可识别格式保持未知，不使用宽松文本子集。引擎记录封禁不代表已核对 action 或当前流量路径的实际阻断效果。

实例与 jail 各缓存 30 秒，相同目标只运行一份在途采集，共用最多 2 个在途采集及每个 30 秒预算窗口最多 16 份新采集；缓存各最多 65 项。单次采集最多 10 秒，单命令最多 2 秒，进程组超时终止。版本输出最多 4 KiB、单元元数据 8 KiB、状态输出 128 KiB、错误输出 4 KiB；Unix Socket 表 2 MiB、进程描述符最多 512 项。完整 jail 列表最多 64 项，单 jail 封禁最多 1024 项，数值 IP/CIDR 解析并去重。Web 共用最多 4 个 Fail2ban 读取请求，实例/jail 请求最多 14 秒，适配 Agent 15 秒传输期限。请求取消不重复启动同一采集；页面卸载或切换 jail 取消读取。

## 当前边界

公开 OpenAPI、Go/TypeScript 声明和显式远程资源同步更新；当前 Agent 协议为 59、数据库为 26，root 防火墙记录仍为 3，Fail2ban 接入记录为 1。首版不提供旧协议兼容。

已有实例默认只读，可由本机 root 另行授予全局服务控制，或接管固定 SSH jail 并执行上述参数应用/停用。独立受管实例的安装/服务控制、Nginx 客户端 jail 应用和手动 ban/unban 见下文；已有 jail 网页/API 修改接入、Docker 转发动作及 CDN 来源处理仍待完成。面板和 Nginx 镜像不增加 Python/Fail2ban，不增加运行时 Nginx 模块安装能力。

实现与集成源码审阅已完成，未运行生成器、构建、类型检查、lint、测试、浏览器、服务或真实宿主机探测/接入命令；发行版、Python、systemd、Fail2ban 与日志后端组合留待 P5 集中验证。

## jail 期望配置与迁移

`GET/PUT /fail2ban/policy` 持久保存最多 32 个 jail，采用加密存储、基础版本比较、幂等保存及同事务审计。保存不要求模块启用，也不改变实例。内置 `nginx-http-401`（全部 401，包含首次认证挑战）及 `nginx-authorization-401`（仅携带 Authorization 后的 401，不覆盖仅凭 Cookie 的认证失败），参数为日志资源标识、动作类型、封禁秒数、统计窗口、阈值和数值 IP/CIDR 白名单；不接收任意路径、正则或 shell。另有 `panel-login-failure`，绑定固定面板日志来源，`resource_id` 须为空、动作须为 host-input；应用须本机批准受管宿主机来源并开启持续会话，详见下文。

`GET /fail2ban/templates` 返回模板；`POST /fail2ban/preview` 核对保存版本、唯一运行日志来源、固定模板、受管实例及对应动作准入，返回当前可应用性及将停用项。日志资源按站点逻辑 ID 绑定，实例授权、动作后端及实际流量路径在应用前重新核对。网页可保存、预览和确认应用 Nginx 客户端 jail 或面板登录宿主机 jail；前者要求已发布客户端拒绝入口，后者核对独立日志、过滤器、宿主机批准与持续会话，无需 Nginx 站点。手动 ban/unban 见下文。

schema 6 加密迁移包可选择 `selection.fail2ban`，以固定 `config/fail2ban.json` 携带期望配置。文件、API 拉取及推送均支持 preserve/merge/replace，默认保留目标；导入重新分配 jail ID，沿用同一业务配置树中的站点标识，冻结目标版本与内容，同 Nginx 配置导入事务保存。失败补偿以新版本恢复原期望，检测外部变更时保留待恢复，不覆盖。源服务、Socket、客户端批准、所有权及封禁/计数不迁移，也不自动安装、启用模块或应用 jail。须核对目标白名单、日志来源和动作路径；保留的目标 jail 可能引用本次已替换的站点。

当前数据库为 26，Agent 为 55。实现及源码集成审阅完成，生成器、构建、类型检查、lint、测试、浏览器及真实实例操作均留待 P5。

## 固定过滤器及官方样例检查

模板同时提供固定 filter 内容的 SHA-256、固定样例及其 SHA-256。过滤器按受管 JSON 字段边界读取数值客户端地址，避免 URI 中伪造地址或状态；仅单行匹配，关闭 DNS。时间戳按 ISO 8601 提取，WAF 附加字段使用同一 JSON 字符串语法。HTTP 日志字段顺序由渲染器和过滤器共同引用，不能由请求内容插入新的字段。

`POST /fail2ban/templates/check` 接受 1–3 个内置 ID，返回检查时间、工具版本/散列、预期与实际地址及明确的通过/未知原因。root Agent 使用固定系统目录或已批准签名组件的官方 `fail2ban-regex 1.1.1`，在 root 私有临时目录写入本程序固定 filter 和对应样例，使用空配置目录、数值地址模式及 UTF-8；不读取现有 jail 配置，不连接 Socket，不接收用户正则、日志路径、命令或任意文本。命令每次最多 2 秒，输出有界，整批最多 10 秒、同目标单份在途、30 秒缓存并有并发/次数预算。版本漂移、超时、未知输出、清理失败或任一检查中断均不返回部分通过；采样结果不表示动作已经适用于流量路径。

受管 Nginx 访问日志新增 `nginxpanel_auth_present`，只记录入站 Authorization 是否非空（0/1），不记录认证头内容。执行器生成 map，原生配置禁止重定义该变量；迁移/恢复预检包含 map 模块，Docker 镜像已预置此能力。日志目录声明 `auth_presence`，jail 保存预览要求来源包含该标记，同时执行固定过滤器检查；须先发布当前 Nginx 配置，再核对实际来源。旧运行日志或缺少标记的来源不据格式名推断可匹配。模块开关不控制日志中的保护状态。

实现及源码集成审阅完成，尚未执行官方工具、生成器、构建、类型检查、lint、测试、浏览器或真实配置发布。P5 需集中核对 Python 正则/日期解析、IPv4/IPv6、首次挑战、转义与字段伪造、实际日志样例及轮转衔接；当前不是已通过验证的模板发布声明。固定 CLI/输出行为依据 [Fail2ban 1.1.1 fail2ban-regex](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2banregex.py) 及[日期剥离实现](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/filter.py)。本机及网页/API 受管 jail 应用见下文，手动封禁控制仍在实施。

## 签名受管引擎的本机安装

无已有 Fail2ban 时，本机 root 可选择准备好的单个 `fail2ban` 签名代码资产（当前固定 1.1.1）。资产须包含 `bin/fail2ban-{server,client,regex}` 及对应官方模块，根目录直接包含 `fail2ban/`；签名运行文件须覆盖实际系统 Python。安装器不执行 pip、不带入独立 Python、不安装软件包，也不改写全局 site-packages。固定解释器以 `-I -S -B` 运行，只添加已认证资产目录；先核对标准库/SQLite，再检查完整官方 server/client 入口、版本及独立配置。

示例中的 UUID、准备计划和资产标识须来自本机实际操作与组件准备结果：

```sh
nginxpanel fail2ban-install --data-dir /var/lib/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <UUID> --release-plan <PLAN_SHA256> --release-select <ASSET_ID> \
  --release-trust /etc/nginxpanel/release-trust.json
```

默认仅安装，不启动、不设置开机启用。首次安装可显式添加 `--fail2ban-start`、`--fail2ban-enable`；发生中断后，使用同一 UUID、源选择及启动/启用选择添加 `--fail2ban-resume`。目标已有固定系统工具、已登记实例、服务、默认 Socket 或无法排除已有实例时，拒绝另建。拒绝覆盖未登记目标、变化的文件、systemd drop-in 或未知实际单元。操作由共同 root 锁串行化，安装意图先持久化再创建文件；文件通过无覆盖原子发布。

安装事件位于 `DATA/agent/fail2ban/managed/history/`，`current.json` 只指向已持久事件。配置及 SQLite 分别位于该目录的操作 UUID 子目录内 `config/`、`state/`；专用服务为 `nginxpanel-fail2ban.service`，Socket/PID 位于 root 私有 `/run/nginxpanel-fail2ban/`。初始无启用 jail，不加载发行版的 jail/filter/action，配置目录出现额外入口会阻塞启动。专用服务的启动前检查重新认证签名代码、系统运行文件、固定解释器与管理程序、精确配置和服务单元；不能用安装时的标准库探测替代每次启动校验。

本机 root 后续可使用以下命令，均需相同 `--data-dir` 和 `--fail2ban-scope host`：

- `fail2ban-managed`：读取安装登记，实际服务状态另行诊断。
- `fail2ban-managed-check`：只读核对完整准入条件及官方配置校验；也是 systemd 的启动前入口。
- `fail2ban-managed-start` / `fail2ban-managed-stop`：只启停独立服务；启动结果核对 root 服务主进程持有的 Socket、同一实例代次、服务端版本及精确登记的 jail 集合（初始为空）。
- `fail2ban-managed-enable` / `fail2ban-managed-disable`：只改变独立服务的开机启用。
- `fail2ban-managed-rollback`：续办撤回独立服务；保留签名资产、私有配置、SQLite 和完整审计，不删除用户已有实例或其数据。

所有程序调用固定、无 Shell，进程组与输出有界；超时或取消不伪造操作成功，安装留为 interrupted，普通服务操作记录待核对结果。撤回中断可重复执行，变更材料不匹配时保留现场供本机处理。管理程序与系统 Python 的文件身份固定，升级后需重新处理准入，不静默跟随新程序。模块开关不控制这些 root 操作，面板展示安装登记、已授权实例及过滤器检查来源；公开安装/服务变更、jail 应用及手动封禁继续接入。

实现与源码集成审阅完成，生成器、构建、类型检查、lint、测试、浏览器、实际组件安装与 systemd 操作未执行，留待 P5。届时需核对两种架构/发行版的签名资产布局、标准库与运行文件约束、前台启动/Socket 归属、无 jail 启动、配置隔离、服务中断/续办/撤回和重启恢复。官方入口与参数依据 [Fail2ban 1.1.1 server](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2banserver.py)、[CLI 配置参数](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2bancmdline.py)。

## 受管实例及过滤器的只读接入

installed 状态的 root 安装登记授权对其专用服务、Socket 和固定官方代码执行只读观察。`GET /fail2ban/instance`、`GET /fail2ban/jails/{name}` 自动选择该登记；无受管安装或已撤回时，已有实例仍只依据 `fail2ban-bind` 的明确接入记录读取。安装未结束、撤回中、登记损坏或两类授权冲突时返回不可用，不改用其他实例。新建已有实例接入会拒绝尚未撤回的受管安装；`fail2ban-binding` / `fail2ban-unbind` 继续只查询/撤销已有实例的独立读取登记，不撤销受管安装本身。

`binding.engine` 和 `Fail2banTemplateCheck.engine` 返回代码来源：`owner` 为 existing/managed/none/unavailable，受管来源同时包括安装 UUID、准备计划、资产、清单摘要及实际 Python 路径/摘要。该对象不声明 jail 所有权。受管实例的读取授权 ID 使用当前安装事件 ID，安装/服务操作产生新事件后，原在途与缓存选择失效；读取不覆盖 root 安装记录，不把它转换成已有实例的接入文件。

每次实际采集前后重新认证签名代码、系统运行文件、解释器及固定配置。只读客户端与过滤器通过隔离的系统 Python 加载相应官方模块，不依赖固定系统目录中另装一套 Fail2ban。客户端仅接收现有固定的 version/status 读取参数；过滤器仍只接受内置 ID、固定 filter/样例和空私有配置目录，不连接运行实例。受管 `fail2ban-regex` 使用官方模块的无参数 `exec_command_line()` 入口，client 使用其 argv 入口。

受管服务采集还核对 systemd 的实际单元/覆盖项/加载版本、主进程所持监听 Socket、实际解释器文件 inode 及完整前台入口参数，前后核对服务代次。签名包及解释器验证纳入最多 10 秒的共享采集任务；仍限制 2 份在途、30 秒窗口 16 份新任务与有界输出，官方工具每次最多 2 秒。30 秒缓存命中返回原采样时间的结果，不作为新的执行校验证据；登记事件变化或撤回时不返回旧选择的成功结果。

保存预览仅在运行实例可确认、版本为当前支持的 1.1.1，且过滤器结果与实例的 `engine` 一致时将 `template_ready` 标为 true。来源不同、版本不同或实例读取错误会阻塞对应 jail；样例检查的原始结果仍保留供核对。网页提供独立的整份策略应用入口，`can_apply` 按模块、目标运行基准及启用项检查结果计算；单 jail 读取接口的 `writable=false`。`managed=true` 仅用于本机受管配置包明确登记且实际可读取的 jail，不根据实例代码来源或名称单独推断所有权和保护状态。

接口合同及自动扫描页面已同步；Agent 为 40、数据库为 25。实现及源码集成审阅完成，生成器、构建、类型检查、lint、测试、浏览器、官方工具和真实实例操作均未执行，留待 P5。需集中核对托管与已有实例的选择/冲突/撤回、事件变化及缓存、实际进程入口与 Socket、签名/解释器漂移、官方模块入口及同源同版本预览等行为。

## Nginx 客户端拒绝入口

HTTP 站点元信息支持 `client_deny=true`，可在 Nginx 配置页声明该入口。需要在站点明确设置可信代理 IP/CIDR、`real_ip_recursive on` 和 `X-Forwarded-For`、`X-Real-IP` 或 `CF-Connecting-IP` 请求头；不接受信任所有来源、主机名代理或下级位置覆盖真实 IP 配置。最多 32 个站点，每个最多 64 个可信代理网段。Stream 和 WAF 策略不能声明此入口。

发布器在站点插入固定作用域和 403 判断，将真实客户端 IP 与站点标识共同匹配。可信代理网段同时生成到不可变修订的保护表，防止修改代理配置后将历史客户端封禁作用到代理地址。实际集合位于 `nginx/client-deny/sets.conf`，独立于业务修订；配置发布、回滚及逻辑迁移只引用目标自身的集合，不复制或重建源封禁。原文禁止引用或重定义保留运行变量，编辑与迁移不能覆盖生成文件。

集合只接受版本化类型数据及确定格式，根目录和文件均由 root 持有，专用 Nginx 组只读。当前格式最多 32 个站点、每站点 1024 个、合计 4096 个地址，文件最多 1 MiB；只接受规范 IP，禁止回环、未指定、组播、网段、任意指令和路径。生成状态与映射同一文件原子初始化，集合代次进入独立运行探针；运行观测必须同时核对业务修订和集合代次，不能只凭 HUP 发送成功认定生效。外部检查和恢复也核对生成内容。

入口初始化空集合，声明本身不表示已启用防护。所需 real_ip、map/volatile 和 geo 能力由目标预检确认，Docker 使用预置模块镜像，不在运行时编译或新增模块。

## 本机 root 的 Nginx 动作授权与执行

宿主机 Agent 在明确 `--metrics-scope=host` 且已配置专用 Nginx 时提供独立的 root 动作桥。Socket 固定为 `agent/fail2ban/nginx/action.sock`，目录 0700、Socket 0600，并以 SO_PEERCRED 只接受 UID 0；Web Socket 不接受这些写入。所有请求和响应沿用 Agent 的 `protocol/code/message/data` 外壳。

本机命令均要求 `--data-dir` 和 `--fail2ban-scope=host`：

- `fail2ban-nginx-status`：读取授权登记、排队状态、采集与确认时间、已确认集合代次、保护地址数、未激活绑定数及失败原因。
- `fail2ban-nginx-bind`：指定 `--fail2ban-operation` 新 UUID、`--fail2ban-nginx-base` 当前登记 UUID（首次为空）、`--fail2ban-jail` 和 `--nginx-resource`。仅允许实际可读取的官方 1.1.1 jail 绑定到当前已发布的客户端拒绝入口。已有实例的接入 UUID 与程序身份被冻结；受管实例冻结安装、资产、清单与 Python 身份，正常服务控制不要求重复批准。
- `fail2ban-nginx-unbind`：指定新操作 UUID、当前登记 UUID 和 jail 撤销动作授权。撤销仅移除本应用的 Nginx 作用域，不将其报告为 Fail2ban 官方解封。
- `fail2ban-nginx-refresh`：只排队一次完整刷新，不接受 IP、网段或任意命令。已有 jail 的 root 所有者可在动作中调用此固定桥；回包的 `queued` 表示排队，不能作为封禁已经生效的证明。

每次授权/撤销保留不可变事件后原子切换指针，以当前登记 UUID 做 CAS；最多 32 个 jail、2048 个授权事件，容量耗尽须本机维护。多个 jail 可绑定同一站点，其封禁按站点取并集，解除一个 jail 的封禁不会移除其他 jail 仍持有的地址。未在当前发布中启用入口的绑定单独计数并停止作用，不从原文或日志名称推断授权。

后台独立于 Web 运行，启动时收集当前官方封禁，周期对账间隔 30 秒，动作合并最短间隔 5 秒。一次收集最长 20 秒、最多 4 个并发官方客户端，单命令沿用 2 秒预算；采集前后及提交前核对客户端、服务、Socket 与授权身份，不返回部分成功。拒绝不支持的网段封禁；回环、未指定、组播地址及站点可信代理受到保护并计数，不进入集合。仅根据官方当前封禁收集，不从历史快照重建封禁或自行延长有效期。

集合更新与配置发布、HTTP-01、恢复和维护互斥。更新前确认当前业务修订及集合代次，保存有界的 before/after 恢复快照，再原子替换、`nginx -t`、必要的 reload 和运行代次核对；相同集合及来源不重复写盘或 reload。高频刷新复用一个独立 root journal 槽位，双快照记录最多 512 KiB，避免耗尽普通操作记录。失败或 Agent 中断先恢复冻结的原集合，验证、reload 并确认原代次后才允许下一批官方收集；遇到外部变化不覆盖，保留 `recovery_required` 并阻止新的 Nginx 写入。状态只有在运行核对成功后才为 `confirmed`；失败不报告有效封禁。

独立 bind/unbind/refresh 不安装或修改 jail、过滤器或现有服务；受管 jail 的动作授权须随下述完整配置包应用，不能单独转移或撤销。管理员完成专用服务的停止或撤回后，只有不可变停用记录、安装身份及实际停止状态均确认，才允许清空该实例对应的 Nginx 集合；异常离线或查询失败保留集合并报告错误。提交集合前持有共同安装锁并重新核对来源。

## 本机受管 jail 配置应用

宿主机 root 可通过独立 jail Socket，向已安装且运行中的独立受管 Fail2ban 1.1.1 提交完整类型化策略。已有实例保持只读。内置 HTTP 401 模板使用 `nginx-client` 动作，须引用当前已发布的唯一受管 HTTP 日志和客户端拒绝入口；面板登录模板使用已批准的宿主机入口和固定 root 登录日志，无需 Nginx。可信代理、管理及本地保护来源按动作加入忽略集合。自定义过滤器、命令或日志路径不接受。

```sh
nginxpanel fail2ban-jails-status --data-dir /var/lib/nginxpanel --fail2ban-scope host
nginxpanel fail2ban-jails-apply --data-dir /var/lib/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <NEW_UUID> --fail2ban-jails-base <SELECTED_ID> \
  --fail2ban-policy-file /root/jails.json
nginxpanel fail2ban-jails-status --data-dir /var/lib/nginxpanel --fail2ban-scope host \
  --fail2ban-operation <NEW_UUID>
```

首次应用省略 `--fail2ban-nginx-base`，后续必须为状态返回的 `selected_id`；CLI 首次提交还会固定状态返回的目标摘要，重试同 UUID 先核对原请求；策略文件是未包裹的 `{"jails":[...]}`，字段与期望策略一致，不是 `PolicyView` 或迁移归档。操作 UUID 与规范化请求绑定，重复提交只返回原操作。普通 status 返回所选配置及待完成操作，不作为运行生效证明；应用提交先返回排队状态，查询操作的 `succeeded/jails_confirmed` 才表示本次 jail 参数核对完成，Nginx 拒绝集合仍有独立确认状态。

执行先冻结安装、服务代次、Nginx 修订与动作授权，持久化配置包和恢复意图；固定过滤器样例及官方候选配置检查通过后，以原子目录交换安装精确的 jail/filter/action 树，使用官方 `reload --all`。固定 action 仅排队刷新，不携带 IP，也不在 Fail2ban 动作内同步查询自己。执行后读取实际 jail、日志、正则、参数、忽略集合及动作命令，并核对原未过期封禁的到期时间。服务使用 UTC；程序不重放缓存封禁、不自行延长到期时间。命令及 reload 语义依据 [官方客户端](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2banclient.py)，封禁时间读取依据 [BanManager](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/banmanager.py)。

失败或重启先恢复原配置与动作授权，核对官方状态库恢复出的原未过期封禁；外部文件、授权或运行状态无法核对时保留 `recovery_required`，阻止新的 Nginx/jail 写入。尚未切换的中断只结束原操作，不擅自重启服务。应用及恢复与安装/服务控制共用 root 锁；未完成操作阻止独立启停、启用/禁用和撤回，并能在维护排空期间继续完成。jail 逻辑 UUID 的站点、模板与动作永久固定，退役后不能复用为其他来源，避免状态库中的旧封禁转移。

配置包及备份树位于安装 UUID 下的 `jail-bundles/`、`jail-configs/`，`jail-current.json` 指向所选包，`jail-identities/` 保留身份约束；以上均为 root 私有、禁止迁移的运行材料。单策略最多 32 项、64 KiB，配置包最多 256 KiB；原封禁时间证明独立存储，最多 4 MiB、每 jail 1024 个地址，journal 仅保存其摘要。

当前 Agent 为 44，策略为 nginxpanel-8，数据库为 26、迁移 schema 为 4。实现及源码集成审阅完成；生成器、构建、类型检查、lint、测试、浏览器、官方实例及真实 Nginx 验收均未执行，统一留待 P5。P5 还须核对目录交换/掉电恢复、官方 reload 与状态库的剩余封禁时间、动作回调无死锁、服务停止及维护衔接。手动封禁/解封、历史、网页/API 安装与独立服务控制已接入，其他动作后端继续实施。

## 网页与 API 的受管 jail 应用

启用 Fail2ban 模块后，在页面保存期望、预览并确认应用。仅支持已由本机 root 安装并启动的独立受管实例，动作支持 Nginx 模板的 `nginx-client` 及面板登录模板的 `host-input`；不依赖防火墙模块开关，Docker 转发及其他内核动作仍不可应用。诊断、读取和保存期望在停用时仍可使用；停用只关闭新应用入口，已有保护继续运行，不隐式卸载或停止服务。在途任务及待恢复状态会阻止停用与对应期望配置修改。

`GET /fail2ban/runtime` 返回明确的可用性、目标摘要、所选配置和待完成操作；所选配置不是实际运行确认。预览增加 `runtime` 与 `removed`，后者列出本次会停用的受管 jail。目标摘要固定安装、服务代次、所选配置及 Nginx/宿主机动作依据；源发生变化必须重新预览。启用项须具备固定模板检查、对应日志与动作准入；Nginx jail 另须当前发布日志和客户端拒绝入口，停用项不依赖日志仍存在。

`POST /fail2ban/apply` 接收 `version/policy_hash/base_id/target`，要求 `security.write`、幂等键和浏览器近期认证，返回 HTTP 202 的 `task_id/operation_id/version`。版本、加密任务材料、原操作 UUID、幂等响应和排队审计同事务提交；后台只提交冻结策略，复用原 Agent jail 执行器，不引入另一份配置渲染或恢复逻辑。首次排队超过五分钟未提交则过期；已开始提交的未知结果始终先核对原记录，不把超时视为操作停止。

`GET /fail2ban/tasks` 返回最近 16 条 jail 配置应用任务，普通 `/tasks/{id}` 也可查询。页面显示应用/补偿/待恢复和终态，提交未知时重试原幂等请求；任务成功只表示 jail 参数和原未过期封禁核对完成，Nginx 集合仍独立确认。已接受记录缺失、冻结材料或响应合同不匹配时保持恢复阻塞，明确拒绝且未接受的请求才结束为失败。完整备份中的隔离任务禁止重新提交。配置应用和手动地址任务共享最多 256 份加密材料，耗尽须本机维护。

本机 root Socket 继续保留独立动作授权和刷新；Web Agent Socket 仅开放同一类型化 jail 应用/查询及下述手动地址入口，不开放 bind/unbind/refresh 或任意命令。所有公开接口与显式远程资源沿用统一 JSON 外壳及权限，页面路由继续自动扫描。API/Go/TypeScript 声明已同步；尚未运行生成器、构建、类型检查、lint、测试、浏览器或真实实例，统一留待 P5。验收需覆盖模块边界、版本/目标漂移、任务幂等和断连恢复、拒绝/记录缺失、迁移/备份隔离及空策略停用。


## 受管 jail 的手动封禁与解封

在受管 jail 详情中输入单个数值 IPv4/IPv6 地址，先查询实时状态。`GET /fail2ban/addresses/status?jail=…&ip=…` 要求 `read`，核对独立受管引擎、当前配置包、官方 jail 参数与固定动作。Nginx jail 另核对当前站点日志/代理、动作授权、运行探针和集合代次；面板登录 jail 无需 Nginx，核对本机宿主机来源/保护/持续会话及所属内核对象。返回规范地址、`target`、引擎当前封禁/到期时间、当前 jail 时长、`can_ban`、`backend` 和对应动作集合状态，不使用旧诊断缓存作为写入依据。本机接口、回环/未指定/组播地址、忽略列表及当前可信代理拒绝手动 ban；宿主机动作同时保护本地链路及本机 root 批准来源。动作依据失效或内核无法证明时禁止新增宿主机封禁，仍允许在官方引擎明确 unban，未知内核状态不会伪装成已解封。

`POST /fail2ban/addresses` 接收 `jail/ip/action/target`，其中 `action=ban|unban`。要求启用管理模块、`security.write`、幂等键及浏览器近期认证；HTTP 202 返回 `task_id/operation_id`。请求材料、幂等响应及排队审计同事务保存，复用持久后台任务与独立 root jail 执行器，按 Nginx、宿主机、实例锁顺序互斥，并与维护准入串行；未接管 jail、全局解封、CIDR、任意命令及封禁时长覆盖均不支持。目标服务、配置或授权变化须重新查询，不自动切换到新目标。首次排队超过五分钟未提交会过期；应用、手动操作、配置变更及服务控制之间互相阻止冲突。

root 在固定官方客户端调用前持久记录已派发；进程中断、超时或丢失回执只观察原操作，不再次调用 ban/unban，也不自动执行相反动作补偿。已封禁地址的 ban 跳过调用，避免续期；unban 即使当前列表没有地址仍调用官方单 jail 入口，以清除该 jail 的持久封禁记录。官方引擎仍决定自动封禁、过期与并发行为，查询与派发之间出现新封禁时以引擎实际结果为准，不承诺独占引擎或精确条件交换。客户端数字回执与当前引擎状态分别保存；回执未知但目标当前状态可证明时明确标注，不把超时或客户端返回成功直接视为动作生效。依据见官方 [BanManager](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/banmanager.py)、[Actions](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/actions.py) 及 [Transmitter](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/transmitter.py)。

`GET /fail2ban/addresses/tasks` 返回最近 16 条手动任务及加密保存的引擎观测快照，Agent 暂离线仍可读取已有快照；不是自动封禁全历史。任务成功只表示所选 jail 的当前引擎状态已证明，对应 Nginx 或宿主机动作唤醒原对账链路，仍需独立查询：多个 jail 合并后，其他 jail 可使同一地址继续处于拒绝集合，集合未包含地址也不证明其他保护放行。公开接口及显式远程转发均使用统一 JSON；页面沿用自动扫描，不增加路由数组。

完整备份中的隔离任务不重放，业务迁移不导出手动记录或运行封禁。当前 Agent 协议为 56，数据库仍为 26、迁移 schema 仍为 6。实现与源码接入审阅完成，未运行生成器、构建、类型检查、lint、测试、浏览器、官方程序或真实服务，统一留待 P5。运行验收需覆盖派发前后中断/回执未知、已封禁不续期、未列出地址的持久解封、保护地址、目标漂移、任务审计/备份隔离、跨 jail 合并及动作集合独立确认。


## 网页与 API 的安装及服务控制

`POST /fail2ban/lifecycle/preview` 接收 `engine_owner/action/plan_id/asset_id/prerelease`，`engine_owner=managed|existing` 明确目标；已有实例仅支持 start/stop/enable/disable。返回影响清单、当前 jail 范围、安装及服务快照和冻结后的 `input`。`action` 为 install/resume/rollback/start/stop/enable/disable；除 install 选择单个已经准备的签名 Fail2ban 资产外，其他操作的源选择字段必须为空。安装沿用组件页的检查/准备结果、固定发行信任和本机 Python 核对，不接受用户路径、服务名、Socket、命令或 pip。缺失 Python 时显示诊断与原因，不假装已安装系统依赖。

权限按动作明确检查：install 要求 `components.manage`；start/stop/enable/disable 要求 `security.write`；resume/rollback 要求两者。预览另需 `read`，写操作要求近期认证和幂等键，OpenAPI 与显式远程合同用 `x-action-scopes` 逐项声明，转发不扩大调用者范围。`POST /fail2ban/lifecycle` 提交预览返回的完整 `input`，HTTP 202 返回持久任务；`GET /fail2ban/lifecycle/tasks` 返回最近 16 条任务及保存的结果快照。资料、任务、幂等响应与排队审计同事务提交，沿用模块操作共享的 256 份容量及备份隔离规则。

首次安装只注册独立服务及私有配置/状态目录，不启动、不设开机启用。启动和开机启用分别预览、确认；install/resume/start/enable 均要求 Fail2ban 管理模块启用；续办是否启动或开机启用仍沿用并显示原意图。stop/disable/rollback 可在关闭管理模块后明确执行；模块开关本身仍不停止服务。续办固定原资产、解释器和原 Start/Enable 意图，后两项在预览中明确显示；不借续办替换新版本。已有系统实例仍只读接入，不由这些入口停止或接管。

root 协调器在 Agent 中独立运行，可用于未配置专用 Nginx 的宿主机；宿主机、维护及组件范围按操作核对。与已有 Nginx 执行、jail 配置、手动封禁、维护和本机服务操作互斥。预览摘要固定安装事件、Python/代码/管理程序身份、服务 PID/运行代次/开机设置、所选 jail 和动作授权；提交与执行前重新核对，漂移必须重新预览。首次排队超过五分钟未派发会过期，派发前持久标记；Agent 中断后只观察原操作，不重放安装或服务控制，也不自动执行相反动作。服务仍在 activating/deactivating/reloading 或存在排队中的 systemd 作业时继续观察，状态无法读取时保留恢复阻塞；不以调用超时或稳定的 ActiveState 推定服务作业已经停止。作业字段按 [systemd v249 的 systemctl 实现](https://github.com/systemd/systemd/blob/v249/src/systemctl/systemctl-show.c#L1011) 读取：无作业为空，有作业为 uint32 编号。服务稳定且原操作仍未确认时先看实际快照，再显式预览续办、撤回或服务操作。

结果核对安装收据、实际服务/开机状态以及必要的官方引擎存活证明，不把 systemctl 成功等同于 jail 或 Nginx 动作生效。API 撤回先证明专用服务已移除，再以冻结前后快照和 CAS 仅撤销该安装的 Nginx 动作授权，保留其他来源授权、签名组件、配置、状态库和审计；外部变化不覆盖，结果不明须复核。集合清理由原 Nginx 对账单独完成，不宣称任务成功即所有流量已经放行。未完成的撤回可重新明确提交，残留原授权阻止直接重建新实例。本机紧急撤回保留原动作授权，须本机逐项撤销或通过 API 完成撤回清理。

页面继续自动扫描现有 `/fail2ban`，按权限选择资产和操作、展示影响并确认，未知提交仅继续原幂等请求，安装/服务快照均标注时间。当前 Agent 为 46，数据库为 26、迁移 schema 为 5。实现与源码集成审阅完成；未运行项目生成器、构建、类型检查、lint、测试、浏览器、Python/Fail2ban、systemd 或真实安装，统一留待 P5。集中验收需覆盖动作权限及远程交集、模块停用边界、签名/Python/配置/服务漂移、首次安装与原意图续办、服务启动/停止/开机状态、派发前后中断、撤回授权 CAS 及重建、维护/备份隔离、Nginx 独立对账和容量。


## 缺失系统 Python 的本机依赖计划与安装

缺失 Python 时，本机 root 可先生成最小系统包计划，再明确安装。当前接入 Debian 12/13、Ubuntu 22.04/24.04/26.04 的 APT，以及 CentOS Stream 9/10 的 DNF 4 原生 API，目标为 amd64/arm64；这些适配尚待 P5 真实系统验证，不作为已验证支持矩阵。只请求 `python3` 及原生解析出的必要依赖，不安装推荐/弱依赖。已有或无法完整核对的 Python、已有 Fail2ban 实例、系统包损坏或需要升级/降级/替换/删除已有包时拒绝此入口，复用或修复已有系统环境分别处理。

```sh
nginxpanel fail2ban-python-plan --data-dir=/var/lib/nginxpanel --fail2ban-scope=host
nginxpanel fail2ban-python-plan --data-dir=/var/lib/nginxpanel --fail2ban-scope=host --fail2ban-python-refresh
nginxpanel fail2ban-python-install --data-dir=/var/lib/nginxpanel --fail2ban-scope=host --fail2ban-python-plan=<计划摘要> --fail2ban-operation=<新UUID> --fail2ban-python-confirm
nginxpanel fail2ban-python-status --data-dir=/var/lib/nginxpanel --fail2ban-scope=host --fail2ban-operation=<原UUID>
```

默认只读取已有软件仓库索引；显式 `--fail2ban-python-refresh` 才允许访问已配置来源并刷新原生元数据缓存，不安装软件包，也不新增仓库、导入信任密钥或运行远程脚本。计划显示每个新增包的准确版本/架构、来源主机、SHA-256、下载及安装占用，并提示维护脚本/既有系统包钩子可能运行。计划保存一小时，最多 256 份；冻结主机、原生工具/解释器身份、软件仓库配置、已安装清单及完整求解结果，安装前重新解析并比较。计划不接受任意包名、程序路径、脚本、仓库或包 URL。

APT 保留来源验证，拒绝源文件中关闭信任/有效期检查的配置；下载后再次逐项核对大小与 SHA-256。实际安装仅提供批准的本地归档及空的来源/索引集合，禁止下载、推荐包、升级和删除，防止重解依赖引入未批准包。DNF 使用系统私有 platform Python 或现有系统 Python 的固定隔离入口，禁用插件及弱依赖，只接受 `PKG_INSTALL`；下载后核对摘要与现有 RPM 信任密钥，签名不能确认则失败，不自动导入密钥。原生事务将批准的集合交给 RPM，保留事务检查与原生锁。依据见 [APT 手册](https://manpages.debian.org/testing/apt/apt-get.8.en.html)、[APT 安装实现](https://github.com/Debian/apt/blob/2.6.1/apt-private/private-install.cc)、[DNF Base API](https://dnf.readthedocs.io/en/latest/api_base.html)、[DNF 事务 API](https://dnf.readthedocs.io/en/latest/api_transaction.html) 和 [DNF RPM 事务实现](https://github.com/rpm-software-management/dnf/blob/4.20.0/dnf/db/group.py)。

操作先写入 root 独立 journal，再派发原生安装；尚未派发的原请求可在五分钟授权期和计划有效期内继续，派发标记保存后同一 ID 仅核对结果。网页与本机命令共用安装记录及执行器。中断或超时可能留下待恢复的原生包状态，不自动执行 `dpkg --configure -a`、DNF 重装或逆向卸载。锁仍被占用或状态无法核对时保留恢复阻塞；查询确认包管理器空闲、原版本包完整安装、系统解释器归属和必要标准库/SQLite 读写后才记录成功，回执未知单独标注。稳定但未达目标的操作记录失败，新的明确计划仍须通过原生完整性检查；损坏环境由管理员通过原生包管理器恢复。新增系统包不随 Fail2ban 撤回自动卸载。

网页/API 已接入 `POST /fail2ban/python` 与 `GET /fail2ban/python/tasks` 及对应显式远程资源。提交要求 `components.manage`、管理模块启用、浏览器近期认证及幂等键。`action=plan` 生成持久任务，`plan_id` 为空，`refresh` 明确是否刷新已有索引；HTTP 202 不代表计划已完成。成功任务返回保存的计划，页面展示版本、来源、摘要、空间与影响后再单独确认 `action=install`，提交原 `plan_id` 且 `refresh=false`。任务历史保存最近 16 条加密结果快照，Agent 离线时仍可查看。安装系统依赖后仍须单独准备并安装签名 Fail2ban，不自动启动服务。

计划生成和安装均由独立 root 协调器推进，耗时原生调用不占用 HTTP 请求或 Nginx 内存锁；维护门禁、共享 root 操作记录及安装锁防止冲突。索引刷新派发前保存标记，成功结果先保存计划及操作引用，再写终态；重启只恢复已保存结果，缺失结果且原生包管理器已空闲时终止该计划，不自动重复刷新。网页未知提交只继续原幂等请求，已接受记录丢失或无法核对时保留恢复状态。任务共用加密材料、审计、容量限制及完整备份隔离，不重放恢复包中的旧任务。

现有网页/API 的 install/resume/start/enable 统一要求管理模块启用，停用、取消开机启用及撤回仍可明确处理已有保护。面板镜像继续不包含 Python/Fail2ban，Nginx Docker 模块继续由镜像预置；未加入动态编译或运行时模块安装。当前 Agent 为 47、数据库为 26、迁移 schema 为 5，root 计划、下载归档及系统包事务不进入业务迁移。

实现与源码集成审阅完成；未运行项目生成器、构建、类型检查、lint、测试、浏览器、Python、APT/DNF/RPM、镜像或真实宿主机操作，统一留待 P5。集中验证需覆盖支持矩阵、索引缺失/刷新/签名/密钥、纯新增限制、包/源/工具漂移、下载与磁盘边界、原生锁、取消/重启/回执未知、CLI 与 API 同一安装记录、近期认证/幂等/权限交集、模块关闭/维护/备份隔离及原生包恢复；不新增 UI 测试，界面由用户验收。系统依赖与官方组件的实际兼容性随后由受管安装再核对。


## 面板密码失败日志与模板

登录入口只在 `auth.ErrUnauthorized` 时提交事件；成功、限流、无效 JSON、数据库/会话错误及重新认证不计为密码失败。Web 取真实 TCP 对端并规范化数值 IP，不采信 X-Forwarded-For、Forwarded、用户名或请求体中的地址。反向代理后的对端通常为代理，不能直接当作原客户端。事件仅包含 root Agent 生成的 UTC 时间、固定 login_failed/tcp_peer、对端和本次请求 UUID，不记录密码、用户名、Cookie、认证头或请求正文。

root Agent 在非开发、root 且 metrics/maintenance 范围均为 host 时准备 `DATA/agent/security/login.jsonl`。目录 0700、文件 root 0600，拒绝链接/特殊文件/额外硬链接/身份或权限变化；独立非阻塞文件锁串行追加与读取。每份 4 MiB，当前及 `.1` 共最多 8 MiB，轮转与追加同步落盘；发现未完成尾记录停止追加，须由宿主机管理员检查。日志独立于 Fail2ban 开关；容器或未确认范围不冒充宿主机来源。Web 追加最多等待一秒，回执不明不重放，保留认证拒绝结果，并按 30 秒间隔记录不含敏感内容的投递未确认警告。

`GET /fail2ban/panel-login` 及对应显式节点资源要求 read，返回固定 source_id/format、采样时间、范围、可用性、容量、原因及最新优先的最多 20 条事件。root 私有同路径 POST 仅用于受限 Agent Socket，不暴露公开事件写入；读接口只扫描两份日志的有界尾部，不启动官方工具或后台轮询。页面显示事件及日志状态，不能据此宣称所有失败均已送达或保护已生效。

内置 panel-login-failure 使用固定字段顺序、数值地址和请求 UUID 的整行过滤器，12 条固定正反样例覆盖 IPv4/IPv6、映射地址、成功/限流、非法地址、伪造/额外字段及不完整记录；同其他模板交由官方 fail2ban-regex 检查。期望配置可随加密业务迁移，面板来源不映射到 Nginx 站点；事件日志、root 路径和运行封禁不进入业务迁移或完整备份材料。目标仍须重新核对来源及动作，不因导入而安装、启用或应用 jail。

面板模板当前不具备自动封禁能力：预览明确返回阻塞原因，root 执行器同样拒绝启用项。宿主机入口动作接入、代理/管理地址保护和实际流量路径验收仍待后续实施。Agent 为 48、数据库为 26、迁移 schema 为 6，无旧协议兼容；接口声明已同步，官方工具、生成器、构建、类型检查、lint、测试、浏览器及真实主机操作均未执行，留待 P5 集中验证，不新增 UI 测试。


## 宿主机入口动作的基础预检

`GET /fail2ban/host-input` 及显式节点资源要求 read，读取 `Fail2banHostInputPreview`；模块停用时仍可诊断。复用现有防火墙管理器的单飞/缓存观测，独立返回 manager_observed_at，避免将缓存时间当作本次目标表采样时间；只有 root、非开发且 metrics/maintenance 均确认 host、排除活动管理器与 legacy/混合后端、各视图完整时才继续。单独核对固定 `inet nginxpanel_fail2ban`，不使用人工端口策略的 `nginxpanel_host` 作为 Fail2ban 集合。目标表不属于完整确认的本机登记/运行记录、来源不完整、代次变化或容量超限均阻止准备，不从名称或标记推断所有权。

闭合的两个目标布局共用有界读取、事务编码和逐表达式/属性/顺序证明；端口规则入口仍固定原目标。宿主机动作固定 INPUT、优先级 -10、默认 accept；类型化集合最多 1024 个数值单 IP 及 1024 项保护 IP/CIDR，拒绝广播、回环、多播、未指定、本地链路地址及保护交集，不接受表名、hook、优先级、表达式或命令。保护规则只从本动作返回，不替其他来源放行；匹配封禁的包直接 DROP，不保留已建立连接的例外。编译和编码本身不创建连接或提交事务。

当前预检采样最多 512 个接口地址为单地址保护，附加固定保留网段，并合并目标本机 root 批准的管理/代理来源；独立登记/当前运行对象、保护来源批准和官方 jail 当前封禁均已完整核对后，才生成排除保护地址后的候选计划摘要/规则数/字节数。`can_prepare` 仅表示当前集合材料和编码成立，`can_apply` 始终 false；快照与预览 marker 不授予所有权，也不能用于直接写入。页面显示条件、独立表、保护来源及官方采集状态、jail、封禁/排除数量；启用的 host-input jail 预览附带 `host_input` 诊断，并继续明确阻塞应用。

预检的 `registration` 核对目标本机 root 登记、独立回执和完整内核指纹；已核对的登记空表或独立运行对象还须具备当前 root 保护与官方来源批准及完整采样，才允许继续生成准备材料。同名未登记表、登记/回执不一致、对象漂移及未恢复意图均阻塞，不从标记单独推断所有权。页面区分未登记、已登记空表、缺失、漂移、待恢复和已释放。预检同目标单份在途、30 秒缓存，后台最多 10 秒，其中独立内核快照最多 3 秒；缓存不作为未来执行前复核。

## 本机 root 空表登记与恢复

以下入口只操作独立固定表 `inet nginxpanel_fail2ban`，不依赖 Nginx、不安装链或 hook、不提交封禁，不是自动保护授权。须本机 root、规范绝对数据目录及 `--fail2ban-scope=host`，容器范围不允许；没有 IPC、网页或远程写入入口。

```sh
# 初次登记；操作标识由调用方生成，同一请求重试必须保留原标识。
nginxpanel fail2ban-host-input-init --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <操作UUID>
nginxpanel fail2ban-host-input-status --data-dir /srv/nginxpanel --fail2ban-scope host
# 结果不明时仅核对原操作，不重发创建或移除事务。
nginxpanel fail2ban-host-input-recover --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <原操作UUID>
# 新移除操作须指定 status 返回的当前登记操作，且目标仍为原样空表。
nginxpanel fail2ban-host-input-remove --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <新操作UUID> --fail2ban-host-input-base <当前登记操作UUID>
```

新建或移除按固定主机锁互斥，并与维护准入协调。root 在 `agent/fail2ban/host-input-registration.json` 与独立 journal 持久写入所有者、请求/事务摘要、原基线和恢复方向后，才发送一次带内核代次前提的独占创建/删除事务；提交前核对命名空间，提交后证明完整空表/缺失和预期代次。ACK 缺失、取消或结果不明均保留原意图，必须显式恢复，不自动重发。已有未登记表绝不接管，有链、规则或未知属性时拒绝修改。

新请求通过 `--fail2ban-host-input-base` 对当前登记操作做 CAS；仅首次无登记时省略。已使用 UUID 不得重放，当前原请求重试只读取结果。恢复仅观察原意图：原空表仍在则确认或报告移除未完成，缺失则确认移除或报告创建未完成；不以失败返回掩盖未完成动作。已确认表在重启/命名空间变化后缺失时，生成关联旧操作的独立释放记录，保留旧审计，不自动重建或修改旧命名空间。重新初始化已释放登记须使用新操作和最新基础标识；恢复产生的新标识应重新读取 status。上述记录不进入完整备份或跨环境配置迁移，目标机必须独立建立自己的登记。

一次性带 hook 执行、规则清除与原意图恢复见下文；已批准官方 jail 的持续采样会话见下文，受管宿主机模板和独立面板 jail 已接通，主机重启后的安全恢复仍待完成，`can_apply` 继续为 false。Agent/数据库/迁移 schema 为 55/26/6，无旧协议兼容。实现已接入并审阅；生成器、构建、类型检查、lint、测试、浏览器、内核操作及真实实例仍统一留待 P5。P5 须集中覆盖双目标隔离、原操作幂等/CAS、持久写入中断、ACK/代次不确定、同名表拒绝、非空/未知属性拒绝、命名空间变化和审计保留；不新增 UI 测试。


## 本机管理与代理来源批准

宿主机 INPUT 动作只按真实 TCP 对端保护和封禁，不根据转发头推断内核来源。来源批准与 jail 的 `ignore_ips` 分开，不表示已自动发现全部代理或 SSH 管理地址；root 应完整列出面板、远程管理、SSH 等需要保护的来源，以及该主机前置代理/CDN 的实际 TCP 来源。内核不能替日志中的 CDN 后客户实施 Nginx 层拒绝，不据此宣称代理后流量已经受保护。

在 root 私有、0600、规范绝对路径的 JSON 文件中明确两个列表，每类最多 128 项数值 IP/CIDR；管理列表不能为空，无代理时也须明确 `proxy_sources: []`，省略或 null 均拒绝。不接受域名、区域地址、映射 IPv6 前缀、默认全地址族网段、未指定/多播/广播地址；规范化网段、去重并排序。示例地址必须替换为该目标的真实管理与代理来源：

```json
{"admin_sources":["192.0.2.10/32","2001:db8:1::/64"],"proxy_sources":[]}
```

```sh
# 须先完成空表登记；首次无批准时省略保护基础标识。
nginxpanel fail2ban-host-protection-approve --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <新操作UUID> --fail2ban-host-protection-file /root/host-protection.json
nginxpanel fail2ban-host-protection-status --data-dir /srv/nginxpanel --fail2ban-scope host
# 替换批准时使用同一 approve 入口及 --fail2ban-host-protection-base <当前批准UUID>。
nginxpanel fail2ban-host-protection-revoke --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <新操作UUID> --fail2ban-host-protection-base <当前批准UUID>
```

批准绑定该目标的 root 所有者、登记操作和网络命名空间；创建前证明登记或运行的完整对象及当前回执，与登记/移除共用固定主机锁，新增批准还与维护准入互斥。仅 root 本机入口可写，无网页/IPC/远程写入能力。`agent/fail2ban/host-protection/events/` 保留最多 2048 个不可变事件，先持久事件再原子发布 current 指针；修改及撤销均关联前一批准，旧事件不改写、不删除。当前同 ID、同内容请求只读取原结果；指针发布中断后，同一请求仅在原基础批准仍当前且登记/命名空间未变化时可继续发布同一事件，不能用旧 ID 回退后来批准。无法读取、摘要或指针不匹配均阻塞，不用空列表冒充成功。

只读预检新增必填 `protection`，分别展示未批准、已核对、失效、撤销或不可确认状态、批准时间及规范来源。登记操作、所有者、命名空间或完整对象变化后原批准失效；重新初始化空表必须重新批准来源。`protected_sources` 只在完整条件满足时返回本地、固定与已批准来源的规范并集，不能漏掉管理/代理范围。缓存仍为 30 秒，未来执行器须重新读取批准及本地地址，不用页面缓存授予写入。撤销仅改变后续动作准入，允许维护期间进行，不直接移除当前运行封禁；官方动作生命周期和安全移除仍由后续执行器接通。

这些批准事件和指针不进入备份或配置迁移，目标机必须独立建立自己的批准，不因模块开关、导入或重启自动批准。`can_apply` 仍为 false；空表及来源批准均不表示自动封禁已生效。Agent/数据库/归档为 55/26/6，无旧协议兼容。实现与源码集成审阅后提交；生成器、构建、类型检查、lint、测试、浏览器、官方工具及真实内核操作仍留待 P5。P5 集中覆盖缺字段/非法来源、规范化并集、CAS/旧 ID 拒绝、不可变事件/指针中断、登记与命名空间漂移、撤销和维护边界，不新增 UI 测试。


## 独立官方封禁来源批准与采集

宿主机候选集合独立于 Nginx 站点、资源和 reload 执行器。先完成空表登记、管理/代理保护批准及官方实例读取授权，再由目标本机 root 使用私有 0600、规范绝对路径 JSON 明确 1 至 32 个 jail 名称；拒绝空列表、重复或非法名称。只读取已经选择并核对的官方 1.1.1 实例，不安装 jail、变更 action 或启动服务。

```json
{"jails":["sshd"]}
```

```sh
nginxpanel fail2ban-host-sources-approve --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <新操作UUID> --fail2ban-host-sources-file /root/host-sources.json
nginxpanel fail2ban-host-sources-status --data-dir /srv/nginxpanel --fail2ban-scope host
# 替换批准须附带 --fail2ban-host-sources-base <当前批准UUID>。
nginxpanel fail2ban-host-sources-revoke --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <新操作UUID> --fail2ban-host-sources-base <当前批准UUID>
```

批准绑定 root 所有者、登记操作、网络命名空间和选定官方实例身份，沿用固定宿主机锁、UUID 幂等和基础批准 CAS；新增批准与维护互斥，撤销仅改变后续准入，允许维护期间进行。先完整采集所列 jail 再保存批准。`agent/fail2ban/host-sources/events/` 最多 2048 个不可变事件，先持久事件再原子发布指针；中断后只有原基础仍当前的同一请求可续办，旧 ID 不回退新批准。无 HTTP/IPC/远程写入入口；事件和指针不进入备份或迁移，目标机必须重新批准。撤销不直接移除运行规则。

采集核对固定客户端、服务版本、进程/调用代次与 Socket 身份，每个 jail 读取两次 `get banip --with-time`，以中间的 `status` 核对完整封禁集合；任一集合或时间记录变化均拒绝整个样本。最多四个 jail 并行，每次输出最多 128 KiB，合并最多 1024 个唯一数值单 IP，完整来源证明最多 4 MiB；不截断、不接受 CIDR 封禁、不将停止或读取失败视为空集合。合并后排除本地、保留、管理和代理保护地址，候选最多 1024 个封禁和 1024 项保护、2050 条规则。

必填 `sources` 返回批准/失效/撤销/不可完整采集状态、jail、采样时间、来源摘要、候选封禁及保护排除数量；不返回原始客户端命令或事务。`time_basis=engine-current` 只表示官方当前集合。官方时间标签由服务端格式化，保留原标签作采样证据，不推断未知时区下的 UTC 到期时间，依据 [Fail2ban 1.1.1 BanManager](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/banmanager.py)。只读预检仍为 30 秒缓存、后台 10 秒总预算，超时拒绝样本；不能将缓存或采样摘要当作执行授权。

当前 Agent/数据库/迁移 schema 为 55/26/6，首版无旧合同兼容。一次性执行、显式恢复及下述持续采样会话已接通，受管宿主机模板与独立面板 jail 见后文，主机重启后的安全恢复仍待完成，`can_apply` 始终 false。实现已集成并完成源码审阅；生成器、构建、类型检查、lint、测试、浏览器、官方工具及真实主机操作均留待 P5，届时集中覆盖来源 CAS/中断、版本及实例变化、集合变化、保护排除、永久封禁/服务时区、超限和离线失败，不新增 UI 测试。


## 宿主机动作的一次性执行与恢复

本机 root 可将批准 jail 的一个完整当前样本同步到独立 INPUT 动作表，或明确移除本应用动作规则。入口仍无网页、IPC 或远程写入，不接受原始 IP、规则、命令、表名或序列化事务；此入口不安装官方 action、不持续同步 ban/unban 或到期，也不更改官方封禁记录。`clear` 是停止本动作的内核执行，不能当作官方解封。

```sh
# 首次运行操作省略 runtime-base；后续使用 runtime-status 返回的最近运行操作 UUID。
nginxpanel fail2ban-host-runtime-apply --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <新操作UUID>
nginxpanel fail2ban-host-runtime-status --data-dir /srv/nginxpanel --fail2ban-scope host
# 原操作结果不明时只恢复观察，不重发。
nginxpanel fail2ban-host-runtime-recover --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <原操作UUID>
# 仅删除本应用的链/hook/规则，保留独立空表与登记；不改变 Fail2ban 中的 ban。
nginxpanel fail2ban-host-runtime-clear --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation <新操作UUID> --fail2ban-host-runtime-base <当前运行操作UUID>
# 再次同步同样使用 --fail2ban-host-runtime-base。
```

每个新事务与登记/来源写入共用固定宿主机锁，使用运行操作自身的 UUID/CAS，与维护准入互斥，并持有既有实例写锁覆盖采集和提交；存在未结束的 Fail2ban 实例/jail 操作时不开始同步。运行规则或待核对事务存在时，受管实例生命周期变更和重新接入/解绑明确拒绝，须先核对并清除本动作；状态读取仍可用。同步前重新排除活动管理器/混合后端，完整证明原登记或已确认运行对象，采集批准来源及新本地保护；持久意图后再次核对原对象、内核代次、命名空间、批准身份、接口地址和官方程序/进程。采样完成至提交最多五秒，操作总预算 30 秒；过期或变化不提交。规则清除不要求官方实例在线或来源仍获批准，也不因第三方管理器出现而拒绝删除已完整证明的本应用规则；同名表、未知属性或对象漂移始终拒绝覆盖。

`agent/fail2ban/host-runtime/intents/` 保存最多 2048 个不可变完整意图，包含原规则、候选规则、来源摘要、原基线及事务摘要；单份意图/检查点最多 256 KiB，root 0700/0600。意图、当前检查点及独立 journal 均持久后才单次发送带代次前提的原子事务。只有全部 ACK、同 Socket 屏障、完整候选语义与预期代次均证明后才确认成功。取消、ACK 不明或确认写入中断保留原意图；不能用后续失败返回掩盖已生效但未确认的规则。

显式恢复只观察唯一候选或原对象指纹：候选完整存在则确认成功，原对象原样存在则确认原事务未生效并保留原规则；均无法证明时保留待恢复，禁止重发、盲目补偿、重建缺失表或恢复历史封禁。意图先落盘但当前指针尚未发布时，只有原基础操作仍当前、登记仍匹配时可按原 ID 接回并观察。终态对象后来漂移或缺失不会改写旧审计。原始空表登记不改写，已确认运行回执接续当前所有权指纹；清除后再移除登记必须证明新空表，不能套用旧句柄。正在执行、未核对或仍含规则的运行记录阻止空表登记写操作。

只读预检新增必填 `runtime`，区分当前已核对规则、空表、未初始化、缺失、漂移及待恢复；规则地址/保护项数量与官方当前候选数量分别展示。`verified` 仅证明当前对象与原已确认运行记录一致，不表示该样本仍等于官方最新封禁或持续保护已启用。旧登记下的终态运行操作只保留历史标识供后续 CAS，不赋予新登记运行权。全部运行材料、意图及 journal 不进入备份/配置迁移，目标仍须重新批准。

当前 Agent/数据库/迁移 schema 为 55/26/6，首版不保留旧合同兼容。一次性执行与下述持续采样会话已接通，受管宿主机模板与独立面板 jail 见下文，主机重启后的安全恢复和其他动作后端仍待完成，网页 `can_apply` 继续为 false。源码实现与集成审阅后提交；生成器、构建、类型检查、lint、测试、浏览器、官方工具、内核写入和真实服务均留待 P5。P5 集中覆盖一次性执行/清除、所有权接续、CAS/旧 ID 拒绝、意图/检查点/journal 中断、ACK/代次未知、原对象/候选恢复、批准/接口变化、离线清除及审计保留，不新增 UI 测试。


## 本机 root 持续采样会话

本机 root 可显式开启独立宿主机同步会话，将已批准且正在运行的官方 jail 当前集合持续同步到独立 INPUT 表。该会话不依赖 Web、Nginx 或管理模块开关；仍须宿主机 Agent 运行、独立登记及保护/来源批准完整有效。启用不安装、启动或启用 Fail2ban，也不接管已有表或其他防火墙管理器。

`fail2ban-host-sync-enable` 接受新的 `--fail2ban-operation`、当前 `--fail2ban-host-sync-base`，以及当前规则操作 `--fail2ban-host-runtime-base`；首个对象对应空基础标识。所有入口均须 `--data-dir` 的规范绝对路径及 `--fail2ban-scope=host`。批准固定本机所有者、登记、命名空间、官方实例和保护/来源批准 ID，持久化不可变事件、父操作及当前指针后才允许后台推进；同一操作重试不改变原批准，历史 ID 不回放。

`fail2ban-host-sync-status` 读取独立执行器状态；`fail2ban-host-sync-refresh` 仅发送固定协议通知，不接受 IP、jail、命令或序列化事务。两者通过 root 专属 0600 Unix Socket；通知合并后立即返回，采集在后台进行，避免官方 action 持锁时等待自身采样。下述受管面板 jail 由配置包安装固定通知 action；已有官方 jail 也可依靠 30 秒后台轮询同步，显式通知最多每 5 秒触发一次，两次采样之间的变化不保证立即反映。

每个批准会话只使用一个持久父操作，自动变化复用其阶段和一个完整原子事务检查点，避免按每个 ban/unban 耗尽全局 2048 条操作容量。新事务只能接续已核对的原对象；待定意图保存到结果完整核对后才能替换。相同集合仍重新采集、证明当前规则及批准，不写新事务；变化时沿用单次内核提交、全部回执、代次和完整语义证明。来源不完整、离线、超限、批准变化或管理器冲突均停止新写入，保留规则并明确报告，绝不将失败当成空集合或从历史样本恢复封禁。

Agent 在同一网络命名空间重新启动时，先观察原候选或原对象解决未知结果，再采集完整新集合；不会重发旧事务。主机重启、命名空间变化、目标表丢失或外部漂移仍禁止盲目重建、重新接管或补偿，目标表缺失时可使用下述本机显式退役并重新登记；本机明确允许的重启恢复见后文；同次启动的丢表及外部漂移仍须显式处理。批准被撤销或替换时立即停止报告当前同步，原规则的清除须明确停用，撤销批准本身不改内核。

`fail2ban-host-sync-disable` 接受新的操作 ID 和当前同步基础 ID，不接受运行基础标识。先持久保存停止意图，冻结后续新样本，再核对在途结果并清除该会话所属规则；清除不需要官方服务在线。清除和空表证明完成后才终结父操作、发布停用指针；CLI 断连后 Agent 可继续核对停止意图。若待定结果、对象漂移或维护阻止清除，状态仍为停用中或待恢复，不报告已停用。相同停用 ID 可续办。

会话有效时禁止手动新 apply/clear、登记变更及受管实例重接入/生命周期写入，须先停用并清除；原事务恢复仍可观察。维护关闭期间只核对在途事务，已空闲的长期父操作不阻塞维护；维护持有期间不采样提交新规则，释放后使用新样本继续。持久批准、停止意图、父操作和运行检查点均不迁移或导入，目标机必须重新授权。

只读宿主机接口必填 `sync`，独立于可能缓存的候选/规则视图。`enabled` 只表示批准仍存在；`current` 仅表示最近完整样本与所属规则已核对，带采样和确认时间，超过 60 秒转为等待核对。页面展示持续状态、排队及采样/核对时间，不提供批准写按钮；`can_apply` 仍为 false。Agent/数据库/迁移 schema 为 55/26/6，首版不兼容旧合同。实现和源码集成审阅后提交，生成器、构建、类型检查、lint、测试、浏览器、官方工具和真实主机操作继续留待 P5；届时集中覆盖启动恢复、停止中断、并发/维护、通知合并、失效批准、相同集合、离线/变化集合、未知结果及审计容量，不新增 UI 测试。


## 受管面板登录 jail 与宿主机动作

jail 执行器独立于 Nginx 启动，通过 `/v1/fail2ban/jails/{status,apply,operations/{id}}` 服务受限 Web Socket 和独立 root 专用 Socket。对应本机命令为 `fail2ban-jails-apply/status`，CAS 使用 `--fail2ban-jails-base`。只配置面板登录 jail 时不要求安装或发布 Nginx；混合策略中的 Nginx jail 仍须核对原发布日志、可信代理及客户端拒绝入口，且执行/恢复仍串行互斥。首版不保留旧命令或旧 Agent 路由。

宿主机来源批准增加明确的 `managed` 范围。root 可在来源文件中填写 `{"managed":true,"jails":[]}`，批准当前受管安装的宿主机 jail；该模式不另列显式名称，从所选受管配置派生，最多 32 项。已有官方 jail 的显式名单继续使用 `managed=false`。空显式名单只在 `managed=true` 时有效，且必须证明受管官方实例、实际完整 jail 名单和当前配置一致，不能将服务离线解释为空来源。此范围不能用于已有系统实例，不批准任意名字、日志路径或命令。

部署顺序为：独立安装并启动受管官方实例；本机建立独立空表登记、保护来源与上述受管来源批准；显式开启持续会话；随后在页面启用模块、保存并预览面板登录模板、应用 jail 配置。所有权及宿主机执行权仍属于本机特权授权，后续受管 jail 配置通过现有网页/API 权限、近期认证和任务执行，不需逐个到主机批准新名称。来源批准及会话不随业务迁移复制。

面板 jail 只读取固定 `agent/security/login.jsonl`，固定 `nginxpanel-host-input` action 在 start/stop/ban/unban 时调用 `fail2ban-host-sync-refresh`，不传地址、jail 名称或命令。配置包冻结保护批准及完整保护前缀，忽略列表合并 root 管理/代理、本地与用户忽略项；实际内核仍以每次新采样的本地/批准保护排除来源。当前宿主机受管动作仅覆盖面板登录模板的本机直连，不用于站点真实客户端、代理或 Docker 转发。

应用先持久操作与固定配置包，再核对官方样例、候选配置及旧封禁记录；目录交换、官方 reload 和运行参数核对后才确认 jail 配置。停止/移除 jail 同样发布完整配置；中断使用原配置、原授权及官方记录核对，不把旧封禁写回引擎。宿主机专用事务不构造 Nginx 授权或运行材料，只有引用 Nginx 的事务才核对、切换和恢复对应登记。宿主机批准变化、开始停止或保护依据变化会阻止新启用配置，清除已停用 jail 不隐式授予新权限。

持续采集从当前不可变受管配置派生启用的宿主机 jail，证明实际完整名单、配置选择及实例代次，再合并官方当前封禁。配置变化立即使此前同步状态转为等待新采样；ban/unban 通知合并后重新读取完整集合，不重放旧样本。jail 任务成功、官方记录和动作执行分别展示：`host_ready/nginx_ready` 及其原因分别报告当前动作准入；就绪只表示准入已核对，宿主机保护以独立 `sync/runtime` 及其采样时间为准。网页 host-input 的 `can_apply` 仍为 false，不提供原始规则写入。

Agent/数据库/归档为 57/26/6，首版无旧合同兼容。源码集成审阅与阶段格式整理后提交，生成器、构建、类型检查、lint、测试、浏览器、官方工具及真实主机操作留待 P5。届时集中覆盖无 Nginx 面板 jail、混合策略、动态来源/空来源、作用域与保护变化、动作回调、reload/目录交换中断、剩余封禁、手动地址操作及维护恢复；不新增 UI 测试。主机重启后的自动恢复、外部漂移处置、已有 jail 接管/全局实例控制和其他动作后端仍待完成。


## 失联宿主机动作范围的本机退役

主机重启、网络命名空间变化或动作表丢失后，旧持续会话和未知运行事务可能无法完成正常停用。当前固定目标必须能完整证明不存在，才允许本机 root 显式退役原已确认登记；存在同名表、读取失败或未知属性均阻止退役，不接管或清除其他对象。未确认的空表登记须先沿原操作执行 `fail2ban-host-input-recover`。

先用 `fail2ban-host-input-status` 取得当前登记 UUID，分别准备新的退役操作 UUID 和后续登记操作 UUID。下例变量须填入实际标识；`released_registration` 使用退役成功返回的 `after_registration`，不是旧登记标识：

```sh
nginxpanel fail2ban-host-input-retire --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation "$retirement_operation" --fail2ban-host-input-base "$current_registration"
nginxpanel fail2ban-host-input-retirement --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation "$retirement_operation"
nginxpanel fail2ban-host-input-init --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation "$new_registration" --fail2ban-host-input-base "$released_registration"
```

退役命令的相同 UUID 和基础标识可续办，状态命令省略操作 UUID 时读取当前退役。结果包含原/新登记、原会话/运行操作、旧/观测命名空间、处置类型和完成时间。`target_missing` 只证明当前目标缺失；`scope_changed` 明确旧命名空间对象未核对。两者均不证明原内核事务未执行，不重发事务、恢复历史封禁或执行逆向补偿。

退役先不可变保存原登记、完整运行意图/检查点、手动回执、持续批准/父回执及原停止意图，再选择当前退役并冻结新写入。原手动在途任务以 `failed/retired_unconfirmed` 终结，保留原结果未知的原因；持续父操作以 `succeeded/disabled_retired` 表示会话关闭，不表示旧规则已清除。原终态手动记录不改写。新停用事件及关联释放登记不覆盖原审计，完整原件保存在 root 的 `agent/fail2ban/host-retirements/events/`，完成缺失证明另存 `receipts/`。

本入口只关闭本机执行权，不向内核提交事务。发布前后须分别读取当前目标；发布中断由独立 Agent 按所选原操作继续，完整完成证明落盘后只补齐同一最终回执。续办期间即使命名空间再次变化，也只能在当前目标缺失证明下关闭旧授权，不将旧事务改投新范围。未完成退役继续阻止登记、保护/来源批准、规则执行、jail 及实例变更；页面通过 `sync.retirement_id` 和待恢复状态展示。退役成功后，旧运行检查点仍保留原文但不再作为当前执行依据。

重新初始化仍需新的 root 操作及目标空缺证明；之后须重新核对并批准管理/代理保护、官方 jail 来源和持续会话，从官方当前完整集合开始。退役及完成材料不进入逻辑配置包或完整备份，API 导入不会继承旧授权。每类事件和全局 journal 均有既有限额，容量不足保留恢复状态，不删除历史记录。

此阶段为 Agent 57、数据库 26、归档 6，首版无旧协议兼容。同机新启动的显式授权恢复见后文，同次启动丢表及外部漂移仍须本机处理；生成器、构建、类型检查、lint、测试、浏览器、官方工具和真实内核操作统一留待 P5，不新增 UI 测试。


## 显式允许的同机重启恢复

开启持续会话时可附加 `--fail2ban-recover-on-boot`。默认不附加，不改变已有系统服务的开机开关。此选项由本机 root 明确允许：在同一 `machine-id`、宿主机初始网络命名空间和新的启动身份下，核对原官方实例、保护及来源批准未撤销、没有停止意图、管理器允许且目标表完整证明不存在后，重建本应用范围。身份文件须 root 持有、不可被其他账户写入并在读取期间保持一致；只保存带域摘要，不将该值作为远程凭据。不能通过复制磁盘上的 root 恢复目录克隆节点身份，正常配置迁移和完整备份均不包含这些材料。

使用新的同步 UUID 和实际当前同步/运行基础标识，例如：

```sh
nginxpanel fail2ban-host-sync-enable --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation "$new_session" --fail2ban-host-sync-base "$current_sync" --fail2ban-host-runtime-base "$current_runtime" --fail2ban-recover-on-boot
nginxpanel fail2ban-host-recovery-status --data-dir /srv/nginxpanel --fail2ban-scope host
nginxpanel fail2ban-host-recovery-cancel --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-operation "$recovery_operation"
```

首个同步或尚无运行操作时，相应基础标识为空。相同启用 UUID 重试须保留原选项；更换策略须先明确停用再开启。重启恢复不会安装或启动 Fail2ban；官方服务尚未就绪、版本/实例改变、保护或来源已替换、停止已记录时不会自行授予新执行权。服务恢复后独立 Agent 可继续核对，无需 Web 或 Nginx 存活。

每次恢复先固定不可变原授权、原范围退役意图和新操作标识，选择恢复并保存父回执；其他宿主机/jail/实例写入暂时阻止。原范围仍按退役流程保存完整意图和未知结果，新空表使用新的所有者及一次性创建意图；任何持久创建只提交一次，中断后只观察原结果。确认新对象后，以相同逻辑保护策略、当前本地地址及相同官方实例重新采集和批准来源，再建立新持续会话。新会话的每个封禁集合仍由普通同步执行器从官方完整当前记录生成，不恢复旧样本、旧规则或旧命名空间事务。

维护关闭时允许原创建和退役继续观察、收尾，不新增对象或批准；协调父操作本身不阻塞维护，真实在途内核事务由原子操作回执负责排空。恢复过程再次重启或命名空间变化时暂停新提交，保留待核对状态；原创建仍只观察，须本机取消本次恢复并显式核对、停用/退役后重新建立授权。已证明创建失败也不自动换 UUID 重试。同次启动丢表、同名表存在或外部漂移均不自动接管。

取消只撤回本次恢复及其尚未完成的新会话执行权，不声明撤销已经发生的创建或清除旧规则；部分登记/批准及空表可保留。取消后按当前现场显式停用或退役，不能靠重启或轮询重开同一恢复。恢复已完成则使用正常同步停用入口。已取消派生会话也不能通过 jail 应用或手动新增封禁绕过；官方明确解封继续沿原权限和记录流程处理。

只读 `sync` 增加 `recover_on_boot`、`recovery_id` 和 `recovering` 状态。恢复父操作成功只表示新授权和会话已发布，不表示当前封禁已生效；须结合后续 `current`、实际采样/核对时间和 `runtime` 查看。原意图、恢复父回执及新授权链留在 root 的 `agent/fail2ban/host-boot-recovery/` 及既有独立目录，每次启动的准备重试使用同一组标识，不按轮询新增历史。归档和 journal 均保留既有限额，容量不足明确停止，不删除原审计。

Agent 为 58，数据库/归档为 26/6，首版无旧合同兼容。源码实现与集成审阅后统一整理格式及差异；生成器、构建、类型检查、lint、测试、浏览器、官方工具及真实主机重启/内核操作统一留待 P5。集中验收需覆盖身份/实例变化、显式停止、准备与各发布点中断、创建未知结果、恢复期间再次重启、维护及取消，不新增 UI 测试。已有实例 jail 接管、全局控制和其他动作/防火墙后端仍待完成。


## 已有实例的全局服务控制

只读接入不会授予启停权。本机 root 可在重新接入正常运行的既有服务时显式附加授权：

```sh
nginxpanel fail2ban-bind --data-dir /srv/nginxpanel --fail2ban-scope host --fail2ban-service fail2ban.service --fail2ban-socket /run/fail2ban/fail2ban.sock --fail2ban-service-control
```

此授权固定到该接入 UUID、服务、Socket 和客户端，并记录实际加载的 unit 及最多 16 个 drop-in 的规范路径、解析路径和 root 文件摘要。待 daemon-reload、其他激活来源、无法完整读取或文件/客户端漂移均拒绝服务控制；变更须本机重新接入。重复相同授权返回原 UUID，变更控制权产生新的不可变接入事件；无该选项重新接入可撤销服务控制，unbind 则撤销整个接入。服务离线时可 unbind，重新 bind 仍要求原所有者先正常启动实例。授权调整与在途任务互斥，有效宿主机持续会话须先显式停用并确认清除。

`BindingView.service_control` 单独展示服务控制授权，不改变 jail 的 managed/writable。网页选择“已接入的全局实例”，使用原 lifecycle 预览、幂等持久任务、security.write 和近期认证链路；既有实例不能通过安装/续办/撤回操作变为独立受管实例。请求不接受服务名或任意命令，BaseID 固定原接入 UUID，摘要包含加载单元授权、客户端、服务状态/代次及当前完整 jail 列表；提交与实际派发前重新核对。停止弹窗明确提示全部 jail（包括 SSH 等系统保护）停止工作，开机设置单独确认。

执行仅调用受信 systemctl 的固定 start/stop/enable/disable，派发前持久标记；取消、超时或 Agent 中断后只观察原目标，绝不重发。启动成功须完整核对官方实例、版本、Socket/主进程归属及 jail 列表；停止成功须服务无 PID、inactive/failed，且 Socket 文件与内核引用都不存在。enable/disable 只核对开机设置，不声称当前保护生效；未知结果与成功回执分别显示。服务控制不改写已有 jail、配置、状态库或动作集合；服务停止也不代表动作集合已清空。离线实例仍可返回 systemd 状态，jail 数据保持不可用，不返回虚构空列表成功。

授权事件、单元摘要和实例任务沿用 root 隔离规则，不随文件/API 逻辑迁移或完整备份授予目标控制权。目标须由本机 root 重新接入并授权。Agent 为 59，数据库/归档仍为 26/6，首版不兼容旧合同。实现及集成源码审阅后统一整理格式和差异；生成器、构建、类型检查、lint、测试、浏览器、官方工具与真实服务操作留待 P5，届时集中覆盖只读拒绝、身份/单元变化、全局停止、离线重启、开机设置、中断及维护互斥，不新增 UI 测试。已有 jail 接管、其他动作/防火墙后端及其余 P0–P5 缺口继续实施。
