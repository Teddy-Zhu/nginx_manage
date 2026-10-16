# Fail2ban 配置、诊断与实例接入

`GET /fail2ban` 返回 `Fail2banObservation`，要求 `read` 权限，沿用统一 JSON 外壳。显式远程资源仅转发登记操作；页面 `/fail2ban` 由 `src/pages` 自动扫描接入。模块默认停用且控制入口暂不可启用，诊断和已授权实例的只读观察不改变模块开关或 jail 所有权。

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

实例与 jail 各缓存 30 秒，相同目标只运行一份在途采集，共用最多 2 个在途采集及每个 30 秒预算窗口最多 16 份新采集；缓存各最多 65 项。单次采集最多 10 秒，单命令最多 2 秒，进程组超时终止。版本输出最多 4 KiB、单元元数据 8 KiB、状态输出 128 KiB、错误输出 4 KiB；Unix Socket 表 2 MiB、进程描述符最多 512 项。完整 jail 列表最多 64 项，单 jail 封禁最多 1024 项，数值 IP/CIDR 解析并去重。Web 共用最多 4 个 Fail2ban 读取请求，实例/jail 请求最多 14 秒，适配 Agent 15 秒传输期限。请求取消不重复启动同一采集；页面卸载或切换 jail 取消读取。

## 当前边界

公开 OpenAPI、Go/TypeScript 声明和显式远程资源同步更新；当前 Agent 协议为 40、数据库为 25，root 防火墙记录仍为 3，Fail2ban 接入记录为 1。首版不提供旧协议兼容。

已有实例当前只读接入。安装/启动与 Socket 激活授权、签名组件运行绑定、完整引擎自检、jail 持久配置与接管、模板/匹配测试、受控 action、ban/unban、历史日志及 CDN 来源处理仍在完整实施范围内。面板和 Nginx 镜像不增加 Python/Fail2ban，不增加运行时 Nginx 模块安装能力。

实现与集成源码审阅已完成，未运行生成器、构建、类型检查、lint、测试、浏览器、服务或真实宿主机探测/接入命令；发行版、Python、systemd、Fail2ban 与日志后端组合留待 P5 集中验证。

## jail 期望配置与迁移

`GET/PUT /fail2ban/policy` 持久保存最多 32 个 jail，采用加密存储、基础版本比较、幂等保存及同事务审计。保存不要求模块启用，也不改变实例。内置 `nginx-http-401`（全部 401，包含首次认证挑战）及 `nginx-authorization-401`（仅携带 Authorization 后的 401，不覆盖仅凭 Cookie 的认证失败），参数为日志资源标识、动作类型、封禁秒数、统计窗口、阈值和数值 IP/CIDR 白名单；不接收任意路径、正则或 shell。面板登录失败模板尚未接入独立日志来源。

`GET /fail2ban/templates` 返回模板；`POST /fail2ban/preview` 核对保存版本、唯一运行日志来源及已有实例，显示当前执行缺口，`can_apply=false`。日志资源按站点逻辑 ID 绑定，实例授权、动作后端及实际流量路径仍须在应用前核对。jail 持久安装、动作桥接及 ban/unban 继续实施；当前页面只保存期望配置和只读观察。

schema 4 迁移包可选择 `selection.fail2ban`，以固定 `config/fail2ban.json` 携带期望配置。文件、API 拉取及推送均支持 preserve/merge/replace，默认保留目标；导入重新分配 jail ID，沿用同一业务配置树中的站点标识，冻结目标版本与内容，同 Nginx 配置导入事务保存。失败补偿以新版本恢复原期望，检测外部变更时保留待恢复，不覆盖。源服务、Socket、客户端批准、所有权及封禁/计数不迁移，也不自动安装、启用模块或应用 jail。须核对目标白名单、日志来源和动作路径；保留的目标 jail 可能引用本次已替换的站点。

当前数据库为 25，Agent 为 40。实现及源码集成审阅完成，生成器、构建、类型检查、lint、测试、浏览器及真实实例操作均留待 P5。

## 固定过滤器及官方样例检查

模板同时提供固定 filter 内容的 SHA-256、固定样例及其 SHA-256。过滤器按受管 JSON 字段边界读取数值客户端地址，避免 URI 中伪造地址或状态；仅单行匹配，关闭 DNS。时间戳按 ISO 8601 提取，WAF 附加字段使用同一 JSON 字符串语法。HTTP 日志字段顺序由渲染器和过滤器共同引用，不能由请求内容插入新的字段。

`POST /fail2ban/templates/check` 接受 1–2 个内置 ID，返回检查时间、工具版本/散列、预期与实际地址及明确的通过/未知原因。root Agent 使用固定系统目录或已批准签名组件的官方 `fail2ban-regex 1.1.1`，在 root 私有临时目录写入本程序固定 filter 和 15 条样例，使用空配置目录、数值地址模式及 UTF-8；不读取现有 jail 配置，不连接 Socket，不接收用户正则、日志路径、命令或任意文本。命令每次最多 2 秒，输出有界，整批最多 10 秒、同目标单份在途、30 秒缓存并有并发/次数预算。版本漂移、超时、未知输出、清理失败或任一检查中断均不返回部分通过；采样结果不表示动作已经适用于流量路径。

受管 Nginx 访问日志新增 `nginxpanel_auth_present`，只记录入站 Authorization 是否非空（0/1），不记录认证头内容。执行器生成 map，原生配置禁止重定义该变量；迁移/恢复预检包含 map 模块，Docker 镜像已预置此能力。日志目录声明 `auth_presence`，jail 保存预览要求来源包含该标记，同时执行固定过滤器检查；须先发布当前 Nginx 配置，再核对实际来源。旧运行日志或缺少标记的来源不据格式名推断可匹配。模块开关不控制日志中的保护状态。

实现及源码集成审阅完成，尚未执行官方工具、生成器、构建、类型检查、lint、测试、浏览器或真实配置发布。P5 需集中核对 Python 正则/日期解析、IPv4/IPv6、首次挑战、转义与字段伪造、实际日志样例及轮转衔接；当前不是已通过验证的模板发布声明。固定 CLI/输出行为依据 [Fail2ban 1.1.1 fail2ban-regex](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2banregex.py) 及[日期剥离实现](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/server/filter.py)。jail 持久安装、动作桥接及封禁控制仍在实施。

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
- `fail2ban-managed-start` / `fail2ban-managed-stop`：只启停独立服务；启动结果核对 root 服务主进程持有的 Socket、同一实例代次、服务端版本及初始零 jail 状态。
- `fail2ban-managed-enable` / `fail2ban-managed-disable`：只改变独立服务的开机启用。
- `fail2ban-managed-rollback`：续办撤回独立服务；保留签名资产、私有配置、SQLite 和完整审计，不删除用户已有实例或其数据。

所有程序调用固定、无 Shell，进程组与输出有界；超时或取消不伪造操作成功，安装留为 interrupted，普通服务操作记录待核对结果。撤回中断可重复执行，变更材料不匹配时保留现场供本机处理。管理程序与系统 Python 的文件身份固定，升级后需重新处理准入，不静默跟随新程序。模块开关不控制这些 root 操作，面板展示安装登记、已授权实例及过滤器检查来源；公开安装/服务变更、jail/action 等继续接入。

实现与源码集成审阅完成，生成器、构建、类型检查、lint、测试、浏览器、实际组件安装与 systemd 操作未执行，留待 P5。届时需核对两种架构/发行版的签名资产布局、标准库与运行文件约束、前台启动/Socket 归属、无 jail 启动、配置隔离、服务中断/续办/撤回和重启恢复。官方入口与参数依据 [Fail2ban 1.1.1 server](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2banserver.py)、[CLI 配置参数](https://github.com/fail2ban/fail2ban/blob/1.1.1/fail2ban/client/fail2bancmdline.py)。

## 受管实例及过滤器的只读接入

installed 状态的 root 安装登记授权对其专用服务、Socket 和固定官方代码执行只读观察。`GET /fail2ban/instance`、`GET /fail2ban/jails/{name}` 自动选择该登记；无受管安装或已撤回时，已有实例仍只依据 `fail2ban-bind` 的明确接入记录读取。安装未结束、撤回中、登记损坏或两类授权冲突时返回不可用，不改用其他实例。新建已有实例接入会拒绝尚未撤回的受管安装；`fail2ban-binding` / `fail2ban-unbind` 继续只查询/撤销已有实例的独立读取登记，不撤销受管安装本身。

`binding.engine` 和 `Fail2banTemplateCheck.engine` 返回代码来源：`owner` 为 existing/managed/none/unavailable，受管来源同时包括安装 UUID、准备计划、资产、清单摘要及实际 Python 路径/摘要。该对象不声明 jail 所有权。受管实例的读取授权 ID 使用当前安装事件 ID，安装/服务操作产生新事件后，原在途与缓存选择失效；读取不覆盖 root 安装记录，不把它转换成已有实例的接入文件。

每次实际采集前后重新认证签名代码、系统运行文件、解释器及固定配置。只读客户端与过滤器通过隔离的系统 Python 加载相应官方模块，不依赖固定系统目录中另装一套 Fail2ban。客户端仅接收现有固定的 version/status 读取参数；过滤器仍只接受内置 ID、固定 filter/样例和空私有配置目录，不连接运行实例。受管 `fail2ban-regex` 使用官方模块的无参数 `exec_command_line()` 入口，client 使用其 argv 入口。

受管服务采集还核对 systemd 的实际单元/覆盖项/加载版本、主进程所持监听 Socket、实际解释器文件 inode 及完整前台入口参数，前后核对服务代次。签名包及解释器验证纳入最多 10 秒的共享采集任务；仍限制 2 份在途、30 秒窗口 16 份新任务与有界输出，官方工具每次最多 2 秒。30 秒缓存命中返回原采样时间的结果，不作为新的执行校验证据；登记事件变化或撤回时不返回旧选择的成功结果。

保存预览仅在运行实例可确认、版本为当前支持的 1.1.1，且过滤器结果与实例的 `engine` 一致时将 `template_ready` 标为 true。来源不同、版本不同或实例读取错误会阻塞对应 jail；样例检查的原始结果仍保留供核对。当前没有 jail 应用动作执行器，`can_apply=false`，所有 jail 仍只读，不因为代码来源为 managed 就标记接管或保护。

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

这条本机动作链不安装或修改 jail、过滤器或现有服务，网页的 jail 应用仍未接通，`can_apply=false`、jail 的 `managed/writable=false` 不变。Agent 为 42，策略为 nginxpanel-8，数据库为 25、迁移 schema 为 4。实现与源码集成审阅完成，构建、类型检查、lint、测试、浏览器、官方实例及真实 Nginx 验收统一留待 P5。
