# 宿主机防火墙策略与诊断

`GET /api/v1/firewall` 要求 `read`，返回统一 `code/message/data/request_id/node_id` 外壳，`data` 为 `FirewallObservation`。已登记远程资源 `/nodes/{connection}/firewall`，沿用目标权限和永久节点身份检查。防火墙页面由 `src/pages/firewall.vue` 自动扫描接入。

仅由 root Agent 在本机以 `--metrics-scope=host` 确认宿主机观测范围；容器、开发模式或未确认范围均不执行宿主机诊断或 Docker API 读取。此授权不允许写规则。`available` 只说明已进入宿主机读取，各管理器和规则视图仍可能未知或不可用；`writable` 及 `docker.writable` 始终为 false。本机 root 空表登记命令使用独立范围授权，不由 API、模块开关或观测授权触发。防火墙模块默认停用，可显式启用；执行还须满足下述独立授权。Fail2ban 的实例接入、受管 jail 与宿主机动作采用独立授权及恢复链路，见 [Fail2ban](fail2ban.md)。

诊断分别返回：

- firewalld 当前运行、panic、默认 zone、活动接口/来源、runtime/permanent policy 及活动绑定，以及配置中的后端选择。通过固定本机 D-Bus 和唯一服务所有者读取，禁止自动启动；配置选择不视为内核运行后端。
- UFW 受信工具可用性、`ufw.conf` 中的 ENABLED、`/etc/default/ufw` 中的 IPV6、`ufw status` 当前状态及 `ufw show added` 用户规则报告；未知配置值保留 null，启用配置与当前状态不一致时告警。报告及编译限制见末节。
- 默认 IPv4/IPv6 iptables 命令后端，以及 nftables、iptables-nft IPv4/IPv6、iptables-legacy IPv4/IPv6 五个独立结构视图。明确版本后再读取显式后端的 save 工具，不切换 alternatives。仅含表/链、hook/priority、默认策略、规则数和 DOCKER-USER 跳转标记，不返回规则表达式、集合内容、注释或计数器。
- Docker `ip/ip6 docker-bridges` 与 `filter/DOCKER-USER` 标记，以及下述实际实例、网络、主机端口映射和按后端/地址族区分的能力报告。挂接观察不等于已核对 DNAT 原始目的或实际数据包路径；原生 nftables 保持实验适配只读。

工具仅从固定系统目录选择 root 保护的文件，保留 xtables multi-call 的原调用名；不接受 API 提供的路径、参数、命令或环境。save 读取全部现有表，不指定单表；以固定受信 false 程序阻止 save 的 modprobe 回退。nft 使用 JSON/numeric/terse 输出。超时、未知格式、输出超限或 nft-save 不兼容表提示均令整个视图不可用，不将前缀作为完整结果。

单次命令期限 2 秒、整个采集上下文期限 6 秒；每次采集只允许一份在途工作，缓存 30 秒，HTTP 请求取消不会另起相同采集。Web 每节点最多 4 个在途读取。nft 原始输出最多 4 MiB、每份 xtables 原始输出最多 1 MiB、stderr 最多 8 KiB；每个结构视图最多 16384 个对象和 384 KiB JSON 元数据。firewalld 最多 128 个 zone、各 zone 最多 256 个接口/来源且总值最多 32 KiB。超限明确失败，原始输出和错误不写入业务响应或日志。

各管理器/CLI 视图独立读取，不保证原子快照。nftables 与 iptables-nft 可展示相同内核对象，不可累计计数；观测到规则不代表已排除其他后端。管理器冲突、孤立管理器标记、地址族后端差异保留告警。`direct-candidate` 只表示未观察到启用的现存管理器，不代表可接管。无活动规则时内核后端保持 unknown；链名和表名不能证明所有权或外部可达性。

## Docker 实例、端口映射与能力

`docker.runtime` 通过固定 `/run/docker.sock` 的 API 1.47 读取本机 Linux Docker 实例、网络与运行容器摘要。与 Nginx 容器运行共用 root Socket 属主/权限及对端检查、固定 API 前缀、禁用代理和重定向的传输；不读取 Docker 上下文、环境端点或用户提供的 URL，不启动 daemon，也不调用容器、网络或镜像的写入接口。列表响应中的标签、挂载等未选字段不保留或返回，未请求容器 inspect、凭据或 exec。

单次采集按固定顺序读取两组 `/info`、`/networks`、`/containers/json?all=false&size=false`，四秒总期限，每份响应最多 256 KiB。两组选择字段规范化后必须完全一致；不重试漂移，不把跨接口读取当作原子快照。最多 128 个网络、128 个运行容器、每容器 16 个网络和合计 1024 项端口记录。完整数量和摘要包含所有项，页面仅显示前 128 个主机映射并明确截断；未发布到主机的 exposed-only 端口不计入，routed 模式的完整发布范围不能从该清单推断。读取失败、字段不完整、漂移或超限时整个运行子报告不可用，内核标记诊断独立保留。Docker 整体公共子报告最多 320 KiB，沿用 30 秒诊断缓存；普通主机入站执行的私有核对不额外读取 Docker API。

每项分别展示主机地址/端口和容器端口，不用 DNAT 后容器端口替代外部发布端口。`0.0.0.0`、`::` 只是通配绑定，不自动选择原始目的地址；缺失主机端口保留为 0。仅将唯一 local bridge、nat 网关模式、运行容器和同地址族端点列为 `bridge_nat_candidate`；rootless、Swarm、非 nat、其他驱动、多个网络、回环路径、SCTP 及 IPv6 发布到仅 IPv4 端点等明确未确认，不将用户态代理视为同族转发。候选仍须核对实际 DNAT、入站及转发出口，不证明已受保护或外部可达。

`docker.capabilities` 按五种策略后端与 IPv4/IPv6 返回十项能力。显式 iptables 的 `observed` 要求完整宿主机视图、管理器和后端一致、实际实例以及同次原生导出中的普通 `DOCKER-USER` 链、FORWARD 首条无条件跳转和 filter 中无其他引用；链名或任意条件跳转不足以证明挂接。当前所有 `supported` 及 `docker.writable` 均为 false，目标绑定、DNAT/路由核对与独立编译见下节；受管代际执行、新连接确认与持久恢复仍待接入。规则页面按报告禁用不支持的 Docker 范围和重新启用操作，展示具体原因；已导入期望可查看、停用或删除，不能据 INPUT 应用声称 Docker 已保护。原生 nftables 继续作为显式实验适配，不自动修改 Docker 后端。

依据：[Docker Engine API 1.47](https://docs.docker.com/reference/api/engine/version/v1.47/)、[官方 API 模型](https://github.com/moby/moby/blob/v27.5.1/api/swagger.yaml)、[Docker iptables 与原始目的匹配](https://docs.docker.com/engine/network/firewall-iptables/)、[端口发布与网关模式](https://docs.docker.com/engine/network/port-publishing/)。本阶段完成源码实现和集成审阅，实际 Docker/API/内核组合仍待 P5 集中验证。

## Docker 发布端口目标计划

`POST /firewall/plan` 对含启用 Docker 规则的已保存策略接入独立目标绑定预览，限显式 iptables-nft/legacy、本机宿主机授权及已确认受控管理连接。此路径读取实际完整规则和两次一致的 Docker 报告，核对所需地址族的 DOCKER-USER 挂接；它不进入主机 INPUT 代际执行器、不创建独立执行记录，也不写入规则。首次省略 `docker_targets` 返回 `plan.docker` 中的映射候选及可选入口地址；不根据源环境推断目标配置。

再次提交可携带 `docker_targets.engine_hash/snapshot_hash/bindings`，每项明确规则、容器、网络、地址族、协议、Docker 主机地址/端口、容器端口、实际原始目的地址及入口接口。最多 128 项、96 KiB；每条启用 Docker 规则的每个地址族、每个主机端口必须完整覆盖，不能把端口区间静默缩成现有映射子集。同一规则、入口及原始目的端口不能绑定冲突容器；映射、协议或来源仍使用目标已保存规则。通配绑定必须选择实际本机入口地址，固定绑定则必须相等；回环、链路本地、映射地址、接口通配及未知接口均不接受。选定目标只定义这些明确映射的覆盖范围，不代表覆盖所有容器或所有通配地址。

Agent 重新读取当前实例、网络和容器，报告摘要不一致时拒绝沿用旧绑定。解析要求运行容器、唯一 local bridge/NAT、同族容器端点及当前实际 bridge 接口；显式 bridge 名直接核对，未命名自建 bridge 按官方生成名称定位后仍核对宿主机接口和 sysfs 类型，不以名称证明链路。入口地址与接口必须实际对应，接口、标识、状态、MTU 及地址在计划期间须一致，最多 512 个接口、合计 2048 个接口地址、512 个可绑定地址和 256 KiB 私有接口报告。

提交完整绑定后，逐项按原生 `nat/PREROUTING` 规则顺序解释普通链 jump/goto/RETURN，最终必须命中 `DOCKER` 中与所选同族容器地址和端口完全一致的 DNAT。仅解释入口、协议、来源/目的前缀、目标端口、LOCAL 地址类型、NEW/ORIGINAL 连接状态及注释；来源条件必须对规则的全部来源前缀有相同结果，部分命中、未知扩展、提前终止、循环或错误目的均拒绝。不从未知扩展后面的 token 推断不匹配。每绑定最多解释 16384 条，全计划最多 65536 条，链深度最多 16。

只读 `NETLINK_ROUTE` GETRULE/GETROUTE 完整读取所需地址族的路由和策略规则，仅支持默认无条件 local/main（及可选 default）查表；条件策略规则、来源专用及 TOS 路由明确阻塞。内核 `FIB_MATCH` 须选中原始目的的所选入口本地路由，以及容器地址经实际 bridge 的 main 表永久 kernel 直连路由；拒绝网关、多路径、nexthop/封装等未支持结果，并与完整清单交叉核对。逐数据报检查来源、序列、边界、截断及 multipart 完成，累计读取和前后核对共限 2 MiB/8192 项、每数据报 64 KiB。摘要仅去除缓存使用计数和时间戳，保留到期与错误；前后完整路由摘要须一致。

每个解析绑定的 `path` 返回 DNAT 摘要/读取条数、完整路由摘要、本地路由摘要、实际出口路由摘要/前缀/表号及 bridge 索引。路径证据计入绑定与程序摘要；环境摘要同时固定完整原生规则、工具、接口和路由。核对后再次读取完整原生规则及 Docker 报告，并核对接口身份和地址，变化、超限或原计划十秒期限内未完成则整体失败，不返回部分成功。前后相等不构成原子快照，也不证明转发设置、其他过滤规则及云安全组允许外部新连接。

主机入站及其 SSH/管理入口保护使用原编译器，Docker 使用独立程序类型，不能传给 INPUT 执行器。Docker 规则同时匹配入口、bridge 出口、同族容器地址/端口、来源，以及 conntrack ORIGINAL 的原始目的地址/主机端口和 NEW 状态。允许使用 RETURN，拒绝或丢弃分别使用相应目标；不使用全面 ACCEPT 绕过 Docker 后续隔离。规则仍仅作用于新连接，不清理 conntrack。完整绑定和两类程序分别参与摘要；包含保护项的两类规则合计最多 8192 条，Docker 程序最多 2 MiB、计划回包最多 512 KiB，页面展示前 128 条并注明截断。IPC 边界使用类型化输入重新编译核对摘要、数量和展示内容，不把展示命令作为执行输入。

完整绑定计划还须核对下节的独立 Docker 本机授权、原回执、当前父登记与 Engine；仅枚举映射不要求子授权。编译器使用独立所有者及本次计划标识生成最多 28 字节的代际链，完整身份写入入口、指针及每条业务规则的标记。`docker.transition` 返回 `DOCKER-USER` 首位 → `NGINXPANEL-DOCKER` 单指针 → 首代链的拓扑、授权/运行程序/批次摘要，以及分地址族的保留规则数量和候选/撤回规模。

初始转换只接受空的应用命名空间。候选批次仅独占创建两条应用链、写入生成规则及插入精确首位入口；撤回批次只删除这些精确规则和空链，不声明、刷新、回放或改写 INPUT、Docker 或第三方配置。内存结构投影须能完整还原原规则；`after_hash` 是投影摘要，不是内核回执。原生完整导出与完整 nft JSON 候选/撤回读取预算均纳入准入，包含两类入口和指针的展开规则合计最多 8192 条；每个地址族单方向批次最多 2 MiB。计划结束前重新核对父子授权，变化或缺失回执拒绝返回成功计划。

完整绑定还固定显式后端双地址族 command/save/restore、禁止模块加载的 `false` 工具及私有读取入口的 ELF 身份和版本；已有已确认 INPUT 范围沿用原工具绑定，空范围重新绑定。官方 go-iptables 的隔离只读桥接核对完整 filter 链清单及 INPUT/原主机代际，并对所需 Docker 地址族增加 FORWARD/DOCKER-USER 的声明、数量、顺序及完整参数序列核对；两类导出不一致时拒绝，不解释或回放第三方扩展。

每个所需地址族使用固定 restore 分别执行候选批次的 `--test`，以及把候选和撤回合成一个 filter/COMMIT 的正反向 `--test`，避免在原空命名空间单独预演删除。完整输入、基线、代际程序、工具摘要及逐次成功结果参与 `dry_run_hash`；`dry_run_commands` 为 2 或 4，进入转换及父程序摘要。非零结果、警告、任何输出、超时、工具变化或预演前后完整规则变化均不生成成功计划。预演后再次核对 Docker/原生规则/路由、固定工具的原生与库读取及候选读取容量，仍使用原十秒期限。`--test` 不安装规则，也不证明外部可达。

目标绑定及路径证据只存在于本次请求、易失计划和页面内存，完整规则、工具、预演证明及正反向批次仅存 root 易失计划；不改写期望规则、数据库或迁移归档，导出、导入和 API 迁移继续只携带中立期望。公开规则预览使用实际代际链及完整身份标记，IPC 边界重新编译核对代际并检查预演摘要及批次数量。页面绑定修改后立即清除旧编译结果，重新读取目标时清除旧选择。`plan.docker.compiled` 表示完成目标路径、独立授权、初始转换编译和官方预演，`can_apply` 保持 false，提交执行会被拒绝。代际执行/更新、新连接确认和持久恢复继续实施。原生 Docker nftables 仍保持实验适配只读。

实现依据：[Moby bridge 名称及端点](https://github.com/moby/moby/blob/v27.5.1/libnetwork/drivers/bridge/bridge_linux.go)、[端口 DNAT 规则](https://github.com/moby/moby/blob/v27.5.1/libnetwork/drivers/bridge/port_mapping_linux.go)、[Docker 转发及原始目的匹配](https://docs.docker.com/engine/network/firewall-iptables/)、[Linux 路由 UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/rtnetlink.h)、[策略规则 UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/fib_rules.h)、[IPv6 FIB 查询及导出](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/route.c)。本阶段仅完成源码实现和集成审阅，未执行 Docker/API/系统能力验证，待 P5 集中验证。

## Docker 转发独立本机授权

Docker 转发授权与 INPUT 规则授权分别登记，当前只批准空的应用命名空间，不安装内核规则。须在真实宿主机由 root 操作，沿用本数据目录已经登记的显式 iptables 后端；可接续空的或已确认主机 INPUT 范围，不能由导入配置、原始标记或其他数据目录取得授权。

先执行 `docker-firewall-registration` 读取当前实例摘要，将返回的 `runtime.engine_hash` 设置为 `DOCKER_ENGINE_HASH`，再明确选择该实例：

```sh
sudo nginxpanel docker-firewall-registration --data-dir /var/lib/nginxpanel --firewall-scope host
sudo nginxpanel docker-firewall-init --data-dir /var/lib/nginxpanel --firewall-scope host --firewall-docker-engine "$DOCKER_ENGINE_HASH"
sudo nginxpanel docker-firewall-recover --data-dir /var/lib/nginxpanel --firewall-scope host
sudo nginxpanel docker-firewall-remove --data-dir /var/lib/nginxpanel --firewall-scope host
```

初始化核对 rootful、Swarm inactive、所选实例与实际 iptables/DOCKER-USER 挂接，绑定本机身份、数据目录、独立所有者、原宿主机占用/登记操作与请求摘要、显式后端及 Docker 实例摘要。两个显式后端、两个地址族的全部原生表都必须不存在 `NGINXPANEL-DOCKER` 前缀链，以及保留链引用或 `nginxpanel:docker:` 标记；不因名称、注释或已有规则而取得所有权。此空命名空间边界也进入主机 INPUT 的完整读取，出现未知 Docker 保留对象时停止准入，保留现场。

`agent/firewall/docker-registration.json` 与独立操作回执分开发布。意图先保存，随后重新核对原父授权、实例及当前完整空命名空间，最后保存终态和回执；回执缺失、冲突或未完成时不授予权限。恢复只推进原元数据操作，不重放规则或 Docker 写入，不自动改绑新实例；第三方规则变化须重新通过完整读取，核对摘要独立记录。终态回执及原请求保持不变，新登记与释放使用新操作并固定上一终态摘要。

初始化尚未完成时，`docker-firewall-remove` 可在重新核对原宿主机授权和空命名空间后撤回原意图，即使 Docker 已离线；原初始化记为失败终态并保留回执。已登记授权的释放同样不要求 Docker 在线，但必须确认没有遗留保留对象。重复初始化、释放及恢复沿用已有状态核对，不覆盖其他实例或宿主机登记。Docker 授权未释放或回执未核对前，不允许释放父 iptables 占用或切换管理器。

这些操作复用业务锁、全局登记锁及维护锁，未完成的意图或缺失回执阻塞独立维护。每次本机命令总期限最多 60 秒，原生完整导出与 Docker API 继续使用原有有界只读入口。登记记录及回执属于 root 材料，不进入业务数据库、文件/API 迁移或完整备份；目标机须重新授权。

公共诊断 `docker.registration` 和防火墙页面分别显示授权状态、登记实例及父登记标识。`registered/verified` 仅表示当前空命名空间授权已核对；`supported`、`writable` 及 Docker 计划的 `can_apply` 仍为 false，不能将授权等同于规则安装或外部可达。已确认 INPUT 诊断补齐后端和原登记标识，供父授权交叉核对。实现与集成源码审阅完成，CLI、Docker/API、构建、类型检查和业务验证仍待 P5，不新增 UI 测试。

## 内核目标表快照

`kernel` 子视图通过固定 NETLINK_NETFILTER GET 操作读取 `inet nginxpanel_host`。root 宿主机授权与原诊断一致，连接不加入 multicast，不接受来自 API 的消息、表名、文件或表达式。固定缓冲逐数据报消费，检查内核来源、端口、请求序列、消息/属性边界、重复属性、multipart 完成与 DUMP_INTR；不使用先累积整个 multipart 再限长的读取方式。不提供计数器 reset 或任何写操作。

读取前后核对非零内核规则代次与由 boot ID/网络命名空间身份派生的摘要。目标表不存在也必须经完整代次核对；目标表存在时，完整读取链/规则及集合、状态对象、flowtable 元数据。存在后面三类对象时整份快照不可用，不把未读取的集合元素或对象内容当作空。内核忽略链 dump 的表筛选时在 root 本地筛选完整有界结果，第三方表不会进入摘要或响应。

摘要保留原始表达式及未知属性，不经过可能忽略未知表达式的库解码；仅去除 UAPI padding 并将基础链动态包/字节计数值归零，保留计数属性的存在/结构、未知属性及对象句柄。摘要不是规则所有权证明，也不证明外部路径可用。单次快照最多 3 秒、每数据报 64 KiB、总接收 8 MiB、总对象最多 8448 个，目标最多 128 条链/8192 条规则。超限、截断、丢失、代次变化、格式未知或不支持的对象均整体失败，不返回部分摘要。读取沿用原单飞与 30 秒诊断缓存；缓存不能充当执行前重新核对。

## 期望规则

`GET /api/v1/firewall/policy` 要求 `read`，返回 `FirewallPolicyView`。未保存时为版本 0 与空规则。`PUT` 要求 `security.write`、浏览器近期认证、`Idempotency-Key` 与精确 `base_version`。策略使用节点主密钥按版本加密，CAS 更新、幂等响应和审计同事务提交；冲突必须重读，不覆盖他人的修改。模块停用时仍允许保存期望；保存只表示待应用。

中立模型支持 UUID、名称、启停、主机入站/Docker 发布端口、IPv4/IPv6/双栈、TCP/UDP、端口区间、来源、allow/deny/reject、顺序、入站接口与备注。最多 1000 条、规范 JSON 256 KiB；每条 1–16 个端口区间、最多 32 个来源。端口区间合并相邻/重叠部分，来源规范化并拒绝重复；CIDR 必须为网络起点，不静默扩大用户地址范围。空来源表示任意来源，非空来源须覆盖所选地址族，双栈须同时提供两种地址族。按顺序、UUID 确定排序。后端和接口是目标绑定，不接受用户命令、路径或可执行文本。

## 编译预览

`POST /api/v1/firewall/preview` 要求 `read` 和已保存版本，浏览器使用 CSRF；同一节点最多一份在途预览，结束前再次核对版本。直接 nftables 编译器使用固定库构造实际表达式与摘要，但不创建连接或发送 netlink 事务；firewalld 与 UFW 编译范围见下节。启用的 Docker 发布端口规则及其他尚未适配的后端明确阻塞，不能降格为 INPUT 或自动切换管理器。

当前编译目标为独立 `inet nginxpanel_host` 表、`input` 过滤基础链、hook 优先级 10、自有链默认 accept。前两条返回回环及 ESTABLISHED/RELATED 流量；业务规则仅匹配 conntrack NEW，按地址族、来源、入站接口、协议和目的端口展开。allow 返回其余系统策略，deny 丢弃，reject 对 TCP 使用 RST、UDP 使用对应地址族不可达响应。未跟踪流量不在本阶段匹配范围内，不清理已有会话。含两条保护规则的总展开数最多 8192，超限失败，不返回部分成功；预览条目最多展示前 128 条，计数及程序摘要覆盖完整结果。

预览复用 Agent 诊断，核对宿主机范围、管理器、legacy/混合后端、nft 视图、目标表及绑定接口，返回观测时间和错误/告警；接口清单最多 512 项。诊断缓存、采集非原子及外部变更意味着结果不是执行授权。`compiled` 只表示表达式生成成功，`can_apply` 恒为 false；存在同名目标表时返回独立登记核对状态，不凭表名接管；空表登记本身不是执行授权；应用须另行生成包含入口保护的 root 计划。允许规则不保证其他基础链、云安全组或外部路径放行。

当上述内核快照可用且固定目标表不存在时，预览另外序列化完整新建 batch：BEGIN 携带 `NFNL_BATCH_GENID`，表/链均使用 CREATE+EXCL，规则只追加到新建的固定链，最后 END。最多 8 MiB，返回消息数、字节数和绑定命名空间、快照与事务字节的摘要；目标表已存在时不生成接管或替换事务。格式标记本身不能证明所有权。序列化不发送事务，不证明内核接受表达式、socket 能承载整份 batch 或已建立恢复能力；执行器仍须持久化独立意图/恢复材料、重新核对、处理回执及未知结果。

## 本机 root 空表登记

仅在宿主机上由 root 显式指定 `--firewall-scope=host`，使用下列本地命令；未向 IPC/HTTP 注册写入入口，默认不运行。容器范围拒绝执行。数据目录及所有父目录须由 root 持有且不可被其他账户写入。

```sh
nginxpanel firewall-init --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel firewall-registration --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel firewall-recover --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel firewall-remove --data-dir /srv/nginxpanel --firewall-scope host
```

`firewall-init` 只独占创建空的 `inet nginxpanel_host` 表，不创建链、hook、规则或默认过滤策略，不承接业务期望策略。先生成随机登记身份，保存 root 私有意图和独立操作记录，再提交带非零内核代次前置条件的 CREATE+EXCL 事务。已有同名表拒绝接管；重复初始化只核对原登记，不重新提交。固定宿主机锁排除不同数据目录的并发登记，新建/移除与原独立维护准入共用锁，已有维护时拒绝新操作。

事务为单个不超过 1 KiB 的数据报，回执总量不超过 64 KiB、提交期限 3 秒，不拆批或自动重发。同 socket 的 GETGEN 屏障前须消费完整回执，包含指向 BEGIN 的提交错误；随后使用独立 3 秒期限重新读取完整目标表。只有正确回执、预期下一内核代次、原命名空间、随机标记及严格空表结构同时成立才登记确认摘要。未知属性、使用者、标志、任何链/规则/集合/状态对象/flowtable 均拒绝空表核对。随机标记仅用于匹配先于提交保存的 root 意图，不单独充当所有权证明。

`firewall-registration` 为只读状态；公开诊断的 `registration` 也用原登记、独立操作回执及同代次完整内核摘要核对，沿用 30 秒诊断缓存。`registered/verified=true` 表示空表登记匹配；`managed/verified=true` 表示已确认运行策略与独立回执及当前完整对象摘要一致。二者均不代表外部可达性或新写入授权。新建/移除的回执丢失、后读失败或 Agent/命令中断留下原意图；`firewall-recover` 不发事务，只核对原对象并完成原记录。表不匹配时拒绝覆盖；表缺失不会自动重建。旧 boot/命名空间且当前目标表不存在时，须本机显式恢复才释放旧登记，不宣称删除了旧命名空间对象。释放原已确认登记使用新的关联操作记录，保留原完成记录。

`firewall-remove` 只删除经完整核对、仍为空且摘要未变的已登记表，仍以代次前置条件排除读写间隙的外部变更；出现任何子对象或漂移都拒绝删除，不执行 flush 或快照覆盖。登记位于 `agent/firewall/registration.json`，操作位于原 `agent/operations`，均不进入逻辑迁移或业务备份恢复。空表无流量作用，故登记步骤没有过滤策略确认窗口。运行执行器接收过策略后，空表命令拒绝修改该登记；使用原运行操作查询、确认或回滚。

## direct-nftables 应用与独立恢复

先停止 Agent，由本机 root 完成空表登记，再在现有 Agent 启动参数中明确设置 `--firewall-scope host --firewall-owner direct-nftables --firewall-ssh openssh`，保留原 `--maintenance-scope host`。默认均为 unconfirmed；开发/容器不允许执行。仅在本机确认没有 SSH 保护需求时才选择 `--firewall-ssh none`，不从命令缺失推断无 SSH。诊断仍用独立 `--metrics-scope host`。执行器持有跨数据目录的宿主机登记锁，已接受的恢复意图不因后续关闭模块或去掉新应用授权而撤销。

直接访问目标节点已确认的受控管理 HTTPS 监听，启用防火墙模块并先保存期望策略。`POST /firewall/plan` 接收 `action=apply` 及保存版本，返回 300 秒有效的 root 私有计划摘要及保护项；`POST /firewall/apply` 接收原 `action/plan_id/version` 和幂等键，返回 202 与独立操作。`GET /firewall/runtime`、`GET /firewall/operations/{id}` 查询 root 状态；`POST /firewall/operations/{id}/confirm` 或 `/rollback` 决定原操作。接口要求 `read/security.write`，变更要求近期认证及浏览器 CSRF；全部拒绝递归转发。期望策略保存和编译预览仍可通过显式远程资源使用。全部 JSON 沿用统一外壳；Agent 协议为 40、数据库为 25。

计划与应用都重新核对实际管理 TCP 对端、已确认监听/来源 ACL、OpenSSH 有效端口、root 监听描述符和现有 SSH 对端，不固定猜测端口 22，不信任代理头。来源与管理端口保护、SSH 端口保护插入业务规则之前；IPv6 通配 SSH 监听保守保护同端口 IPv4。没有可核对保护来源的地址族，若策略可能阻止该地址族 SSH 端口则拒绝执行。保护限于列出的端口及来源，所有接口共享；没有本地目标地址选择语义。SSH 或监听、来源、接口、保存版本、内核代次变化均要求重新计划。存在其他管理器、legacy/混合后端或任一后端规则视图不完整时拒绝新应用。

root 保存完整原确认策略、候选策略、保护项、随机所有者/计划标记及恢复方向后才写内核。只接受 root 编译的固定表事务，原始 API 不能传入 wire、表名、表达式或命令；完整匹配表、基础链、顺序、原始表达式及已知内核默认字段，再以 `NFNL_BATCH_GENID` 在单个原子 batch 内替换本应用表。已知字段之外的内容、漂移或第三方对象阻止覆盖；不 flush 全局 ruleset。数据报、ACK、socket 缓冲及后读均有界；不能容纳完整事务时拒绝，不拆批。只有 ACK、原命名空间、预期代次及完整候选后读都通过才进入确认窗口；未知提交转入原恢复方向，禁止重发候选。

确认窗口为 120 秒，兼用单调时钟与持久期限。候选核对后关闭并重建 root 持有的管理监听，丢弃旧监听队列，撤销除应用响应外的旧连接；应用响应关闭 HTTP 连接。确认须来自新监听上新建的非回环 TCP/TLS 连接，旧会话、预先排队的连接或 HTTP 头均不能证明。确认前再次核对候选对象和期限，只记录实际连接来源及 `controlled-listener` 范围；这不证明所有业务端口、其他控制节点或云安全组可达。

Agent 独立循环在超时、Web 通道中断、监听故障或停止时恢复最后确认策略（首次应用前为原空表）；重启永不继续等待未确认候选。提交方向先持久保存，回执丢失后只用原意图和完整目标语义核对；中断恢复不会把刚完成但尚未保存回执的恢复当作新的漂移。已确认对象每 30 秒核对，缺失时只恢复最后确认版本；陌生同名对象不覆盖，失败保留 `recovery_required`。本机 root 可用 `nginxpanel firewall-rollback --data-dir /srv/nginxpanel` 提交持久救援请求，由运行中的 Agent 处理；离线候选在下一次启动时恢复。

运行恢复材料位于 root 私有 `agent/firewall/runtime.json` 与原 `agent/operations`，不进入业务备份或迁移。模块停用须明确选择保留或移除本应用规则，不停止系统管理器，不撤销既有确认/恢复。保留时提交 `firewall_rules=keep`；移除按下节完成确认后引用原操作停用。`src/pages/firewall-apply.vue` 自动扫描接入计划、入口保护、限时确认和回滚，`firewall-rules.vue` 管理期望及编译预览。[逻辑迁移](migration.md)可显式导出中立期望规则，默认保留目标；合并/替换须重新绑定目标后端和接口，以版本及内容约束同事务保存，Nginx 失败时一并补偿期望。迁移不自动启用模块或应用内核规则，仍须本流程独立确认。完整备份只保留期望草稿，恢复不直接应用规则。

已确认规则同时约束[管理入口变更](management-listener.md)：root 在入口提交及新连接确认前证明当前对象，按实际确认策略完整核对候选端口、来源与各规则接口。冲突、漂移或未知记录阻止新入口变更，原入口及独立恢复保留；调整防火墙后须先独立确认再变更监听，不以草稿替代运行状态。入口修改不自动重写保护项；后续显式防火墙应用会重新采集当前监听与来源。仅证明本应用规则的判定，不代替其他规则和外部可达性验证。

## SSH 与保护来源持续核对

`GET /firewall/runtime` 的 `protection_observation` 将已确认规则中的保护项与当前宿主机输入分开展示。root 独立记录保存原 SSH 保护方式、实际监听、管理地址/ACL 和原实际控制来源；本机后台每 30 秒复用计划的同一采集与生成逻辑，以 3 秒总期限读取实际 OpenSSH 监听及现有 SSH 对端。来源中已被更大 CIDR 覆盖的冗余项会归一化，普通来源内新建 SSH 会话不会仅因多出一个主机前缀就报告差异。单次最多 512 个 SSH 监听和 128 个保护项；超限、读取不完整或未知授权不产生一致结果。请求只读取缓存，不随调用者 IP 增加保护，不依赖 Web 存活。

观察状态为 `current`（采样时与原计划一致）、`changed`、`unavailable` 或 `not_applicable`。结果固定 `plan_id`、采样时间、当前 SSH 保护方式/实际监听及重新核对的保护项；超过 45 秒、确认计划变更、入口变更待确认或核对尚未完成时不能沿用旧的一致状态。采样只比较保护依据，不证明内核对象或外部可达性。模块停用但保留规则后仍核对；空表或已确认移除不需要保护核对。

SSH 监听、实际保护来源或已确认管理地址/ACL 的变化不会自动扩展或删除已确认规则。自动扫描的应用页分开展示保存保护与采样结果；差异可通过对当前已保存版本重新计划、应用及新连接确认更新，无需伪造期望版本变化。管理入口的正式变更继续先受现有策略核对约束；停用入口后仍保留原控制来源的 SSH 保护依据，下一次明确计划决定新保护。

应用动作确认前再次进行新采集并证明候选内核对象，采样不代替该复核。保护依据变化时沿原操作恢复最后确认策略，返回真实 `rolled_back` 结果并要求重新计划；未知读取拒绝确认，原期限和独立超时恢复继续有效。核对使用原期限约束，不延长 120 秒窗口。移除动作不因已经决定删除的保护项变化而重新应用过滤规则，仍核对空表及新连接。页面按实际操作状态提示，不将到期或保护变化后的恢复显示为确认成功。

root 防火墙记录为 3，旧格式不兼容；观察缓存不写入业务库、备份或迁移包。更新保护仍需原模块、权限、本机授权与独立确认，不自动接管 SSH 配置或变更系统服务。

## 移除本应用规则与停用管理

`POST /firewall/plan` 使用 `{"action":"remove","version":已确认运行版本}`，版本取自 `GET /firewall/runtime`，不使用可能尚未应用的期望版本。移除可在模块停用后执行，仍需 root 原宿主机/所有者授权、完整已确认对象证明及目标实际管理连接；不接受附带新策略或原始命令。计划核对来源、SSH、监听及同代次基线，展示将移除的规则数量。提交仍使用 `/firewall/apply`，原动作参与计划和幂等绑定。

移除只以单批事务将本应用拥有的表替换为带独立标记的空表，不保留链、hook、conntrack 例外或入口保护规则。第三方表不在事务范围，任何未知对象或漂移均阻止覆盖。空表登记保留用于以后重新应用；删除本应用规则不等于明确允许端口，其余系统策略和云防火墙仍然生效。期望规则草稿不改写。

移除仍有 120 秒新 TCP/TLS 确认窗口。确认前原运行策略是唯一恢复目标，未知提交、失联、超时、停止或重启均沿原操作恢复；确认后 root 保存“规则已移除”的独立记录，重启或空表缺失只恢复空表，不重新应用旧规则。`Runtime.confirmed_action=none|apply|remove` 区分初始、已确认规则及已确认移除，`confirmed_plan_id/confirmed_operation_id` 固定对应计划与操作；操作响应也包含 `action`。root 运行记录格式为 3，旧格式不兼容。

`PUT /system/modules/firewall` 停用时必须指定 `firewall_rules`。`keep` 明确保留已确认规则；`remove` 另需 `read/security.write` 及已确认的 `firewall_operation_id`，只有原操作仍为当前确认的移除结果且无活动变更才停用；后续应用失败并恢复该空表时仍可引用原确认操作，后续成功应用会使其失效。初始空表经核对且尚无已确认规则时无需生成空的移除操作，可省略操作 ID 直接停用。公共执行提交与最终停用共用锁，防止停用核对期间插入新应用；失败不伪造停用成功，可继续引用同一操作重试。启用或其他模块拒绝携带停用选项。自动扫描的功能模块页面提供保留/先移除选择，防火墙应用页完成移除和新连接确认后提供最终停用；远程转发不执行移除流程。

当前已接入 direct-nftables、firewalld、UFW 与显式 iptables-nft/legacy 的主机入站计划、应用、确认和独立恢复。Docker 实例及端口映射只读报告、显式目标绑定、DNAT/路由核对、独立本机空命名空间授权、首代正反向切换及固定工具/官方预演已接入；代际执行、新连接确认及持久恢复仍待实施。Fail2ban 的独立动作链路见 [Fail2ban](fail2ban.md)。实现与集成源码审阅已完成，未运行构建、类型检查、lint、测试、浏览器、服务或真实规则操作；真实发行版/内核/Docker 矩阵在 P5 集中验证。

接口依据：[firewalld D-Bus](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)、[nftables 手册](https://netfilter.org/projects/nftables/manpage.html)、[iptables-save](https://man7.org/linux/man-pages/man8/iptables-save.8.html)、[Docker 原生 nftables 后端](https://docs.docker.com/engine/network/firewall-nftables/)。

内核格式与规则代次依据：[Linux v6.1 nf_tables UAPI](https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/netfilter/nf_tables.h)、[nf_tables GET/代次实现](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nf_tables_api.c)、[nfnetlink batch 代次前置条件](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nfnetlink.c)。这些源码依据不能替代 P5 真实内核矩阵验收。


Fail2ban 宿主机动作使用独立固定目标 `inet nginxpanel_fail2ban`。共享快照、编码和语义证明通过闭合目标枚举选择布局，不接受调用方表名；人工端口规则的所有公开写入仍固定 `nginxpanel_host`。本机 root 可独立登记、核对、恢复及移除原样空表，采用另一所有者、持久记录、主机锁与操作/CAS，绝不接管已有未登记表；空表无链/hook，不表示保护已生效。预检核对独立登记、目标本机 root 管理/代理保护批准及官方 jail 来源的完整当前采样后，才合并本地保护并排除保护地址生成封禁候选材料，本机 root 一次性同步/清除和持久意图恢复已接入，已确认运行回执接续原登记的当前对象指纹；已批准官方 jail 的独立持续采样会话、同命名空间 Agent 启动核对及持久停用清除已接入；受管面板登录 jail 已接入固定通知模板，主机重启后的安全恢复及其他动作后端仍待完成。详情见 [Fail2ban 宿主机动作](fail2ban.md)。Agent 为 55；实际双目标隔离和内核矩阵留待 P5。

## firewalld policy 配置诊断

`firewalld.policy_inventory` 分别读取官方 `policy.getPolicies/getPolicySettings/getActivePolicies` 与 `config.getPolicyNames/getPolicyByName`、`config.policy.getSettings`，见 [firewalld D-Bus 合同](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)。运行、永久和活动配置分开展示；runtime/permanent 为 null 只表示对应清单未包含该 policy，采集失败则整份 inventory 不可用且不返回成功前缀。配置对象名称支持 policy set 的斜线限定名称，不转换为文件路径。

每项保留目标、优先级、配置字典及活动清单返回的入口/出口 zone、rich rule 数量、配置条目总数、地址伪装标志与完整返回配置摘要，不向 Web 返回原始 rich rules、服务描述或转发地址。活动清单中的 zone 是该活动 policy 的绑定，不证明每个 zone 的接口均处于活动状态。配置条目总数包含服务、端口、源端口、转发端口、协议、ICMP 和 rich rules。摘要包含全部已支持字段、D-Bus 类型、空值及列表顺序；缺省字段与显式空值可能产生不同摘要，不能据此推断规则语义等价。未知字段、签名或结构使采集明确不可用，不忽略未识别配置。

运行与永久 policy 合并后最多 64 项，单份返回字典最多 512 KiB、合计 2 MiB；rich rules 最多 8192 项、其他列表字段最多 1024 项、每对象最多 8192 个规则条目、各方向最多 128 个 zone。采集 policy 最多 1.5 秒，仍受原 firewalld 3 秒与全局 6 秒诊断期限约束；D-Bus 单帧最多 1 MiB、整次 firewalld 接收最多 8 MiB。末尾再次比较清单和活动绑定，再核对服务唯一所有者；同一服务内的读取仍非原子快照，不能代替执行前复核、内核对象证明或新连接确认。

自动扫描的防火墙页面展示仅运行、仅永久、配置摘要一致或不同及活动状态。该诊断不创建 policy、不写规则、不 reload firewalld、不修改运行或永久配置；本机 root 空 policy 登记见下节，业务规则应用、永久确认和独立恢复见末节。Agent 为 73，数据库/迁移归档仍为 32/6；实现待 P5 集中验证。

## firewalld 主机 policy 编译预览

选择 `backend=firewalld` 后，保存仍只更新加密期望。预览使用[官方 policy 模型](https://firewalld.org/documentation/man-pages/firewalld.policy.html)与 [rich language](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html)，生成固定 `nginxpanel-host` policy，入口 `ANY`、出口 `HOST`、优先级 `-100`、默认目标 `CONTINUE`。不选择或重新绑定系统 zone，不创建对象，不采用已弃用的 direct 接口。

只编译启用的主机入站规则。显式入站接口无法等价转成 rich rule，Docker 发布端口也不能改为主机流量，两者均整体拒绝编译；停用项不生成规则。按规范化后的业务顺序和 UUID，依次展开地址族、来源与合并端口区间，每项分配唯一负优先级 `-32768` 至 `-24577`，避免零优先级按动作分链或同优先级无序造成先后语义变化。规范化来源、协议和数字端口进入固定语法，名称、备注和用户表达式不进入程序。

`allow/deny` 分别生成 `accept/drop`，TCP reject 使用 `tcp-reset`，UDP 使用对应 IPv4/IPv6 的端口不可达。`accept` 可能结束 firewalld 后续 zone/policy 的过滤，不能描述成只退出本应用链；其他内核基础链和云安全组仍可拒绝。会话、回环和 DNAT 的先行处理由 firewalld 本身决定；这些 rich rules 不带显式 conntrack NEW 条件，不能沿用 direct nftables 对未跟踪流量的排除声明。

展开最多 8192 项，完整 policy 设置规范 JSON 最多 480 KiB，为返回字典的类型标记、缺省字段和独立身份元数据保留空间。`program_hash` 包含固定 policy 身份、全部设置、所有 rich rules 及其顺序；`settings_bytes` 覆盖完整配置。页面只展示前 128 项，分别列出业务顺序对应的 rich rules 和实际后端优先级；不把 policy 展开数标为内核总规则数或额外加入未生成的保护规则。

预览结合已有宿主机诊断核对单一 firewalld、panic、混合/缺失后端视图、完整 runtime/permanent policy 清单及已有活动 policy 的优先级。同名对象尚无独立登记时拒绝接管，同优先级明确阻塞，先行的其他 policy 保留范围核对提示；诊断缓存不构成执行授权。统一响应的 `firewalld` 只在该后端编译成功时非 null，直接 nftables 的内核表信息保持独立；UFW 在 `expression` 展示命令且后端优先级为 null，其他后端表达式为空。

`compiled=true` 仅代表完整生成，`can_apply` 仍为 false。firewalld 使用独立执行计划、运行/永久配置确认及持久恢复意图，见末节；原 direct nftables 执行器不处理这些 rich rules。跨环境迁移可保存中立期望并查看独立编译限制，仍不自动启用、创建、reload 或应用 firewalld。实现待 P5 集中验证，未执行真实 D-Bus 操作或宿主机变更。


## firewalld 本机 root 空 policy 登记

下列命令须在停止 Agent 后，由真实宿主机 root 明确指定范围。沿用固定宿主机登记锁（跨数据目录）及独立维护准入锁，不提供 HTTP/IPC 写入入口。

```sh
nginxpanel firewalld-init --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel firewalld-registration --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel firewalld-recover --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel firewalld-remove --data-dir /srv/nginxpanel --firewall-scope host
```

`init` 要求完整观察到单一、非 panic 的 firewalld、已知后端和完整内核视图，且没有直接 nftables 登记、运行恢复材料或同名目标表。固定 `nginxpanel-host` 在 runtime 和 permanent 中都必须不存在；不凭同名对象或 description 标记接管。先保存绑定本机身份、随机所有者、原操作、D-Bus 服务及进程身份和固定设置的 root 意图及独立回执，再通过[官方 config.addPolicy](https://firewalld.org/documentation/man-pages/firewalld.dbus.html) 一次性创建永久空 policy。固定 ANY 到 HOST、priority -100、CONTINUE，无 rich rules、端口、服务、转发或 masquerade；其余每个返回字段都必须为文档允许的空值或 false。

永久对象准备完后，root 状态为 `prepared`，独立操作仍待确认；网页/API 的 `firewalld.registration` 显示 `recovery_required`。系统不调用全局 reload，因为它还会激活其他待提交的永久配置。操作者须另行审核本机全部永久配置并自行执行 firewalld reload，再调用 `recover`；仅当完整 runtime/permanent 设置摘要、原随机标记、独立回执和 ANY/HOST 活动绑定均一致时登记为 `registered`。这仅证明空 policy 登记，不证明内核原子性、业务规则生效或外部可达，预览仍不开放应用。

`remove` 仅接受原登记且完整一致的空 policy，记录关联原操作的新意图后调用原配置对象的官方 `remove`，只移除永久对象。运行空对象尚在时为 `releasing`，待操作者审核并自行 reload 后再 `recover`，运行和永久均消失才为 `released`。重复初始化或移除只核对已完成状态；未完成时必须恢复原意图，不能重复写入。直接 nftables 登记与执行也拒绝未释放的 firewalld 登记。

`recover` 只读取 firewalld 并更新原 root 回执，绝不重新提交创建或删除。已持久化但尚未提交的方法可结束为未执行；提交结果未知时，原对象的完整随机标记可证明创建已经发生。对于原服务进程仍在的未知请求，对象暂时缺失不能证明它不会迟到；firewalld 自身的明确异常回执只证明处理已结束，仍须核对对象：新建未留下对象记失败，移除后原完整空对象仍在则保留登记并记失败，异常名称留在原回执。通用超时、NoReply 或断开不算此证明。没有明确回执时，须在本机核对原服务进程已结束（启动身份、PID 和进程启动时间）后，才能结束相应的缺失结果。对象漂移、接口不完整、超限、服务变化或回执冲突保持待恢复，不吞错或自动接管。

未知请求是否还可能迟到，复用 DNS 独立恢复的有界 `/proc` 启动/PID/启动时间核对；仅变更总线名称不构成原处理进程已退出的证明。登记保存在 `agent/firewall/firewalld-registration.json` 及 root 独立操作日志，绑定宿主机 machine-id 摘要；业务备份和跨环境配置迁移不包含这些材料，也不复制源机所有权。D-Bus 使用固定本机系统总线、唯一服务所有者和 NoAutoStart，沿用单帧 1 MiB、总接收 8 MiB、每次连接 3 秒预算，提交前再次核对固定对象和服务身份。firewalld 没有条件写入接口，因此操作期间应避免其他管理员并发修改目标 policy；该登记入口不宣称提供 CAS 或全局原子快照。

本阶段未运行生成器、构建、类型检查、lint、测试、浏览器或真实 D-Bus/宿主机命令，待 P5 集中验证。


## firewalld 策略应用、确认与独立恢复

完成上述空 policy 登记后，本机 root 将 Agent 明确设置为 `--firewall-owner firewalld --firewall-scope host --firewall-ssh openssh --maintenance-scope host`；仅在本机确无 SSH 保护需要时使用 `--firewall-ssh none`。Agent 持有宿主机原登记锁，核对本机身份、原登记操作、随机所有者、完整配置及活动绑定。已有 firewalld 或直接 nftables 业务恢复材料时，新的所有者选择只撤销新操作授权，原执行器继续恢复；两套材料同时存在或记录损坏时报告冲突，不自动接管。

`GET /api/v1/firewall/runtime` 分别返回 `backend`、`can_plan` 和执行就绪的 `available`。firewalld 计划沿用原权限、模块、近期认证和实际受控管理连接要求，支持应用与移除已确认规则。重新采集非回环控制来源、管理允许来源、实际 OpenSSH 监听和 SSH 会话来源，不接受客户端自报保护来源或转发头。DNS、管理监听和防火墙待确认变更串行；维护准入同时核对防火墙待恢复状态。

保护项和业务规则共享 8192 条/480 KiB 完整配置预算，保护项在前，所有展开项采用唯一负优先级；rich rule 使用[官方 Rich_Rule 输出顺序](https://github.com/firewalld/firewalld/blob/main/src/firewall/core/rich.py)。计划核对单一管理器、完整后端、panic、活动 policy 优先级，以及原已确认 runtime/permanent 配置的完整摘要，返回全部计数和前 128 条表达式。`can_apply=true` 还要求实际 D-Bus introspection 确认运行 `setPolicySettings(sa{sv})` 与永久 `update(a{sv})` 接口；不盲试签名，不以文档中额外 timeout 参数代替实际接口。计划有效期 300 秒，最多保留 8 份；配置摘要不冒充内核事务，事务摘要和字节保持空/0。

执行只通过[官方 policy D-Bus 接口](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)更新原登记对象的 `rich_rules`；保留描述、目标、优先级、zone 和其他空设置，不调用 direct、reload、全局 runtimeToPermanent 或创建新 policy。提交前重新核对实际接口、服务唯一所有者、完整配置基线和 panic；本机 root 独立意图先于每次调用持久保存。运行规则逐项调整，不承诺单批原子性。完整回读证明候选运行规则及原永久配置后，重新创建管理监听并关闭其他旧连接，从提交意图开始计算的 120 秒期限由 Agent 持久状态及单调时间共同约束。

确认必须经候选生效后新建的目标管理 TCP/TLS 连接，重新检查 SSH/保护来源、管理器/优先级和完整候选配置；通过后才写永久规则并完整回读两份配置，再持久保存确认结果。移除同样先清空运行 rich rules、新连接确认后清空永久 rich rules，仅保留原空 policy，不删除全局 firewalld 或影响其他 policy。停用管理可保留规则；按移除方式停用须引用当前已确认的移除回执，初始空登记无需虚构移除操作。管理监听修改在核对已确认完整配置后，再检查候选端口及所有允许来源不会被本应用规则拒绝。

`agent/firewall/firewalld-runtime.json` 保存本机/原登记身份、原确认与候选策略、保护依据、操作期限、两份完整配置回执及每次调用的总线和进程身份；上限 2 MiB，操作摘要与 root 日志一致。调用成功或 firewalld 自身明确异常回执证明处理结束；超时、断连或仅总线名称变化均不构成证明。结果未知时禁止重放或覆盖，等待原进程的启动/PID/启动时间证明其结束后再恢复；本机 `firewall-rollback` 可请求恢复，也遵守这一约束。

未确认、期限已到、控制通道中断、Agent 停止或重启均恢复最后确认的运行和永久配置；重启不续做未确认候选。恢复先处理运行规则，再处理永久规则，只接受原登记完整设置和持久旧/新程序中的精确表达式子集，以容纳逐条写入的部分失败；第三方规则、元数据漂移、对象或活动绑定缺失均保留待恢复，禁止盲目覆盖或重建。已确认配置每 30 秒核对，原受管规则缺失时仅恢复有原业务意图且可证明的规则；不重建缺失的 policy，不自动接管同名对象。恢复与保护采样不依赖 serve 或模块启用，也不因撤销新操作授权停止。诊断 `managed` 表示已确认配置及独立回执通过，候选或未知调用期间保持未核对状态。

`accept` 可能结束后续 firewalld 过滤，其他内核链和云安全组仍可能阻止连接；会话、回环和 DNAT 先行处理由 firewalld 决定，不声称只匹配 NEW。原空登记命令不负责业务材料退役，有业务恢复材料时禁止重新登记或移除原登记。root 材料不进入跨环境配置迁移，目标节点仍须独立登记及应用。Agent 为 73，数据库/迁移归档仍为 32/6。实现及源码审阅完成后集中整理格式，未执行生成器、构建、类型检查、lint、测试、浏览器或真实宿主机操作，待 P5 集中验证。


## UFW 用户规则、编译与保护计划

诊断增加 `ufw.ipv6` 和 `ufw.rule_inventory`。Agent 只运行固定的 `ufw show added`，使用受信绝对路径、固定 C 语言环境、两秒命令期限及 2 MiB 输出上限。用户规则报告须完整符合已知格式，最多 8192 条、每条最多 4096 字节；未知内容、控制字符、无效 UTF-8、失败或超限均返回不可用，不返回成功前缀。公开报告仅展示前 128 条且最多 64 KiB，保留完整报告计数与 SHA-256。启用及 IPv6 配置分别从 root 持有的固定文件读取，未知或歧义保留 null；不求值 shell 内容。

官方 `show added` 会合并部分相同双栈命令，汇总顺序也不等于各地址族完整内核顺序。报告文本仅供诊断展示，不能重放、据此恢复内核、推断完整系统策略或认领含本应用注释的第三方规则。状态、配置、用户报告及内核结构为独立读取，不承诺原子快照。

UFW 编译支持启用的 `host_input`、TCP/UDP、单端口/范围、IPv4/IPv6/双栈、来源、接口和 allow/deny/reject，沿中立策略的优先级及稳定 ID 顺序生成参数数组。任意来源和目标显式写为对应地址族的 `/0`，避免隐式扩展另一地址族。编译注释使用固定前缀、规则 ID 和匹配条件摘要；业务名称及备注不进入参数。命令预览来自生成参数，不通过 shell，报告文本不进入编译器。`program_hash` 覆盖全部参数和顺序，最多 8192 条及 2 MiB 规范参数 JSON；页面只展示前 128 条。

UFW 添加相同匹配条件可能更新原动作或注释，不能用不同注释保留重复规则。因此编译器拒绝同地址族、协议、规范来源、目标端口及接口的重复匹配项，即使动作不同。此检查只排除本次期望内部重复；现有第三方规则冲突及插入位置仍须在执行链路独立核对。Docker 发布端口明确阻塞；不把 INPUT 命令视为 FORWARD 保护。

逻辑预览核对单一已启用 UFW、完整用户报告、混合/缺失内核视图、绑定接口及 IPv6 配置。`generated_rules` 表示生成命令数，后端优先级为 null，不增加未生成的会话或回环规则。UFW 自身的默认策略、会话与回环处理保持不变；allow 可能提前结束后续 UFW 规则，其他内核链及云安全组仍可拒绝连接。

本机 root 先使用与 Agent 相同的规范绝对数据目录完成初始授权：

```sh
nginxpanel ufw-init --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel ufw-registration --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel ufw-recover --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel ufw-remove --data-dir /srv/nginxpanel --firewall-scope host
```

UFW 没有独立空 policy 对象，此登记只授权空规则命名空间，不创建任何规则，也不调用 enable、reload、reset 或删除命令。初始化要求完整确认单一启用的 UFW、全部后端视图、无直接 nftables 目标表、无其他登记/业务恢复材料，且固定配置中不存在本应用明文或十六进制标记。第三方已有规则保留；相同标记不能提供所有权证明，发现标记但无原写入回执时拒绝接管或释放。

随机所有者、本机 machine-id 摘要、原操作、前后宿主机占用及配置/工具基线保存在 `agent/firewall/ufw-registration.json`，独立回执存入 root 操作日志。固定 `/var/lib/nginxpanel-host/ufw-owner.json` 在进程退出后仍阻止不同数据目录分别接管同一宿主机，登记、计划和释放共用原跨目录宿主机锁及维护准入。操作先保存原意图/回执，再核对和发布宿主机占用，源配置在前后核对中变化则保持待恢复。释放先发布不可再授权的 `releasing` 占用，终态本机回执完成后才发布 `released`；中断后 `recover` 续办同一元数据意图，不重放 UFW 写入，不覆盖其他所有者。完成释放后的宿主机复用不依赖旧数据目录继续存在，原审计回执不被本操作删除。重复操作只核对原结果。

授权释放仅允许当前固定配置无本应用标记；业务规则须单独移除，不由授权释放代办。已授权元数据不证明任何规则已经安装；计划还须重新核对真实管理连接、工具、配置和候选结果。直接 nftables/firewalld 新登记和新执行器会拒绝未释放的 UFW 占用；原已接受的其他后端恢复继续执行，仅撤销冲突的新写入授权。待恢复的 UFW 元数据操作阻塞同一节点新的可达性/维护变更。

完成本机授权后，root 明确设置 `--firewall-owner ufw --firewall-scope host --firewall-ssh openssh --maintenance-scope host` 后，运行状态返回 `backend=ufw`；`can_plan` 表示可尝试准备计划，`available` 还须重新核对当前本机授权、用户配置及运行状态。准备或恢复在途时 `available=false`。确无 SSH 保护需求时才选择 `--firewall-ssh none`。`POST /api/v1/firewall/plan` 可准备已保存策略的 apply 或原已确认版本的 remove 计划，须近期认证并直接使用目标已确认的管理 HTTPS 连接；apply 还须启用模块。移除不附带新策略，由 Agent 从原确认回执取回策略；运行状态只投影当前本机授权下、与 root 回执一致的已确认选择及原操作。采集实际连接、受控来源及 OpenSSH 监听，保护项先于业务项。重复保护合并；业务条目与保护匹配条件完全相同时由保护项覆盖，单独报告计数。既有 nftables/firewalld 恢复材料仍由原执行器处理，不因选择 UFW 撤销原恢复职责。

UFW 计划通过同一 POST 接口创建后台准备，立即返回 `preparation` 的固定 ID、动作/版本、进度和原期限；携带 `preparation_id` 查询原结果，附加 `cancel_preparation=true` 取消在途准备。创建和取消须近期认证，纯查询保留读取与安全写入权限检查，不因持续轮询而再次要求近期认证。准备不依赖原 HTTP 连接存活，不长期持有 DNS、管理监听或防火墙状态互斥锁；在途准备阻止新的可达性变更、应用及维护。完成后重新核对原监听版本、实际 SSH 监听及保护来源，计划另有 300 秒有效期，最多八份。页面可重新打开并查看进度及取消；Agent 重启保留失败原因，不恢复私有写入授权或自动应用。最新准备摘要保存在 root 私有 `ufw-preparation.json`；摘要损坏只阻止新受理，不阻止原业务恢复。停止、救援或控制通道丢失会取消准备。

计划期间独占跨数据目录的宿主机登记锁，绑定原登记操作及宿主机占用；注释包含原随机所有者、计划 ID 和规则摘要，完整程序摘要随绑定更新。读取受信 UFW CLI 及固定 `/etc/ufw/{ufw.conf,user.rules,before.rules,after.rules,user6.rules,before6.rules,after6.rules,sysctl.conf,before.init,after.init}`、`/etc/default/ufw`，必需文件缺失或不受信则拒绝；IPv6 规则文件在 IPv6 启用时必需。每份最多 2 MiB、合计最多 4 MiB，摘要包括内容、存在性及文件身份/时间；`tool_hash` 单独标识 CLI 文件。

从受信 CLI 的已知 Python 3 shebang 绑定解释器，以 `-I -S -B` 隔离用户环境、当前目录和 site 自动初始化。定位器只通过 `site.getsitepackages()` 与 `PathFinder` 查找常规系统 UFW 源包，不执行 UFW 模块或 `.pth/sitecustomize`。同包的 `__init__`、applications、backend、backend_iptables、common、frontend、parser、util 八份受信 `.py` 原文与 CLI 一起复制到私有目录；描述与每次预演只导入这些固定源文件，拒绝 UFW 导入逃逸，不读取宿主机 UFW 字节码。标准库及系统共享库仍由系统安装提供，不声称完整操作系统依赖闭包。

从固定源码的 `ufw.common` 描述读取编译路径，要求启用完整性检查、配置目录为 `/etc`、状态目录为 `/lib/ufw` 或 `/usr/lib/ufw`、后端目录为 `/sbin` 或 `/usr/sbin`。绑定该后端目录的 IPv4/IPv6 command、save、restore，状态目录的 ufw-init，以及固定 PATH 首个 cat/false；不绕过不受信的同名遮蔽。工具每份最多 16 MiB、源文件每份最多 512 KiB、绑定材料合计最多 64 MiB，绑定摘要包含内容、调用/解析路径、文件身份/时间、解释器版本、声明配置和固定辅助程序摘要。预演后重新读取原路径及文件核对，变化则拒绝；该前后观察不提供原子锁定，也不授权调用 ufw-init 或真实规则写入。

官方 UFW 的插入、删除等路径可能通过 `iptables-restore --noflush` 重载全部已启用地址族的用户文件，同时刷新用户日志链。因此计划在累积预演前后另行核对完整重载范围，不能只核对新增入站规则。使用同次绑定的实际 IPv4/IPv6 command、save、restore 路径读取版本，后端须一致且与本次完整管理器观察相同，不从 PATH 或默认命令版本猜测后端；读取规则使用绑定的 save 工具，禁止 modprobe 回退。每次最多两秒、1 MiB 标准输出及 8 KiB 标准错误，任何警告均拒绝。完整导出须结构有效，包括其他表；只比较固定 filter 用户链的规则，不将其他表、Docker 或 Fail2ban 规则纳入重放材料。

每个启用地址族核对最多 16 个可能被重载的入站、出站、转发、日志及限速链，原运行规则须与同次读取的持久用户文件一致。按 append/prepend 语义计算原生文件的链内顺序；存在的链须为普通用户链，缺失链不能遗漏非空源规则。比较只支持 UFW 显式条件及标准日志/限速展开的 TCP、UDP、multiport、conntrack、limit、recent、comment 匹配和固定目标。规范化地址、协议、传输匹配的隐式加载、已知 LOG/REJECT/limit/recent 默认参数与等价限速单位，保留匹配模块顺序及其全部选项；不对有状态模块重排，不按注释认领规则。未知扩展、参数、目标、错误编码、额外运行规则、顺序或内容不一致均保持只读并拒绝计划。每条规则最多 128 个词，源与运行报文规则均有 8192 条预算；前后重载摘要须一致，不因计数器及导出时间变化误判规则漂移。实际执行前仍须重新绑定和复核，当前观察不证明全局内核原子性。

同次受信读取的固定配置原文复制到 `/run/nginxpanel-host` 下的私有目录，使用官方 `--datadir=<私有目录>` 重定向配置读取，不需要挂载命名空间或增加权限。私有配置及父目录分别使用 0600/0700；只创建固定路径，不接收用户路径。生成参数只使用显式数字选择条件，不调用应用配置命令，因此私有 `applications.d` 为空；既有应用 tuple 及报文规则仍须完整保留，不据此忽略或删除旧规则。

原已确认程序和包含保护项的候选程序分别最多 8192 条，合计最多 16384 次预演。先重新编译原 root 确认记录，并核对当前用户文件中每个受管 tuple 及完整报文块的内容、顺序；允许其他来源规则穿插，不以编号或单独注释认领。缺失、重复、改写或未知本应用标记均拒绝，包括非用户文件及未启用 IPv6 文件中的标记。私有副本的官方 CLI 固定使用 `--datadir=<私有目录> --dry-run delete ...` 删除原类型化参数，再按目标顺序逆序执行 `--dry-run prepend ...` 添加候选；移除计划只删除原程序。每步删除须恰好去掉一个原受管完整块，并保留其余全部块的内容与相对顺序；新增须核对首块及全部旧块。执行器不提供真实 CLI 写入模式。

同一准备使用一个固定源码的隔离 Python 进程，以封闭的逐行 JSON 请求依次调用官方 CLI 的 delete/prepend dry-run。每次 CLI 创建新的前端/后端实例读取当前私有文件；通过官方 `util.msg_output` 同时捕获消息与基于文件描述符的规则输出，禁止用重定向 stdout 破坏官方 fileno 语义。Go 完整核对当前候选并更新私有文件后才发送下一条命令；严格握手、帧预算和无额外输出的正常退出均须核对，进程输出不是宿主机写入许可。

每次完整候选核对通过后，仅将官方输出中的原生用户文件原子替换到私有副本，下一步读取该累积结果；最终按地址族核对新程序前缀及其余来源规则的原内容和相对顺序。每步最多两秒、原始输出 5 MiB、标准错误 8 KiB，删除和新增的原始输出累计处理最多 4 GiB；逐帧处理并释放，不累计保留全部原文。JSON 响应帧最多 30 MiB，每份累积候选最多 2 MiB，并受原后台准备的 300 秒总期限约束。使用固定 C 环境、禁写 Python 字节码及私有 TMPDIR，遗留目录达到 16 份时拒绝新增。任意命令失败、超时、警告或超限均拒绝整份计划；退出码零仍须核对完整已知候选格式、完整原生表达式及对应地址族的更新结果。`prepend` 对已有匹配项会跳过，缺少新候选时判为冲突。完成后有界核对私有目录的完整文件清单、固定源码、全部配置内容及存在性，额外文件、源码/配置意外改写或清理失败均不发布部分结果。预演前后重新核对宿主机固定源文件、工具路径/摘要、本机授权及原确认记录，变化则拒绝；不写宿主机 UFW 配置或规则。

UFW 根据 tuple 重建用户文件，普通注释只保存在 tuple，并不进入内核报文表达式。计划使用同次受信读取的 `user.rules/user6.rules` 内容逐块核对：新增首块须与类型化生成参数的地址族、来源、接口、TCP/UDP、单端口/范围和动作完全对应，TCP reject 还须生成 RST；其余 tuple 及对应全部报文规则必须保持原顺序、原内容。新增块夹带规则、旧块丢失/重排、无报文 tuple、未绑定 tuple 的自定义原生规则或未知文件结构均拒绝，不根据注释认领规则。既有与生成 tuple 合计最多 8192 条，完整生成原生规则材料受 2 MiB 预算约束。

日志段须保持一致；限速段变化仅允许官方 dry-run 固定 IPv4 开启、IPv6 关闭的能力默认值与源文件不同，且只涉及精确已知的限速链及标准辅助规则，单独提示待核对。精确匹配官方空初始模板时允许预演生成标准链、日志及限速段；任意自定义空文件不作为初始模板。最终候选保留原日志与限速辅助规则，不能把 dry-run 的能力默认值当成实际写入或内核能力；数值型入站规则不需要触发真实能力探测。投影后再次核对完整用户块、顺序和重载表达式，未知变化均拒绝。

累积 dry-run 核对的是隔离文件批次，不证明候选已生效或第三方规则所有权。UFW dry-run 本身跳过普通 UFW 写入锁，宿主机前后摘要仅检测漂移，不提供原子锁定。计划 `ufw` 字段增加源码与工具绑定摘要 `toolchain_hash` 和解释器版本 `python_version`，并展示配置、CLI、按实际执行顺序计算的完整预演输出摘要 `dry_run_hash`、按目标顺序计算的原生材料摘要 `native_program_hash`、保留的非本应用原生 tuple 数量 `preserved_rules` 及命令/保护计数；`batch_hash` 使用 v3 摘要域，绑定原配置基线、源码与工具、完整原生程序、各步输出和最终两个用户文件的内容摘要、大小及存在性。`reload_backend/reload_hash` 标识本次原运行重载范围及绑定的 command/save/restore 版本，使用 v2 摘要域保留每个固定链的存在性和有序规则；`reload_chains/reload_rules` 展示实际存在的用户链和报文规则数量，后者包含日志、限速规则，与 tuple 数量不同。私有临时目录在预演结束后清理，计划材料本身不作为持久执行回执。

root 私有计划保留已核对地址族的原用户文件、完整候选、配置身份清单、全部工具绑定及原/候选内核链镜像，随原最多八份计划过期释放；不通过 API 返回原文件。封闭重载程序仅声明两个状态涉及的固定 UFW 用户链；恢复时撤销本次新增而原先不存在的链，不重放内置链、其他表、第三方跳转或历史计数器。全部输入、原生块保留、辅助规则、链存在性及双向程序均须通过原策略的重新编译核对。

私有受理器先核对原本机授权、配置、工具及全部原内核状态，再保存 `agent/firewall/ufw-change.json`（最多 64 MiB，修复快照同限）及 root 父业务回执。快照冻结原转换、确认期限和每个地址族/方向的独立调用 ID；后续状态推进不得改变原意图或重开终态。底层传输不接受调用方提供的规则、路径或材料，只从原快照选择对应调用。候选须仍在执行期限内，恢复只允许原补偿状态；固定参数为 noflush、有限 xtables 等待和禁止模块加载。正常 Apply/Decide 调度已接入，仅完整准备并重新核对通过的私有计划可受理；准备中、失败、取消或失效的计划不授予写入。

正常应用流程在独立业务锁下受理并提交各地址族，原/候选内核镜像相同则不重复写入；受理后不依赖原 API 请求继续存在，执行仍受原确认期限约束。完整核对内核候选及原持久文件后，才发布等待确认并重建管理监听，关闭其他旧连接。确认要求来自新监听的非回环 TCP/TLS 连接、当前管理监听版本，以及未变化的保护来源、管理器、配置和全部内核镜像。先保存新连接来源和持久化阶段，再安装文件；最终持有宿主机登记及官方 UFW 锁核对全部候选文件与内核后发布 `succeeded`。确认检查点已保存而父回执发布中断时只修复该回执，不重开终态或改为回滚；检查点尚未确认则补偿原操作。

受理、提交及最终恢复核对使用官方 `/run/ufw.lock`。UFW 使用 POSIX `lockf`，此处使用与之互斥的 Linux OFD 写锁，不能用互不相干的 `flock` 替代。固定锁文件须为 root 持有的单链接普通文件，重新核对原路径/inode；同一打开描述符传给子进程并保留到退出，父进程退出不会提前释放仍在运行的子进程所持锁。锁只排除遵守它的 UFW 操作，直接外部写入仍须由内核前后核对发现。

UFW Agent 另持有独立的 `ufw-agent.lock`，防止另一个 IPC Socket 启动的 Agent 将仍在等待确认的操作误判为崩溃并恢复；该控制器锁不替代逐操作业务锁、登记锁或官方管理锁。本机 root 的原操作恢复/救援仍独立可用。正常确认窗口内不执行例行补偿；超时、明确回滚、救援、控制通道或监听丢失、Agent 停止及错误状态才补偿，失败按原操作有界重试。启动不恢复旧确认监听证明，立即补偿所有未确认操作，不延长原期限。救援 ID 保存在原检查点并跨新操作继承，不重复处理已完成请求。

最新子进程检查点使用 `agent/firewall/ufw-execution.json`，每次调用另在原 root 操作日志保留 `firewall.ufw.restore` 回执。意图绑定父操作、原登记、宿主机、地址族、批次/程序/工具与输入摘要、固定许可程序及工具文件身份。先落盘 `prepared`，再启动只等待一次性管道许可的隔离 Python 子进程；PID、boot ID 和启动时间进入 `permitted` 检查点及审计回执后才发送许可。随后同一进程以固定文件描述符 exec 受信 restore ELF，保留原调用名供 xtables multi 使用；固定 false 描述符阻止 modprobe 回退。解释器、restore 和 false 均重新核对，拒绝 set-id、文件能力及未知能力属性；父线程保持到子进程结束，并设置父进程死亡信号。无许可时 EOF 不会执行工具；许可发布后的中断按未知结果处理。

每个进程最多三秒，标准输出/错误各 8 KiB，只有完整、无输出或警告的成功退出才记录进程成功；这不证明内核规则已生效。相同调用 ID 只读取原回执，不重新提交；不能确认结束时保留原许可。Agent 启动、独立循环/停止及本机 `ufw-recover` 先以 boot ID/PID/启动时间和 pidfd 只终止原进程实例，等待结束后保留未知结果。子进程终态不会直接结束父操作。

root 业务快照 schema 为 3，绑定原已确认选择、原文件内容/属主/模式/扩展属性、已完成救援 ID，以及每个地址族候选和恢复临时文件的独立 ID。候选持久化函数要求先保存有效的新连接来源和原确认期限；先在 `/etc/ufw` 创建排他临时文件，完整写入并同步内容、ACL 与安全标签，再将 inode、设备、时间及完整属性回执保存到原 root 意图，之后才原子替换固定用户文件并同步目录。准备回执一经发布不得更换；中断后的原临时路径只按冻结意图核对清理，不能认领内容相同的其他文件。全部候选文件和内核镜像须完整回读，才能供上层发布确认结果。该函数由新连接确认流程调用，发布失败先读取实际检查点，再决定补偿或修复确认回执。

原业务恢复先持久化补偿方向，并在官方管理锁下先恢复已由本操作替换的持久文件，再逐地址族恢复内核。当前文件只能是原文件或本次已记录 inode 的候选/恢复文件；外部修改不覆盖。未安装的部分临时文件按原 ID 清理，恢复文件准备中断可续办；保留原内容、属主、模式、ACL 及安全标签。内核完整镜像须等于原状态或原候选：已恢复的不写入，仍为候选的只执行原预分配恢复调用，其他状态拒绝覆盖。执行前重新核对固定配置、工具和全部地址族；结束后核对本地址族，最终在官方管理锁下重新核对全部原内核及恢复后的持久文件，才发布父操作 `rolled_back`。原进程未结束、配置/工具漂移、额外规则或回执冲突均保留 `recovery_required`，不以成功退出或缺失回复代替内核结果。发布中断从原快照修复同一回执，进程/父操作未结束时继续阻止计划、授权释放及维护。

确认后的启动及周期核对会重新编译原确认记录，对当前持久用户文件证明所有权，并核对其全部运行镜像；允许其他来源规则合法变化，不重放历史第三方快照。官方状态/报告读取在 OFD 锁前完成，锁内重新核对启用/地址族配置、绑定工具、固定源文件及内核。只有运行镜像能证明仅缺失原确认入站规则时才修复；额外、重排、缺失第三方规则、重复选择器造成的身份歧义、原生受管块变化、缺失入站链、管理器停用或绑定工具变化均保持只读。修复载荷只含原确认程序派生的带位置 `-I`，不声明或清空链、不重建管理器钩子、不改写持久文件；位置由当前完整配置与内核投影计算。管理监听变更继续使用该独立确认记录和当前运行核对。

修复使用独立 `agent/firewall/ufw-repair.json`（schema 1）与 `firewall.ufw.repair` 元数据回执，绑定原 root 确认检查点、当前配置文件身份、工具摘要、各地址族原镜像和预分配调用 ID。原成功业务回执保持终态。子进程回执 schema 为 2，增加封闭的 `repair` 目标，仍通过固定描述符、持久 PID 许可和官方管理锁执行；API 不能提交修复报文。中断先结束原进程并修复回执，再核对完整原/修复后镜像；已完成部分不重复插入。未知或未开始结果仅在原镜像重新证明后使用另一预分配 ID，每地址族最多三次；已返回但没有修复结果的调用不自动重试。未知漂移保留 `recovery_required` 并阻止新计划、授权释放和维护。当前配置或运行基线变化时，只有重新证明当前全部第三方规则及受管原生块后，才能将旧修复记为 `superseded`（操作回执为 `cancelled`），由当前基线另建意图；不把旧意图改报成功或绕过未变化基线的失败限制。最终全地址族、固定源和工具核对后才发布修复成功，发布中断从原检查点续办。

本机 `ufw-recover` 接入未确认补偿和确认规则修复；`ufw-registration` 返回独立 `repair` 摘要及回执核对原因。只读登记视图支持 `managed`，须核对原确认记录、当前原生配置及全部运行镜像，不以标记接管；该状态不授权新写入。修复材料和回执不进入备份或迁移。

正常应用、新连接确认、持久化、确认规则缺失修复和新写入准入已接入；准备完成的计划返回 `can_apply=true`，应用时仍重新核对期望版本、入口保护、本机授权、完整配置/工具与内核基线。运行视图在空授权范围或已移除状态下须重新核对当前配置，不凭旧回执按移除方式停用管理。官方非 dry-run 能力探测会创建和清除临时内核链，底层传输不调用该路径，也不据工具绑定自动授权它。上述条数、字节及期限是实现边界，不代表已完成千条规则容量验收；工具升级不自动更换原绑定。迁移只保存中立期望，不复制本机登记、宿主机占用或 root 回执，在目标另行授权并准备保护计划。Agent 为 86，数据库/迁移归档仍为 32/6，无旧合同兼容；Nginx Docker 模块仍在镜像中预置。实现与源码审阅完成，未运行生成器、构建、类型检查、lint、测试、浏览器、真实 UFW/iptables 命令或宿主机变更，API 生成产物及行为统一待 P5 集中验证。

依据：[Ubuntu UFW 手册](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html)、[Ubuntu 官方 UFW 0.36.2 源码归档](https://archive.ubuntu.com/ubuntu/pool/main/u/ufw/ufw_0.36.2.orig.tar.gz) 中的 CLI `--datadir`、`util._findpath/create_lock/open_files/close_files`、`applications.get_profiles`、`frontend.get_show_added`、`UFWCommandRule.get_command`、`UFWRule.match/format_rule`、`_read_rules/_write_rules`、`initcaps`、`conf/user.rules` 与 `conf/user6.rules` 及后端规则更新流程。

重载和格式核对依据另含该 UFW 源码的 `set_rule/_reload_user_rules/_get_logging_rules`、[上游 iptables-restore 手册](https://man7.org/linux/man-pages/man8/iptables-restore.8.html) 对 noflush 下仍重建已声明用户链的说明、[iptables-save 手册](https://man7.org/linux/man-pages/man8/iptables-save.8.html)、[扩展手册](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html) 及 [Netfilter 官方 iptables 1.8.11 源码](https://www.netfilter.org/projects/iptables/files/iptables-1.8.11.tar.xz) 的 `iptables-restore.c` / `xtables-restore.c` 无链声明命令派发、`xshared.c` 插入位置解析，以及 TCP/UDP、multiport、conntrack、recent、limit、LOG 和 IPv4/IPv6 REJECT 扩展保存/默认值实现。

Python 隔离及源包定位依据：[命令行选项](https://docs.python.org/3/using/cmdline.html)、[site 模块](https://docs.python.org/3/library/site.html)、[importlib](https://docs.python.org/3/library/importlib.html)。

进程许可与恢复依据：[Python execve 描述符及进程替换语义](https://docs.python.org/3/library/os.html#os.execve)、[父进程死亡信号](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)、[pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)、[pidfd_send_signal](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html) 与 [Linux OFD/POSIX 文件锁互斥和继承语义](https://man7.org/linux/man-pages/man2/F_OFD_SETLK.2const.html)。


## iptables 主机入站编译

`iptables-nft` 与 `iptables-legacy` 使用独立的类型化参数编译器，按规范业务顺序展开 TCP/UDP、单端口/范围、来源、入站接口及 IPv4/IPv6；仅为实际使用的地址族生成规则。每族先返回回环和 ESTABLISHED/RELATED 流量，保护项先于业务项；业务规则仅匹配 conntrack NEW。allow 使用 ACCEPT，可能提前结束调用链后续过滤；deny 使用 DROP，TCP reject 返回 RST，UDP reject 使用对应地址族的端口不可达。未匹配流量返回调用链，不修改全局 INPUT 默认策略。逻辑目标为 `filter/NGINXPANEL-HOST`，名称和注释不构成所有权证明，不生成链创建、跳转或宿主机写入。

全部生成规则含基础返回与入口保护合计最多 8192 条，完整参数及目标身份 JSON 最多 2 MiB，摘要覆盖所选后端、完整顺序和两个地址族；页面显示每族显式工具名、数量、总字节及前 128 条业务表达式，不依赖默认 alternatives 推断显式工具。逻辑预览复用完整五份内核视图，核对单一管理器、目标后端、显式 command/save 观测和 filter/INPUT 默认策略；混合后端、读取不完整或同名链存在时给出明确原因，已有 INPUT 规则及默认 DROP 单独提示。编译不探测/加载内核扩展，也不证明规则能被执行工具接受。

跨环境迁移复用同一编译及环境检查，只保存中立期望；接口仍须显式映射，源配置不授予目标规则所有权。逻辑预览保持 `can_apply=false`，实际执行须使用下述独立代际计划、限时应用与原操作恢复链路。Docker 发布端口不转换为 INPUT，转发挂接与原始目的连接跟踪另行适配。管理入口的中立策略判定已接入各后端保护编译，包括 UFW；这只核对本应用对新连接的处理，不证明其他系统规则或外部路径可达。

语义依据：[iptables 官方手册](https://man7.org/linux/man-pages/man8/iptables.8.html)、[conntrack 与 REJECT 扩展手册](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)；Docker 转发边界见 [Docker iptables 文档](https://docs.docker.com/engine/network/firewall-iptables/)。本阶段未运行生成器、构建、类型检查、lint、测试或真实 iptables 命令，行为与容量待 P5 集中验证。


## iptables 本机空命名空间授权

本机 root 可显式登记 `iptables-nft` 或 `iptables-legacy`；不根据默认 alternatives 选择后端，不修改其设置，不创建链、不加载内核模块、不安装规则。须在真实宿主机范围操作，并与其他防火墙登记/执行器共用宿主机锁：

```sh
nginxpanel iptables-init --data-dir /srv/nginxpanel --firewall-scope host --firewall-backend iptables-nft
nginxpanel iptables-registration --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel iptables-recover --data-dir /srv/nginxpanel --firewall-scope host
nginxpanel iptables-remove --data-dir /srv/nginxpanel --firewall-scope host
```

初始化必须明确后端；其他操作沿用原登记，不接受替换后端。原登记未释放时不能改用另一个后端。登记/释放前核对完整五份内核视图、无启用管理器、无直接 nftables 目标表、其他本机授权及恢复材料，以及两后端/双地址族原生导出中的目标链、引用和 `nginxpanel:host:` 标记。任何未知或不完整读取均阻止授权；不是凭空链、名称或注释认领原规则。外部规则按完整参数和顺序做前后漂移核对，时间头和包计数不参与配置摘要。

独立 root 意图及回执保存在数据目录的 `agent/firewall/iptables-registration.json` 和 `agent/operations`；`/var/lib/nginxpanel-host/iptables-owner.json` 持久绑定宿主机、数据目录、后端及原操作，防止其他数据目录重复授权。释放先发布中间占用、再保存终态回执、最后发布释放墓碑；崩溃后只核对原意图，不重放任何规则命令。未完成登记/释放阻止新的维护及可达性操作；其他防火墙新授权/执行拒绝尚未释放的占用，已受理操作仍按原恢复路径处理。

宿主机诊断 API 的 `iptables_registration` 及防火墙页面显示后端、授权和本次核对；`registered/verified` 证明当前空命名空间授权，`managed/verified` 证明已确认策略的完整代际、固定工具及原独立回执一致，二者均不证明外部入口可达。迁移预检核对目标自己的授权，源机占用、root 授权与回执不迁移。主机入站应用、更新、移除、新连接确认、持久保存及缺失规则修复已接入，通过独立完整准入的计划返回 `can_apply=true`；Docker 转发仍未适配。实现及源码审阅完成，生成器、构建、类型检查、lint、测试、浏览器与真实主机操作均待 P5。


## iptables 代际计划

在完成本机空命名空间授权后，Agent 须显式配置 `--firewall-owner iptables-nft` 或 `iptables-legacy`、`--firewall-scope host`、`--maintenance-scope host` 和本机确认的 `--firewall-ssh openssh|none`。通过目标实际管理 HTTPS 连接生成 apply 计划，root 固定原授权与回执，采集当前管理入口、OpenSSH 监听及来源保护，并在前后两次完整环境读取一致时保存计划；只读计划五分钟有效，最多保留八份。更新及移除绑定原确认来源与独立成功回执，复用原工具，不因重新计划更换工具；移除使用原确认版本，不要求期望草稿仍为该版本。

逻辑编译结果转换为固定入口链 `NGINXPANEL-HOST` 和包含随机所有者、计划及完整逻辑摘要的代际链。INPUT 跳转计划位于首位，入口链只保存一个精确指针；基线 RETURN、入口保护与业务规则均携带完整代际身份。生成规则数包含跳转和指针，最多 8192 条，完整代际程序最多 2 MiB。ACCEPT 可能结束后续 INPUT 判断，不表示其他过滤路径或云安全组允许。

原生完整导出保留各链规则顺序及所有参数，第三方扩展只参与不透明读取与漂移核对；跨链声明顺序、计数器和导出时间不参与摘要。初始候选仅生成失败即停止的 `-N` 建链、受管追加和首位跳转，不声明或刷新已有用户链；反向材料仅精确删除本次跳转、指针及生成规则，再删除空受管链，不重放第三方历史规则或全局策略。完整原始/投影镜像和双向批次保留在 root 私有计划，正反批次合计最多 4 MiB，整个私有计划最多 16 MiB；Web/API 只返回摘要、计数与目标链。

初始代际计划已接入下述固定工具、官方预演及完整 nft JSON 候选容量准入，`can_plan` 与 `available` 分别表示可尝试准备和执行就绪。持久执行意图、子进程回执、确认及独立恢复见下节；官方 go-iptables 链读取、原生完整导出及容量准入均通过后，计划返回 `can_apply=true`，root 应用入口仍重新核对原计划。运行就绪状态须重新读取当前受管范围和固定工具，空授权及移除确认均不能仅凭旧回执允许停用模块。两个地址族不承诺共同原子性，Docker 转发仍未适配。迁移保留中立期望，在目标重新授权并准备，不迁入上述 root 材料。生成器、构建、类型检查、lint、测试、浏览器及真实主机命令仍待 P5 集中验证。


### 固定工具与官方预演

每个初始计划固定所选后端的 IPv4/IPv6 command、save、restore 及模块加载阻断工具；从固定系统目录选择首个既有命令，不绕过不可信遮蔽，不使用默认 alternatives。绑定原调用名、解析路径、散列、inode/设备、大小、权限及修改时间，要求受信普通 ELF、无 set-id 或文件能力；六个后端工具须报告相同后端及发行版本，并核对各自 command/save/restore 与 IPv4/IPv6 版本标识；接受官方版本输出中的规范工具名或相同显式后端名。原生工具合计最多 64 MiB，每份最多 16 MiB；另固定本程序作为子进程入口，最多 128 MiB，其身份也进入工具摘要。系统共享库和 xtables 扩展仍由宿主机提供。

调用从固定描述符执行，并保留原始 argv[0] 供多功能 ELF 选择 applet；显式模块加载也指向固定阻断工具的描述符。只读传输仅允许版本、完整规则导出、受限 filter 链读取和无条件带 `--test --noflush --wait 1` 的 restore；实际写入使用下述独立父操作与子进程许可。每次两秒、规则导出 1 MiB、链读取 2 MiB（含最大位宽计数器余量）、其他输出最多 8 KiB；超时终止原进程组，父线程死亡结束子进程，任何警告、输出超限或预演非空输出均拒绝计划。

每个使用地址族执行两次官方预演：一次完整候选，一次在同一 filter 镜像中先候选再精确撤销。后者去掉中间 COMMIT，不向仍为空的真实命名空间提交独立反向批次。两种模式始终有 --test；成功只表示官方工具接受本次材料，不是已安装规则、内核行为或端口可达证明。预演前后以绑定的 save 重新采集所有使用地址族，并核对原完整规则；随后再次检查完整双后端环境、原授权及工具未变。候选同时预留 1 MiB、16384 项、单行 128 KiB 及原元数据的后续读取预算，过大时拒绝计划。

私有计划冻结工具身份、版本、每次输入摘要/大小及无输出成功结果，统一摘要覆盖完整预演；Web/API 展示 `toolchain_hash/dry_run_hash/dry_run_commands`。源码实现及集成审阅完成，当前未运行真实工具、生成器、构建、类型检查、lint、测试或浏览器，均留待 P5；本次不增加 UI 测试。

完整 nft JSON 视图另外保留 4 MiB、16384 个对象及 384 KiB 结构摘要预算，要求 schema 1。容量证据来自同次完整读取，留在 root 内；只从原生完整代际或已确认有序子集证明的链中扣除当前自有内容，保留 INPUT 跳转和分隔空白的保守余量。生成选项按封闭语法预留 JSON 结构、最坏字符串展开和最大位宽数值，第三方所有数值也预留增长空间；IPv4/IPv6 分别取原、新代际最大贡献，覆盖逐族切换和补偿组合。计划前后、受理及候选提交前重新检查，原策略修复同样准入；补偿只要求原恢复目标的容量，不因失败候选的大小阻止精确清理。超限或两种读取视图的自有链数量不一致时停止，不能将不完整诊断当作成功。保守容量限制可能早于逻辑规则条数上限生效，实际容量留待 P5 验收。


### go-iptables 业务读取

使用官方 `github.com/coreos/go-iptables v0.8.0`，不替换模块或修改上游代码。库只在固定本程序 ELF 的隔离子进程中运行，显式路径指向私有只读 applet；桥接层只接受版本、filter 链清单、INPUT 及本应用固定/代际链读取，再通过原固定描述符传输执行明确的 nft 或 legacy 工具。要求 1.6.0 及以上版本并使用 `--wait 1`，不开放库的修改方法或无界锁回退。

每次读取有八秒总期限，原父进程身份、子进程组和父线程死亡信号均受约束；私有输入最多 4 MiB，返回值仅为原输入摘要。链清单、INPUT 受管跳转位置及受管链规则须与同次原生完整导出一致；第三方表达式保持不透明，其完整漂移仍由原生导出判断。临时目录由 root 私有创建并清理，清理失败拒绝本次读取，遗留目录达到 16 个停止新的读取并要求本机核对；不据此清理可能仍被使用的目录。缺少 filter/INPUT 的未使用地址族不运行会加载表的链读取。

实现依据：[官方 go-iptables v0.8.0 源码](https://github.com/coreos/go-iptables/blob/v0.8.0/iptables/iptables.go) 的 `New/Path/IPFamily/Timeout/ListChains/List/GetIptablesVersion`。尚未执行真实工具，版本和双栈行为统一待 P5 验收。


### 业务执行意图与原操作恢复

原业务快照保存在 `agent/firewall/iptables-change.json`，最多 32 MiB；小型操作回执保存完整快照摘要。快照冻结原本机授权、机器身份、完整工具和规则基线、入口保护、双向批次及每地址族一个候选调用和八个不同的补偿调用 ID。正常 Apply 已接入受理和逐地址族提交，须核对仍有效且可应用的私有计划；逻辑预览与本机空授权本身均不授予业务写入。源机授权、快照、调用许可及回执不进入迁移包。

子进程意图保存在 `iptables-execution.json` 及独立操作回执，最多 32 KiB。写入器只从原父快照选择候选或补偿材料；同一调用 ID 仅返回原结果。先持久发布准备状态，再以固定本程序 ELF 启动管道门，保存原 boot/PID/启动身份后才发送一次性许可；子进程核对父身份及完整许可后，以相同 PID 执行固定 restore ELF。固定参数为 `--noflush --wait 1`，模块加载指向固定 false；程序、restore、阻断工具及独立执行锁均由描述符传递。正式 xtables 锁仍由官方工具处理，独立执行锁随原进程保留。每次三秒、stdout/stderr 各 8 KiB，有警告、超限、超时或未知结果均不能报告成功。

Agent 启动、循环、停止、显式回滚及本机 `iptables-recover` 已接入原操作恢复；变更 owner 选择不撤销原操作。先按原机器和 PID 实例通过 pidfd 确认结束，不以超时推定执行失败；再核对完整当前代际、首位跳转、指针及候选原调用回执。补偿恢复原确认代际；首次应用则精确删除本次规则及空链，不提交原第三方快照，当前第三方规则可保留变化。调用结果未知时只在原进程结束并重新完整观察后使用下一个预分配补偿 ID，不重放原 ID；补偿已成功却重新出现同一代际时停止自动覆盖。最终在授权及执行锁内确认两后端/双地址族均恢复原确认范围且回执完整，才发布 `rolled_back`。

工具、原授权、规则拓扑或回执冲突保留 `recovery_required`，并阻止新授权、释放、维护及其他可达性写入；不替换原工具绑定。主机 INPUT 的 go-iptables 业务读取及完整执行准入已接入，Docker 转发仍待适配。完整 nft JSON 候选容量准入已接入上述计划与写入路径。当前只完成源码实现与集成审阅，生成器、构建、类型检查、lint、测试、浏览器和真实宿主机操作均留待 P5，不新增 UI 测试。

### 新连接确认与确认规则修复

候选完整后读并核对原调用后，操作进入 `waiting_confirmation`，重新建立管理监听并关闭旧连接。确认须使用规则生效后由该监听新接受的非回环 TCP/TLS 连接，原 120 秒期限不延长；再次核对实际管理来源、监听版本、SSH 保护依据、规则绑定接口、完整代际及原回执后，将确认来源和策略原子保存到 root 快照。此快照是直接模式的持久期望，不生成全局 iptables-save 启动文件。确认发布回执中断只补齐原记录，不将已保存成功操作重新回滚。

启动时未确认操作仍恢复原确认范围，首次应用恢复为空；已确认策略由 Agent 循环、监听变更核对及本机 `iptables-recover` 独立维护。只允许当前剩余受管规则为原规则的有序子集、指针和首位跳转准确或缺失；未知规则、重复、重排、额外引用及其他保留名称均阻止自动修复。修复只创建缺少的受管链、按原位置补回缺失规则及跳转，不删除或重放第三方规则。接口消失时不提交新规则，原操作精确补偿仍可继续。

每次修复先依据当前完整环境重新生成缺失批次并通过固定 restore 的官方 `--test`，再保存独立 `iptables-repair.json` 意图、摘要回执和每地址族三个不同的调用 ID。子进程复用原持久许可、身份核对及执行锁，完整当前地址族与修复前镜像一致才提交；同一 ID 不重放。原结果未知且进程已结束时才使用下一个固定 ID；明确结果仍有缺失时保留待恢复。外部基线变化时原修复保存为 `superseded`，从当前状态另建意图；最终完整代际核对后只发布修复终态，不改写原成功业务操作。独立快照最多 32 MiB，全部 root 材料仍不迁移。救援请求 ID 随原快照持久保存，重启不重复消费已完成请求。


### 已确认策略更新与移除

每个新操作仅携带上一份确认策略、工具绑定及其原独立成功回执的有界引用，不嵌套历次完整快照。计划及受理均核对该来源仍为当前确认状态；运行中保留旧确认期望，新连接确认成功才发布新期望。失败、超时、停止或重启恢复旧期望，旧成功回执不改写。原确认状态为已移除时，后续应用失败仍保留该移除确认及操作引用；释放后重新登记的新命名空间不继承旧登记授权。

每地址族在同一个 filter 批次内先创建并填充新代际，再向固定入口插入新指针并按完整参数删除旧指针，最后精确撤销旧代际规则并删除空链；不按不稳定编号覆盖既有规则，不提交第三方历史配置。新增地址族建立入口及首位跳转；移除地址族只撤销本应用精确跳转、指针及空链。移除计划的 `hook_position=0` 表示候选不保留该族跳转；第三方保留数量排除本应用旧规则。正向和同表正反向材料均须通过固定官方预演。

恢复先撤销可证明的完整候选；原确认链或部分规则因主机重启而缺失时，沿原独立成功来源另建受限修复意图，全部地址族恢复完整后才完成当前回滚。移除后的空范围同样须由新连接确认，确认后不再重建已删除规则；本机授权可另行释放，期望草稿及历史回执保留。主机入站计划完成完整执行准入后可应用，Docker 转发仍未适配。
