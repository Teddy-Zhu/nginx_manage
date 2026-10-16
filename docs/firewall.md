# 宿主机防火墙策略与诊断

`GET /api/v1/firewall` 要求 `read`，返回统一 `code/message/data/request_id/node_id` 外壳，`data` 为 `FirewallObservation`。已登记远程资源 `/nodes/{connection}/firewall`，沿用目标权限和永久节点身份检查。防火墙页面由 `src/pages/firewall.vue` 自动扫描接入。

仅由 root Agent 在本机以 `--metrics-scope=host` 确认宿主机观测范围；容器、开发模式或未确认范围均不执行诊断命令。此授权不允许写规则。`available` 只说明已进入宿主机读取，各管理器和规则视图仍可能未知或不可用；`writable` 及 `docker.writable` 始终为 false。本机 root 空表登记命令使用独立范围授权，不由 API、模块开关或观测授权触发。防火墙模块默认停用，可显式启用；执行还须满足下述独立授权。Fail2ban 仍不可启用，默认停用时可读取独立的[宿主机诊断](fail2ban.md)。

诊断分别返回：

- firewalld 当前运行、panic、默认 zone、活动接口/来源，以及配置中的后端选择。通过固定本机 D-Bus 和唯一服务所有者读取，禁止自动启动；配置选择不视为内核运行后端。
- UFW 受信工具可用性、`ufw.conf` 中的 ENABLED 和 `ufw status` 当前状态；未知值保留 null，启用配置与当前状态不一致时告警。
- 默认 IPv4/IPv6 iptables 命令后端，以及 nftables、iptables-nft IPv4/IPv6、iptables-legacy IPv4/IPv6 五个独立结构视图。明确版本后再读取显式后端的 save 工具，不切换 alternatives。仅含表/链、hook/priority、默认策略、规则数和 DOCKER-USER 跳转标记，不返回规则表达式、集合内容、注释或计数器。
- Docker `ip/ip6 docker-bridges` 与 `filter/DOCKER-USER` 标记、FORWARD 跳转线索。未核对 Docker 实例、DNAT 原始目的地址或实际数据包路径；原生 nftables 标记保持实验适配只读。

工具仅从固定系统目录选择 root 保护的文件，保留 xtables multi-call 的原调用名；不接受 API 提供的路径、参数、命令或环境。save 读取全部现有表，不指定单表；以固定受信 false 程序阻止 save 的 modprobe 回退。nft 使用 JSON/numeric/terse 输出。超时、未知格式、输出超限或 nft-save 不兼容表提示均令整个视图不可用，不将前缀作为完整结果。

单次命令期限 2 秒、整个采集上下文期限 6 秒；每次采集只允许一份在途工作，缓存 30 秒，HTTP 请求取消不会另起相同采集。Web 每节点最多 4 个在途读取。nft 原始输出最多 4 MiB、每份 xtables 原始输出最多 1 MiB、stderr 最多 8 KiB；每个结构视图最多 16384 个对象和 384 KiB JSON 元数据。firewalld 最多 128 个 zone、各 zone 最多 256 个接口/来源且总值最多 32 KiB。超限明确失败，原始输出和错误不写入业务响应或日志。

各管理器/CLI 视图独立读取，不保证原子快照。nftables 与 iptables-nft 可展示相同内核对象，不可累计计数；观测到规则不代表已排除其他后端。管理器冲突、孤立管理器标记、地址族后端差异保留告警。`direct-candidate` 只表示未观察到启用的现存管理器，不代表可接管。无活动规则时内核后端保持 unknown；链名和表名不能证明所有权或外部可达性。

## 内核目标表快照

`kernel` 子视图通过固定 NETLINK_NETFILTER GET 操作读取 `inet nginxpanel_host`。root 宿主机授权与原诊断一致，连接不加入 multicast，不接受来自 API 的消息、表名、文件或表达式。固定缓冲逐数据报消费，检查内核来源、端口、请求序列、消息/属性边界、重复属性、multipart 完成与 DUMP_INTR；不使用先累积整个 multipart 再限长的读取方式。不提供计数器 reset 或任何写操作。

读取前后核对非零内核规则代次与由 boot ID/网络命名空间身份派生的摘要。目标表不存在也必须经完整代次核对；目标表存在时，完整读取链/规则及集合、状态对象、flowtable 元数据。存在后面三类对象时整份快照不可用，不把未读取的集合元素或对象内容当作空。内核忽略链 dump 的表筛选时在 root 本地筛选完整有界结果，第三方表不会进入摘要或响应。

摘要保留原始表达式及未知属性，不经过可能忽略未知表达式的库解码；仅去除 UAPI padding 并将基础链动态包/字节计数值归零，保留计数属性的存在/结构、未知属性及对象句柄。摘要不是规则所有权证明，也不证明外部路径可用。单次快照最多 3 秒、每数据报 64 KiB、总接收 8 MiB、总对象最多 8448 个，目标最多 128 条链/8192 条规则。超限、截断、丢失、代次变化、格式未知或不支持的对象均整体失败，不返回部分摘要。读取沿用原单飞与 30 秒诊断缓存；缓存不能充当执行前重新核对。

## 期望规则

`GET /api/v1/firewall/policy` 要求 `read`，返回 `FirewallPolicyView`。未保存时为版本 0 与空规则。`PUT` 要求 `security.write`、浏览器近期认证、`Idempotency-Key` 与精确 `base_version`。策略使用节点主密钥按版本加密，CAS 更新、幂等响应和审计同事务提交；冲突必须重读，不覆盖他人的修改。模块停用时仍允许保存期望；保存只表示待应用。

中立模型支持 UUID、名称、启停、主机入站/Docker 发布端口、IPv4/IPv6/双栈、TCP/UDP、端口区间、来源、allow/deny/reject、顺序、入站接口与备注。最多 1000 条、规范 JSON 256 KiB；每条 1–16 个端口区间、最多 32 个来源。端口区间合并相邻/重叠部分，来源规范化并拒绝重复；CIDR 必须为网络起点，不静默扩大用户地址范围。空来源表示任意来源，非空来源须覆盖所选地址族，双栈须同时提供两种地址族。按顺序、UUID 确定排序。后端和接口是目标绑定，不接受用户命令、路径或可执行文本。

## 编译预览

`POST /api/v1/firewall/preview` 要求 `read` 和已保存版本，浏览器使用 CSRF；同一节点最多一份在途预览，结束前再次核对版本。直接 nftables 编译器使用固定库构造实际表达式与摘要，但不创建连接或发送 netlink 事务。启用的 Docker 发布端口规则及其他尚未适配的后端明确阻塞，不能降格为 INPUT 或自动切换管理器。

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

当前仅开放 direct-nftables 主机入站执行。Docker 转发路径、其余管理器/iptables 写入适配、Fail2ban action 仍待实施。实现与集成源码审阅已完成，未运行构建、类型检查、lint、测试、浏览器、服务或真实规则操作；真实发行版/内核/Docker 矩阵在 P5 集中验证。

接口依据：[firewalld D-Bus](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)、[nftables 手册](https://netfilter.org/projects/nftables/manpage.html)、[iptables-save](https://man7.org/linux/man-pages/man8/iptables-save.8.html)、[Docker 原生 nftables 后端](https://docs.docker.com/engine/network/firewall-nftables/)。

内核格式与规则代次依据：[Linux v6.1 nf_tables UAPI](https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/netfilter/nf_tables.h)、[nf_tables GET/代次实现](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nf_tables_api.c)、[nfnetlink batch 代次前置条件](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nfnetlink.c)。这些源码依据不能替代 P5 真实内核矩阵验收。


Fail2ban 宿主机动作使用独立固定目标 `inet nginxpanel_fail2ban`。共享快照、编码和语义证明通过闭合目标枚举选择布局，不接受调用方表名；人工端口规则的所有公开写入仍固定 `nginxpanel_host`。本机 root 可独立登记、核对、恢复及移除原样空表，采用另一所有者、持久记录、主机锁与操作/CAS，绝不接管已有未登记表；空表无链/hook，不表示保护已生效。预检读取独立登记后可继续生成空集合准备材料，实际封禁及带 hook 的运行恢复仍未接通。详情见 [Fail2ban 宿主机动作](fail2ban.md)。Agent 为 50；实际双目标隔离和内核矩阵留待 P5。
