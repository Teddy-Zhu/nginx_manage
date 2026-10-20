# 工程合同

配置修订通过一个服务写入：原文、SHA-256、资源绑定与结构化投影同事务保存；原文及投影使用节点主密钥 AES-256-GCM 加密，附加数据绑定修订与逻辑资源 ID。完整原文接口要求 `config.secrets`，写入同时要求 `config.write`；浏览器读取/编辑原文须在五分钟内重新认证。安全指令还要求 `security.write`。

Crossplane 0.4.89 负责配置树语法分析，独立源码区间负责定点修改。稳定资源通过块前的 `# nginxpanel:resource <UUID>` 关联，不按域名猜测；同块的 JSON 元信息注释保存名称、备注与启停状态。include 文件继承实际调用位置的上下文，多处接入的资源文件拒绝歧义映射。未标记块保留原生可编辑状态，不自动认领；未登记指令可保存在独立草稿，但不能成为有效期望状态。

表单映射覆盖多条监听、域名、唯一直接转发 location 的前缀/上游/请求头/超时/缓冲/缓存/上游 TLS，以及证书路径、响应头、真实 IP、日志与 Stream 会话参数。字段以 `value/tokens/lines` 区分单值、同条指令参数和有序多条指令；新增、替换与移除只修改对应原文区间。请求/响应头仅映射已知变量；重复单值指令、参数注释、复杂 location、共享 include 等使相关字段只读。上游成员仅可编辑唯一接入、单一字面引用且没有 include 的组；变量引用或共享组保持原生编辑。

创建支持可选加权上游组。复制默认停用；可可靠映射的私有上游组同时复制，已知按资源分区的日志路径使用新 ID，其他原文保留。删除不猜测清理可能仍有原生引用的上游定义。启停只改变元信息；执行器在发布副本中排除停用资源，原文仍留在修订中。新建 HTTP/Stream 默认使用受管 JSON 日志格式，排除查询参数、凭据与业务载荷。日志轮转、查询及保留策略继续在 P2 接入。

手动证书保存为独立资源及不可变版本：校验有序 PEM 链、私钥匹配、SAN、服务器用途、签名与链有效期；支持 RSA 2048–8192、ECDSA 至少 256 位及 Ed25519。公开根可由校验进程信任库补齐，私有 CA 须附自签根；不自动获取缺失中间证书，不以 Common Name 代替 SAN。证书链和规范化 PKCS#8 私钥按资源/版本分别加密保存；普通列表与详情只返回元数据。列表仅含最新版本，详情最多保留 32 个版本；当前引用展示有数量上限，历史引用另计。导入新版本不修改已有绑定，手动证书不自动续期。

配置中的证书链与私钥须引用 `certificates/<UUID>/<version-UUID>/fullchain.pem` 与 `privatekey.pem`；固定系统 CA 快照只允许用于信任链指令。所有有效修订在同一事务校验证书引用并记录引用投影，HTTPS 绑定检查同一证书版本、链有效期及全部站点域名/IP 覆盖；通配 SAN 不覆盖根域名。不能可靠核对的域名模式须先通过原生配置整理。当前/历史修订引用均阻止删除，保留回滚材料；历史保留清理入口后续实施。草稿不锁定证书，删除后需重新解决引用才能成为有效修订。

任务从加密存储加载修订所需材料，通过受限 IPC 交付 Agent，操作日志不含 PEM。Agent 独立核对材料与配置引用、链和域名，并在已有持久操作记录后写入 root 私有不可变版本目录；文件、目录 fsync 后原子发布，已有版本仅接受相同内容。证书及私钥散列进入原有发布依赖清单，只有运行证书指纹确认后才记录已生效修订。证书准备或 Nginx 校验失败不切换运行修订；不确定的提交沿用原操作标识核对，不生成第二份版本。

HTTP/HTTPS 混合监听可表单配置仅对 HTTP 返回 308 的跳转，保留主机、请求路径与查询参数，目标端口须为当前站点 HTTPS 监听。HSTS 与其他响应头分别映射；HSTS 参数、作用域、参数注释或继承响应头无法可靠映射时保持原生编辑，标准跳转可与 WAF 共存。HSTS 仅由 HTTPS 客户端处理，preload 标记不代表已加入浏览器预加载名单。ACME DNS-01/HTTP-01、订单、证书版本、自动续期与显式自动部署已接入；HTTP-01 与跳转及 WAF 使用受控入口协调，签发和实际运行部署保持独立状态。

ACME 账户使用 lego/v5 5.5.2，CA 只允许 Let's Encrypt 测试/正式固定环境。先在同一事务保存加密账户密钥、注册任务及幂等结果，再由独立 Web worker 联系 CA；Nginx 队列不会抢占账户任务，也不等待 CA 网络请求。首次与重启均先按原密钥查询账户，仅明确返回 accountDoesNotExist 才注册；超时后保留原密钥，失败人工重试受持久冷却时间限制并尊重 Retry-After。CA 响应限制为 1 MiB，保存的账户资源限制为 64 KiB，不允许重定向或跨 CA endpoint，不读取 lego 的 TLS 信任覆盖变量。账户私钥与注册资源加密，列表只含公钥散列、邮箱、状态及 CA 账户 URL；任务与审计不保存 CA 原始响应或凭据。移除本机账户记录不注销 CA 账户。

DNS 凭据字段由 Cloudflare/阿里云 DNS/腾讯云 DNSPod 描述生成，保存不发起远端请求，权限和区域归属在签发任务中核对。写操作要求 config.write、config.secrets 及浏览器近期认证，使用资源版本与幂等键；字段全部加密且不回显。更新省略 secrets 保留旧材料，明确提供对象则完整替换，可省略不再使用的可选字段；null、未知字段与空值拒绝。挑战适配使用显式配置对象，不修改进程全局环境；阿里云 SDK 会输出签名请求的 DEBUG=dara 模式被拒绝。


`/acme-profiles` 管理独立签发配置；创建不发起申请，`/{id}/issue` 排队执行所选 DNS-01 或 HTTP-01，`/{id}/orders` 查看保留订单，`/{id}/archive` 停用并保留证书与历史。写操作沿用权限、近期认证、资源版本、幂等和审计。一个配置只允许一个在途订单任务，域名最多 64 项并规范为有序 ASCII SAN；DNS-01 支持普通及通配域名，HTTP-01 仅支持普通域名。新订单先事务保存加密 P-256 密钥、CSR、凭据快照与任务，随后联系 CA。恢复使用原密钥、CSR 和凭据，不静默切换新凭据；新订单使用当前凭据。活跃配置阻止账户、凭据删除及证书手动替换，停用后可转手动管理。

提交意图先于 newOrder 持久化，HTTP 201 的 Location 在解码响应之前保存；已知 URL 重启后先查询，签发结果先与不可变证书版本同事务保存，再清理临时验证材料。缺少 URL 的不确定创建不会自动重发；显式新建须确认重复申请风险，且不得留下未清理材料。失效订单仍可恢复清理，完成后须显式新建；人工重试有冷却；轮询的 Retry-After 截止时间随订单持久化，重启继续遵守。任务采用短事务，远端轮询不持有数据库事务；单次签发工作期限 20 分钟，单独清理期限 3 分钟。

DNS-01 使用 lego 协议及传播检查，提供商 SDK/REST 使用固定 HTTPS endpoint、拒绝重定向并限制每次响应为 1 MiB，只进行有界 TXT 查询和精确 ID 操作，不使用按记录名批量删除的清理例程。写入前加密持久化 CNAME 解析后的目标、区域、值、已有同值记录 ID 与写入意图，并锁定验证名；重启核对唯一挑战值以恢复丢失的创建响应。预存同值记录只借用、不删除；其他值保留，已记录 ID 内容被外部改动则阻止清理。网络不确定的创建尚未查到记录时保留意图与锁，不重复创建、不宣称清理完成；后续恢复再次核对，持续未知须本机处理。失败清理进入 recovery_required，明确恢复后才能继续或停用，不静默抛弃记录。接口不返回 TXT 值、提供商记录 ID、凭据、私钥或 CSR。

HTTP-01 不启动临时 TCP 80 服务，也不停止专用 Nginx。站点原文以 `location ^~ /.well-known/acme-challenge/ { return 404; }` 明确选择验证入口；执行器只在运行副本替换为固定 Unix socket 代理。仅对有效 token 形状的专用路径提前结束服务端重写，并在该 location 精确豁免业务准入、标准认证与继承限流；自定义重叠路径、共享入口或重复域名不猜测归属。申请要求每个域名在已确认运行修订中具有唯一的字面 server_name 和明文 80 端口监听，不支持通配域名、80 端口 TLS 或 proxy_protocol。操作者须确认公网端口和 A/AAAA 指向，本机 DNS 与 HTTP 检查不冒充公网验证，多入口可达性以 CA 结果为准。

Agent 的验证响应器使用独立 Unix socket，只接受 Nginx worker UID；与特权 IPC 分离。材料位于受管数据目录的 `acme/http01`，目录 0700、文件 root 0600；最多 128 个有效租约、2048 个订单清理记录，每订单 64 个 token、单文件 256 KiB。文件名绑定订单 UUID，token 仅接受 22–256 位 base64url 字符，内容严格为 token 与 43 位账户指纹。租约最长一小时，worker 使用 30 分钟，逐请求检查域名、方法和到期时间；只响应 GET/HEAD，拒绝其他路径、未知或过期 token。租约与材料使用原子 rename/fsync，Web 先持久化订单清理意图再调用 Agent，每次恢复使用先持久化的递增租约序号；清理按订单 ID 和序号幂等执行并保留无材料的清理记录，迟到的创建/发布不能复活已清理租约，旧清理不能删除新序号材料。未确认清理则保留恢复状态。数据库任务与 Agent 租约均阻止 Nginx 并发操作，过期材料不再响应；显式新建或停用仍要求确认清理结果。

正式 ACME 证书须验证到系统信任根；测试链验证签名、有效期和服务器用途，允许以 CA 返回链尾作为测试信任锚，标记 acme_staging。环境随不可变版本及 Agent 材料传递，测试链不加入系统根。签发与运行部署分开；新版本不会覆盖已有材料或绑定，需要选择版本后走统一保存、校验、应用和指纹确认。自动续期采用已持久化的 ARI/实际寿命计划；自动绑定部署显式启用后沿用统一 Nginx 任务，首次绑定须人工完成。

访问列表原文位于 `security/acl/<UUID>.conf`，含受管名称/备注注释，规则是有序 IP/CIDR 加明确的末条允许或拒绝。列表可被多个 HTTP 代理引用；修改保存为统一修订，应用流程不另设入口。混合规则只读，存在原生规则或子路径覆盖时不允许表单绑定；删除要求先解除全部 include 引用。安全写入检查新旧期望树及被替换的已生效树，不能通过删除最后一条安全指令绕过 `security.write`。

基础 WAF 使用 `security/waf/<UUID>/http.conf` 的 map/共享区定义及 `server.conf` 的站点规则；名称、备注与启停记录在受管注释，其余字段从原生指令反向投影，不另存可写策略副本。支持每来源请求限速、突发额度、并发数、请求体上限、大写方法白名单、精确/前缀拒绝和豁免路径。同一策略绑定的站点共享每来源额度；IP/CIDR 复用访问列表。豁免只影响方法检查与限流，不跳过 ACL、明确拒绝路径或请求体限制；观察模式仅影响请求限速和并发限制。原生继承规则、子路径覆盖、共享 include、多个策略引用或不能可靠反向映射的指令保持原文编辑，表单不猜测叠加行为。停用策略在发布副本中排除两个文件的内容；删除前须解除引用。

Agent 仅对本机 root 登记的可信 Nginx 执行有时限、输出有界的 `-V`，解析版本与完整编译参数；动态模块检查批准内容、ELF 标识及不可变副本，只有当前发布通过运行确认后才计入动态能力，不将文件存在或动态编译参数当作已加载。能力报告和 WAF 页面分别解释缺失或未知能力；启用策略由服务校验必需模块与版本，最终发布仍执行真实 `nginx -t`。启用策略时，受管 HTTP JSON 日志追加策略 ID、方法/路径拒绝原因及已使用限流模块的状态字段；未绑定站点记录空策略标识。自定义/关闭的访问日志不保证包含这些字段。事件查询与日志轮转已接入 P2，安全事件摘要仍待补齐，不能据保存结果声称策略已经生效。

原文差异比较完整逻辑树，按稳定文件 ID 标明新增、移除、移动及内容变化；共享 include 和全局上下文保守列出可能受影响的资源，ID 展示最多 100 个并返回总数。浏览器提供逐行差异与原文对照；大文件直接对照原文，差异查看不保存配置。修订原文及差异要求 `config.secrets` 和浏览器重新认证，不写入任务或审计日志载荷。

外部检查只读取专用实例当前发布目录，以数据库最近确认修订、Agent 持有的发布身份和清单重建预期运行副本；不得因读取快照而创建目录、刷新 CA 或写入运行文件。检查文件修改、缺失、额外文件及类型/权限异常，拒绝符号链接、硬链接、非 root 文件、越界或超限读取；证书依赖只返回散列。单次目录检查最多 512 个条目、实际内容合计 8 MiB，文件最多 512 KiB；详情只返回一个文件，序列化 IPC 响应最多 4 MiB，超限明确失败。目录检查不完整时禁止捕获和恢复；主配置缺失不能捕获，但完整快照可从已保存期望修订恢复。清单或发布身份不能核实时拒绝检查及自动恢复，须本机处理，不把未知状态显示为无冲突。

捕获外部内容须再次核对发布快照散列和期望基础版本；期望树已移动、删除或修改同一文件时拒绝自动合并。只移除可逐字证明反向还原的生成控制及 include 路径，不能可靠还原时保留磁盘原文并提示安全整理。单文件变更合并到期望树后保存独立加密草稿，沿用原有解析、映射、幂等和审计，不改变期望或运行修订；草稿不可应用。磁盘修改不等于 Nginx 已加载该内容。

`POST /nginx/external/restore` 显式恢复当前已保存期望修订，要求 `config.write/config.secrets/security.write`、浏览器重新认证、期望基础版本及完整冲突快照。浏览器先展示目标与最近生效修订的原文差异，再确认重新加载；若要恢复历史内容，应先将其保存为期望修订。幂等响应、任务、快照摘要及排队审计同事务保存。Agent 独立重建已生效源树证明、核对快照，在自己的持久操作记录之后准备证书和新候选，并在切换前再次核对快照。普通应用仍拒绝外部冲突。

逻辑配置修订与物理发布身份分开；每个新操作使用操作 ID 作为不可变发布目录和独立运行探针。恢复保留原外部目录，不覆盖、删除或将其作为回滚目标。切换前失败保持原发布指针；可能切换之后无法确认则进入 `recovery_required` 并阻止冲突操作。Agent 重启仅依照独立记录继续验证、切换和确认已授权候选，不重新执行外部内容。任务必须同时匹配逻辑修订和物理发布身份，确认运行后才更新已生效修订。既有证书和模块版本不覆盖；依赖损坏时须选择有效新版本并保存，或本机修复，不能声称自动恢复任意依赖或损坏清单。当前 Agent 协议为 28，不提供首版之前的协议或目录兼容分支。

配置树 `base_version` 指向当前有效期望状态；草稿使用独立不可变修订，不改变该版本。错误草稿没有有效投影、不会创建任务。保存不等于实际应用。`validate` 创建真实 `nginx -t` 任务，不改变运行修订；`apply` 创建应用任务，也可用 `/nginx/apply` 应用已保存修订。校验、应用和外部恢复互斥且不能用于草稿。执行保留幂等操作标识、提交意图及 Agent 接受记录；超时先查询独立执行记录，已接受记录缺失时转为恢复状态。任务终态和已观察修订同事务记录，只有确认成功或确认回滚才更新 `config_head.applied_revision`。

Agent 只监听 Unix Socket，使用 `SO_PEERCRED` 校验唯一授权 UID。生产 Agent 要求 root；开发 Agent 不执行宿主机写操作。Agent 不访问业务数据库。策略默认不允许外部 include、任意路径、未批准模块、Lua/JS/Perl、任意文件服务与可执行扩展。原生动态模块仅接受本机 root 启动清单中的精确路径和散列，Web 与 Agent 使用相同批准路径，接口不能扩展清单。选择定点写入主配置并保留同一修订；模块在独立记录之后复制到 root 不可变目录，绑定二进制散列并通过真实候选校验及运行确认。详见 [模块接入](native-modules.md)。未来开放系统只读 include 仍须独立 root 策略。Nginx 执行仅由本机 root 参数启用；worker 与 Web 使用不同的非 root 账户。`nginx-init` 只生成无站点基线，不启动或接管已有服务。执行器验证固定二进制、PID 及实际启动参数，通过 pidfd 向专用主进程发送 HUP。

发布保留数据库原文，只对生成副本注入独立 Unix Socket 修订探针、可信运行身份/临时路径和受管日志格式，并将 include 固定到不可变发布目录。受管缓存使用固定独立目录和预算，默认绕过凭据/Cookie 请求及带 Set-Cookie 的响应；HTTPS 上游默认启用证书与 SNI 校验，未指定全局 CA 时固定一份可信系统 CA 快照。源文件、发布文件与证书依赖分别校验散列；外部修改暂停普通应用。先持久化切换意图再原子切换 active，新的本地连接确认修订、主进程监听归属及 HTTPS 证书指纹；UDP 仅确认监听，不冒充应用层健康。普通应用的未确认切换在 Agent 重启后恢复上一受管修订；外部恢复仅继续完成新候选，无法证明运行结果时均保留 `recovery_required`。

Agent 操作记录使用独立文件、原子 rename、文件与目录 fsync。记录只含操作 ID、输入摘要、修订、阶段与期限，不含原文、秘密或日志载荷；最多 2048 条，达到上限须本机维护，不能无界写入。DNS 普通文件流程使用另存快照的独立可达性检查点，防火墙后续接入同一排他边界；副作用前保存旧状态与期限，确认或补偿由 Agent 独立完成，重启先恢复未确认操作，恢复记录不进入业务备份。未实现恢复适配的所有者保持只读。

组件信任合同：来源、固定版本、架构、ABI、文件散列和许可证进入签名清单；root 独占激活目录。安装、启用、启动与卸载是不同动作；系统组件不自动迁移或替换。实际组件安装/升级及健康检查在 P4 接入，当前不接受任意组件包或系统软件安装请求。

资源预算见 `internal/limits`。配置树最多 128 文件、单文件 256 KiB、总计 2 MiB、嵌套 32 层；WAF 最多 32 个策略，每类路径最多 128 项，每种限流共享区固定 1 MiB；证书最多 128 个资源、每个 32 个版本，单份材料合计 128 KiB、私钥 PEM 16 KiB、链长 16、DNS/IP SAN 合计 64，单次发布材料合计 1 MiB；最多 128 个发布目录，校验候选及保留的外部副本也计入，清理入口尚未交付，达到上限须本机维护；监听/TLS 确认各最多 256 项，证书文件引用最多 128；HTTP/IPC 请求最多 4 MiB，最终序列化请求超限则明确失败；ACME 账户最多 16 个、DNS 凭据最多 32 组、每组最多 2 个字段且单字段不超过 2 KiB；活跃签发配置最多 128，总保留配置/订单各最多 2048，每配置最多 32 个订单，DNS 恢复记录最多 8192，每条最多 16 个原有/创建记录 ID，提供商查询最多 20 页共 2000 条；任务排队最多 100，Nginx、ACME 账户和签发各一个 worker；普通分页每页最多 100。监控、日志、暂存、备份与 SSE 的初始预算已固定，启用对应功能时必须在实际入口执行，常量本身不代表该功能已经交付。

DNS 管理器探测须追溯实际持久来源；写入须本机显式确认所有权和宿主机范围，并满足相应适配器及独立恢复条件。已验证系统组合和边界以[验证记录](validation.md)为准，不据接口开放宣称已通过完整能力矩阵。工具已安装、模块启用、服务运行、系统兼容性验收是独立事实；未知运行状态返回 null。未接入 Agent 时，Web 不展示容器/本进程环境为宿主机事实。


受管 Nginx 日志只接受来源 ID（固定受管 live 路径的 SHA-256）和筛选条件，不接受文件路径。HTTP 和 Stream 使用预留 JSON 格式；HTTP 缺省访问日志注入不含 query 的结构化全局日志；缺省主错误日志固定至受管全局 error.log。允许的 live 文件仅限 nginx/<UUID>/access.log、error.log，stream/<UUID>/access.log、error.log、session.log 和 nginx-global/access.log、error.log，前缀均为 logs/。归档使用 Agent 生成的 UUID 后缀，用户原文不能引用归档或临时文件；活动文件预建为 0640、历史关闭后为 root 0600。原生文本和含此类历史的来源要求 config.secrets，浏览器再加五分钟内认证；展示与下载统一尽力脱敏，不提供原始内容绕过入口。Stream 仅返回会话状态、协议与收发字节等适用字段；原生文本仅支持时间及脱敏消息关键字。

日志轮转 owner 来自 root 命令行 --nginx-log-owner=agent|external|unconfirmed，默认 unconfirmed；只有明确唯一 Agent 所有者才运行轮转/压缩/清理及修改策略，不能从网页接管外部规则。root 独立状态保存版本与策略，Web 以 system.write、近期认证、幂等标识及 base_version 修改并审计，不由 Agent 写业务库。rename 和策略操作先持久化意图；USR1 只发往已核对专用 master 的 pidfd，之后检查 master 与直属子进程是否仍持有原 inode，未确认关闭时禁止压缩或删除。压缩按每轮 16 MiB 原始输入分段，保留原文件到 gzip 与状态均持久发布后才移除；恢复与清理只处理 root 清单派生、身份核对过的文件。时间、每站点/Stream 资源空间、全局空间及历史数量上限优先清理最旧已关闭文件；活动文件不会强制截断。磁盘不足 5% 或维护失败显示原因，不宣称轮转阈值或配额是瞬时硬限制。

日志预算：单发布最多 512 个来源、总保留 2048 个；受管资源日志目录总数最多 682；总历史 16384 个、每来源 128 个，关闭历史可因配额或数量上限提前清理。查询时间窗口最多七天，每页最多 100 行，单行解析最多 64 KiB，扫描预算 16 MiB（行片段至多额外 64 KiB）；最多四个并发读取、32 个身份绑定游标，空闲五分钟过期并关闭文件。游标绑定筛选条件，上一页重试返回相同结果；失效或遗漏范围显式提示，不能无声跳过历史。gzip 使用流式游标，分页不重复解压前缀。实时 SSE 最多 16 连接、每连接四页缓冲、两秒轮询、十秒写入期限及十分钟连接期限，校验会话存活、epoch、Token 权限/到期与原生日志认证；过期游标重新读取最近视图时报告缺口。下载使用独立新查询，最多 10000 行、8 MiB 内容、约 16 MiB 扫描及二十秒；首行为脱敏、跳过、缺口与截断摘要，HTTP 成功为 application/x-ndjson，失败仍使用统一 JSON 外壳。所有展示按文本转义。


基础监控通过固定类型 Agent IPC 采集宿主机 `/proc`、`/sys` 与本地文件系统统计，Web 不读取自身容器指标；生产 Agent 须在本机设置 `--metrics-scope=host`，开发 Agent 和检测到容器的执行器保持不可用。采集上限为 128 个核心（另含总计）、32 个接口、32 个本地文件系统及四个固定 systemd 单元，单样本 64 KiB；单飞采样任务避免阻塞的文件系统操作堆积 goroutine。CPU 不重复计算 guest，iowait/任一计数器减少、启动身份/核心集合变化、接口重建和采样中断均使相关速率不可用；网络速率为 bit/s，累计量为字节。内存依据 MemAvailable，磁盘使用率分母为已用加普通用户可用空间，保留空间与 inode 单独报告。口径依据 Linux 内核 proc 文档（https://www.kernel.org/doc/html/latest/filesystems/proc.html）及 statfs（https://man7.org/linux/man-pages/man2/statfs.2.html）。

监控模块默认停用，停用后停止采样；设置独立版本 CAS、幂等响应与审计同事务保存，写入要求 monitoring.write 和浏览器近期认证。15–300 秒采样只在内存保留最新样本与当前分钟聚合，按分钟批量落盘；阈值转换即时保存条件及本机事件，使用持续超限/恢复窗口与滞回，缺失样本不清除超限。事件最多 1024 条/24 小时，外部通知投递由通知模块的独立队列处理。历史保留 1–24 小时、最多 1440 分钟及 32 MiB 聚合载荷，单分钟最多 128 KiB；字节配额不代表整个 SQLite 文件大小。禁用、重启和设置变更不覆盖同分钟已有聚合；采样空档与缺失值不补零。

`/monitoring/latest`、`/monitoring/settings`、`/monitoring/history` 沿用统一 JSON 外壳与权限。查询固定指标/维度与字段，最多 24 小时/300 个聚合点、并发两次与五秒期限，返回平均/最小/最大/有效样本数及空档标记。服务器页面由 pages 自动扫描，内置 SVG 显示趋势、CPU 核心、磁盘/inode/保留空间、网络及固定服务状态；隐藏页面暂停轮询，卸载取消请求，概览展示最新资源摘要。实现及生成代码已接入，构建、类型检查、测试和真实宿主机口径验收仍待 P5。


外部通知采用本节点加密渠道与独立持久队列，默认停用；读取仅返回目标主机/部分 chat ID 与凭据配置状态，不返回完整 URL、Token 或共享密钥。渠道 CRUD、策略、发送测试及手动重试要求 notifications.write、浏览器近期认证与幂等键；渠道和策略使用版本 CAS，变更、审计和幂等响应同事务。地址/凭据字段省略或 null 表示保留，显式空串清除；停用的未完整渠道可保存，启用时校验目标与必需凭据。修改/停用/删除渠道取消原版本待投递项，在途结果明确标为不确定；删除后保留脱敏投递历史。停用通知模块仅暂停外部发送，有效事件和队列继续按配额清理，重新启用后处理仍有效的待发送项。

任务失败/补偿/待恢复与监控阈值转换通过数据库触发器同事务形成脱敏事件，不把任务 last_error、配置正文或秘密放进通知；同类任务故障按资源与小时合并。证书到期观察最新版本及生效修订仍引用的版本，预警提前量取配置天数与实际寿命三分之一的较小值，并考虑已保存续期时刻，过期另发严重事件；每个版本/级别只记录一次，删除版本同步清理信号标识。数据目录容量采用固定本地路径的有界单飞读取，不冒充整机磁盘；可用 MiB 或比例不足即告警，恢复需同时达到容量阈值 1.2 倍与比例加 2%。局部信号不可读不阻止已有事件投递。任务分类包含后续备份/迁移/更新失败，相关业务生产者仍随 P3/P4 实现。

投递先持久保存意图、尝试次数及租约，再于事务外发送 HTTPS；全局至少间隔 5 秒，每渠道至少 10 秒，单请求最多 10 秒且不能越过事件到期时间。不跟随重定向，不保存原始 HTTP 错误、响应正文或完整敏感 URL。Telegram 使用官方 JSON sendMessage 接口，检查 ok 并遵守 retry_after；规范见 https://core.telegram.org/bots/api#sendmessage 与 https://core.telegram.org/bots/api#responseparameters 。临时网络错误、限流和服务端错误按带抖动退避重试；每项最多 1–8 次、有效期 1–24 小时，手动重试不重置次数或绕过服务端冷却。永久拒绝保留失败记录，失败不回滚业务。重启仅恢复租约过期且仍有效的发送意图；结果不确定可能重复送达，Webhook 接收端按 node_id + event.id 幂等，不宣称 Telegram 端到端恰好一次。

Webhook 请求体为版本 1 的 NotificationPayload，包含 node_id 与事件 id/kind/resource_kind/resource_id/severity/state/summary/occurrences/created_at/last_seen_at/expires_at；同一投递的正文保持不变。携带 X-NginxPanel-Event-ID、X-NginxPanel-Node-ID，Idempotency-Key 为 SHA-256(node_id + ":" + event.id)。可选 Bearer 认证及 HMAC-SHA256：X-NginxPanel-Timestamp 为每次请求的 Unix 秒，X-NginxPanel-Signature 为 sha256= 加 HMAC(共享密钥, 时间戳 + "." + 原始正文) 的小写十六进制。接收方应校验签名、时间窗口与幂等键，使用原始正文计算签名。

本机事件最多 2048 条/7 天、投递最多 8192 条、渠道最多 16 个，正文与加密渠道各最多 8 KiB；容量压力优先清理终态投递，丢弃未完成项与事件历史截断的计数在通知页显示。通知页面由 pages 自动扫描，概览提示投递异常，页面隐藏暂停轮询、卸载取消读取。配置/队列/API/页面已接入并生成合同代码；尚未运行构建、类型检查、lint、测试或实际通知投递，P5 统一验证。


主机 DNS 与 ACME DNS 凭据分离。`/host/dns` 返回解析器入口、所有者线索、IPv4/IPv6 地址、搜索域、可确认的持久配置、最近期望与当前任务；入口值不冒充 NetworkManager/resolved 的完整运行解析状态。普通文件适配覆盖无外部管理器的普通 `/etc/resolv.conf`，须本机设置 `--dns-scope=host --dns-owner=regular-file` 并在请求中明确接管；开发、容器、符号链接、自动生成标记、已发现的网络管理器、netplan 或未知组合保持只读。NetworkManager、纯静态 networkd/resolved 及 netplan 的 networkd/NetworkManager 静态源已接入下述独立适配；networkd/netplan 自动 DNS 与 ifcfg 等其他组合仍待实现，不能将已接入适配标记为 DNS 全范围完成。

DNS 使用 Plan → Apply → Confirm/Rollback。计划 5 分钟有效，绑定源内容、文件身份、权限与扩展属性的散列；每用户独立存放加密计划，最多保留 64 个未过期计划。所有写操作要求 host.dns.write、浏览器近期认证和幂等键；计划/任务/审计/幂等响应按业务事务保存，已提交任务保留独立加密快照。确认后的期望配置才进入 host_dns_desired；恢复只刷新匹配原期望的文件身份证明，不将外部配置当作原期望。未提交任务可取消，提交后由同一 Agent 操作 ID 查询和恢复，不能依据 API 超时重复创建 root 操作。

普通文件适配固定路径、拒绝符号/硬链接及不安全权限，源最多 16 KiB；仅替换 nameserver/search/domain，保留无关选项与注释、UID/GID、权限、ACL/SELinux 等扩展属性，原子替换并 fsync。支持 1–3 个 IPv4/IPv6 DNS 地址、最多 6 个搜索域，IPv6 区域限制为合法接口标识；不预填公共 DNS。解析检查由环境指定 1–2 个完整域名，通过 Go 系统解析链执行，不依赖 dig/nslookup 或固定外站；应用后等待解析器配置缓存刷新，再在 8 秒内核验，确认前再次核验并检查文件未被外部修改。解析链成功不代表每个 DNS 服务器均已单独探测。格式依据 Linux resolv.conf 手册 https://man7.org/linux/man-pages/man5/resolv.conf.5.html ，解析接口见 https://pkg.go.dev/net#Resolver 。

Agent 的 `agent/reachability/reachability.json` 在任何 DNS 副作用前保存本次原文/属性、候选、期限与状态，最多 128 KiB，root 私有且不进入业务备份；普通操作日志只保存摘要。节点锁与宿主机全局 DNS 锁阻止重复所有者，DNS 与管理监听在 Agent 内按固定锁顺序排他；防火墙后续接入须复用该约束。确认期限 45–180 秒，进程内同时使用单调时钟；API 停机不确认也不取消该期限，Agent 停止/重启先尝试恢复未确认变更。自动恢复遇到外部内容或属性变化时不覆盖，保留 recovery_required 和快照，禁止后续写入；磁盘不足时仍尝试使用既有持久意图恢复，不能因记录新阶段失败就跳过恢复。仅清理该操作的受限临时文件。

DNS 文件路由页面自动扫描，提供只读来源、显式接管、计划差异、确认倒计时、提交/取消/恢复和期望偏差；轮询不重叠，隐藏暂停，卸载取消读取，待确认时提高轮询频率。接口、数据库模型和路由代码随当前合同生成；系统组合及恢复验证见[验证记录](validation.md)，未验证范围仍待 P5。


NetworkManager 适配须本机设置 `--dns-scope=host --dns-owner=networkmanager`；固定本机 system bus，不接受远程 D-Bus 地址、对象路径或 nmcli 命令。当前写入条件为 NetworkManager ≥ 1.44、已激活且无待保存修改的直接以太网/Wi-Fi 连接、安全的 `/etc/NetworkManager/system-connections/*.nmconnection` 持久源及可用的连接版本接口，并核对 DnsManager 与解析器入口归属（default 文件/链接，或 systemd-resolved 的标准链接）。unmanaged 默认模式、dnsmasq/resolvconf/netconfig 等其他入口组合、生成/临时/外部连接、netplan 生成源、ifcfg、控制器从属设备、加密/特殊 DNS 地址、缺少接口或其他未知组合保持只读；具体系统组合及验收边界见[验证记录](validation.md)。

连接以 UUID 与接口绑定目标，IPv4/IPv6 分别编辑服务器、搜索域及自动获取；入口、连接有效 DNS、运行设置与持久设置分开展示，读取不到保持未知。临时应用使用 `GetAppliedConnection` 版本检查和保留外部 IP 的 `Reapply`；确认前不保存 profile，确认后使用 `Update2(to-disk|no-reapply,version-id)`，再次核对运行和持久状态。仅修改 DNS 地址、非路由搜索域与 ignore-auto-dns，保留路由域、DNS 优先级/选项、IP/网关/路由及其他连接；不重连设备或重启整套网络。完整设置保留 D-Bus variant 签名，IPv6 地址/路由元组使用相应结构类型回写；无法保真编码的复合属性阻止变更。完整设置仅在 root 内存中用于带版本的更新，不调用 GetSecrets，不将 keyfile、密码或全量 profile 进入 Web/业务备份；读取帧、设备数、属性及文件大小均有上限。各目标期望配置分别加密保存，只有确认成功才更新。

独立 root 恢复记录分别保存原始运行/持久 DNS 属性和已授权的新值。期限到达、解析失败或未确认的 Agent 重启恢复两份原值；从最新设置合并 DNS 字段，不恢复整个旧网络 profile。未知 RPC 保留对应 daemon/对象/连接身份、版本及 boot ID/PID/start ticks。原进程已退出时才能直接解除迟到调用阻塞；仍存活时，恢复须通过版本推进阻止迟到写入：运行值尚未改变时，必要时短暂重用已授权的新 DNS 再恢复，以避免无变化 Reapply 不推进版本；只看到旧值不能宣称恢复完成。未证明原进程退出时跨 daemon、system bus 或连接身份变化，出现非快照 DNS，或无法确认版本推进时进入 recovery_required，保留快照并阻止后续冲突写入。已验证的恢复场景及其余系统矩阵缺口见[验证记录](validation.md)。

D-Bus 语义依据 [NetworkManager Device](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.html)、[Settings.Connection](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.Connection.html) 和 NetworkManager 官方实现；使用的 godbus 版本固定为 v5.2.4。


networkd/resolved 观测通过本机 network1 的 ListLinks/Describe 和 resolve1 的逐网卡 DNSEx/Domains 读取。须由本机确认 `--dns-scope=host --dns-owner=networkd`；开发、容器和未确认范围保留只读原因。接口分别返回已加载源路径、按当前磁盘优先级解析的源路径与散列、磁盘 DNS 字段、networkd 已加载的静态/运行时/DHCP/RA 值，以及 resolved 链路值；resolved 存在本身不能证明持久所有者。生成目录继续标记为 generated；netplan 来源关联线索见下文，不能据此宣称已证明实际所有权或生成一致性。

resolved 的两个标准运行文件只用于观测：读取前通过本机系统总线取得 resolve1 唯一服务拥有者的 Unix UID，接受 root 或该服务账户持有的安全常规文件，并在读取后复核服务拥有者未变。权限、链接数、文本及扩展属性预算和读取一致性检查仍生效；持久配置及所有写入快照继续要求 root 持有，不接受 API 指定路径或任意非 root 所有者。

磁盘投影覆盖固定系统目录中的同名 `.network` 及 `.network.d/*.conf` 优先级、空值重置、`/dev/null` 屏蔽、连续行、搜索/路由域及显式 DHCPv4/DHCPv6/RA 的 UseDNS、UseDNR 和 UseDomains 策略。未显式设置的策略保持 null；不填入公共 DNS 或臆测继承值。未知转义/语法、旧 DHCP 节继承规则、超限、非安全 root 文件/目录、符号链接及读取期间变化均保留未知状态与原因。仅散列和 DNS 投影进入 API，原始配置文本不进入 Web。接口按固定帧、网卡、文件、属性及总量预算读取。

networkd 的 Plan/Apply/Confirm/Rollback 仅接管纯静态 DNS：配置须来自本机 `/etc/systemd/network`，合并后的 `[Match] Name=` 为唯一接口字面名称，最后生效源须为已有的安全本机文件，磁盘与已加载源路径一致，磁盘、networkd 与 resolved 的 DNS 值一致，且入口为 resolved 标准链接。DHCPv4/DHCPv6/RA 的 UseDNS 必须显式关闭，UseDomains 明确为 no；UseDNR 未设置时继承已关闭的 UseDNS，显式启用则只读。自动、共享、生成、厂商源及特殊端口/SNI/接口区域地址保持只读。目标使用观测返回的 `networkd:<接口名>`，配置使用 `servers/search`，不接受源路径或命令。

临时应用只调用经过签名检查的 SetLinkDNSEx/SetLinkDomains，不重启网络、不 Reload/Reconfigure，不调用同时清除其他 DNS 策略的 RevertDNS。保留搜索域顺序、路由域、IP/网关/路由和其他解析策略。运行状态与环境验证域名核验后才允许确认；确认时只在最后本机源追加或替换固定 DNS 专用尾段，保留原文、权限及扩展属性，运行覆盖继续生效并由持久源支持下次启动。源与运行状态变化后拒绝沿用旧计划，各目标确认期望分别加密保存。

root 独立快照保存前后文件、运行 DNS、其他源散列、期限和每次写入前的调用意图。超时、解析失败或未确认重启先撤销自己的持久写入，再局部恢复 DNS；外部偏离不覆盖。networkd 不提供版本条件写入，未知 RPC 必须确认原 daemon 已退出后才能继续恢复，进程身份以 boot ID/PID/start ticks 核对；system bus 重连或仅看到旧 DNS 均不构成调用结束证据。无法确认时保留 `recovery_required`，禁止后续冲突操作，不自动重启网络服务。静态支持范围以外的完整策略恢复仍待实施。

netplan 上游观测复用上述宿主机范围授权。固定 networkd 与 NetworkManager 生成路径可与合并源中的同名定义及 renderer 关联；返回 `netplan.state=associated|unresolved`、定义/设备类型、合并源路径、源摘要及 DNS 字段。名称关联不证明当前生成内容与源一致，也不授予写入权限；未匹配的命名或 renderer 冲突保留待确认。页面将源设置与 backend/解析器实际状态分开展示，不把生成文件中的 DNS 当作唯一持久来源。

源读取按 `/lib/netplan`、`/etc/netplan`、`/run/netplan` 的同名遮盖，再按文件名排序进行映射递归合并、序列追加与标量覆盖，语义依据 [Netplan 配置](https://netplan.readthedocs.io/en/latest/netplan-yaml/)及 [generate 层级合同](https://netplan.readthedocs.io/en/1.0/netplan-generate/)。仅接受安全 root 普通 `.yaml`，允许标准 merged-/usr 别名；每目录最多 64 项、有效文件最多 64 份，每份 16 KiB、总量 256 KiB，节点最多 16384、深度最多 32。固定 Go YAML v3.0.5 只解析有界节点，不展开别名。重复键、合并键、自定义标签、类型冲突、多文档及读取变化保留未知；源原文、Wi-Fi 密钥和解析器错误原文不进入响应或日志。

DNS 投影包括显式地址、搜索/路由域、DHCPv4/v6、UseDNS 策略及可选 accept-ra；未显式设置的 DHCP、UseDNS 与 RA 均保持 null，不把后端默认值冒充源字段。特殊地址、超限、未识别 DNS 属性、RA overrides 及 backend 透传覆盖不伪造可用投影。观测结束再次核对目录和源文件，变化后清除摘要与设置。普通读取不调用原生生成器或修改配置。

netplan 源写入须本机设置 `--dns-scope=host --dns-owner=netplan`，沿用 `networkd:<接口名>` 或 NetworkManager 的 `UUID@接口名` 目标及现有计划/应用/确认/回滚 API。当前范围为同名 Ethernet 定义、明确关闭 DHCPv4/DHCPv6/RA、单一已有 `/etc/netplan/*.yaml` nameservers 字段及源、生成文件与已加载 DNS 一致的静态目标。networkd 须按网卡名称独占、无 drop-in 且与 resolved 一致；NetworkManager 须为 ≥1.44、按接口名称独占、无 802.1X 秘密的直接 Ethernet 连接，其 IP 方法为 manual/disabled/ignore/link-local，两个有效地址族共用搜索/路由域。cloud-init 等外部生成标记、共享/未知源、Wi-Fi、自动来源及其他组合保持只读。观测同时返回两种后端的目标，页面按所选目标编辑；迁移预检识别这两类显式授权目标，只携带逻辑 DNS 期望，不迁移本机所有者授权或恢复记录。

计划和应用均在 root 私有临时目录调用固定受信 ELF 生成器，以同一有效 YAML 集分别生成当前与候选结果；冻结程序摘要，限制执行时间、输出及文件树，不返回原生诊断或秘密。当前原生输出必须逐字匹配目标生成文件，候选仅允许 networkd 的 DNS/Domains 行或 NM 的 dns/dns-search 行与选定源 nameservers 字段变化，所有其他生成材料保持一致。准备流程的 D-Bus/生成调用共用 12 秒期限，原生生成仍受每次 3 秒及合计 7 秒限制，公开计划调用预留响应时间。固定中性 argv[0] 避免 systemd generator 模式，并设置 `SYSTEMD_OFFLINE=1` 与 `SYSTEMD_IN_CHROOT=1`，隔离原生启动阶段的 systemctl 路径；依据 [Netplan 原生生成器](https://github.com/canonical/netplan/blob/1.1/src/generate.c)及 [systemd 环境变量合同](https://github.com/systemd/systemd/blob/main/docs/ENVIRONMENT.md)。不运行 `netplan apply/try`，不重载整网。

netplan/networkd 应用仅通过原有 networkd DNS 专用 D-Bus 调用调整所选网卡，系统解析验证后才可确认。root 独立记录同时冻结 YAML 与生成文件的前后内容、属性、完整有效源清单及运行状态；确认先原位原子保存原 YAML 的 nameservers 字段，再原子保存已核对的生成文件。超时、未确认重启及失败先撤销自己的 YAML 和生成文件写入，再按原调用意图与 daemon 退出证明局部恢复运行 DNS；外部修改不覆盖，无法确认保留 `recovery_required`。接口及页面已接入，真实系统组合统一在 P5 验收。

netplan/NM 连接的临时应用只调用带版本的 Reapply，保留静态 IP 方法及原始 ignore-auto-dns 属性。确认先原子保存 YAML，再使用 `Update2(in-memory|no-reapply,plugin=keyfile,version-id)` 更新同一路径 `/run` 连接，禁止 to-disk 将其迁移至 `/etc`。该接口会改写运行目录文件，依据 [NM 更新标志](https://networkmanager.dev/docs/api/latest/nm-dbus-types.html)及 [Update2 合同](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.Connection.html)；root 在消费调用意图前核对磁盘 DNS、全部非 DNS 字段及原始属性，再捕获文件摘要，原子保存已批准的原生生成内容。只接受 root:root 0600 生成文件；文件比对识别键/分组顺序、空分组、当前 UUID、只读时间戳、Ethernet 类型别名、地址/网关等价编码，以及 [IPv6 addr-gen-mode 的磁盘默认语义](https://networkmanager.dev/docs/api/latest/settings-ipv6.html)，其他差异不推测等价。运行/持久非 DNS 设置均冻结摘要，仅排除 NM 自行更新的只读 activation timestamp。恢复先撤销源及已知生成文件，再以版本推进或原 daemon 退出证明恢复两份 DNS，最终核对源、生成文件及 profile；外部偏离和未知写入窗口中无法归属的文件保留 `recovery_required`，不能冒充恢复成功。不存在整网重启或重新激活连接路径。

原生语义依据 [systemd v257 networkd DNS 调用](https://github.com/systemd/systemd/blob/v257/src/network/networkd-link-bus.c)、[DNS 状态序列化](https://github.com/systemd/systemd/blob/v257/src/network/networkd-state-file.c)、[systemd.network 策略](https://github.com/systemd/systemd/blob/v257/man/systemd.network.xml) 和 [resolve1 接口](https://github.com/systemd/systemd/blob/v257/man/org.freedesktop.resolve1.xml)。源码调查与接口同步不构成系统能力验收；集中验证仍在 P5。


## 跨环境配置迁移与固定镜像模块

`/migrations/export`、`/migrations/plan`、`/migrations/{id}/execute` 与 `/migrations/pull` 使用同一严格归档、目标预检及配置事务；状态读取为 `/migrations`、`/migrations/{id}`。加密原生树和显式选择的逻辑秘密在目标重新加密，节点身份、管理通道及目标主机设置保留。API 拉取只访问本次授权源端的固定 HTTPS 导出方法，拒绝重定向，不持久保存源 Key；拉取与执行均保存幂等结果。缺失镜像模块、证书/配置冲突或未就绪运行状态不能应用，草稿不代表生效。权限、边界与实际未实现范围见 [迁移合同](migration.md)。

迁移依赖、修订、任务与审计同事务保存。应用失败须先确认原运行修订，再补偿原期望指针、本次迁入的防火墙期望及本次启用模块；发生外部变化时保留恢复状态。当前树的 `version` 是配置头代次，历史读取仍返回不可变修订自身版本；恢复旧指针会递增配置头代次，下一次保存分配更大的修订版本，避免旧客户端继续写入。导入的停用自动化配置及不可变依赖保留用于审计重试。

[Docker Nginx 配方](../deploy/docker/README.md) 在构建阶段检查并预置所需静态模块，发布能力清单、编译参数及二进制散列；运行时不下载、编译或增装模块。迁移/应用仍核对实际执行器能力，不凭镜像清单伪造运行确认。完整 Docker 接入、组件激活与实际签名发布仍待 P4，当前未构建镜像或执行真实迁移。

原生首次安装仅接收本机 root 批准的程序和配套静态产物，受信路径/架构/散列不替代发行签名。安装意图绑定数据根、管理回环地址、代码/前端内容和 Nginx 程序；只允许同计划续装，拒绝已有非空数据或不同服务。root 持有版本目录、指针、unit、模块批准清单与恢复记录；Web/worker/IPC 身份分离，Web 无 Linux capabilities，业务秘密及执行目录互相隔离。Nginx 与 Agent/Web 分别受 systemd 管理，重启面板不联动停止代理。默认准备文件，显式 `--start` 才启用服务；active 不是业务验收。实现见 [原生安装](../deploy/native/README.md)，安装、服务、沙箱权限及故障矩阵尚未验证，统一留到 P5；不将此入口视为已交付签名更新、组件安装或完整 Docker 运行。

发行资产准备合同：root 固定公钥和 repository，使用 Ed25519 验证域分隔前缀及原始 manifest 字节；清单/签名/信任均不由业务迁移覆盖。只认证后解析有界清单及同一清单内的依赖，根选择项显式给出；组件入口可按平台唯一匹配，多个候选时必须指定资产 ID。在线发现只使用此 GitHub 仓库，标签和渠道须匹配已认证清单；API 元数据使用 ETag/有界缓存和持久限流，Token 仅从 root 私有文件读取，资产只向固定 GitHub 存储域名重定向且移除认证头，签名前不下载组件归档。`manifest_verified` 只表示清单与准入条件，`prepared` 表示归档及已声明运行文件核验后进入 root 不可变目录；两者均不代表安装、兼容性验收或运行成功。USTAR 的物理头逐块核对，拒绝元数据扩展及链接，完整 gzip/文件散列通过后才同目录不覆盖 rename；既有副本不覆盖、复用前重验，容量不足不清除唯一版本或恢复材料。单节点准备串行，信任与系统依赖变更会阻止发布。发布侧使用同一模型、资产/依赖校验、归档预算和签名域，SPDX/来源副本绑定签名文件散列；`signed` 只表示本地产物生成，实际上传和激活分别处理。构建任务与持有私钥的发布任务分开，当前禁止声明自动回滚，真实项目许可及仓库配置不能用占位值代替。具体模型、预算和命令见 [发行准备](releases.md) 与 [发布流程](publishing.md)，组件激活和维护更新仍待 P4，实际验证留到 P5。

原生组件 API 复用上述发行合同，仅接收 nginx/fail2ban 检查或准备，使用 `components.manage`、写入重新认证、统一 JSON 和幂等任务。准备须引用本人成功检查，精确绑定标签、资产、计划、清单和信任散列；root 下载前重新核对。任务输入/结果加密，提交意图先落盘，结果不明查询原 ID；记录缺失或回执不一致保持待恢复，不自动重复执行。Agent 独立保存操作，重启只复核既有发布回执；页面 `/components` 来自文件路由扫描。此入口不激活运行版本，不供 Docker 运行时增装模块，迁移自动安装与运行接入仍待实施。

原生 Nginx 安装绑定为 root 所有的只读记录，签名计划/资产与本机批准程序互斥，禁止首次安装覆盖为另一版本。安装器、systemd exec 入口及 Agent 共用同一程序与内容身份；启动只读核验签名回执、当前公钥/仓库及系统运行文件。清单有效期约束新的安装批准，既有批准按记录时间复核，不能由业务请求传入时间或历史公钥；撤销密钥、内容改动或运行依赖漂移阻止启动。安装绑定不等于服务运行；页面单独显示实际确认。运行中切换与维护恢复不由首次安装入口承担，Docker 不使用该入口补模块。


配置维护合同：普通写 API 在子系统锁前获取共享准入；已有 Nginx、ACME、DNS、组件及迁移任务在 draining 阶段继续收尾，DNS 确认/回滚仍可结束既有操作，自动续期/部署和通知暂停启动新工作。Web 在途操作与非终态任务归零后先持久化 root 请求意图，再以同一 UUID 取得 Agent 独立维护锁。Agent 核对自身执行记录、组件记录、HTTP-01 租约与日志归档状态；无法核实空闲不进入 held。等待超时不代表外部工作已停止，已请求 root 锁须取得释放确认才恢复写入。锁记录不随业务库恢复，Agent 重启刷新 epoch 并重新核验；数据库缺少独立锁时关闭准入，由具备 system.write 与 auth.manage 的管理员显式释放，标识冲突或持久化异常保留待恢复状态。进入/恢复均要求近期认证并审计，进入使用幂等键；释放持久化终态标记以阻止迟到的取得请求。维护只暂停配置及相关执行，不停止已有代理流量、只读观测或登录会话，不宣称数据库所有字节冻结。原生安装显式设置 --maintenance-scope host，开发及未确认范围不能进入宿主机维护；完整快照、组件切换和更新 worker 仍待接入。


推送迁移合同：父任务冻结一次导出，目标配置包散列、节点身份和基础版本固定；目标通过同 UUID 的接收回执及计划事务避免重建，执行仍使用原计划及幂等键。所有远程响应限长并核对目标身份；目标返回的诊断不直接作为通用任务错误，预检摘要中的本次 Key/口令做替换。源端授权与包分别在任务密文内，终态清除活动材料；一小时到期不等于远程工作停止，可能已提交者保留恢复材料，重新授权只继续原阶段。原目标计划已确认后丢失时禁止重新创建；目标补偿结果单独核实，不把草稿/保存/预检当作已应用。源与目标按各自实际操作检查权限，维护期间已接收父任务继续排空，新迁移被共享准入阻止。

迁移依赖准备使用 `migration.dependencies` 父任务，授权仅覆盖本机固定发行信任中的缺失 Nginx 资产检查与准备。父授权不超过迁移有效期和 30 分钟；组件子任务、幂等回执与父关联同事务提交，重启仅核对原子任务。准备必须匹配迁移所需能力及已检查的标签/资产/清单/信任，不能替换已有实例、安装系统包或编译/增装 Nginx 模块。`prepared` 不解除运行、完整性或模块启用准入；不确定结果保留恢复状态。计划重新预检保留原基础版本、资源 ID 和有效期，不创建新资源。

原生安装允许明确选择仅 Web/Agent。Nginx 未安装使用 root 只读绑定记录的 `owner=uninstalled`，程序/版本/散列/签名字段必须为空；记录缺失或已装资产失效仍是错误。Agent 可在此状态提供目标依赖预检及可信准备，初始化与启动入口继续要求有效安装；普通启动不会安装组件。Nginx unit 的只读条件入口仅对明确未安装跳过，其余校验错误报告失败。

原生未安装槽位的首次安装由独立 root `component-install` 进程执行，先保存带原维护 UUID、资产计划、完整选项及原绑定的安装记录，再初始化并检查受管空基线，以比较原绑定的方式原子发布新绑定。仅允许本机已登记程序、固定专用 unit 与签名准备资产；不替换已有实例，不安装模块或系统包。启用和启动分别显式授权；重启 Agent 后，以 Web 身份核对同源安装、基线完整性及请求的运行状态才记成功。安装记录不属于排空的普通任务，但非终态阻止原维护锁释放；中断后只接受原操作显式续办，未发布绑定可显式取消，审计与生成基线保留。锁取得/释放与执行器准入共用跨进程锁，原记录不随业务库恢复。Web/API 首次安装任务已调用同一执行器，原生安装器登记独立 systemd 模板，启动固定 UUID 实例而不重启已有 worker。任务按准备回执固定资产与散列，要求原维护会话 held；十分钟授权与递增控制序号持久化，重启不续期、旧请求不覆盖新授权。Web 对账核实原独立记录与实际服务状态，非终态任务也阻止 Web 侧释放；记录缺失保持待恢复，不能假定未执行。续办/取消均重新授权且只使用原资产和选项，迁移父任务自动协调仍待接入。

## 管理入口独立恢复

Agent 合同为 35。主回环 HTTPS 与部署/就绪绑定不变，可选远程入口按版本、权限、近期认证和幂等键写入。root 持久保存候选、原配置及 120 秒期限，只有候选代次的新 TCP/TLS 连接可确认，记录实际来源。Agent 持有 TCP 描述符并通过 UID 核验的 unixpacket 通道交付应用终结 TLS，使用 shutdown 撤销已交付连接；超时、Web 通道中断或 Agent 重启恢复原入口，失败保留 recovery_required。源地址不从 HTTP 头推断；回环和旧连接不能确认。停用须走主回环入口，root 本机命令可独立提交持久停用救援请求。私钥只保存在 root 私有状态及受限 IPC，不进入公开响应、业务备份或迁移包。提交及确认前还须证明当前受管防火墙对象，并按已确认策略完整核对候选端口、来源 CIDR 及接口；冲突不更改原入口，核对不延长确认期限。只证明本应用策略判定，不将草稿、模块开关或单一来源的新连接当作全部来源放行。详见 [管理入口](management-listener.md)。

完整灾备运行合同：本机 root 的 `backup-restore-apply` 先持久批准原安装意图及计划，固定非 root 助手再调用私有 `POST /v1/nginx/disaster`。端点只接受协议、原恢复 UUID、计划摘要、当前维护 epoch 和补偿方向，返回沿用 Agent 的 `protocol/code/message/data` 封装；配置及证书材料只从计划绑定的 root 0400 固定请求读取。执行复用原 Nginx 候选/校验/切换/运行观察，子操作 UUID 为计划 UUID，并关联原完整恢复 UUID；Agent 重启只处理已接受记录。root 补偿批准不可撤销或被应用请求覆盖，先确认原 Nginx 逻辑修订与物理部署，再补偿业务文件。运行确认保持父事务 `recovery_required`、维护停机、root 写入屏障和数据库恢复屏障；本机 root 对账入口通过独立非 root 副本、固定意图及二次只读逐表/逐行比较，终止源在途流程并保存真实运行对应的已生效修订；源外部结果继续待核对。`data_reconciled` 仍保留父事务及两层恢复屏障。本机 root 的 `backup-restore-activate` 明确接受不可回退提交，生成独立完成数据库并二次只读核对；父事务先保存 `activation_committed`，再安装副本、以原程序启动和检查就绪。就绪成功后才发布原维护完成授权，Agent 锁释放及应用数据库持久释放均确认后记录成功。启动后仅续办原激活，禁止原文件/Nginx 补偿覆盖新写入；自动化仍停用，外部结果待人工核对。详见 [完整备份](backups.md)。

本机就绪合同为 2，root 专用 Unix socket 沿用统一 JSON 封装与对端进程/受信程序核验。`GET /v1/maintenance-release/{restore_id}/{maintenance_id}` 只读核对当前数据库的原恢复屏障已完成、原维护会话已 released 且维护任务已 succeeded；不执行释放，不开放到公网 API。独立恢复记录保留就绪及应用释放证据，状态查询不将历史证据当作实时健康状态。

迁移与完整恢复的目标能力预检沿 nginx.conf 的实际 include 关系区分 HTTP/Stream，保留共享 include 的各自上下文，只统计启用且可达的配置。map/geo/types/split_clients 的行按数据处理，map 的 volatile 参数及其 include 单独识别。HTTP 与 Stream 的 map、连接限制、访问控制和日志不能互相替代；HTTP proxy/headers/geo/split_clients/charset/gzip 与 Stream 默认子模块同时检查目标编译参数和必要版本。已选且当前本机批准的动态模块可作为待加载候选，必须继续经过 Agent 的配置、ABI 和运行确认；仅有当前运行能力不能替代本次 load_module 路径批准。Docker 缺失能力须更换预置镜像；源模块只能显式映射至批准路径或在静态能力已预置时移除，不传输模块二进制。编译参数及 Stream 模块边界依据 [Nginx 构建源码](https://github.com/nginx/nginx/blob/release-1.30.6/auto/options)、[Stream map](https://nginx.org/en/docs/stream/ngx_stream_map_module.html) 和 [Stream 连接限制](https://nginx.org/en/docs/stream/ngx_stream_limit_conn_module.html)。


宿主机防火墙只读诊断通过 `GET /firewall` 和显式远程资源返回 FirewallObservation，区分管理器、命令后端、独立 IPv4/IPv6 规则结构和 Docker 路径标记。未知/超限不作为停用或完整读取；本机宿主机观测授权、读取预算和未交付边界见 [防火墙诊断](firewall.md)。统一 JSON 外壳及自动扫描页面沿用当前合同，Agent 协议为 40，真实系统验收留待 P5。

防火墙期望策略通过 `GET/PUT /firewall/policy` 读写，版本 CAS、加密载荷、幂等响应与审计同事务；写入要求 `security.write` 和浏览器近期认证。`POST /firewall/preview` 要求 `read`，固定已保存版本，生成直接 nftables 表达式与程序摘要并核对 Agent 环境和目标接口。全部使用统一 JSON 外壳与显式远程资源；页面自动扫描。保存与预览不触发内核写入，`can_apply` 恒为 false，不替代独立恢复或新连接确认。数据库迁移为 24，Agent 协议为 40；边界见 [防火墙](firewall.md)。

防火墙 `kernel` 子视图由 root 在宿主机范围内通过只读 NETLINK_NETFILTER 固定 GET 操作采集。前后内核代次和命名空间须一致，未知原始表达式保留参与摘要，不以宽松解码后的子集认领规则；不完整读取不产生可用快照。预览在目标表不存在时编码带 `NFNL_BATCH_GENID` 的独占新建事务并返回摘要/规模，摘要绑定命名空间和快照，不提供执行授权。该策略预览事务仍没有发送入口；本机 root 已另行接入固定空表登记、提交回执/完整后读、中断核对及受管空表移除，公开 registration 子视图返回核对状态。direct-nftables 主机入站执行现通过独立计划、原子应用、120 秒新 TCP/TLS 确认及 root 超时/重启恢复接入；运行 API 仅允许直接连接目标节点，写入还需模块启用和本机授权。其余适配继续实施。Agent 协议为 40，数据库为 25；详见 [防火墙](firewall.md)。

防火墙运行合同：`/firewall/runtime`、`/firewall/plan`、`/firewall/apply` 与 `/firewall/operations/{id}`（含 confirm/rollback）使用统一外壳并拒绝递归转发。计划绑定保存版本、完整内核基线、实际管理连接与 SSH 保护；应用先保存 root 意图，独立操作不依赖业务库恢复。确认须使用规则生效后重建监听的新非回环 TCP/TLS 连接，范围限于该管理入口；未确认、Web 失联、Agent 停止/重启均恢复原确认策略。root 运行记录及恢复意图不进入业务备份/迁移；已确认对象缺失按原版本恢复，漂移拒绝覆盖。模块停用须明确选择保留规则或引用已确认的移除操作；既有确认与恢复继续可用。Agent 为 35，数据库为 25；其他后端、Docker 及 P5 真实系统验收仍未完成。

防火墙逻辑迁移使用 schema 4 的固定归档项和 `selection.firewall`，文件及 API 拉取/推送共用导入事务。目标默认 preserve，显式 merge/replace 必须指定后端并完成绑定接口映射，冻结目标期望版本及内容并重分配规则 ID；应用 Nginx 失败时以新版本补偿原期望，冲突保留待恢复。任何迁入模式都不启用模块或写内核，生效沿用目标独立计划和新连接确认。规则预览有界且远端摘要脱敏，列表不携带完整规则；公开响应及 Agent 合同不变，详见 [迁移](migration.md)。

防火墙执行合同明确 `action=apply|remove`，计划/提交/操作均固定动作。移除绑定已确认运行版本，保留期望草稿，将经完整证明的受管表原子替换为空表；新连接确认前恢复旧规则，确认后只维护已移除的空表状态。停用 `firewall_rules=remove` 须引用当前已成功确认的移除操作；已核对的初始空表可直接停用。核对与最终开关写入同公共执行锁；keep 明确保留规则，未完成移除不报告模块停用。Agent 为 35、root 运行记录为 3，数据库为 25；无旧格式兼容，详见 [防火墙](firewall.md)。

防火墙 `protection_observation` 返回绑定原确认计划的独立保护依据采样，区分 current/changed/unavailable/not_applicable，包含采样时间、当前 SSH 方式/实际监听及重新核对的保护项。30 秒后台采样、3 秒读取期限、45 秒有效期，不由 GET 启动采集或根据调用方新增来源；模块停用后的已保留保护仍核对。应用确认前另行新采集：依据变化恢复原策略并返回真实 rolled_back，读取未知不允许确认，核对不延长原期限。差异只能经明确重新计划、应用、新连接确认更新，不自动重写 SSH 或内核；root 记录为 3、Agent 为 35，数据库为 25。详见 [保护来源核对](firewall.md)。


## Fail2ban 宿主机诊断

`GET /fail2ban` 与显式远程读取资源返回 `Fail2banObservation`，要求 `read` 权限，沿用统一 JSON 外壳。默认停用时仍可诊断：root Agent 确认宿主机范围后，有界读取固定系统程序/客户端版本、隔离 Python 标准库及 SQLite 内存能力、解释器软件包归属、固定 systemd 单元与默认 Socket 文件。只读元数据不连接实例，不触发 Socket 激活或安装/启动；程序存在、服务活动、完整引擎就绪与 jail 保护不互相替代，未知保持可见。采集单份在途、30 秒缓存，页面自动扫描且仅首次/手动刷新。模块控制暂不可启用；已有运行实例经本机授权后可只读接入，jail 期望配置已接入，运行控制继续实施；当前 Agent 协议为 40、数据库为 25。边界及官方依据见 [Fail2ban](fail2ban.md)，真实系统验证留待 P5。


已有 Fail2ban 实例由本机 root 的 `fail2ban-bind/binding/unbind` 固定服务、Socket 和客户端批准，独立历史先于当前指针持久化，撤销不停止保护。`GET /fail2ban/instance` 与 `/fail2ban/jails/{name}` 及其显式远程资源只读已有 jail；采集前后核对运行身份、主进程 Socket 归属、客户端散列/版本与当前批准，拒绝激活依赖及漂移。完整有界解析状态，失败不伪造零值或返回部分记录，封禁仅代表引擎记录，动作适用性单独核对。缓存和预算覆盖实例及 jail，页面取消旧读取并显示真实采样时间。Agent 协议为 40，已有实例接入记录为 1，数据库为 25；不开放任意客户端命令或路径输入，详见 [Fail2ban](fail2ban.md)。


Fail2ban 期望配置使用 `GET/PUT /fail2ban/policy`、内置模板清单与版本化预览，沿用统一 JSON 及显式远程资源。最多 32 个类型化 jail，加密保存、CAS、幂等与审计同事务；保存不修改运行实例，当前 `can_apply=false`。schema 4 配置包的 `selection.fail2ban` 与固定归档项仅携带期望，文件/API 拉取/推送的 preserve/merge/replace 同 Nginx 导入事务及失败补偿集成，冻结版本与内容，不覆盖后续修改。数据库为 25，Agent 为 40，无旧包兼容。边界见 [Fail2ban](fail2ban.md)。


Fail2ban 固定过滤器/固定样例及 `POST /fail2ban/templates/check` 已接入官方工具检查，要求 read，固定内置 ID、程序目录/版本、独立临时材料和执行预算。结果区分可读取与样例通过，附带工具/内容散列及采样时间；失败不返回部分通过。保存预览要求日志的 `auth_presence` 标记与过滤器检查同时就绪，仍不表示 jail 已安装或动作生效。Agent 为 40，数据库仍为 25、迁移 schema 为 4；[详细边界与待验收项](fail2ban.md)。

Fail2ban 诊断新增必需的 `managed` 安装登记对象，区分 absent/unavailable、reserved/ready/installed、interrupted 和 rolling-back/rolled-back，不作为实际引擎健康或 jail 保护证明。本机 root 的 `fail2ban-install` 接受操作 UUID、固定已准备计划与资产、信任文件及显式启动/开机启用选择；`fail2ban-managed*` 只操作专用服务。没有公开安装/服务控制 HTTP 接口；模块开关不发起这些操作。安装事件及指针位于 root 私有目录，接入详见 [Fail2ban](fail2ban.md)。Agent 协议为 40，数据库为 25；尚未执行实际系统验收。

Fail2ban 的 `binding.engine` 与模板检查 `engine` 统一携带 existing/managed/none/unavailable 来源及受管安装/计划/资产/清单/Python 身份。已完成的本机受管安装直接授权其固定客户端只读观察和固定样例工具；已有实例保持独立明确接入，冲突及中间状态不隐式改选。当前安装事件 ID 参与读取授权及缓存选择，实际采集前后认证程序，受管进程核对实际解释器、参数及单元。保存预览还要求检查与实例同来源、同受支持版本；jail 仍只读且不可应用。共享采集上限为 10 秒，单命令 2 秒，保留原缓存时间和并发预算。Agent 协议为 40、数据库为 25；实际验证留待 P5。

配置迁移新增 `selection.monitoring`、`monitoring` 导入选项和计划摘要，包含采样/保留/阈值设置，默认保留目标。目标替换须 monitoring.write，冻结基础版本并同事务导入；草稿不修改监控，应用失败按版本及完整内容补偿。迁移归档当前 schema 4，Agent 仍为 40、数据库仍为 25，JSON 外壳和页面自动扫描不变。详见 [迁移边界](migration.md)。

Nginx HTTP 站点元信息新增可选 client_deny，声明受管客户端拒绝入口而不启动或应用 jail。当前 Agent 合同为 44、策略 nginxpanel-8，数据库为 26、迁移 schema 为 4。独立类型化集合、逐站点可信代理保护及集合代次探针接入发布/回滚/外部检查；本机 root 的独立 Socket 接受固定 bind/unbind/refresh/status，使用 Agent 统一外壳，授权 CAS 与不可变事件、官方当前封禁合并、串行更新及单槽恢复快照已经接通。排队与运行确认分开，root 授权和实际封禁不迁移；公开 jail 应用复用同一执行器，独立动作授权和刷新仍仅 root 可用。详情见 [Fail2ban 客户端入口](fail2ban.md)。

受管 jail 使用 `POST /v1/fail2ban/jails/apply`、`GET /v1/fail2ban/jails/status` 与 `GET /v1/fail2ban/jails/operations/{id}`，由 root Socket 与受限 Web Agent Socket 共用同一执行器。请求固定 protocol/operation_id/base_id/target/policy，完整类型化策略最多 64 KiB，配置包 UUID 做 CAS、请求摘要做幂等；提交返回排队操作，状态中的 selected_id 只表示所选配置，运行及 Nginx 集合分别核对。仅明确登记且可读取的本应用 jail 返回 managed=true，所有 jail 仍 writable=false，公开预览按目标基准及启用项检查计算 can_apply；代码来源与配置包选择共同使读取缓存失效。失败恢复原配置、授权及官方剩余封禁时间，无法确认时保留恢复阻塞。所有 root 配置包、身份、备份树、封禁时间证明及执行记录不迁移。数据库及归档版本不变；实际验证留待 P5。


受管 jail 的公开合同新增 `GET /fail2ban/runtime`、`POST /fail2ban/apply` 与 `GET /fail2ban/tasks` 及对应显式远程资源。应用固定 version/policy_hash/base_id/target，要求 security.write、幂等与近期认证，HTTP 202 返回持久任务；复用独立 root 执行器，只允许已运行受管实例的 nginx-client 动作。预览返回运行基准和将停用项，can_apply 按实际条件计算；单 jail 查询仍 writable=false。目标摘要纳入安装、服务代次、Nginx 部署/清单、所选配置与动作授权，返回操作增加 request_hash/target 供后台严格核对。模块可显式启用且不安装/启动/停止服务；应用与恢复期间阻止对应期望写入。新增加密 fail2ban_operations 表，数据库为 26，Agent 为 44，归档 schema 仍为 4；无旧协议兼容。未执行生成器与运行验证，留待 P5。


主机 DNS 配置迁移新增 `selection.host_dns`、`host_dns.mode=preserve|map`、逐源显式目标及可选目标配置，文件导入、API 拉取与推送共用同一逻辑。只导出已确认期望配置；映射要求 host.dns.write，缺失/重复目标、跨配置类型及接口区域转换须明确处理。计划返回候选及目标就绪条件，保存只暂存加密材料，不改写运行 DNS 或伪造已确认期望；目标 DNS 页面载入后重新生成原计划并单独确认。推送严格核对源包散列、映射、配置与阶段，不重放接管或恢复授权。迁移归档当前 schema 为 5，Agent 仍为 44、数据库仍为 26；统一 JSON 与自动扫描路由不变。未运行生成器、构建、类型检查、测试或真实操作，待 P5；详见 [主机 DNS 迁移](migration.md#主机-dns-配置迁移)。


受管地址的公开合同新增 `GET /fail2ban/addresses/status`、`POST /fail2ban/addresses`、`GET /fail2ban/addresses/tasks` 及显式远程资源。输入限定本应用 nginx-client jail、单个规范数值 IP、ban/unban 与本次 target；提交要求 security.write、近期认证、幂等和模块启用。root 固定官方客户端参数，派发前持久标记，结果不明只观察原操作，拒绝自动重发或逆向补偿；已封禁 ban 不续期，unban 同时清除所选 jail 的持久记录。本机/忽略/代理地址禁止 ban。引擎当前状态、客户端回执和 Nginx 受管集合运行代次独立返回，其他 jail 可继续拒绝同一地址。共享加密任务材料、审计、恢复隔离和容量上限；手动操作不进入业务迁移。Agent 为 45，数据库仍为 26、归档 schema 为 5；单 jail 诊断 writable=false 不充当写入授权。声明与页面已接入，未执行生成器或运行验证，待 P5；详见 [Fail2ban](fail2ban.md)。


Fail2ban 独立实例新增 `POST /fail2ban/lifecycle/preview`、`POST /fail2ban/lifecycle` 与 `GET /fail2ban/lifecycle/tasks` 及对应显式远程资源。install 仅使用已准备的单个签名资产并注册服务，不启动或开机启用；resume/rollback/start/stop/enable/disable 固定当前实例。`x-action-scopes` 明确 install 的 components.manage、服务控制的 security.write、续办/撤回的两者；预览另需 read，写入要求近期认证及幂等。预览冻结安装/依赖/服务代次与开机设置/jail/动作授权，后台复用原本机执行器，派发后不自动重放；install/resume/start/enable 受管理开关约束，停用/撤回可明确处理保留保护。撤回只清理该安装授权，CAS 不覆盖外部变化，Nginx 集合独立确认。独立 root 协调器纳入维护和共享操作互斥，任务/审计/加密快照/备份隔离已接入，页面继续自动扫描。Agent 为 46、数据库为 26、归档为 5；未运行项目生成器或运行验证，待 P5。详见 [Fail2ban](fail2ban.md)。


本机 root 新增 `fail2ban-python-plan/install/status`，仅用于缺失系统 Python 的固定最小系统包计划、显式确认和原操作核对；原生 APT/DNF 4 保留签名与锁，不提供任意包、仓库、命令或自动重放。root 独立计划/journal 与下载材料不迁移，公开依赖 API 尚未接入；现有生命周期 install/resume/start/enable 均受管理模块开关约束。Agent/数据库/归档版本保持 46/26/5，运行验证待 P5，详见 [Fail2ban](fail2ban.md)。


Python 依赖公开合同新增 `POST /fail2ban/python`、`GET /fail2ban/python/tasks` 及对应显式远程资源。plan 异步生成保存一小时的固定系统包计划，可显式刷新既有索引；install 独立确认原 plan_id 且禁止同时刷新。写入要求 components.manage、管理模块启用、近期认证及幂等，202 仅表示排队；最近 16 条任务包含保存的计划/安装结果，Agent 离线仍可读取。网页与本机 CLI 共用安装记录和原生执行器，未派发请求限授权期内继续，派发标记后不自动重放；计划生成同样保存派发标记与结果引用，重启不自动重复索引刷新。共享互斥、维护、加密任务/审计与备份恢复隔离均已接入，业务迁移不携带系统包事务。当前 Agent/数据库/归档版本为 47/26/5，首版无旧协议兼容；声明已同步，项目生成器及运行验证留待 P5。详见 [Fail2ban](fail2ban.md)。


配置迁移当前为 schema 6，ExportInput/Manifest/Plan 明确 `mode=portable|encrypted`。portable 普通归档口令为空、selection 全 false，仅从受管字段重建 HTTP/Stream、ACL 与基础 WAF，站点停用并列出省略；不转移原文、自由字符串或其他可选材料。encrypted 继续强制口令和秘密权限，按选择实际写入文件。导出基础权限为 backup.export，完整原文额外检查 backup.secrets/config.secrets，均要求浏览器近期认证；目标替换权限不降低。普通导入强制模式/封装一致及规范化重建核对，加密包先认证完整 age 流；共用映射、依赖、执行和恢复。API 拉取/推送显式使用加密模式。Agent/数据库仍为 47/26，接口声明已同步，生成器及运行验收留待 P5；无首版旧包兼容。详见 [配置迁移](migration.md)。


面板密码认证失败新增 root 私有 `POST /v1/fail2ban/panel-login`、只读 GET 及公开 `GET /fail2ban/panel-login` 与显式节点资源。事件由 Web 的真实 TCP 对端和请求 UUID 提交，root 生成 UTC 时间及固定类型，拒绝非数值地址；不接收公开事件写入或自定义日志路径。公开统一外壳中的 Fail2banPanelLoginStatus 携带来源/格式/范围/原因、8 MiB 容量边界和最近 20 条 Fail2banPanelLoginEvent。追加回执不明不重放，不改变密码认证拒绝结果；日志就绪不等于封禁生效。内置模板增加 panel-login-failure，官方检查最多 3 个模板；面板 resource_id 为空且仅 host-input，Nginx 模板仍要求站点 UUID。保存/迁移不应用保护，预览及 root 明确拒绝面板启用项，等待宿主机动作后端。当前 Agent/数据库/归档为 48/26/6；首版不兼容旧协议，声明同步，项目生成器及运行验证留待 P5。详见 [Fail2ban](fail2ban.md)。


宿主机入口动作的只读 `GET /fail2ban/host-input`、root 对应 GET 和显式节点资源统一返回 Fail2banHostInputPreview，含必填 registration/protection；host-input 启用项的 jail 预览附带同一诊断。registration 由目标本机 root 独立记录、操作回执和同代次内核指纹核对，不能用名称或标记冒认所有权。未登记同名表、非空/变化对象、意图或回执待恢复时阻塞准备；原样已登记空表须具备当前本机管理/代理来源批准才能生成空集合材料，can_prepare 不授予执行权，can_apply 始终 false。四个 fail2ban-host-input-* 本机 root 命令负责固定空表登记、状态、只读恢复及移除，使用独立所有者/路径/锁、操作 UUID、基础操作 CAS 和先持久后单次提交；结果不明不重放，缺失确认表通过关联释放记录保留旧审计。记录不进入备份/迁移，公开 API 不接收表名、表达式、消息或写入授权；人工端口规则仍固定原目标。Agent/数据库/归档为 51/26/6，无旧协议兼容，声明已同步；生成器及运行验证仍待 P5。带 hook 的运行恢复、官方生命周期和面板 jail 应用继续实施，详见 [Fail2ban](fail2ban.md)。


protection 返回目标本机 root 管理/代理来源批准的状态、ID、时间、策略散列和规范来源，不接受 Web 写入。三个 fail2ban-host-protection-* 本机命令提供明确列表批准、状态及撤销，使用操作 UUID/CAS、先不可变事件后原子指针，关联旧批准但不改写审计。批准绑定 root 所有者、登记操作及命名空间；漂移、撤销、缺失、未知格式或无法完整核对均不能准备。两个来源列表必须明确，管理来源非空、每类最多 128；本地来源持续采样并与批准来源合并。新增批准与维护互斥，撤销只改变后续准入且不直接删除封禁；所有状态不随备份/迁移复制。Agent 为 51，数据库/归档仍为 26/6，声明同步；运行恢复和封禁桥接仍待实施，生成器与运行验证仍待 P5。


受管 jail 的 root 执行器独立于 Nginx，jail 事务冻结官方实例、所选配置及可选 Nginx/宿主机授权摘要。面板登录宿主机动作仅使用固定 root 日志和不带 IP/jail 参数的同步通知；须目标本机明确批准 managed 来源及持续会话。官方完整来源动态派生自当前受管配置并核对真实名单，最多 32 项；配置切换使旧同步观察等待新采样。公开 runtime 增加 host_ready/host_reason、nginx_ready/nginx_reason，sources 增加 managed；配置成功、官方记录及动作执行状态保持独立，Agent 为 55、数据库/迁移为 26/6，不兼容旧合同。仅 Nginx 相关事务包含其运行/登记及恢复材料，宿主机事务无需 Nginx。所有 root 授权、配置包和运行检查点仍不进入配置迁移。实际验收留待 P5。


手动地址入口复用独立 jail 执行器及统一任务，支持 nginx-client 与受管面板登录 host-input。AddressStatus 必填 backend，未知宿主机规则返回 action_state=unknown、空 generation、can_ban=false 及原因；已核对官方引擎仍可明确解封，不能据此宣称内核已经清除。新宿主机封禁须当前批准/持续会话和所属对象完整可证明，目标摘要纳入宿主机批准；内核代次观察与任务的引擎结果独立。新任务准入与维护串行，执行持 Nginx（若存在）→宿主机→实例锁，派发后只观察原操作，终态唤醒对应原动作对账。Agent 为 56、数据库/归档仍为 26/6，声明已同步，实际验证留待 P5。


目标端 `POST /migrations/pull` 新增可选 `dependencies`，复用既有组件准备/原生首次安装授权与任务；`MigrationPlan.pull` 返回自动迁入的 state、stage、mode、error 和 deadline。预检模式禁止此授权；需要 components.manage，首次安装另需 system.write。授权只保留本地最小权限与冻结输入，期限不超过原计划 30 分钟，不保存源 API Key 或包口令；原任务缺失停止重新创建，过期不取消已提交操作。数据库新增迁入协调字段（schema 27），Agent 仍为 64，归档仍为 6；完整恢复清除源授权。MigrationReceiver 声明同步当前归档 schema 6。统一返回及自动扫描页面不变；尚未运行生成器、构建、类型检查、测试或真实迁移，留待 P5。


手动地址合同新增必填 engine_owner=managed|existing，以及提交时的 adoption_id（managed 为空，existing 必须为本机有效接管 ID）；地址状态查询增加同名参数，existing 必须提供 adoption_id。同一地址 API、任务、加密回执及显式远程资源覆盖已接管 SSH jail，页面复用同一地址面板并按所有者/接管 ID 筛选历史。发送前与发送后沿用完整原生运行证明，固定官方单 jail banip/unbanip；existing-ssh 动作状态返回 unknown，仅确认引擎，不能推断内核阻断。原接管/参数/服务/配置变化、保护地址或任务缺失停止提交；派发标记持久后不重放及不逆向补偿。Agent 为 65、数据库为 27、归档为 6；没有旧协议分支。未运行生成器、构建、类型检查、测试或真实 Fail2ban，待 P5。

完整 SSH 地址状态读取复用原有读取预算和缓存，后台上限 90 秒，HTTP 仅等待本次 12 秒；后续相同查询跟随同一读取，完成后保留 30 秒且不刷新采样时间。最多 2 个并行读取、每 30 秒 16 次启动及 65 项；管理写入始终重新核对完整实际运行证明。


离线恢复新增 root 只读 `backup-restore-external` 及固定非 root 描述符助手：原对账摘要、类别和游标固定输入，每页最多 64 条，完整清单摘要覆盖全部分类源记录，绑定原恢复/对账。激活输入新增 external_review（完整清单摘要及按类别排序的 count/sha256/resolution/evidence），只接收 verified/remediated/no_effect 人工结论；空清单也显式提交空数组。两个数据库助手独立重新扫描，覆盖或摘要不符不批准激活。复核为管理员声明，不推断第三方结果、不发送请求或重放；原结论随 schema 2 激活意图和报告不可变保存，所有重试核对原内容。输入上限 32 KiB、证据每项 512 字节；最多 10 类、每类 100 万条、每字段 16 MiB、扫描总材料 2 GiB，沿用原助手期限。Agent/数据库/归档仍为 65/27/6，公开 JSON 和自动扫描路由不变。未运行构建、类型检查、lint、测试或真实恢复，待 P5。


默认发布规格包含 nginx-linux-amd64/arm64，入口为 bin/nginx，版本取发布工具内嵌 nginx-source-lock.json，归档名同时绑定 Nginx 版本与面板发行版本。资产固定 static、Linux、any/any 和静态模块特征；目标选择只消除发行版动态库约束，不承诺实际系统运行验收。native-nginx-source-and-static-runtime provenance 绑定原发布仓库/版本/提交/资产/workflow、程序散列，以及 native_nginx 中的源码配方散列、完整参数、musl-gcc 版本、runner 镜像、nginx -V 与系统包清单散列及三份静态运行库名称/路径/包版本/散列/许可文件。SPDX 的四份源码、三份运行库和程序须与原材料完全对应，运行库 LicenseRef 原文须匹配归档 copyright/GPL-3。发布工具不执行输入 ELF，复用静态闭包检查并要求配方内各模块具有已定义对象符号；证据副本仍逐字节匹配签名文件清单。组件接收、首次安装、迁移准备和 Docker 模块策略不增加新协议或运行时编译入口。


Agent 66 的 Fail2ban 发行资产使用 system-python ABI，architecture/distribution/distribution_version 为 any，runtime_files 为空，python 声明 cpython 及包含边界的 minimum_minor/maximum_minor（接收端只接受 9–14 内范围，主版本固定 3）。其他组件拒绝此 ABI/字段。实际准备及复核使用固定 root 保护 /usr/bin/python3，经 -I -S -B 在两秒内探测固定标准库、SQLite 内存读写与标准 GIL 模式；16 KiB stdout/4 KiB stderr、进程组超时终止，前后核对路径、inode 与散列。readiness 不等于官方服务运行成功；安装仍按原 root 记录绑定实际本机解释器身份。默认 fail2ban 组装来源以 fail2ban-official-code 绑定原发布身份、workflow、配方/逐源文件清单/入口版本记录散列及组装 Python 版本；签名工具核对官方入口/版本/兼容文件和许可、逐源文件清单及 SPDX。目标不运行安装脚本、pip、包内解释器或上游默认 jail/action，不保留首版前旧 ABI 兼容分支。

原生 Nginx 运行组件切换使用 `component.nginx.switch` 独立 root 子记录及 schema 1 固定意图摘要；Web/API 通过 `component.nginx.switch.dispatch` 父记录和独立 systemd 实例执行同一核心。Agent 协议为 67，数据库为 28。公开 `/components/switches` 的创建/列表/详情及原任务 resume/rollback 沿用 `code/message/data/request_id/node_id`，Agent 端点沿用 `protocol/code/message/data`。创建绑定签名准备结果、当前程序散列及逻辑/物理发布标识，并要求明确停机确认；每次启动授权五分钟、序号严格递增且最多 32 次，已领取授权不能重用，补偿指令不能被后续续办改回前进。派发与子操作身份、固定快照和实际运行终态须一致，非终态同时阻止 Web 与 root 释放原维护会话。只读查询不控制服务；备份恢复隔离的源任务不提交、不续办、不补偿。具体命令与限制见 releases.md。


审计读取改为明确时间窗口及游标合同，不保留首版前的 offset/数组返回。`GET /audit` 要求 from/until（Unix 秒，含端点、单次最多九十天），可按 principal/action/resource_id/outcome/request_id 精确筛选，limit 为 1–100、默认 30。统一 JSON 的 data 为 rows/start_cursor/cursor/more/scanned/notice；复合排序为 created_at/id 倒序。初次读取固定只追加审计表的 rowid 上界，HMAC 游标绑定条件与页大小，十分钟到期，进程/数据库恢复重启后失效。start_cursor 可重读当前页，包含第一页，不因新日志插入改变同次翻页边界；单页扫描最多 5000 条，可能返回空页但 more=true，须沿 cursor 继续。最多四个并发读取，查询三秒；数据库增加复合分页索引，版本为 29，Agent 仍为 67。

`POST /audit/export` 接收同一筛选条件，不接受分页游标，要求 read、浏览器 CSRF 及近期认证；机器凭据保持自身 read 授权。十秒内扫描最多一万条并输出最多 8 MiB，同节点只允许一个归档，与查询共用四个读取槽；超过范围返回 AUDIT_EXPORT_TOO_LARGE，不交付部分成功文件。成功为 application/x-ndjson，首行 nginxpanel_audit_archive/schema=1 清单含归档 ID、节点、准备时间、条件、count 与 rows_sha256，后续每行为 type=entry/row。rows_sha256 覆盖全部原始记录行（含每行 LF、不含清单行），X-Archive-SHA256 覆盖整个文件，浏览器核验后才提供下载；空结果也是显式零条清单。源审计记录保留，audit.export/prepared 记录描述归档准备而非网络交付。坏标识、无效 UTF-8 或超限元数据明确失败，不跳过或改写记录。JSON 错误继续使用统一封装；查询及下载均登记显式远程节点合同并核对目标身份和归档摘要。未运行生成器、构建、类型检查、lint、测试或服务，待 P5 集中验证。


系统文件日志由 root Agent 管理，Web 无直接目录权限。`logs/application/events.jsonl` 保存 warning/error 的固定级别、代码位置及可选有效请求 UUID；不收集原消息、错误属性、配置或请求载荷。`logs/security/events.jsonl` 从已提交身份/凭据审计提取固定操作及结果；独立 Fail2ban 面板失败输入仍沿用其即时追加和不确定结果不重放合同。`logs/tasks/<task UUID>/events.jsonl` 保存创建及每次状态/阶段变更，数据库触发器与原任务同事务提交，未回填旧任务历史。生产 Web 运行期间通过最多 256 条内存缓冲及 8192 条数据库队列投递；进程异常退出可能丢失尚未入库的应用元数据。内存/数据库队列满会累计并投递 `log.delivery_gap`，后续系统查询及下载保守标记缺口；持久队列在 Agent 失联时保留。单批最多 64 条，root 先保存字节、inode、偏移意图，完成精确已有前缀后同步文件及回执；序号确认前不删除队列，恢复不重新分配事件序号。最多保留 32 个投递代次，超限明确停止接收，须本机维护。

这些来源沿用 `/logs/sources`、`/logs/query`、`/logs/stream`、`/logs/download`、短期游标及同一四路查询并发/扫描预算，仅支持时间与元数据关键字筛选。无需配置 Nginx，开发 Agent 不产生系统文件日志。`GET /logs/policy` 的 data 改为带 `scope=system|nginx` 的可用策略数组，`PUT` 须同时指定 scope/base_version/policy；各范围独立版本、幂等及持久恢复。系统默认 Agent 轮转，application 使用错误保留期，security/task 使用访问保留期，均只压缩与删除已确认关闭的文件。轮转阈值为十五秒巡检软阈值；每轮最多 32 个系统来源轮转及 32 项任务退役清理。系统目录最多 1024 个来源，超过 960 时可提前退役最旧已结束且已关闭的任务历史，保留期不覆盖容量限制；无法释放时明确阻塞投递，最终队列溢出按缺口报告。Nginx 的发布来源验证及唯一轮转所有者规则不变。完整备份的离线隔离会清空源投递队列及缺口计数、重置投递代次，对账暂停源任务日志触发器；独立逐表验证继续覆盖日志表及 SQLite 序号，不在新环境重放旧投递。生成器及运行验收待 P5。


Fail2ban 运行实例升级新增 `POST /fail2ban/upgrade` 与 `GET /fail2ban/upgrade/tasks`。写入为 check/prepare/run 三个独立持久任务，均要求 components.manage 与 security.write、模块启用、近期认证、浏览器 CSRF 和幂等键；check 固定签名来源，prepare 另绑定检查 target，run 只引用准备 UUID 和 intent_sha256，不接收本机路径、命令或新的信任来源。HTTP 202 仅表示排队，公开 JSON 继续统一封装，远程节点合同同步。共享加密操作记录和原任务 UUID，root 元数据队列固定子 UUID、本机信任与 Nginx 来源，独立后台工作器执行长时诊断/准备或原整体升级父事务；既有不可变子材料/审计和父阶段隔离仍是执行依据。五分钟只限制尚未派发的排队授权，已接受的原记录缺失不重建授权。read 返回最近 16 条保存结果，不执行实时保护证明。只有 protection_verified 为升级成功；原版本恢复确认保持 failed/original_protection_verified，恢复未确认保留隔离。Agent 协议为 109，数据库/迁移归档仍为 32/6，无首版前兼容路径；生成器及运行验证留待 P5 隔离环境。


组件离线接收新增 GET/POST /components/offline、PUT /components/offline/{id}/assets/{asset} 和 DELETE /components/offline/{id}，显式远程合同同步，JSON 继续统一封装。写入要求 components.manage、近期认证和浏览器 CSRF，列表额外要求 read；创建的幂等键必须是上传 UUID。原始清单与签名采用 base64，不接收新信任、公钥、仓库或路径；按固定本机信任与目标平台验签后，只写签名清单中指定归档。256 KiB 顺序分块及相同前缀重试，字节和目录同步后返回进度，不以接收完整代替归档认证。清除先发布不可变标识，再只删除原归档，保留签名、原材料和审计；32 项记录、512 项目录/文件、1 GiB 暂存、一天授权，均含中断遗留容量。原组件任务增加可选 offline_id，检查和准备绑定同一来源；准备继续引用本人检查和精确标签/选择/计划/清单/信任摘要，重新验签并沿用完整散列及严格解包，不回退在线源、不启动安装。当前 Agent 为 110，数据库/归档仍为 32/6；未执行生成器、构建或运行验证，待 P5 隔离环境。

当前合同为 Agent 111、数据库 33、迁移归档 6。独立 web 资产纳入组件检查/准备；POST /components/frontend/activate 以本人 prepare_task_id、精确准备摘要和 frontend_base_id/expected_frontend_id 创建 component.activate 任务，要求 components.manage/system.write。操作 frontend 回执明确区分发布 release_id 与 activated，概览 frontend 只描述当前选择。GET /system/version 新增 frontend_id/frontend_entries，使用本机已批准入口资源识别页面版本；原生和容器就绪观察按实际批准前端核对。新增激活与检查/准备共用数据库互斥约束；显式远程端点同步检查两个写权限。


Nginx 容器镜像管理提供 `/nginx/images/upgrades` 列表/创建、`/{id}` 查询与 `/{id}/resume` 续办，远程节点逐项登记同一路由。创建引用 `maintenance_id`、`prepare_task_id`，并要求 `allow_downtime=true`；不接收镜像地址或任意文件路径。写操作要求 `components.manage`、`system.write`、重新认证与幂等键。两类镜像共用 `ImageUpgradeInput/Authorization/Operation/Task`，输入以 `component=panel-launcher|nginx` 固定资源，并绑定停机许可；查询按组件及所有者隔离。Nginx 的 `failed/rejected` 仅表示未触及服务且原运行已联合确认；未确认结果仍为 `recovery_required`。Nginx 切换重启 Agent，因此完成回执的 `ready_epoch` 可更新，但必须属于原维护会话；面板 launcher 替换继续要求原 epoch。root 连续授权最多 32 项且每项只消费一次，本机救援沿原意图记录 `local-root`。对外仍使用 `code/message/data/request_id/node_id` 封装。

签名发布的准备与激活分开准入。组件检查/准备可以对同 API 主版本、无组件依赖的独立静态面板资产先行验签暂存；不满足当前接收端最低 Agent/launcher 要求时，`ComponentRelease.staging_only=true`，其状态参与准备计划身份。其他组件、独立前端及跨 API 主版本继续拒绝不满足接收端要求的发行。`ComponentPanelPreparation` 返回从已验签程序实际读取的 `agent_protocol`、`launcher_version` 和 `requires_coordination`；后者按目标协议与当前执行器合同计算。暂存只证明签名、文件及目标自身声明一致，不能作为切换许可。普通面板更新、Agent 独立更新及 Nginx 镜像替换/拉取拒绝需要协调部署的准备结果；面板运行镜像可单独拉取，跨协议替换需显式停机许可；root 的普通版本选择和首次绑定也核对当前协议。页面明确标识此类目标；Agent 变更使用下述协调更新；跨 launcher 协议先完成运行镜像替换。

面板更新可携带 `coordinate_agent=true, allow_downtime=true`，两项必须同时启用。权限、重新认证、幂等、节点转发、准备任务所有者及单个活动更新约束与普通更新一致；目标仍须允许自动回滚并使用已暂存的签名程序。容器协调更新核对已安装运行镜像的实际 launcher 协议与目标一致，原生部署不依赖 launcher；先冻结原/目标 Agent 程序、原进程与安装服务散列，再让已验签的目标程序只读检查现有独立日志和组件准备记录。原 worker 保存快照并停止面板后停止 Agent、切换固定程序、通过目标程序的非 root 辅助入口核对新 Agent 与原维护会话，再切换/启动面板并联合核对维护 epoch。失败时停止候选面板、恢复原 Agent、选择原面板程序并恢复匹配快照；终态与维护释放仍是不可反转的提交边界。启动/停机先保存派发意图，未知派发不重放；未知程序、服务定义或进程代次保留恢复状态。

root 维护身份和面板/Agent/镜像/首次 Nginx 安装及切换的持久意图使用独立 `protocol.Journal=1` 身份，IPC 仍严格校验当前 `protocol.Agent`。存储授权验证保留原协议值与全部输入/序号/时限约束，读取不执行历史授权；组件回执按原接收端核对要求及协调标志。目标程序预检失败发生在停机之前，不宣称任意未来版本都能读取当前日志。`deployment-upgrade-resume` 仅本机 root 可为原事务追加五分钟、连续序号的救援授权，允许原维护记录仍处于 closing；主机重启后的新进程须绑定原固定程序和服务，原意图不改写，登记新 boot 代次后只允许恢复原版本。同 boot 未知进程及不明启动不自动重放。跨 launcher 协议先通过面板运行镜像事务完成基础部署，再进行面板/Agent 协调更新。

面板镜像创建输入可携带 `allow_downtime`，root 对需要协调的目标强制要求 true。根部署绑定增加必填的 `launcher_release`，指定与镜像程序散列相同的不可变已验签程序。替换前检查目标提供的本机桥接 schema 1；当前程序仅在 launcher 协议不同的情况下调用该固定程序，由它使用自身协议完成状态、操作查询及原代次控制。桥接只接受固定三类动作、绑定摘要、请求 UUID 和有界 JSON，返回统一 `code/message/data/request_id`，重新核对实际容器/宿主 PID；不解析未知 launcher IPC、不修改服务权限。镜像替换以原应用、数据库、HTTPS 和维护会话就绪为独立提交点；失败恢复原镜像。其后面板/Agent 更新失败恢复原应用和 Agent，保留已独立确认的新运行镜像。两步均复用原维护会话、各自原意图及期限，Nginx 镜像与模块不随之改变。Agent/数据库/归档为 122/37/6。

## 原生安装 SELinux 文件上下文

安装登记为 v14，固定 `nginxpanel_files` CIL 仅为本应用代码、数据、运行目录及保留 unit 声明文件上下文；root 安装意图绑定 SELinux 部署类型和完整规则散列，重放提取当前模块复核。已有未知/修改/停用/覆盖模块或关键路径的本地规则冲突均拒绝继续，不静默覆盖。代码目录的文件类型允许后续版本按父目录继承，Docker 数据使用共享容器标签。缺少目标工具/策略或标签应用失败时保留安装记录并明确失败；进程域及系统防护状态沿用目标系统配置，详见[原生部署](../deploy/native/README.md#selinux-文件标签)。
