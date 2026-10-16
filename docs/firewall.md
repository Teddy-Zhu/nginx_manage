# 宿主机防火墙策略与诊断

`GET /api/v1/firewall` 要求 `read`，返回统一 `code/message/data/request_id/node_id` 外壳，`data` 为 `FirewallObservation`。已登记远程资源 `/nodes/{connection}/firewall`，沿用目标权限和永久节点身份检查。防火墙页面由 `src/pages/firewall.vue` 自动扫描接入。

仅由 root Agent 在本机以 `--metrics-scope=host` 确认宿主机观测范围；容器、开发模式或未确认范围均不执行诊断命令。此授权不允许写规则。`available` 只说明已进入宿主机读取，各管理器和规则视图仍可能未知或不可用；`writable` 及 `docker.writable` 始终为 false。模块管理仍禁止启用防火墙写入和依赖它的 Fail2ban。

诊断分别返回：

- firewalld 当前运行、panic、默认 zone、活动接口/来源，以及配置中的后端选择。通过固定本机 D-Bus 和唯一服务所有者读取，禁止自动启动；配置选择不视为内核运行后端。
- UFW 受信工具可用性、`ufw.conf` 中的 ENABLED 和 `ufw status` 当前状态；未知值保留 null，启用配置与当前状态不一致时告警。
- 默认 IPv4/IPv6 iptables 命令后端，以及 nftables、iptables-nft IPv4/IPv6、iptables-legacy IPv4/IPv6 五个独立结构视图。明确版本后再读取显式后端的 save 工具，不切换 alternatives。仅含表/链、hook/priority、默认策略、规则数和 DOCKER-USER 跳转标记，不返回规则表达式、集合内容、注释或计数器。
- Docker `ip/ip6 docker-bridges` 与 `filter/DOCKER-USER` 标记、FORWARD 跳转线索。未核对 Docker 实例、DNAT 原始目的地址或实际数据包路径；原生 nftables 标记保持实验适配只读。

工具仅从固定系统目录选择 root 保护的文件，保留 xtables multi-call 的原调用名；不接受 API 提供的路径、参数、命令或环境。save 读取全部现有表，不指定单表；以固定受信 false 程序阻止 save 的 modprobe 回退。nft 使用 JSON/numeric/terse 输出。超时、未知格式、输出超限或 nft-save 不兼容表提示均令整个视图不可用，不将前缀作为完整结果。

单次命令期限 2 秒、整个采集上下文期限 6 秒；每次采集只允许一份在途工作，缓存 30 秒，HTTP 请求取消不会另起相同采集。Web 每节点最多 4 个在途读取。nft 原始输出最多 4 MiB、每份 xtables 原始输出最多 1 MiB、stderr 最多 8 KiB；每个结构视图最多 16384 个对象和 384 KiB JSON 元数据。firewalld 最多 128 个 zone、各 zone 最多 256 个接口/来源且总值最多 32 KiB。超限明确失败，原始输出和错误不写入业务响应或日志。

各视图独立读取，不保证原子快照。nftables 与 iptables-nft 可展示相同内核对象，不可累计计数；观测到规则不代表已排除其他后端。管理器冲突、孤立管理器标记、地址族后端差异保留告警。`direct-candidate` 只表示未观察到启用的现存管理器，不代表可接管。无活动规则时内核后端保持 unknown；链名和表名不能证明所有权或外部可达性。

## 期望规则

`GET /api/v1/firewall/policy` 要求 `read`，返回 `FirewallPolicyView`。未保存时为版本 0 与空规则。`PUT` 要求 `security.write`、浏览器近期认证、`Idempotency-Key` 与精确 `base_version`。策略使用节点主密钥按版本加密，CAS 更新、幂等响应和审计同事务提交；冲突必须重读，不覆盖他人的修改。模块停用时仍允许保存期望；保存只表示待应用。

中立模型支持 UUID、名称、启停、主机入站/Docker 发布端口、IPv4/IPv6/双栈、TCP/UDP、端口区间、来源、allow/deny/reject、顺序、入站接口与备注。最多 1000 条、规范 JSON 256 KiB；每条 1–16 个端口区间、最多 32 个来源。端口区间合并相邻/重叠部分，来源规范化并拒绝重复；CIDR 必须为网络起点，不静默扩大用户地址范围。空来源表示任意来源，非空来源须覆盖所选地址族，双栈须同时提供两种地址族。按顺序、UUID 确定排序。后端和接口是目标绑定，不接受用户命令、路径或可执行文本。

## 编译预览

`POST /api/v1/firewall/preview` 要求 `read` 和已保存版本，浏览器使用 CSRF；同一节点最多一份在途预览，结束前再次核对版本。直接 nftables 编译器使用固定库构造实际表达式与摘要，但不创建连接或发送 netlink 事务。启用的 Docker 发布端口规则及其他尚未适配的后端明确阻塞，不能降格为 INPUT 或自动切换管理器。

当前编译目标为独立 `inet nginxpanel_host` 表、`input` 过滤基础链、hook 优先级 10、自有链默认 accept。前两条返回回环及 ESTABLISHED/RELATED 流量；业务规则仅匹配 conntrack NEW，按地址族、来源、入站接口、协议和目的端口展开。allow 返回其余系统策略，deny 丢弃，reject 对 TCP 使用 RST、UDP 使用对应地址族不可达响应。未跟踪流量不在本阶段匹配范围内，不清理已有会话。含两条保护规则的总展开数最多 8192，超限失败，不返回部分成功；预览条目最多展示前 128 条，计数及程序摘要覆盖完整结果。

预览复用 Agent 诊断，核对宿主机范围、管理器、legacy/混合后端、nft 视图、目标表及绑定接口，返回观测时间和错误/告警；接口清单最多 512 项。诊断缓存、采集非原子及外部变更意味着结果不是执行授权。`compiled` 只表示表达式生成成功，`can_apply` 恒为 false；存在同名目标表时必须由未来独立执行器核对受管登记，不凭表名接管。允许规则不保证其他基础链、云安全组或外部路径放行。

上述接口均使用统一 JSON 外壳，显式远程资源沿用节点身份与权限交集；`src/pages/firewall-rules.vue` 自动扫描接入，可新增、编辑、删除、启停、排序并保存/预览，不提供内核应用按钮。逻辑迁移保留目标防火墙策略并在遗漏清单中明确显示；完整备份随数据库保留期望草稿，恢复不应用规则。

本阶段未实现可执行 Plan/Apply/Confirm/Rollback、root 受管对象登记与已确认运行状态持久化、独立超时/重启恢复、新 TCP/TLS 连接确认、Docker 转发路径、其余写入适配或 Fail2ban action。模块仍不能启用写入。未运行构建、类型检查、lint、测试、浏览器或宿主机工具；以上为实现合同，真实发行版/内核/Docker 矩阵待 P5 集中验证。

接口依据：[firewalld D-Bus](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)、[nftables 手册](https://netfilter.org/projects/nftables/manpage.html)、[iptables-save](https://man7.org/linux/man-pages/man8/iptables-save.8.html)、[Docker 原生 nftables 后端](https://docs.docker.com/engine/network/firewall-nftables/)。
