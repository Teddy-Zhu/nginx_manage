# 签名发行资产与准备

初次安装见[部署指南](deployment.md)，日常组件更新顺序见[运维文档](operations.md#组件准备与更新)。本文提供签名材料及各独立维护入口的合同；当前状态和已运行范围分别以[进度清单](progress.md)、[验证记录](validation.md)为准。

已接入离线 `release-verify/release-prepare` 和在线 `release-check/release-fetch` 本机命令。验证入口只验签、检查清单及解析依赖闭包，返回 `state=manifest_verified`；准备入口继续核对归档、宿主机运行依赖并发布不可变副本，返回 `state=prepared`。准备不等于安装、启用或运行；不执行包内程序、脚本或包管理器，也不迁移数据库或切换当前版本。

## 信任与签名

安装时由本机 root 保存 `/etc/nginxpanel/release-trust.json`。目录及其上层必须由 root 持有且不可被组/其他账户写入，文件不允许链接或额外硬链接。最多 8 个固定公钥；轮换/撤销只修改此本机配置，普通配置迁移不覆盖它。`repository` 为固定 `owner/repo` 身份，也是在线发现和下载唯一仓库。

```json
{
  "schema": 1,
  "repository": "owner/nginxpanel",
  "keys": [{"id": "release-2026", "public_key": "<Base64 编码的 32 字节 Ed25519 公钥>"}]
}
```

示例占位值须替换为经独立渠道核对的发布者公钥，不能使用下载包自行携带的公钥作为信任根。验证工具本身也须先由本机管理员批准；不能先执行待验证包里的未知程序，再声称签名提供了启动信任。

`release-manifest.sig` 是 JSON，字段为 `schema=1`、`key_id`、`signature`。签名使用标准 Ed25519，消息为 UTF-8 字节 `nginxpanel-release-manifest-v1\n`（末尾为一个实际换行）拼接 **未经修改的完整 manifest 文件字节**；`signature` 为规范标准 Base64 的 64 字节签名。签名后不能再格式化 manifest。公钥也使用规范标准 Base64。此流程不生成或托管发布私钥。

验签前只读有界文件和签名信封，认证后解析清单；JSON 拒绝未知字段、重复字段、非法 UTF-8、尾随值及过深结构。清单须匹配本机信任中的仓库并使用当前 schema；准备还须匹配接收端 API 主版本并满足 Agent/launcher 最低版本。有效期必须明确、未过期、最长两年；创建时间不得超过本机时间 5 分钟。预发布必须显式 `--release-prerelease`。

## 清单合同

清单字段以 `internal/releases/model.go` 及 `images.go` 为唯一模型，包含 `schema/repository/version/channel/created_at/expires_at/api_major/database_schema/minimum_agent_protocol/minimum_launcher/frontend_version/automatic_rollback/notes/assets/images`。版本使用 SemVer，channel 为 stable/prerelease；数据库 schema 和自动回滚标志是后续激活准入的材料，准备流程不据此承诺已迁移或能够回滚。发布工具从本次版本独立批准的策略读取 `automatic_rollback`，签名时重新核对，见 [发布流程](publishing.md#本机入口)。镜像引用、平台摘要与 OCI 元数据也受同一清单签名保护；`release-images` 的只读认证入口见 [固定镜像发行](publishing.md#固定镜像发行)。

每个资产登记唯一 ID、组件、版本、Linux 架构、发行版及版本、ABI、必要系统文件的长度/权限/散列、归档长度/散列、展开总长、逐文件清单、同清单内的精确依赖 ID、许可文件、HTTPS 上游来源、维护状态及 Nginx 模块声明。仅允许 panel/web/nginx/fail2ban 四种组件；固定入口依次为 `nginxpanel`、`index.html`、`bin/nginx`、`bin/fail2ban-server`。panel 须包含 `web/index.html`，其版本与发行版本一致；独立 web 的版本与 frontend_version 一致。

`abi=static` 不允许系统运行文件约束，ELF 主入口不得有解释器或动态库依赖；`abi=constrained` 必须固定实际发行版/版本和所需系统文件。静态资产可声明 distribution/distribution_version 为 any/any；web 和 Fail2ban 纯代码资产的 architecture 可为 any。宿主机动态依赖可位于 `/usr/lib/`、`/lib/`、`/lib64/` 或固定 `/usr/bin/python3[.版本]`，解析系统链接后再核对 root 文件身份、长度、权限与散列。依赖缺失、漂移或冲突直接失败，不回退安装其他管理器或组件。

Fail2ban 固定使用 `abi=system-python`、Linux、architecture/distribution/distribution_version=any，并声明 `python={implementation:"cpython",minimum_minor:9,maximum_minor:14}`（边界均包含，主版本固定 3）。此 ABI 不携带 runtime_files；准备和复核通过固定受信 `/usr/bin/python3` 以 `-I -S -B` 探测标准库/SQLite 和标准 GIL 模式，不固定其他机器的 Python 文件散列。安装时另固定目标机实际解释器身份，后续漂移仍拒绝运行；详细边界见 [组件发布](publishing.md#fail2ban-官方代码组件)。

[Fail2ban 体积与首组轮询 CPU/RSS 实测](validation.md#fail2ban-体积与轮询资源首组实测2026-10-21)记录了冻结组件包、解包占用、两种架构的基础面板镜像大小，以及已有 Python 场景的数据。数据仅适用于记录中的资产散列、解释器和负载，不据此推断其他运行时依赖或生产负载。

文件清单每项为 `path/sha256/size/mode`，mode 使用 JSON 十进制 420（0644）或 493（0755）。路径为规范相对路径，只允许字母、数字、`_ . / + -`，最多 256 字节/16 层，禁止文件/目录冲突。许可文件必须实际包含且非空。ELF 主入口检查实际架构、直接动态依赖和固定 `$ORIGIN/lib`（Nginx 为 `$ORIGIN/../lib`）搜索路径；这些静态约束不代替后续 `nginx -t`、ABI 和运行确认。Fail2ban 只准备代码，拒绝包内 ELF，所需 Python 来自目标已有的受信解释器，不捆绑运行时或执行 pip。

依赖闭包必须无循环、无悬空引用，同一组件不能选出不同资产。只准备明确选择项及其依赖，不因为清单里存在可选组件就全部安装。仅 maintained 资产可准备；superseded/end-of-life 不静默作为替代。Nginx features 为发布者声明，不能冒充实际模块探测；Docker 继续使用构建时预置模块的固定镜像，不调用运行时模块安装/编译。

## 操作入口

所有离线输入放在 root 持有的受信目录，归档文件名直接取自已认证清单，不接受 URL 或包内执行路径。

```sh
/opt/approved/nginxpanel release-verify \
  --release-manifest /opt/approved/release-manifest.json \
  --release-signature /opt/approved/release-manifest.sig \
  --release-select panel-linux-amd64

sudo /opt/approved/nginxpanel release-prepare \
  --release-manifest /opt/approved/release-manifest.json \
  --release-signature /opt/approved/release-manifest.sig \
  --release-assets /opt/approved/assets \
  --release-select panel-linux-amd64
```

准备目录固定为 `/opt/nginxpanel/prepared/<plan-id>/`，包含依赖资产各自目录、原始 manifest/signature 和计划记录。root 文件锁串行处理；同文件系统暂存完成、gzip/逐文件复核、运行依赖及信任再次确认后，使用不覆盖 rename 一次发布整个闭包。相同计划复用前重新核对所有文件及记录，外部修改不会被覆盖。失败清理本次暂存，清理失败记录日志并由容量准入保留；崩溃残留和既有版本不会自动删除。

准备好的 panel 路径可以作为 [原生安装器](../deploy/native/README.md) 的 `--binary` 和 `--web-dir` 输入，仍须由本机 root 明确安装/启动。预备资产不会改变已有系统 Nginx、管理监听、业务开关或当前程序指针。

## 在线发现与下载

在线命令需要本机 root，使用同一信任配置、显式资产 ID 和准备目录。未指定标签时只查询最新稳定版；预发布必须同时指定完整 `v` 前缀 SemVer 标签和 `--release-prerelease`。GitHub 的发行标签、渠道与签名清单必须一致。

```sh
sudo /opt/approved/nginxpanel release-check --release-select panel-linux-amd64
sudo /opt/approved/nginxpanel release-fetch --release-select panel-linux-amd64
sudo /opt/approved/nginxpanel release-fetch \
  --release-tag v1.2.3-rc.1 --release-prerelease \
  --release-select panel-linux-amd64 \
  --release-token-file /etc/nginxpanel/github-token
```

公开仓库无需 Token。私有仓库可使用仅授予目标仓库 Contents 读取权限的 Token，放在 root 持有的 0600 文件中；只接受文件路径，不接受明文命令参数或环境代理。Token 不进入缓存、输出或日志；信任和 Token 在请求前重新核对，变更时停止原操作。

请求只发往 `api.github.com`；下载路径根据固定仓库和资产数字 ID 构造，不使用响应中的任意 URL。仅资产下载可重定向到 `release-assets.githubusercontent.com` 或 `objects.githubusercontent.com`，最多两次；跨主机删除 Authorization，禁止 HTTP、用户信息、其他主机及非公网解析。TLS 正常验证，响应头/正文/时间均有上限，失败不自动重试。只有完整清单验签、发行身份及整个选择闭包匹配后才下载归档；逐归档校验签名长度/散列后交给同一 `Prepare`，不下载未选择的可选组件，不进行 Docker 模块增装。

`/opt/nginxpanel/release-downloads` 为 root 0700 缓存目录，同机在线操作串行。单槽元数据使用 ETag/304、Cache-Control 和 Age；发现请求至少间隔 60 秒，缓存新鲜期最多一小时，no-cache 要求重验证、no-store 不保留响应。已认证清单可缓存，每次使用仍验签并核对有效期、信任、目标平台和选择项；缓存身份绑定仓库、标签、信任文件及 Token 身份。403/429、Retry-After 和主限流重置期限会持久记录，等待期不继续联网，也不将陈旧响应当作成功。

单次在线流程最多 10 分钟，单请求最多 3 分钟；元数据最多 2 MiB/64 个发行文件（包含归档及证据），缓存记录最多 6 MiB。下载目录最多 8 组暂存、256 项和 512 MiB，创建和下载前预留容量。失败只清理本次暂存；崩溃残留计入预算，需本机管理员核对维护，不自动删除恢复材料。

## 资源边界与后续

manifest 最多 2 MiB/16 个资产/合计 4096 个文件，准备计划最多 4 MiB，显式选择最多 4 项。单归档最多 128 MiB，展开最多 256 MiB，闭包压缩加展开合计最多 512 MiB；系统依赖核验合计最多 128 MiB。准备文件与目录合计最多 8192 项；保留目录最多 32 组、32768 项、2 GiB，预算不足时停止并要求本机维护。

仅接收单一 gzip 流包裹的 root USTAR，物理头逐块检查，拒绝 PAX/GNU 扩展、链接、设备、未知/重复文件、非零填充及额外压缩流。归档首先校验完整签名散列，再解包；复制期间再次散列并检查文件身份，gzip CRC 和完整文件清单通过后才发布。

[发布工具与 CI 流程](publishing.md) 已接入面板/web 及 amd64/arm64 静态 Nginx 的打包、签名、源码/依赖 SBOM 和草稿发布，尚未运行或发布；项目采用 MIT 许可，正式仓库签名配置仍需提供。Nginx 默认资产按固定源码配方预置模块，可复用现有准备、首次安装及迁移依赖准备入口。Fail2ban 官方代码组装、许可/兼容文件、来源和默认签名发行也已接入，复用现有组件准备与受管安装；原生 Nginx 维护切换本机命令见后文；Web/API、其他组件切换和完整系统验收仍待补齐。

## 面板版本暂存

本机 root 可将已准备的 `panel-linux-<当前架构>` 计划复制到 `DATA/runtime/releases/<内容散列>`，供后续独立更新执行器使用。沿用准备时的目标主机和接收协议身份，检查当前公钥、签名有效期、静态 ELF、程序版本与 Agent/launcher 协议，并核对同版前端文件。只在程序已通过签名散列核对后执行固定 `version` 命令。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-runtime-stage \
  --data-dir /srv/nginxpanel --release-plan <已准备的面板计划散列>

sudo /opt/nginxpanel/current/nginxpanel panel-runtime-staged \
  --data-dir /srv/nginxpanel --release-plan <同一计划散列>
```

自定义本机信任文件须与准备一致；预发布须显式传入 `--release-prerelease`。完整目录同步并不覆盖发布后，才写入 root 只读的 `runtime/approvals/<计划散列>.json`。首次绑定和暂存共用发布锁，最多保留 32 个版本和 64 个批准记录；中断前已复制但未批准的目录不能作为更新授权。相同计划重复暂存使用原批准时间、主机/协议身份和初始信任散列重新认证当前公钥，增加无关公钥不改变计划，撤销签名公钥则拒绝续用。续用仍需保留原准备计划及签名材料；只读查询不下载或执行程序。

`state=staged` 仅表示持久副本及其批准记录就绪，返回数据库 schema、协议门槛和签名回滚声明供后续准入使用。不切换当前版本、不迁移数据库、不重启面板或 Nginx/Fail2ban；独立 worker、版本切换、健康检查与失败回滚编排已在后续更新入口接入。本入口尚未运行，统一留到 P5 集中验证。

## 面板程序版本选择

原生和 Docker 面板均使用 root 持有的 `runtime/launcher.json` 运行绑定与 `runtime/current` 内容版本指针。绑定明确 `native/docker` 模式、专用身份、监听和初始版本，禁止直接转换部署方式。原生安装通过 `panel-native-bind` 复制本机批准的程序及前端；systemd 的固定 `panel-native-serve` 入口再执行所选持久版本。`/opt/nginxpanel/current` 继续提供宿主机 Agent 和安装工具，普通面板选择不改动它。初始化完成记录 `runtime/binding.ready` 防止指针丢失后重装工具擅自退回初始版本。

正式 `init/serve` 在取得 root 写锁后核对实际执行文件 inode，`serve` 还检查运行模式、监听、版本和所选前端；旧启动入口与新选择发生竞争时，旧程序在读取主密钥、数据库或运行迁移前退出。安装器从已选择的持久程序执行初始化，重复首次安装不会用初始程序打开新版数据。开发入口仍独立运行。

本机 root 的 `panel-runtime-select` 要求原维护会话未释放、当前 Agent epoch、已经完整认证且未过期的本机快照，以及已签名批准的暂存计划；执行前必须停止 `serve`。它复核当前专用账户、运行绑定、当前公钥、原批准与完整产物。程序的 `version` 输出从内嵌迁移取得 `database_schema`，并与签名清单核对；目标 schema 不得低于当前程序或快照，不能以旧快照绕过程序降级检查。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-runtime-select \
  --data-dir /srv/nginxpanel --release-plan <已暂存计划散列> \
  --panel-selection <新的版本选择UUID> --recovery-snapshot <本机快照UUID> \
  --maintenance-id <原维护UUID> --maintenance-epoch <当前Agent-epoch>
sudo /opt/nginxpanel/current/nginxpanel panel-selection-status \
  --data-dir /srv/nginxpanel --panel-selection <原版本选择UUID>
```

选择前持久保存 `panel.select` 独立记录，固定原版本、目标版本、运行绑定散列、批准散列和快照。指针仅允许从原版本原子切换至目标；中断后以原操作续行，第三种版本或授权偏离时停止覆盖。未完成记录阻止释放维护会话；已成功请求的重放仅返回原记录，不重新覆盖后续版本选择。临时指针按操作使用固定名称，与初始化和暂存共用发布锁。

`version_selected` 仅表示程序指针已持久化；本入口不重启服务、打开数据库或释放维护会话，不报告应用健康。独立 worker 的自动编排、匹配程序与数据的自动回滚及清理见下文；本命令仅提供程序选择。尚未运行以上入口、服务、安装器、构建或测试，统一留到 P5。

## 面板进程维护

本机 root 的 `panel-service-control` 仅控制已绑定的管理面板，要求同一未释放维护会话及当前 Agent epoch；本阶段合同使用 Agent 协议 18、launcher 协议 2。原生模式核对安装意图 v9、已加载且没有 drop-in 的固定 `nginxpanel.service`，检查 UID/GID、主进程、实例与启动标识、执行文件、固定参数及 systemd cgroup；Docker 模式认证 launcher 的 UID、独立容器 PID 1 和执行散列，使用 boot ID 与 serve 实例 UUID 区分进程。Docker 状态中的 PID 属于容器命名空间，原生 PID 属于宿主机。

停止前同步独立 `panel.service` 意图，再发布 root 只读的 `run/panel-service-hold.json`。普通 `init/serve` 在写锁内检查标记；launcher 在容器重启后保留控制入口并保持停机。停止确认同时要求受管进程已结束、面板写锁可获取；保留停机标记后才能继续快照与版本选择；一次持久停机只允许从原停机版本确认一次目标选择，其原操作仍可续行。恢复与停机标记共用原子发布，最多保留 32 份未批准的中断临时标记，超限需本机处理。管理进程的维护范围不包含正在服务流量的 Nginx 或 Fail2ban。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-service-control \
  --data-dir /srv/nginxpanel --panel-service-operation <新的停机UUID> \
  --panel-service-action stop --maintenance-id <原维护UUID> --maintenance-epoch <当前Agent-epoch>
sudo /opt/nginxpanel/current/nginxpanel panel-service-status --data-dir /srv/nginxpanel
# 按前文入口捕获快照并完成签名版本选择后，以新的操作标识启动。
sudo /opt/nginxpanel/current/nginxpanel panel-service-control \
  --data-dir /srv/nginxpanel --panel-service-operation <新的启动UUID> \
  --panel-service-action start --panel-service-stop <原停机UUID> --panel-selection <原版本选择UUID> \
  --maintenance-id <原维护UUID> --maintenance-epoch <当前Agent-epoch>
sudo /opt/nginxpanel/current/nginxpanel panel-service-operation \
  --data-dir /srv/nginxpanel --panel-service-operation <原操作UUID>
```

启动原版本时省略 `--panel-selection`；启动新版本须关联该次停机后的完整版本选择记录，并再次核对当前公钥与批准。启动意图落盘、确认数据恢复标记已解除后，才移除匹配原停机事务的标记并启动固定入口。中断后按原操作续行，先查询实际受管状态；同一 launcher boot 中只有明确不存在原回执才派发，跨 boot 的派发先持久记录并有数量上限。未知进程身份或结果保留 `recovery_required`。成功请求重放返回历史记录，后来的进程与停机标记不被历史重放改变。

持久停机标记或未完成的进程记录会阻止维护释放。`started` 表示已观测到目标进程实例；就绪检查见下文。完整程序/数据回滚、升级提交及清理由独立更新 worker 编排，见下文。尚未执行控制入口、systemd、launcher、服务、构建或测试，统一留到 P5。

## 面板就绪观察

本机 root 的 `panel-readiness` 关联原维护会话、已完成的启动操作及原恢复快照，返回当次观察证据。生产 `serve` 在持有写锁后提供 `DATA/run/readiness/readiness.sock`，并在同目录发布管理 TLS 的公开证书；此 Socket 仅接受 root 对端，返回统一的 `code/message/data/request_id/node_id`。Agent 可访问这项 IPC，业务目录和私钥仍被其挂载命名空间隐藏。开发模式不提供此入口。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-readiness \
  --data-dir /srv/nginxpanel --panel-service-operation <原启动UUID> \
  --recovery-snapshot <原快照UUID> \
  --maintenance-id <原维护UUID> --maintenance-epoch <当前Agent-epoch>
```

观察端以 Unix 对端凭据、实际执行文件和原进程标识认证应用；Docker 还核对经认证 launcher 的宿主机 PID、直接父子关系与 PID 命名空间。原生 systemd 实例或 launcher boot/serve 实例变化均拒绝复用旧启动回执。应用初始化最多等待 90 秒，整次观察最多四分钟。等待期间不持有维护准入锁，允许重启后的应用与 Agent 恢复同一 held 会话。

数据库查询由非 root 应用执行：schema 必须等于目标程序声明，节点、期望/生效修订和配置版本须等于快照；维护双方均须 held、epoch 一致、没有在途操作。已有生效修订还须通过 Agent 核对 Nginx 运行修订、完整性及外部修改状态。root 仅核对固定密钥/TLS 文件与快照散列，继续保持业务 SQLite 不由 root 解析。

实际管理监听须属于同一应用进程，探测按安装配置选择 HTTP 或 HTTPS；HTTPS 固定本机管理证书，两种协议均只访问本机地址并拒绝重定向和代理。检查健康与版本 API 的统一响应、节点身份、版本和协议，再核对全部已发布前端文件及入口内容的长度与散列。前后两次应用/进程/密钥材料核对不一致时明确失败。新目标继续核对原签名批准；停机或数据恢复标记未解除时不提供就绪证据。

返回包含原启动/快照/绑定散列、进程实例、应用状态、管理监听与前端核对数量和观察时间，仅表示该时间点的结果；独立更新执行器见下文。本命令不释放维护、不启动进程、不恢复数据、不删除快照。原生 HTTP 部署中的实际更新及补偿恢复已验证，具体范围见 [当前进度](progress.md)。

## 独立面板更新事务

`update-worker` 在待替换 `serve` 之外以 root 运行，要求已完成的签名暂存、同一 held 维护会话及当前 epoch。固定流程为：一致性快照、持久停机、版本选择、新进程启动、就绪观察、提交结果、协调原维护会话释放。发布须明确声明允许自动回滚；不支持直接降低 schema，不自动升级宿主机 Agent、launcher、Nginx 或 Fail2ban。使用前须部署理解本合同的 Agent 21。

原生安装登记 v12 为 native 和 Docker 面板统一安装 `nginxpanel-update@.service`。该 root 服务独立于 `serve` 和 Agent 的生命周期，只接受原操作 UUID，由固定 `panel-update-worker` 加载 root 记录；请求不能指定可执行程序、数据目录或信任文件。服务不自动重启，最长运行 40 分钟，收到停止信号后留出补偿时间。运行前核对安装意图、ready、root 服务文件及 systemd 实际加载的片段、账户、类型、drop-in 和 reload 状态。

Agent 21 提供内部 IPC `POST /v1/panel/updates` 与 `GET /v1/panel/updates/{id}`，沿用统一响应封装。新建须传递已签名暂存的 `plan_id`、原 `maintenance_id`、`prerelease`、操作 UUID、发起人 `actor`、原请求 `request_id`、当前 epoch、连续 `sequence` 和五分钟内的 `authorization_until`；首个 command 为 `update`，后续为 `resume`。Agent 先持久保存完整原意图和逐次授权，再启动固定服务。启动授权由 worker 在锁内一次性认领。相同序号与内容只查询原操作，不能重复启动；启动结果未知或服务停止后须使用下一个序号显式续办。历史授权不可修改，续办不改变原目标、快照及总执行期限。过期启动授权不能触发后续变更，已经运行的事务仍按原补偿规则处理。

查询同时核对实际服务状态与 root 原记录；失去运行进程的未完成事务保留 `recovery_required`，不伪造成功。已提交或补偿完成的事务只收取原维护释放回执，查询可补齐此收尾记录，不能触发停机、切换或恢复。上述入口为 Agent 内部合同；面向用户的 Web/API 任务与更新结束后的救援材料清理已接入。


Web“组件准备”可单独选择面板；准备过程除验证及下载签名静态面板产物外，还将同版程序与前端暂存到持久版本目录，并返回版本标识、数据库版本与自动回滚声明。面板不与 Nginx/Fail2ban 共用准备计划，暂存不切换当前版本或启动新程序。安装登记 v12 允许 Agent 仅在受管 runtime 目录完成此暂存。

Web“面板更新”及公共 API `GET/POST /api/v1/panel/updates`、`GET /api/v1/panel/updates/{id}`、`POST /api/v1/panel/updates/{id}/resume` 已接入同一任务服务。写操作要求 `components.manage`、`system.write`、有效登录会话或有效机器 Token，以及幂等键；浏览器同时校验 CSRF。新建绑定已成功暂存的准备任务和原 held 维护会话。任务输入与每次请求加密保存，历史请求追加保留；发起人和请求标识同时保存在 root 授权记录中，数据库补偿后仍可追溯。联系 Agent 前先记录提交尝试，使更新快照和数据库回滚后仍能确认原操作。

后台先读取 root 原记录，只为未提交的当前授权发起一次提交；仅 root 在持有原 worker 锁且尚未发布父事务时返回的 `PANEL_UPDATE_REJECTED` 可终结为执行条件拒绝；提交结果未知或已提交记录缺失时持续查询并保留待恢复状态，不重建 root 事务。数据库补偿后可以观察 root 中更晚的授权或已完成结果，观察不会重新派发这些授权。显式续办在核实原服务停止、事务未结束与当前维护 epoch 后追加请求；从未提交过的原任务可以重新授权首次启动。已提交而缺失的原记录须本机恢复。单任务最多保留 64 条本地请求，root 最多接受 32 次连续授权；手动释放维护锁会拒绝尚未结束的更新任务。

```sh
sudo /opt/nginxpanel/current/nginxpanel update-worker \
  --data-dir /srv/nginxpanel --panel-update <新更新UUID> \
  --release-plan <已暂存计划ID> --release-trust /etc/nginxpanel/release-trust.json \
  --maintenance-id <原维护UUID> --maintenance-epoch <当前Agent-epoch>
sudo /opt/nginxpanel/current/nginxpanel panel-update-status \
  --data-dir /srv/nginxpanel --panel-update <原更新UUID>
```

完整意图和固定子操作标识在副作用前进入独立 `panel.update` 记录。进程派发、恢复前文件清单及就绪证据作为内部子记录原子嵌入父记录，不生成与父任务相互阻塞的顶层任务；内部子标识只能由原更新续行，不用于单独执行叶操作。每个维护会话只允许一个更新事务，待恢复更新会阻止其他高风险操作和维护释放。

切换前失败时确认原程序仍运行且没有停机/恢复标记后中止。进入停机后的失败使用原快照补偿：停止受管进程、选择原不可变程序、恢复匹配数据和密钥材料、启动原版本，再核对就绪。补偿不依赖新目标仍被签名信任；继续前进和启动新目标仍重新验签。未知进程、其他停机标记、恢复偏离或当前授权失效保留 `recovery_required` 与全部救援材料。

前进期限二十分钟，进程控制每次三分钟，自动补偿最多十五分钟；同一操作重新执行会先核对已持久记录与实际状态。Agent 重启后须使用同一未释放会话的当前 epoch。历史终态重放仅返回原结果，不重新切换程序、恢复数据库或改变后来的运行状态。

`committed`、`compensated` 或无副作用的 `aborted` 是恢复写入的持久授权点，先进入 `waiting_confirmation`。维护服务通过 Agent 的统一状态读取 `completion`，持久记录释放意图并由原会话协调释放；worker 核对独立释放回执后设置 `release_acknowledged` 和最终结果。已提交但释放超时只等待或续行原事务，不自动恢复旧快照；提交后的程序重启按正常已提交版本处理。失败与完整补偿均保留原失败原因，并以失败退出状态报告。

候选 Web 异常退出导致 Docker 启动器重启时，更新执行器对控制 Socket 缺席、尚未监听及正在启停的状态最多等待 30 秒；对端身份或旧回执核对失败直接保留待恢复结果。

已安装执行器自身有缺陷、无法完成原协调事务时，本机 root 可用独立批准的修复程序执行 `deployment-upgrade-resume --operation-id <原UUID> --foreground`。此入口仅续办已有协调事务，追加有时限的 root 授权，在前台沿原目标、维护会话和快照完成处理；修复程序须位于 root 持有且普通用户不可写的目录。网页/API 不开放此选项。

协调更新已恢复原程序与数据库、且原回滚启动完成后，整机重启会使原进程回执失效。必须通过本机 root 救援登记当前 Agent 启动代次；网页/API 续办不能自行批准新代次。救援分别记录宿主机内核启动身份及经过认证的面板启动器观测，沿原事务、原快照和原回滚方向追加独立停止/启动回执，再核对数据库、配置、管理 HTTPS 及 Agent 就绪，原完成回执保持不变。父记录最多保留四对跨启动回执，历史 root 救援批准追加保留，容量不足时在控制进程前拒绝。尚未确认结果的启动派发跨越整机重启时继续保留待恢复状态，禁止重放原派发。

独立 root CLI、Web/API 更新任务及专用服务托管已接入。更新结果与原维护释放确认后清理本事务的快照及恢复暂存；未完成事务继续保留恢复材料并受既有容量上限约束。原生 HTTP 环境已完成实际协调部署、失败补偿恢复和前端资源一致性核对，其他部署与升级组合的验证范围见 [当前进度](progress.md)。

恢复材料清理仅在 `release_acknowledged=true` 后开始；`cleanup.state` 为 `pending/running/blocked/done`，错误、资源数量、字节数及时间独立于更新结果返回。删除前将只属于原快照 UUID 和原恢复操作 UUID 的路径、inode、权限、大小、内容散列写入 root 父记录。每次续清理先检查整个剩余目录树，再逐项删除，允许原清单中的资源已被前次清理删除；遇到未知文件、链接、身份或内容变化则保留并报告。Agent 每 30 秒择一收尾，失败至少间隔 10 分钟重试，单次处理最多 5 分钟；重启继续使用原清单。Web 终态任务仍同步清理状态，不重开维护、不覆盖业务写入、不改变成功或补偿结果。

清理保留 root 审计记录、共享 `recovery.key`、当前/前一程序及前端版本。`recovery_required` 的材料不按 TTL 删除。未获原快照批准、助手目录残留、无法归属的 `.snapshot-*` 暂存及其他未知资源不自动删除，须本机核对；清理完成仅指原批准清单，不能视为全目录垃圾回收。清理无需打开当前数据库或长时间持有配置写入准入锁。数据库迁移为 19，Agent 合同为 21，安装登记现为 v12。

## 本机面板恢复快照

本机 root 的 `panel-snapshot-capture` 须提供已经 held 的维护会话及当前 Agent epoch。捕获期间持有维护释放所用的 root 锁，拒绝尚有独立副作用任务执行中或待恢复的节点。SQLite 助手降为 `nginxpanel` 专用账户，使用 [VACUUM INTO](https://www.sqlite.org/lang_vacuum.html) 生成包含 WAL 中已提交内容的一致性副本，不直接复制活动数据库，也不以 root 解析业务数据库。助手有两分钟期限、512 MiB 单文件限制，整次捕获期限五分钟，输出仅在 root 分配的私有暂存目录中生成。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-snapshot-capture \
  --data-dir /srv/nginxpanel --recovery-operation <新操作UUID> \
  --maintenance-id <已持有的维护UUID> --maintenance-epoch <当前Agent epoch>

sudo /opt/nginxpanel/current/nginxpanel panel-snapshot-check \
  --data-dir /srv/nginxpanel --recovery-operation <原操作UUID>
```

快照按固定资源清单捕获 `app/panel.db`、`secrets/master.key` 和节点 TLS 证书/私钥；配置树原文、证书/ACME 私钥和凭据的权威数据已在数据库中。此入口只服务面板维护，不打包整个数据目录，不修改 Nginx/Fail2ban、Agent 执行记录或主机运行状态，也不替代完整灾备。节点身份、数据库 schema、期望/生效修订、资源散列、捕获程序散列及维护授权一起进入清单。

使用 `DATA/agent/panel-recovery/recovery.key` 中独立生成的 root 本机 age 密钥加密，不使用业务主密钥或离线灾备私钥。密文和批准记录在 root 专用目录同步并不覆盖发布后才返回 `captured`。原操作重复捕获只检查既有批准副本，不重新生成未知捕获；检查入口不依赖运行中的面板、业务数据库或业务密钥，会认证完整密文、加密清单、逐项资源及流尾部。已有快照而本机恢复密钥缺失时拒绝生成替代密钥。

单份期限 24 小时、最多八份、密文总预算 2 GiB，新增前按最大单份预留容量；超限明确失败。期限只报告 `expired`，不自动删除救援依据。中断留下的不完整密文或助手暂存须本机处理；不能将一次捕获成功视为已授权后续恢复，恢复仍须核对未释放的同一维护会话。

## 本机快照数据恢复

本机 root 可在停下 `serve` 后恢复同一未释放维护会话中的快照。恢复前须安排与快照匹配的程序版本；本入口只安装数据，不选择版本、启停服务或认定应用健康。Agent 重启导致会话处于 closing 时，使用其当前 epoch 核对原维护身份；已释放的旧维护标识不能重新用于覆盖后续写入。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-snapshot-restore \
  --data-dir /srv/nginxpanel --recovery-operation <新恢复UUID> \
  --recovery-snapshot <原快照UUID> \
  --maintenance-id <原维护UUID> --maintenance-epoch <当前Agent epoch>

sudo /opt/nginxpanel/current/nginxpanel panel-restore-status \
  --data-dir /srv/nginxpanel --recovery-operation <原恢复UUID>
```

正式部署通过安装意图 v9 在初始化前登记 `run/panel-writer.lock`：root 持有文件及上层目录，专用面板组仅可打开并获取锁。应用初始化和启动先取得该锁，再读取主密钥和数据库；开发模式单独使用开发写锁。恢复执行器使用同一个 inode 取得独占权，面板仍在运行时拒绝执行。

在改变业务文件前持久保存独立 `panel.restore` 意图和 root 只读启动标记，完整认证并暂存解密资源，保留当前数据库、WAL/SHM 和密钥的原始字节及散列。每次恢复的现场保留预算最多 2 GiB，解密源沿用快照容量边界；每份快照最多保留八次恢复目录，中断暂存也有数量上限，超限需本机处理。业务目录中的复制临时文件按操作和资源使用固定名称，重试仅移除同次操作的未批准临时输出。恢复前副本用于保留现场，不将失败进程留下的数据库字节宣称为一致性备份。按固定名称移除旧 WAL/SHM，安装主密钥和 TLS 材料，最后原子替换数据库；恢复后逐项确认内容、归属并同步相关目录。

中断后以原恢复 UUID 和快照 UUID 继续，只接受保存的原状态或已批准目标；发现其他内容时进入 `recovery_required` 并停止覆盖。失败保留独立记录、前后副本和启动标记，阻止面板启动及维护释放。完整数据安装先记为 `files_restored`，随后解除启动标记；已完成请求重放只返回原结果，不再次覆盖已启动面板的数据。已批准的完整解密源可独立于运行中的面板、业务密钥和原加密输入续行，部分解密或缺失批准不能使用。

`files_restored` 只说明数据安装完成；版本切换、readiness 与清理由独立更新 worker 编排，见上文。恢复保留维护会话，不重启 Nginx/Fail2ban。尚未运行恢复命令、安装器、服务、构建或测试，统一留到 P5。

## 组件页面与任务

原生 Agent 由本机 root 设置 `--component-scope host`，沿用 `--release-trust` 与可选 `--release-token-file`；默认未确认范围及开发 Agent 不准备组件。Web/API 不接收仓库 URL、公钥、Token 或文件路径，`components.manage` 权限及有效登录会话约束此入口。页面 `/components` 自动扫描接入，使用统一 JSON 外壳；`GET /api/v1/components` 读来源，`GET/POST /api/v1/components/tasks` 读本人任务或提交带幂等键的检查/准备。

检查可用 `components: ["nginx"]`（可另选 `fail2ban`）按架构/发行版唯一匹配，多个匹配项须使用明确 `assets` ID，不猜测最新 ABI。准备须引用本人成功检查任务 `check_task_id`，显式绑定 `tag/prerelease/assets/plan_id/manifest_sha256/trust_sha256` 及原检查的可选离线上传 `offline_id`；过期、来源变化或系统运行依赖缺失时停止准备。root Agent 再次验证全部材料；在线来源在下载前核对期望散列，离线来源仅使用原上传归档。`runtime_ready` 只说明已声明的本机运行文件满足校验，不代表实际执行或 ABI 验收。

Web 将任务输入及精简结果分别加密，保留最多 64 项，单条 64 KiB；root 使用独立私有操作目录和同等记录上限，单次期限十分钟，节点串行。提交意图先于 IPC 持久化；接受情况不明只查询原 ID，记录缺失进入待恢复，阻止新任务。Agent 重启对中断准备仅重新验签并复核既有不可变回执；不凭超时判定未落盘，不替换未知目录。容量用尽或材料无法确认须由本机维护，不能直接删除记录后重试。

原生安装器预建 root 持有的 `/opt/nginxpanel/prepared` 与私有 `/opt/nginxpanel/release-downloads`，Agent unit 仅增加这两处写范围。准备成功只产生受信产物；原生首次安装见后文；Web/API 首次安装、原生 Nginx 维护切换及迁移依赖准备复用已有执行器；Docker Nginx 模块继续固定在镜像中。

## 网页/API 离线签名上传

组件页支持发布清单、签名文件和原始 `.tar.gz` 资产的离线接收。所有 JSON 继续使用统一响应外壳，写入要求 `components.manage`、有效登录会话和浏览器 CSRF；列表额外要求 `read`。显式远程节点沿用同一合同，上传目标随页面节点上下文固定，不自动访问新发行仓库或安装运行时依赖。

- `POST /api/v1/components/offline`：`Idempotency-Key` 必须是新的上传 UUID。正文的 `manifest/signature` 是原始文件的 base64，`components/assets` 按与在线检查相同的规则选择，`prerelease` 必须显式授权预发布。签名按本机信任验证后返回 `ComponentOfflineUpload`，包含精确计划、签名归档名称/SHA-256/长度及已接收偏移。相同 UUID 同材料读取原结果，不同材料拒绝，不覆盖旧上传。
- `GET /api/v1/components/offline`：返回最多 32 条保存的上传状态，包含已清除及已过期记录。刷新页面或进程重启后可重新选择本地原文件，按服务端进度继续。该读取不执行归档解包、代码或组件安装。
- `PUT /api/v1/components/offline/{id}/assets/{asset}`：正文为 `{offset,data}`，`data` 为最多 256 KiB 原始字节的 base64。禁止跳过前缀或覆盖不同字节；重试比较原前缀，并可续写因中断只保存了一部分的相同块。写入与目录均同步后才返回实际进度。最后一块只证明字节接收完成，完整资产认证仍由准备任务执行。
- `DELETE /api/v1/components/offline/{id}`：先原子发布清除标识并落盘，再只移除该计划列出的归档；相同请求可继续中断清除。原清单、签名、上传材料和标识保留，禁止复用已清除 UUID，不删除已准备产物、安装版本或审计。Web/Agent 有未结束组件任务时拒绝，预防清除正在使用的来源。

上传存于 `<data>/agent/component-uploads`，目录/文件为 `0700/0600`，仅宿主机 root Agent 可写，开发 Agent 不创建材料。每次最多两个完整选择的独立资产（面板单独准备）；单清单 2 MiB、签名 4 KiB、单归档 128 MiB，上传期限取清单有效期和一天中的较早者。保存最多 32 个上传及遗留暂存目录、512 项目录/文件和 1 GiB；清除归档释放字节额度，原记录保留，记录上限需本机维护。未确认的临时材料计入容量，不自动删除未知恢复或审计依据。

接收完成后，以该上传的 `offline_id/tag/assets/prerelease` 创建原 `/components/tasks` 检查任务，`components` 不填、三个准备摘要为空。确认准备时仍引用本人成功检查 UUID，并保留相同 `offline_id` 和精确摘要。离线执行不回退到在线下载；当前签名、公钥撤销、清单期限、平台、完整归档 SHA-256、严格 USTAR 文件树和系统依赖均沿用既有验证，面板继续执行同一版本暂存。已保存上传过期、被清除或当前信任变化时不能由旧检查重新准备；已原子发布的准备回执仍沿原中断对账入口核对。

Agent/数据库/归档为 110/32/6，无首版前兼容路径。源码实现与集成完成，生成器、构建、类型检查、lint、测试、浏览器及真实上传/解包/安装未执行，待 P5 隔离 Docker/虚拟机集中验收；不增加 UI 自动化测试。验收须覆盖签名/平台/选择拒绝、重复请求错绑、完整及部分分块重试、断连/重启续传、偏移和前缀冲突、清除发布/删除中断、来源过期/撤销、检查来源替换、篡改归档和解包拒绝、维护准入及容量边界。

## 原生运行绑定

已准备的单一 Nginx 资产可由原生安装器通过 `--nginx-plan/--nginx-asset` 直接接入，见 [原生安装](../deploy/native/README.md)。固定 `component-path/component-bind/nginx-runtime` 命令分别负责准入解析、不可变本机安装批准和执行；Web 不能创建或覆盖绑定。Agent 和 systemd 使用同一绑定，实际版本须匹配签名资产，启动不依赖 GitHub 或下载缓存。

`Prepared` 现在为纯只读回执核验，恢复不会创建锁或补发归档。已安装运行使用 root 本机批准时间验证原清单的准入有效期，并以当前受信公钥及仓库重新验签、复核完整原计划/文件和系统依赖。原批准信任散列只用于重建不可变回执身份，不替代当前验签；添加无关公钥不触发无关版本失效，撤销签名公钥仍拒绝启动。此规则不用于新检查/准备，业务请求也不能提交批准时间或旧信任材料。


## 原生 Nginx 运行组件维护切换

本机 root 可使用 `component-switch` 将已运行的专用原生 Nginx 换成已准备的签名资产。入口要求原生安装 v14 已完成、Nginx 与 Agent 正常运行、独立维护会话已持有，以及明确允许重启停机。Docker 继续使用固定镜像及构建时预置模块，本入口不编译或增装模块。Web/API 已接入同一切换核心，其他组件的运行版本切换仍待接入。

```sh
sudo /opt/nginxpanel/current/nginxpanel component-switch \
  --data-dir /var/lib/nginxpanel \
  --nginx-switch-operation <新的操作UUID> \
  --maintenance-id <已持有的维护会话UUID> \
  --maintenance-epoch <当前维护epoch> \
  --release-plan <已准备的Nginx计划SHA256> \
  --release-select <计划中的Nginx资产ID> \
  --release-trust /etc/nginxpanel/release-trust.json \
  --confirm-nginx-downtime
```

受管签名和本机批准的原程序均可作为原组件；候选只接受签名准备资产。当前发布、证书和依赖须完整，候选须通过当前完整运行配置和编译版本校验；活动配置包含动态模块时拒绝直接切换。原不可变组件、原绑定和发布目录保留，不改变期望配置、数据库或服务开机启用状态。

独立记录固定原选择、候选、当前发布摘要及两个原生服务文件摘要。执行器核对 systemd 的实际加载、无 drop-in、无待重载，以及进程归属与固定入口，再停止 Agent、取得配置执行锁、停止专用 Nginx、原子选择候选并启动。实际 executable、编译版本、发布探针、监听归属、TLS 和重启后的 Agent 来源及逻辑/物理发布均确认后才记录成功。

前进期限十分钟；失败后在八分钟独立期限内补偿原组件，并重新确认运行。新候选的签名失效不阻止补偿；原组件自身的文件和已安装来源仍须可信。遇到第三种组件选择、发布或服务偏离、未知进程和无法确认的服务状态时保留 `recovery_required` 与维护会话，不覆盖外部状态。

`component-switch-status --data-dir <目录> --nginx-switch-operation <原UUID>` 只读持久记录，返回的是历史确认，不保证查询时仍在运行。中断后使用 `component-switch-resume`，或使用 `component-switch-rollback` 明确补偿；二者只接受原操作 UUID、数据目录与当前 `--maintenance-epoch`，不得替换来源或会话。Agent 已重启时须使用同一会话的新 epoch；服务未就绪时可由本机 root 从原维护记录读取。续办先核对实际选择与服务；目标已经正常运行时仅补齐确认。终态重放只返回原记录，另一次切换须使用新操作和新的准入。未完成记录阻止释放维护锁；终态后由原维护流程收尾。本入口尚未运行，留待 P5 集中验证。


网页“组件切换”通过文件扫描路由接入，选择已完成的组件准备任务和 Nginx 资产，核对当前版本并明确允许停机。API 为 `GET/POST /components/switches`、`GET /components/switches/{id}` 及 `POST /components/switches/{id}/resume`、`POST /components/switches/{id}/rollback`；写操作须有 components.manage/system.write、原已持有维护会话、幂等键及浏览器有效登录会话。创建输入固定 expected_sha256、expected_revision、expected_deployment，空基线的两个发布标识也须显式传入空字符串。

API 持久保存加密任务及 root 派发父记录，由 `nginxpanel-switch@.service` 启动独立 worker，候选校验及服务控制不占用 Agent 请求。父记录固定唯一子操作；查询、服务重启和重复请求均不重用已领取授权。每次启动授权五分钟，原任务最多 32 次授权，记录总量最多 64 项；初次子操作仍使用十分钟前进及八分钟补偿期限，续办不延长前进期限。独立服务失败后，只有显式新授权才清除失败状态并启动；状态查询仅对账。补偿请求持久生效，后续续办继续补偿；尚未建立子操作时取消派发记为 failed/cancelled_before_switch，不虚构运行恢复证明。断连、记录缺失或执行状态不明时保留原任务与维护锁；完整备份恢复中的源切换任务隔离，不向新环境重放。页面/API、独立服务及故障恢复尚未实际执行，待 P5 集中验证。


## 独立前端发布与激活

组件页可单独选择 `web`，在线和离线来源均沿用原签名检查及准备任务。前端不能与面板或其他组件合并准备；清单 API 主版本、数据库合同必须适合当前受管后端，Agent/launcher 下限仍按发布验证。服务器不构建前端，也不执行 web 资产中的程序。准备只发布不可变目录，`frontend.release_id` 是静态发布身份，`activated=false` 不代表已切换。

`POST /api/v1/components/frontend/activate` 接收 `ComponentCreateInput`：`input.action=activate`，`prepare_task_id` 引用本人成功准备，`check_task_id` 为空；保留原准备的标签、资产、离线来源和精确计划/清单/信任摘要，并从组件概览的 `frontend` 绑定 `frontend_base_id/expected_frontend_id`。要求 `components.manage`、`system.write`、有效登录会话、浏览器 CSRF 和幂等键。显式远程端点使用相同合同及两个权限；普通 `/components/tasks` 不接受激活动作。

激活使用已有加密组件任务、独立 root 操作记录、审计和 10 分钟预算，提交意图先于 IPC。执行前重新认证已准备原资产与当前信任，核对后端身份及当前前端。原选择与目标写入 `runtime/frontend-operations/<UUID>.json`，随后原子发布 `runtime/frontend.json`，落盘并复核后才返回激活完成。失败恢复原选择；Agent 重启仅按原记录核对，批准的新文件不可读时在原后端与原资源均得到证明后恢复旧选择。未知指针或恢复无法核对时保留 `recovery_required`，不重放激活。历史任务的 `activated=true` 说明该次选择已完成，实时状态仍以概览为准。

独立静态产物位于 `runtime/frontend/<发布ID>/web`，目录由 root 持有且为 0755、文件为 0444。每份最多 4096 个文件、总计 64 MiB、单文件 8 MiB、清单 1 MiB；最多保留 16 份发布或遗留暂存，以及 64 条激活意图。达到上限须本机维护，不删除原救援、审计或未知目录。现有原生 Agent 写范围与 Docker 只读 runtime 挂载已覆盖该目录，应用不获得发布目录写权限。

生产静态服务仅从批准清单读取文件，并在返回前核对长度与 SHA-256。页面入口和无内容散列文件使用 `no-store`；内容散列资源使用不可变长缓存，当前目录缺失的同类资源可从上一前端读取。面板联合更新前另行保存前一程序来源；新后端默认使用自身配套前端，旧独立前端不会自动套用到不同后端。更新及补偿的 HTTPS 就绪观察核对实际批准选择及全部文件。

`GET /api/v1/system/version` 返回 `frontend_id/frontend_entries`。页面对照实际加载的模块、样式及预加载入口资源，在版本变化时提供重新载入按钮，并确认未保存修改；不自动刷新。该检查始终针对提供页面的本机面板，节点业务操作仍使用显式选中节点。当前 Agent/数据库/归档为 111/33/6；接口声明与实现同步，生成器、构建、类型检查、lint、测试、浏览器及真实切换尚未执行，留待 P5 隔离环境集中验证。


## 已验签发行说明与接收端要求

组件检查结果和离线上传信息保留清单签名覆盖的 `notes/requirements/receiver`，展示 API 主版本、目标数据库结构、Agent/launcher 下限、配套前端版本和自动回滚标志。发行说明按纯文本显示，不执行 HTML 或 Markdown。说明最多 8 KiB UTF-8、默认 JSON 编码后最多 16 KiB，仅允许 LF 和 TAB 控制字符；空说明在接收端显示为未提供，发布工具要求非空说明。

在线检查在签名、清单结构、仓库、标签、渠道、有效期及当前信任核对通过后，即使接收端版本不满足要求，也将已认证的 `announcement` 保存在失败任务中，错误码为 `COMPONENT_RECEIVER_INCOMPATIBLE`。说明包含要求、当前接收端版本及差异，不含准备计划 ID、资产或可执行授权；失败任务不能用于准备或激活。未经认证、来源不一致、清单过期或信任变化的响应不会保留此说明。离线创建仍须通过完整接收准入，版本不满足时直接拒绝并返回要求差异。

接收端不满足要求时，页面提示选择匹配 API 的发行，或由节点管理员处理 Agent/launcher 更新后重新检查；容器方式通过替换受信任镜像更新。独立 Agent 升级见下一节，跨协议变更仍须协调部署。Agent/数据库/归档为 112/33/6；本轮仅完成实现和源码审阅，生成器、构建、类型检查、lint、测试、浏览器、发布工具及真实系统操作均留待 P5 隔离集中验证。


## 独立 Agent 与宿主机工具升级

本机 root 可使用已经准备的单一签名静态面板资产升级 `/opt/nginxpanel/current` 中的 Agent 与固定宿主机工具。目标须与当前选中面板的 Agent 协议、数据库结构和 launcher 合同一致；不替换 `runtime/current`、容器 launcher 镜像、Nginx 或 Fail2ban，不迁移业务数据库。可使用本机命令，或通过网页/API 创建和续办持久任务。

安装器的固定 Agent 入口允许追加本机 root 批准的 `--dns-scope/--dns-owner` 与 `--firewall-scope/--firewall-owner/--firewall-ssh` 键值参数；只接受既定枚举，每个选项最多一次。升级保留参数原顺序，并继续绑定完整服务文件散列和实际进程参数；程序、数据目录、允许 UID、Nginx 绑定及维护范围等固定字段变更，或未知、重复参数均拒绝升级。

先通过原组件流程检查和准备面板资产，并在系统页取得已排空的维护会话及 Agent epoch，再提交新的操作 UUID：

```sh
sudo /opt/nginxpanel/current/nginxpanel agent-upgrade \
  --data-dir /srv/nginxpanel --agent-upgrade <新操作UUID> \
  --release-plan <已准备的面板计划散列> \
  --maintenance-id <已持有的维护UUID> --maintenance-epoch <当前Agent-epoch>
sudo /opt/nginxpanel/current/nginxpanel agent-upgrade-status \
  --data-dir /srv/nginxpanel --agent-upgrade <原操作UUID>
sudo /opt/nginxpanel/current/nginxpanel agent-upgrade-resume \
  --data-dir /srv/nginxpanel --agent-upgrade <原操作UUID>
```

首次提交绑定原程序散列及指针、原 Agent 进程/启动身份、运行绑定、目标签名暂存批准、两个 systemd unit 散列和十分钟前进期限。独立 `nginxpanel-agent-upgrade@.service` 在停止原 Agent 后原子切换程序指针，再启动候选；通过真实可执行文件 inode、完整参数、服务 cgroup、Invocation、启动时钟和以专用 Web 身份执行的同协议维护请求确认就绪。原 Agent 停止不会终止此 worker，Unix 对端 UID 白名单不放宽。

失败由 worker 在独立十分钟窗口恢复原程序及 Agent；原始批准版本以固定散列恢复，不要求候选签名继续有效。异常指针、服务文件、进程或维护身份无法确认时保留 `recovery_required`。进程中断后只能沿原 UUID 显式续办，原前进期限不续期；原维护记录必须仍在，过期仅允许补偿。幂等重放不重新派发；本机命令创建的操作使用原 UUID resume，网页/API 创建的操作须通过原任务续办接口重新授权。升级与补偿未确认前阻止维护锁释放及其他维护动作；成功或完整补偿后由原维护流程恢复写入。

程序发布在 root 持有的 `/opt/nginxpanel/agent-releases/<程序SHA-256>`，不覆盖旧目录，保留最多八项（含本次暂存），单程序最多 192 MiB；审计在节点私有 `agent/operations`，不进入业务迁移或灾备包。原安装器同时登记固定 worker；自定义 drop-in、缺失模板或未登记服务须本机处理，不能以首次安装器覆盖现有安装。Agent/数据库/归档为 114/34/6；本轮只完成实现与源码集成审阅，构建、测试、服务控制和故障注入待 P5 隔离环境集中验证。

网页进入「Agent 升级」，选择当前用户可读取且已完成签名暂存的面板准备任务，在原维护会话处于 held 时提交。`POST /api/v1/agent/upgrades` 接收 `maintenance_id` 和 `prepare_task_id`，要求 `components.manage`、`system.write`、有效登录会话及幂等键；浏览器同时要求 CSRF。`GET /api/v1/agent/upgrades` 与 `GET /api/v1/agent/upgrades/{id}` 读取本人任务，`auth.manage` 可读取其他用户任务。`POST /api/v1/agent/upgrades/{id}/resume` 要求相同写权限、原维护会话、当前 epoch、新幂等授权和已停止且未结束的原 root 事务。返回统一使用 `code/message/data/request_id/node_id`，成功受理为 HTTP 202。远程节点仅转发这些明确资源，并核对相同权限。

任务和授权加密保存，单次启动授权五分钟，root 最多保留 32 次连续授权，本地每任务最多保留 64 次请求、共 64 项任务。派发标记先提交，HTTP 断开、Agent 重启或服务启动结果不明后只查询原记录；曾提交但 root 记录缺失时须本机处理。源备份隔离任务不得在恢复目标提交或续办。面板更新与 Agent 升级不能并行；事务确认后在配置维护页显式释放维护锁。首次安装器预建 root 程序发布目录，并登记 `/etc/tmpfiles.d/nginxpanel.conf` 以在开机时创建共享安装锁目录；Agent 服务只获得发布子目录写入权，程序指针仍由独立升级服务切换。


### 面板运行镜像替换

容器面板在“运行镜像”页选择已完成的签名面板准备任务，持有配置维护会话后更换 launcher 镜像。当前应用、前端选择与业务数据库保留；运行镜像须已在目标主机按摘要准备。统一 API 为 `GET/POST /api/v1/panel/images/upgrades`、`GET /api/v1/panel/images/upgrades/{id}` 和 `POST /api/v1/panel/images/upgrades/{id}/resume`，创建字段为 `maintenance_id`、`prepare_task_id`。写请求需要组件管理、系统写权限、有效登录会话或显式授权 Token、幂等键；远程节点使用已登记的同资源转发路径。

持久任务与 root 意图分别保存，签名清单决定镜像地址，禁止调用者指定 Docker 地址、宿主路径、任意镜像或发布信任。启动/续办授权有效期五分钟、连续保存并仅领取一次；断连、进程停止和结果不明只查询原 UUID，显式续办不延长原十分钟前进期限。独立 worker 的失败恢复和本机救援见 [Docker 部署说明](../deploy/docker/README.md#面板容器与-launcher-对端核对)。页面退出不取消 worker，替换期间页面可能断开，恢复连接后继续查询原任务。

面板更新、Agent 升级和运行镜像替换共用活动任务限制，未结束时不能释放维护；完整备份中的隔离源任务保留审计和结果，不参与目标的新任务活动限制，不能从目标续办或重放。实际容器重建、恢复、权限和远程调用尚未执行，待 P5 隔离集中验证。

## 签名镜像拉取

完成面板签名准备后，组件页展示同一发行的本机架构镜像。选择“拉取镜像”会创建独立 `component.pull` 持久任务；API 为 `POST /api/v1/components/images/pull`，请求使用 `ComponentCreateInput`，其中 `prepare_task_id` 为本人的成功准备任务、`check_task_id` 为空，`input.action=pull`、`input.image_id=panel-launcher|nginx`，其余标签、资产、计划与签名散列须和准备结果一致。写入口要求 `components.manage`、`system.write`、有效登录会话或显式授权 Token、幂等键，远程节点沿登记路径转发。镜像拉取应在进入配置维护之前完成。

root 重新核对准备目录及当前发布信任，从签名清单推导固定 GHCR 摘要和 Linux amd64/arm64 平台；不接受用户镜像地址、Docker 地址或 Registry 凭据。当前入口下载可公开访问的发行镜像；私有包访问策略须由发布方在发布前安排。通过固定 Docker Engine API 1.47 读取下载进度，十分钟期限、8 MiB 总进度、64 KiB 单条进度与 65,536 条记录上限；HTTP 成功但流中报错也判失败。下载后核对实际镜像摘要、配置、架构、卷声明及签名启动器字节，过程只创建并删除未启动的元数据容器。已有镜像核对通过则复用，仅权威镜像缺失允许下载。

启动意图先持久化。Web 断连只查询原 UUID，Agent 重启后按原 root 意图重新验签并只检查本地内容；已存在且核对通过则确认就绪，其他情况记录失败，显式新建任务才可再次下载。不删除缓存层、既有镜像或运行容器，也不修改当前部署选择。首次安装可使用 [Docker 部署说明](../deploy/docker/README.md#签名镜像下载) 的 root 命令。下载就绪与运行切换分别授权；实现待 P5 隔离验证。
