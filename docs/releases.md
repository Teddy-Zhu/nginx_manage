# 签名发行资产与准备

已接入离线 `release-verify/release-prepare` 和在线 `release-check/release-fetch` 本机命令。验证入口只验签、检查清单及解析依赖闭包，返回 `state=manifest_verified`；准备入口继续核对归档、宿主机运行依赖并发布不可变副本，返回 `state=prepared`。准备不等于安装、启用或运行；不执行包内程序、脚本或包管理器，也不迁移数据库或切换当前版本。构建、测试、命令运行及真实系统矩阵仍待 P5 集中验证。

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

验签前只读有界文件和签名信封，认证后解析清单；JSON 拒绝未知字段、重复字段、非法 UTF-8、尾随值及过深结构。清单须匹配本机信任中的仓库，使用当前 schema/API 主版本，并满足接收端 Agent/launcher 最低版本。有效期必须明确、未过期、最长两年；创建时间不得超过本机时间 5 分钟。预发布必须显式 `--release-prerelease`。

## 清单合同

清单字段以 `internal/releases/model.go` 及 `images.go` 为唯一模型，包含 `schema/repository/version/channel/created_at/expires_at/api_major/database_schema/minimum_agent_protocol/minimum_launcher/frontend_version/automatic_rollback/assets/images`。版本使用 SemVer，channel 为 stable/prerelease；数据库 schema 和自动回滚标志是后续激活准入的材料，准备流程不据此承诺已迁移或能够回滚。镜像引用、平台摘要与 OCI 元数据也受同一清单签名保护；`release-images` 的只读认证入口见 [固定镜像发行](publishing.md#固定镜像发行)。

每个资产登记唯一 ID、组件、版本、Linux 架构、发行版及版本、ABI、必要系统文件的长度/权限/散列、归档长度/散列、展开总长、逐文件清单、同清单内的精确依赖 ID、许可文件、HTTPS 上游来源、维护状态及 Nginx 模块声明。仅允许 panel/web/nginx/fail2ban 四种组件；固定入口依次为 `nginxpanel`、`index.html`、`bin/nginx`、`bin/fail2ban-server`。panel 须包含 `web/index.html`，其版本与发行版本一致；独立 web 的版本与 frontend_version 一致。

`abi=static` 不允许系统运行文件约束，ELF 主入口不得有解释器或动态库依赖；`abi=constrained` 必须固定实际发行版/版本和所需系统文件。静态资产可声明 distribution/distribution_version 为 any/any；仅 web 的 architecture 可为 any。宿主机动态依赖可位于 `/usr/lib/`、`/lib/`、`/lib64/` 或固定 `/usr/bin/python3[.版本]`，解析系统链接后再核对 root 文件身份、长度、权限与散列。依赖缺失、漂移或冲突直接失败，不回退安装其他管理器或组件。

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

[发布工具与 CI 流程](publishing.md) 已接入面板/web 的打包、签名、源码/构建依赖 SBOM 和草稿发布，尚未运行或发布；项目许可和仓库签名配置仍需提供。Nginx/Fail2ban 组件构建、Web 上传/组件 API、安装/切换任务、维护准入、独立更新 worker 及回滚、迁移自动准备和完整 Docker 激活仍在 P4 后续范围内。

## 面板版本暂存

本机 root 可将已准备的 `panel-linux-<当前架构>` 计划复制到 `DATA/runtime/releases/<内容散列>`，供后续独立更新执行器使用。沿用准备时的目标主机和接收协议身份，检查当前公钥、签名有效期、静态 ELF、程序版本与 Agent/launcher 协议，并核对同版前端文件。只在程序已通过签名散列核对后执行固定 `version` 命令。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-runtime-stage \
  --data-dir /srv/nginxpanel --release-plan <已准备的面板计划散列>

sudo /opt/nginxpanel/current/nginxpanel panel-runtime-staged \
  --data-dir /srv/nginxpanel --release-plan <同一计划散列>
```

自定义本机信任文件须与准备一致；预发布须显式传入 `--release-prerelease`。完整目录同步并不覆盖发布后，才写入 root 只读的 `runtime/approvals/<计划散列>.json`。首次绑定和暂存共用发布锁，最多保留 32 个版本和 64 个批准记录；中断前已复制但未批准的目录不能作为更新授权。相同计划重复暂存使用原批准时间、主机/协议身份和初始信任散列重新认证当前公钥，增加无关公钥不改变计划，撤销签名公钥则拒绝续用。续用仍需保留原准备计划及签名材料；只读查询不下载或执行程序。

`state=staged` 仅表示持久副本及其批准记录就绪，返回数据库 schema、协议门槛和签名回滚声明供后续准入使用。不切换当前版本、不迁移数据库、不重启面板或 Nginx/Fail2ban；独立 worker、版本切换、健康检查与失败回滚编排仍待接入。本入口尚未运行，统一留到 P5 集中验证。

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

`version_selected` 仅表示程序指针已持久化；本入口不重启服务、打开数据库或释放维护会话，不报告应用健康。独立 worker 的自动编排、匹配程序与数据的自动回滚及成功清理仍待接入；不应将此命令作为已完成的升级 API。尚未运行以上入口、服务、安装器、构建或测试，统一留到 P5。

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

持久停机标记或未完成的进程记录会阻止维护释放。`started` 表示已观测到目标进程实例；就绪检查见下文。完整程序/数据回滚、升级提交及清理仍待独立更新 worker 编排。尚未执行控制入口、systemd、launcher、服务、构建或测试，统一留到 P5。

## 面板就绪观察

本机 root 的 `panel-readiness` 关联原维护会话、已完成的启动操作及原恢复快照，返回当次观察证据。生产 `serve` 在持有写锁后提供 `DATA/app/readiness.sock`；此 Socket 仅接受 root 对端，返回统一的 `code/message/data/request_id/node_id`。开发模式不提供此入口。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-readiness \
  --data-dir /srv/nginxpanel --panel-service-operation <原启动UUID> \
  --recovery-snapshot <原快照UUID> \
  --maintenance-id <原维护UUID> --maintenance-epoch <当前Agent-epoch>
```

观察端以 Unix 对端凭据、实际执行文件和原进程标识认证应用；Docker 还核对经认证 launcher 的宿主机 PID、直接父子关系与 PID 命名空间。原生 systemd 实例或 launcher boot/serve 实例变化均拒绝复用旧启动回执。应用初始化最多等待 90 秒，整次观察最多四分钟。等待期间不持有维护准入锁，允许重启后的应用与 Agent 恢复同一 held 会话。

数据库查询由非 root 应用执行：schema 必须等于目标程序声明，节点、期望/生效修订和配置版本须等于快照；维护双方均须 held、epoch 一致、没有在途操作。已有生效修订还须通过 Agent 核对 Nginx 运行修订、完整性及外部修改状态。root 仅核对固定密钥/TLS 文件与快照散列，继续保持业务 SQLite 不由 root 解析。

实际 HTTPS 监听须属于同一应用进程，并固定本机管理证书、拒绝重定向和代理。检查健康与版本 API 的统一响应、节点身份、版本和协议，再核对全部已发布前端文件及入口内容的长度与散列。前后两次应用/进程/密钥材料核对不一致时明确失败。新目标继续核对原签名批准；停机或数据恢复标记未解除时不提供就绪证据。

返回包含原启动/快照/绑定散列、进程实例、应用状态、HTTPS 核对数量和观察时间，仅表示该时间点的结果；独立更新执行器见下文。本命令不释放维护、不启动进程、不恢复数据、不删除快照。尚未执行此入口、服务、构建或测试，留到 P5 集中验证。

## 独立面板更新事务

`update-worker` 在待替换 `serve` 之外以 root 运行，要求已完成的签名暂存、同一 held 维护会话及当前 epoch。固定流程为：一致性快照、持久停机、版本选择、新进程启动、就绪观察、提交结果、协调原维护会话释放。发布须明确声明允许自动回滚；不支持直接降低 schema，不自动升级宿主机 Agent、launcher、Nginx 或 Fail2ban。使用前须部署理解本合同的 Agent 20。

原生安装登记 v11 为 native 和 Docker 面板统一安装 `nginxpanel-update@.service`。该 root 服务独立于 `serve` 和 Agent 的生命周期，只接受原操作 UUID，由固定 `panel-update-worker` 加载 root 记录；请求不能指定可执行程序、数据目录或信任文件。服务不自动重启，最长运行 40 分钟，收到停止信号后留出补偿时间。运行前核对安装意图、ready、root 服务文件及 systemd 实际加载的片段、账户、类型、drop-in 和 reload 状态。

Agent 20 提供内部 IPC `POST /v1/panel/updates` 与 `GET /v1/panel/updates/{id}`，沿用统一响应封装。新建须传递已签名暂存的 `plan_id`、原 `maintenance_id`、`prerelease`、操作 UUID、发起人 `actor`、原请求 `request_id`、当前 epoch、连续 `sequence` 和五分钟内的 `authorization_until`；首个 command 为 `update`，后续为 `resume`。Agent 先持久保存完整原意图和逐次授权，再启动固定服务。启动授权由 worker 在锁内一次性认领。相同序号与内容只查询原操作，不能重复启动；启动结果未知或服务停止后须使用下一个序号显式续办。历史授权不可修改，续办不改变原目标、快照及总执行期限。过期启动授权不能触发后续变更，已经运行的事务仍按原补偿规则处理。

查询同时核对实际服务状态与 root 原记录；失去运行进程的未完成事务保留 `recovery_required`，不伪造成功。已提交或补偿完成的事务只收取原维护释放回执，查询可补齐此收尾记录，不能触发停机、切换或恢复。上述入口为 Agent 内部合同；面向用户的 Web/API 任务已接入，救援材料清理仍待补齐。


Web“组件准备”可单独选择面板；准备过程除验证及下载签名静态面板产物外，还将同版程序与前端暂存到持久版本目录，并返回版本标识、数据库版本与自动回滚声明。面板不与 Nginx/Fail2ban 共用准备计划，暂存不切换当前版本或启动新程序。安装登记 v11 允许 Agent 仅在受管 runtime 目录完成此暂存。

Web“面板更新”及公共 API `GET/POST /api/v1/panel/updates`、`GET /api/v1/panel/updates/{id}`、`POST /api/v1/panel/updates/{id}/resume` 已接入同一任务服务。写操作要求 `components.manage`、`system.write`、近期认证或有效机器 Token，以及幂等键；浏览器同时校验 CSRF。新建绑定已成功暂存的准备任务和原 held 维护会话。任务输入与每次请求加密保存，历史请求追加保留；发起人和请求标识同时保存在 root 授权记录中，数据库补偿后仍可追溯。联系 Agent 前先记录提交尝试，使更新快照和数据库回滚后仍能确认原操作。

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

当前实现为独立 root CLI；Web/API 更新任务、专用服务托管、成功后的快照/恢复暂存清理仍待接入，暂时保留恢复材料并继续受既有容量上限约束。尚未执行 worker、安装器、服务、构建、生成器或测试，待 P5 集中验证。

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

`files_restored` 只说明数据安装完成；版本切换、readiness、当前 Nginx 状态确认及成功清理仍由后续独立更新 worker 接入。恢复保留维护会话，不重启 Nginx/Fail2ban。尚未运行恢复命令、安装器、服务、构建或测试，统一留到 P5。

## 组件页面与任务

原生 Agent 由本机 root 设置 `--component-scope host`，沿用 `--release-trust` 与可选 `--release-token-file`；默认未确认范围及开发 Agent 不准备组件。Web/API 不接收仓库 URL、公钥、Token 或文件路径，`components.manage` 权限及写操作重新认证约束此入口。页面 `/components` 自动扫描接入，使用统一 JSON 外壳；`GET /api/v1/components` 读来源，`GET/POST /api/v1/components/tasks` 读本人任务或提交带幂等键的检查/准备。

检查可用 `components: ["nginx"]`（可另选 `fail2ban`）按架构/发行版唯一匹配，多个匹配项须使用明确 `assets` ID，不猜测最新 ABI。准备须引用本人成功检查任务 `check_task_id`，显式绑定 `tag/prerelease/assets/plan_id/manifest_sha256/trust_sha256`；过期、来源变化或系统运行依赖缺失时停止准备。root Agent 再次验证全部材料，在下载归档前核对期望散列。`runtime_ready` 只说明已声明的本机运行文件满足校验，不代表实际执行或 ABI 验收。

Web 将任务输入及精简结果分别加密，保留最多 64 项，单条 64 KiB；root 使用独立私有操作目录和同等记录上限，单次期限十分钟，节点串行。提交意图先于 IPC 持久化；接受情况不明只查询原 ID，记录缺失进入待恢复，阻止新任务。Agent 重启对中断准备仅重新验签并复核既有不可变回执；不凭超时判定未落盘，不替换未知目录。容量用尽或材料无法确认须由本机维护，不能直接删除记录后重试。

原生安装器预建 root 持有的 `/opt/nginxpanel/prepared` 与私有 `/opt/nginxpanel/release-downloads`，Agent unit 仅增加这两处写范围。准备成功只产生受信产物；原生首次安装见后文；Web 安装、运行中切换和迁移自动准备仍待后续接入，Docker Nginx 模块继续固定在镜像中。

## 原生运行绑定

已准备的单一 Nginx 资产可由原生安装器通过 `--nginx-plan/--nginx-asset` 直接接入，见 [原生安装](../deploy/native/README.md)。固定 `component-path/component-bind/nginx-runtime` 命令分别负责准入解析、不可变本机安装批准和执行；Web 不能创建或覆盖绑定。Agent 和 systemd 使用同一绑定，实际版本须匹配签名资产，启动不依赖 GitHub 或下载缓存。

`Prepared` 现在为纯只读回执核验，恢复不会创建锁或补发归档。已安装运行使用 root 本机批准时间验证原清单的准入有效期，并以当前受信公钥及仓库重新验签、复核完整原计划/文件和系统依赖。原批准信任散列只用于重建不可变回执身份，不替代当前验签；添加无关公钥不触发无关版本失效，撤销签名公钥仍拒绝启动。此规则不用于新检查/准备，业务请求也不能提交批准时间或旧信任材料。
