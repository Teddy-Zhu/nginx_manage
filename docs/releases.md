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

## 组件页面与任务

原生 Agent 由本机 root 设置 `--component-scope host`，沿用 `--release-trust` 与可选 `--release-token-file`；默认未确认范围及开发 Agent 不准备组件。Web/API 不接收仓库 URL、公钥、Token 或文件路径，`components.manage` 权限及写操作重新认证约束此入口。页面 `/components` 自动扫描接入，使用统一 JSON 外壳；`GET /api/v1/components` 读来源，`GET/POST /api/v1/components/tasks` 读本人任务或提交带幂等键的检查/准备。

检查可用 `components: ["nginx"]`（可另选 `fail2ban`）按架构/发行版唯一匹配，多个匹配项须使用明确 `assets` ID，不猜测最新 ABI。准备须引用本人成功检查任务 `check_task_id`，显式绑定 `tag/prerelease/assets/plan_id/manifest_sha256/trust_sha256`；过期、来源变化或系统运行依赖缺失时停止准备。root Agent 再次验证全部材料，在下载归档前核对期望散列。`runtime_ready` 只说明已声明的本机运行文件满足校验，不代表实际执行或 ABI 验收。

Web 将任务输入及精简结果分别加密，保留最多 64 项，单条 64 KiB；root 使用独立私有操作目录和同等记录上限，单次期限十分钟，节点串行。提交意图先于 IPC 持久化；接受情况不明只查询原 ID，记录缺失进入待恢复，阻止新任务。Agent 重启对中断准备仅重新验签并复核既有不可变回执；不凭超时判定未落盘，不替换未知目录。容量用尽或材料无法确认须由本机维护，不能直接删除记录后重试。

原生安装器预建 root 持有的 `/opt/nginxpanel/prepared` 与私有 `/opt/nginxpanel/release-downloads`，Agent unit 仅增加这两处写范围。准备成功只产生受信产物；原生首次安装见后文；Web 安装、运行中切换和迁移自动准备仍待后续接入，Docker Nginx 模块继续固定在镜像中。

## 原生运行绑定

已准备的单一 Nginx 资产可由原生安装器通过 `--nginx-plan/--nginx-asset` 直接接入，见 [原生安装](../deploy/native/README.md)。固定 `component-path/component-bind/nginx-runtime` 命令分别负责准入解析、不可变本机安装批准和执行；Web 不能创建或覆盖绑定。Agent 和 systemd 使用同一绑定，实际版本须匹配签名资产，启动不依赖 GitHub 或下载缓存。

`Prepared` 现在为纯只读回执核验，恢复不会创建锁或补发归档。已安装运行使用 root 本机批准时间验证原清单的准入有效期，并以当前受信公钥及仓库重新验签、复核完整原计划/文件和系统依赖。原批准信任散列只用于重建不可变回执身份，不替代当前验签；添加无关公钥不触发无关版本失效，撤销签名公钥仍拒绝启动。此规则不用于新检查/准备，业务请求也不能提交批准时间或旧信任材料。
