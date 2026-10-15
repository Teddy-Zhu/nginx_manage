# 签名发行资产与离线准备

已接入 `release-verify` 和 `release-prepare` 本机命令。前者只验签、检查清单及解析依赖闭包，返回 `state=manifest_verified`；后者继续核对离线归档、宿主机运行依赖并发布不可变副本，返回 `state=prepared`。准备不等于安装、启用或运行；不执行包内程序、脚本、包管理器或网络下载，也不迁移数据库或切换当前版本。构建、测试、命令运行及真实系统矩阵仍待 P5 集中验证。

## 信任与签名

安装时由本机 root 保存 `/etc/nginxpanel/release-trust.json`。目录及其上层必须由 root 持有且不可被组/其他账户写入，文件不允许链接或额外硬链接。最多 8 个固定公钥；轮换/撤销只修改此本机配置，普通配置迁移不覆盖它。`repository` 为固定 `owner/repo` 身份；目前不从该值下载。

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

清单字段以 `internal/releases/model.go` 为唯一模型，包含 `schema/repository/version/channel/created_at/expires_at/api_major/database_schema/minimum_agent_protocol/minimum_launcher/frontend_version/automatic_rollback/assets`。版本使用 SemVer，channel 为 stable/prerelease；数据库 schema 和自动回滚标志是后续激活准入的材料，准备流程不据此承诺已迁移或能够回滚。

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

## 资源边界与后续

manifest 最多 2 MiB/16 个资产/合计 4096 个文件，准备计划最多 4 MiB，显式选择最多 4 项。单归档最多 128 MiB，展开最多 256 MiB，闭包压缩加展开合计最多 512 MiB；系统依赖核验合计最多 128 MiB。准备文件与目录合计最多 8192 项；保留目录最多 32 组、32768 项、2 GiB，预算不足时停止并要求本机维护。

仅接收单一 gzip 流包裹的 root USTAR，物理头逐块检查，拒绝 PAX/GNU 扩展、链接、设备、未知/重复文件、非零填充及额外压缩流。归档首先校验完整签名散列，再解包；复制期间再次散列并检查文件身份，gzip CRC 和完整文件清单通过后才发布。

在线 GitHub 发现/受限下载、发布构建与私钥签名工具、SBOM、Web 上传/组件 API、安装/切换任务、维护准入、独立更新 worker 及回滚、迁移自动准备和完整 Docker 激活仍在 P4 后续范围内；本入口不宣称这些能力已经交付。
