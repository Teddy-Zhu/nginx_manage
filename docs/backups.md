# 完整加密备份

当前已接入一致性捕获、加密归档、定期任务、保留与清理、鉴权下载，以及非 root 离线检查、停机恢复准备、准备报告查询与清理，以及绑定目标回退快照的 root 固定材料接入、独立目标计划、文件安装、运行应用、数据对账、最终激活及激活前原资源补偿。页面 `src/pages/backups.vue` 由页面元信息自动扫描，固定操作当前本机。实现尚未运行生成器、构建、类型检查或业务测试，等待 P5 集中验证。

完整备份与[跨环境配置迁移](migration.md)、面板更新使用的本机 root 救援快照是三种不同用途和格式。跨环境业务导入继续使用迁移预检及执行器。当前完整备份支持灾备/克隆材料准备及受屏障保护的固定文件安装和补偿；目标组件、运行配置协调与激活事务仍待补齐，不能直接覆盖数据库后启动。

## 包内容与一致性

归档为流式 age 加密的固定清单 tar，包含 `manifest.json`、SQLite 业务数据库、配套 32 字节主密钥及主入口 TLS 证书/私钥。数据库包含配置原文、资源投影、证书与凭据、管理员、远程授权、任务、审计及历史。清单记录包与源节点身份、程序版本与生产发布摘要、部署方式、数据库/Agent/解析器/策略版本、期望及已应用修订、Nginx 能力和每项材料的大小与 SHA-256。

捕获通过统一维护准入等待写入及宿主机操作完成，使用 `VACUUM INTO` 创建包含已提交 WAL 数据的一致性 SQLite 快照。非 root 面板进程校验快照、复制匹配密钥与 TLS 材料，持久保存清单后释放维护边界，再流式加密。加密结果的大小和散列在改名发布前持久保存，完成并删除明文暂存后才允许下载。中断的捕获或加密不被冒认为成功；发布阶段可以核对原文件身份继续完成。

不打包 Agent 信任与救援记录、监听恢复记录、Nginx/组件可执行文件、镜像、系统服务、操作系统网络配置、运行日志或生成的生效目录。目标恢复仍须匹配源程序与数据版本，检测并准备可信组件、镜像能力和目标路径；Docker Nginx 缺失模块必须使用匹配的预置镜像，不能运行时编译或增装。

## 加密与授权

手动备份可选择规范的 age X25519 公钥或 16–256 字节口令。口令仅保留在创建任务的面板进程内存中，不进入数据库、任务清单、审计或归档。进程重启后未完成的口令任务失败，原幂等键继续返回原任务，不悄悄另建任务。归档与解密口令应分开保管。

定期备份仅接受 age X25519 公钥。管理员在离线设备使用 `age-keygen` 生成密钥，将私钥离线保管，只将公钥填写到面板并确认已保存私钥。服务器不接收或常驻恢复私钥。保存策略要求近期认证及 `backup.export/backup.secrets/system.write`，包含 1–168 小时周期、保留策略和不超过未来 366 天的明确授权期限。机器凭据授权不能超过该凭据期限。

执行前重新核对原主体、浏览器账户安全代次、机器凭据撤销/权限/到期及当前策略版本。失效、停用或过期后不继续捕获或发布，并释放原任务的维护会话；策略错误及失败通知沿用现有 `backup.failure` 队列。同一次策略审批的授权失败只建立一条失败任务。停机期间错过的周期不批量补跑。

## API 与下载

JSON 请求与失败响应沿用统一 `code/message/data/request_id/node_id` 外壳。全部备份接口须直接连接被操作节点，不经控制节点递归转发。

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/backups` | 策略、最近 128 条可见记录与容量上限 |
| `POST /api/v1/backups` | 近期认证及 `Idempotency-Key` 创建任务，返回 202 |
| `GET /api/v1/backups/{id}` | 原任务及归档身份 |
| `DELETE /api/v1/backups/{id}` | 近期认证后清理结束任务的文件，或续办 `cleanup_failed` 清理 |
| `GET/PUT /api/v1/backups/policy` | 查询/版本比较保存策略 |
| `POST /api/v1/backups/{id}/download` | 浏览器签发绑定当前会话的 60 秒单次下载票据 |
| `GET /api/v1/backups/{id}/download` | 浏览器携带原会话和票据，或机器 Bearer 直接下载 |

创建输入为 `{name,encryption,recipient,passphrase}`；`encryption` 为 `recipient` 时提供公钥、口令留空，`passphrase` 时提供口令、公钥留空。读取要求 `backup.export`；创建及策略修改另需 `backup.secrets/system.write`；下载另需 `backup.secrets` 和浏览器近期认证。主体只能查看、下载或清理自己的记录，`auth.manage` 可管理其他主体。票据不是匿名下载链接，数据库仅保存其散列。

下载前校验加密文件散列与原发布身份，通过普通附件流下载，不将整个归档装入浏览器内存。最多同时下载 2 个，每次最多 5 分钟，期间复查会话/凭据；中断须重新签发票据并下载完整文件，不提供 Range 分段续传。`X-Backup-SHA256` 和记录中的散列用于核对加密文件。下载打开记录不等于客户端已成功保存文件。

## 容量与清理

业务数据库最大 512 MiB，单个加密归档最大 514 MiB，备份区配额 2 GiB，最多 16 个归档/部分归档。捕获前计算已有密文、明文暂存及新备份所需余量，并核对磁盘可用空间。新备份完成前不提前删除旧的成功归档来腾空间。

保留策略默认 7 份/30 天，可设 1–15 份、1–90 天，统一应用于本机已完成的归档；超过数量或任一期限即清理。删除先持久化意图，再删除固定文件并保存完成状态，下载中的文件暂缓删除。任务、幂等记录及审计保留，备份历史最多 512 项；维护会话仍受现有 64 项历史上限约束，到限会明确失败并需要本机历史维护。历史归档管理仍是完整首版待补工作，不通过删除审计绕过上限。

数据目录下 `backups` 和 `.work` 为面板账户持有的 0700 目录，秘密文件为 0600。捕获到发布的明文暂存窗口上限 15 分钟；进程运行时清理到期/失败暂存，重启后继续清理。进程未运行期间不会执行 TTL 清理，残留仍由私有目录权限保护。未知文件、链接或归属变化不会被递归删除。清理失败保留可见状态，释放原维护会话后由管理员恢复存储并续办。

原生安装登记升级为 v12，预建备份目录并赋予 Web 写权限；Nginx、Agent、组件安装与面板更新服务屏蔽该目录。Docker 面板沿用非 root 的持久数据目录。当前不保留旧安装登记的兼容分支。

## 离线检查

在离线设备使用匹配版本程序，以非 root 账户执行：

```sh
nginxpanel backup-inspect --backup-file ./backup.tar.age < ./offline-credentials.json
```

标准输入仅接受不超过 8 KiB 的单个 JSON 对象，二选一：`{"identity":"AGE-SECRET-KEY-…"}` 或 `{"passphrase":"恢复口令"}`。解密材料不通过命令行参数传入；输入文件由离线持有人自行保护，不能随归档上传到服务器。

检查在私有临时目录有界解密，拒绝清单外资源、链接、路径变化、重复/多余 tar 项和未完成 age 认证。校验每项散列、主密钥探针、TLS 配对、SQLite 完整性/外键及清单身份；匹配当前版本时还检查期望/已应用配置原文与投影解密。所有出口清理本次固定临时材料。不会迁移数据库 schema、安装材料或运行包内脚本。

输出 `format_compatible` 仅表示数据库、Agent 与解析器/策略版本匹配，不代表目标可恢复。返回在途任务数量及隔离要求。下述停机准备会隔离数据；完整恢复事务仍须检测宿主机依赖、保留目标回退快照、安装匹配材料、协调真实运行状态并处理失败补偿，不覆盖 Agent 独立救援历史。


## 停机恢复准备

此阶段只生成私有准备材料和未完成检查清单，不写入目标业务数据库、切换运行程序、安装组件、解除停机或激活配置。先通过现有独立维护和服务停止事务，取得目标的持久停机标记；普通 `systemctl stop` 不足以构成此边界。准备要求源、目标及当前程序的数据库 schema、Agent/解析策略和程序版本匹配，不在导入中升级源数据库。

在目标宿主机由 root 调用，操作标识须为新 UUID：

```sh
nginxpanel backup-prepare --data-dir /srv/nginxpanel \
  --restore-operation "$RESTORE_ID" --backup-file ./backup.tar.age < ./restore-input.json
nginxpanel backup-preparation --data-dir /srv/nginxpanel --restore-operation "$RESTORE_ID"
nginxpanel backup-preparation-cleanup --data-dir /srv/nginxpanel --restore-operation "$RESTORE_ID"
```

准备输入是最多 8 KiB 的 JSON：

```json
{
  "mode": "clone",
  "source_node_id": "源节点 UUID",
  "target_node_id": "目标当前节点 UUID",
  "archive_sha256": "检查所得加密文件 SHA-256",
  "maintenance_id": "目标原持久停机事务的维护 UUID",
  "preserve_node_identity": false,
  "source_offline_confirmed": false,
  "credentials": {"identity": "AGE-SECRET-KEY-…"}
}
```

`credentials` 也可仅提供 `passphrase`。解密材料通过临时标准输入交付，不放进参数、环境、数据库或准备报告；输入文件需自行保护并在交付后清理。root 核对当前部署及原停机绑定，只向已批准的固定程序传递加密文件描述符，以面板 UID/GID 和专用 IPC 组执行；归档 SQLite 的读取、可信 schema 比对及数据改写均在非 root 下完成。子进程失败或调用中断不表示准备成功，原标识可能留有可清理的部分目录；输出中断后应查询原标识，不能自行认定操作未执行。

`clone` 总是生成不同于源和目标旧身份的新节点 ID。`disaster` 默认也生成新身份；只有同时明确 `preserve_node_identity=true`、`source_offline_confirmed=true`，确认原实例停止后才保留源身份。两种模式均保留目标管理员用户名、密码散列及主入口 TLS，提升安全代次、删除会话和 bootstrap 授权、撤销导入 API 凭据。保留源业务主密钥以解密配置、证书及凭据；源远程连接、配对材料不继承，原远端凭据撤销结果保持待核对。

准备数据默认关闭除配置编辑外的功能模块、定期备份授权、通知渠道与投递、ACME 自动续期/部署；DNS 挑战记录隔离，主机 DNS 计划和缓存清空，不操作真实 DNS。旧迁移计划失效，源归档记录标记不可下载。未结束任务保存原状态并隔离，不派发或重试；源维护会话不继承为目标授权。源审计完整保留，并合并目标审计；同 ID 不同内容拒绝覆盖，目标合并超过 64 MiB 拒绝继续，不删除审计腾空间。

准备数据库持有独立的 `restore_barriers` 启动屏障，正常数据库入口在运行迁移或启动 worker 前拒绝打开未完成恢复的数据。复制准备文件不能构成可用恢复；禁止手动改表或清除屏障来启动。报告中的待检查项包括 root 回退快照、目标可信组件与预置镜像能力、路径及端口映射、配置重新发布、旧任务实际结果和外部授权协调。后续须依次完成目标计划、固定文件安装、运行应用、数据对账及显式激活；任何单阶段成功均不代表完整恢复可用。

材料位于 `DATA/staging/restore` 的 0700 目录，固定文件为 0600，最多两项准备；配额 2 GiB，另预留 SQLite 回滚日志与可用磁盘余量。创建时间在解密前落盘，报告有效期为 15 分钟；查询重新核对资源散列、密钥、TLS、数据库身份、管理员及启动屏障，过期显示 `expired=true`。服务运行时按原期限清理，持续停机时不会自动执行 TTL，需要上述清理命令；清理要求持久停机及写锁，只删除本操作的固定私有文件，并识别有界 SQLite 回滚日志，遇到未知文件或归属变化拒绝删除。准备清理不会更改原加密备份、目标业务文件或 Agent 独立记录。


## 固定材料接入与目标回退依据

`backup-adopt` 将指定准备报告对应的四项材料固定到 `DATA/agent/disaster-recovery`，并绑定同一维护会话下的目标回退快照。此阶段生成 `adopted` 记录，仍不安装文件、启动业务、解除启动屏障或宣称恢复成功。

先保持原持久停机和维护授权，通过当前已批准程序捕获目标本机回退快照，再接入准备材料。快照与准备的顺序不影响含义，但目标数据库、主密钥、入口 TLS 及 WAL 身份必须保持一致；不要使用旧维护会话的快照。捕获程序的二进制散列须等于当前已批准程序：

```sh
/srv/nginxpanel/runtime/current/nginxpanel panel-snapshot-capture \
  --data-dir /srv/nginxpanel --recovery-operation "$RESTORE_SNAPSHOT_ID" \
  --maintenance-id "$RESTORE_MAINTENANCE_ID" --maintenance-epoch "$RESTORE_EPOCH"
/srv/nginxpanel/runtime/current/nginxpanel backup-adopt \
  --data-dir /srv/nginxpanel --restore-operation "$RESTORE_ID" < ./adopt-input.json
/srv/nginxpanel/runtime/current/nginxpanel backup-adoption \
  --data-dir /srv/nginxpanel --restore-operation "$RESTORE_ID"
/srv/nginxpanel/runtime/current/nginxpanel backup-adoption-cleanup \
  --data-dir /srv/nginxpanel --restore-operation "$RESTORE_ID"
```

接入输入最多 8 KiB，不再提供恢复私钥或口令：

```json
{
  "preparation_sha256": "backup-preparation 返回的 preparation_sha256",
  "snapshot_id": "目标本机回退快照 UUID",
  "maintenance_id": "原持久停机的维护 UUID",
  "epoch": "该维护会话当前 Agent epoch"
}
```

准备摘要由程序对准备报告规范 JSON 计算，调用者明确指定，不能仅依赖可变暂存路径。root 在独立维护准入及业务写锁内核对原停机、当前批准程序、目标回退快照和目标文件；回退快照通过本机密钥完整认证，不接受只有清单而没有可用密文的快照。Agent 重启后仍须提供原维护会话的当前 epoch；回退快照的历史捕获 epoch 和首次接入批准记录保留。

材料复制到 root 专用目录并逐项比对大小及散列，固定文件为 root 0400。随后固定非 root 助手核对这份副本的业务密钥、管理 TLS、可信 schema、数据库及管理员身份、源修订解密和隔离状态。SQLite 通过 root 持有且面板组只读的固定临时数据库投影打开，不通过面板可写路径解析；临时投影位于 `DATA/run/disaster-check`，不含额外私钥，完成或失败后清理。root 不解析归档 SQLite，非 root 助手不能修改固定材料和核对投影。

接入意图和批准记录先落盘，再原子发布目录；重复请求只续办原准备摘要、原停机、原程序与原回退快照。查询显示 `intent_incomplete`、`copying`、`adopted`、`cleaning`、`cleaned` 或 `absent`。原准备过期后不能从 Web 暂存新增材料，但已经固定完整的副本可以在接入期限内继续核对。接入期限最多 24 小时，且不超过原回退快照期限；过期显示 `expired=true`，不重新授权安装，也不自动删除恢复依据。

root 接入区最多两项活动操作、配额 2 GiB；连同清理历史最多保留 128 项，到达上限后停止新接入，等待后续受控归档。核对区最多两项数据库投影，每项最大 512 MiB，另检查实际磁盘余量。进程被终止时可能留下固定暂存或只读投影，原操作续办或显式清理会核对并处理。清理要求仍处于原停机且没有恢复写屏障，先持久进入 `cleaning`，删除材料后保存完成记录并进入 `cleaned`，断电后可按原标识继续。原意图、已有批准记录和清理记录继续保留，原标识不能复用于新接入。只删除本操作的固定材料和核对投影，不删除目标回退快照、业务文件、其他归档或 Agent 执行记录；未知文件、链接、权限变化及阶段冲突均停止处理。

该入口为本机 root 命令，不新增 Agent/Web 的暂存目录访问权限，也未新增安装执行服务。固定文件安装、运行应用与补偿见下节；期望/生效数据库协调、业务屏障解除及激活仍须补齐。


## 目标恢复计划

在文件安装前使用本机 root 命令生成计划，原持久停机和维护授权须保持有效：

```sh
/PANEL_RUNTIME/current/nginxpanel backup-restore-plan --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
/PANEL_RUNTIME/current/nginxpanel backup-restore-plan-status --data-dir /var/lib/nginxpanel --restore-operation <计划UUID>
```

生成输入最多 32 KiB，包含独立 `plan_id`、原 `adoption_sha256`、当前 `epoch` 和可选 `mappings` 对象。映射复用逻辑迁移的参数跨度处理，完整数据库恢复保留文件、证书及版本标识，不重新分配资源身份。映射仅处理已识别的监听、域名、上游、解析器、证书与模块参数；模块路径可显式映射为空以移除对应 `load_module` 指令，其他参数不接受空映射。不执行脚本或接受归档自带策略。未映射的系统信任材料、缺失模块或目标运行漂移会阻止安装；Docker 所需能力仍须来自预置镜像。

root 持有维护准入与写锁，核对原目标文件和回退快照；固定非 root 助手通过 root 只读投影解析准备数据库，查询目标固定 Unix socket 的 Nginx 能力与运行状态，核对目标原已应用修订、配置/证书和隔离状态。无阻塞时，助手从原固定数据库复制独立暂存，以计划 UUID 创建新的期望修订，原文、资源投影、证书引用、恢复报告与审计同事务保存；源修订历史保留，已生效修订仍为空，不创建应用任务。原文与普通保存共用修订写入实现，配置仍以源业务主密钥加密。计划保存候选配置、证书材料、目标能力及解析策略摘要；预览不返回完整配置内容、证书私钥或业务主密钥；地址与映射保留供复核。预检复用逻辑迁移的 Nginx 能力及运行准入，未连接目标 Agent 时报告不可用。

助手同时生成规范 Nginx 请求，固定新修订、目标原运行修订、映射原文及证书材料。root 将发布数据库和请求固定为 `DATA/agent/disaster-configs/<计划UUID>/panel.db` 与 `nginx.json`，只复制并核对散列，不以 root 解析 SQL。目录为 root 0700，文件为 root 0400；`nginx.json` 含配置原文与证书私钥，最多 24 MiB，不出现在命令响应、IPC 请求或计划预览中。助手退出后，另一次非 root 只读核对通过五个固定描述符重验数据库、主密钥、管理 TLS 及 Nginx 请求，按源历史与原映射重新计算候选，逐项核对新修订原文、投影、证书材料/引用、恢复报告与请求一致性。计划绑定两份发布文件的大小/散列、节点/修订版本和该次核对证明；未完成核对时不保存可安装批准。

计划列出配置诊断、缺失能力、监听/域名/上游复核和待协调事项；展示最多 64 项步骤，所有步骤均参与准入判断，待完成类别单独保留。`can_install` 只许可安装受屏障保护的文件；旧任务、外部授权、宿主机可达性、保持停用的自动化及运行配置应用仍须协调，不表示可激活。计划有效期最多 30 分钟，且不超过原接入期限。

计划以 root 0400 保存到 `DATA/agent/disaster-plans`，最多保留 128 项；原计划不可改写，修改映射使用新的计划 UUID，相同标识只查询原结果。查询返回历史计划、`expired` 及固定副本是否仍存在的 `publication_available`，不重新观测能力或续期；副本存在不替代安装前的散列核对。新建安装必须明确提供计划 ID/摘要、匹配的原接入批准，并通过计划准入；已保存安装意图的续办保留原计划绑定，不延长原安装期限。计划只准备隔离数据库中的期望修订，不替换业务文件、安装组件、执行 `nginx -t`、切换运行配置或解除屏障。

发布副本与助手暂存各最多两项活动计划；root 发布区配额 2 GiB、连同清理回执最多 128 项，单个数据库最多 512 MiB，配额及磁盘余量包含 Nginx 请求、复制暂存与事务日志。助手暂存位于 `DATA/staging/restore-plans/<计划UUID>`，正常结束会清理；中断后可显式续办清理。使用以下本机 root 命令清理指定计划的发布副本和助手暂存，不需要离线解密材料：

```sh
/PANEL_RUNTIME/current/nginxpanel backup-restore-plan-cleanup --data-dir /var/lib/nginxpanel --restore-operation <计划UUID>
```

已有安装意图或未结束执行记录时，须先完成原件补偿；不能通过清理副本绕过恢复事务。清理持久经过 `.cleaning-` 至 `.cleaned-`，可按原标识续办，保留 root 发布回执和原计划；不删除业务文件、目标原件、源修订或 Agent 历史。副本清理后原计划不可重新生成安装材料，修改映射或再次生成须使用新计划 UUID。

## 独立文件安装与补偿

接入并生成有效目标计划后，通过当前已批准程序执行以下本机 root 命令，操作标识沿用原准备/接入 UUID。安装标准输入最多 8 KiB，包含明确选择的 `adoption_sha256`（`backup-adoption` 的 `adoption.sha256`）、`plan_id`、`plan_sha256` 和原维护会话当前 `epoch`。补偿仅要求原接入摘要和当前 epoch；若同时提供计划标识/摘要，必须与原批准一致：

```sh
/PANEL_RUNTIME/current/nginxpanel backup-restore --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
/PANEL_RUNTIME/current/nginxpanel backup-restore-status --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
/PANEL_RUNTIME/current/nginxpanel backup-restore-rollback --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
```

安装先重新核对目标回退快照的完整认证、原停机、当前程序与目标资源，保存不可变安装意图，再保存独立 Agent 执行记录和写入屏障。屏障存在时不能启动业务进程、释放维护锁或清理接入材料。目标数据库、WAL、SHM、主密钥和管理 TLS 的实际原文件另存到 root 0700 的 `DATA/agent/disaster-restores/<UUID>/before`，固定副本为 root 0400；全部保留并持久记录 `installing` 后才允许修改业务文件。安装及原件保留区最多八项、2 GiB，磁盘预留同时包含原件、最大单项替换暂存和余量；达到上限停止，不删除既有恢复依据。

固定写入器先移除目标 WAL/SHM，安装密钥与入口 TLS，最后安装计划绑定的发布数据库；不会安装尚未映射的原准备数据库。重试逐项只接受原值或本次批准值，临时复制完成后再次检查目标漂移、核对散列并同步目录；发现外部变化停止覆盖。全项匹配后记录 `stage=files_installed`、`state=recovery_required`，仍保留 root 写入屏障、原持久停机和数据库内部恢复屏障。该结果仅表示文件安装，不表示 Nginx、宿主机依赖或完整恢复可用；状态查询返回最后持久执行记录。

`backup-restore` 只续办原摘要、原程序、原停机和原目标。接入期限内可继续未完成安装；期限到达不扩展授权，保留材料及屏障供查询或补偿。Agent 重启后须从原维护会话取得当前 epoch；首次审批 epoch 和安装意图保持不变。

`backup-restore-rollback` 先持久记录补偿方向，后续只能继续该方向。已提交 Nginx 子操作时，先按下节完成原运行补偿，再恢复业务文件；原数据库先恢复，再恢复匹配 WAL/SHM。不变更网络、第三方资源或 Agent 救援历史。原文件缺失、散列变化、外部漂移或补偿写入失败均保留屏障与 `recovery_required`。原值全部核对并持久保存 `files_compensated/rolled_back` 后，仅解除本操作的 root 写入屏障；原停机和维护授权仍保留，不能据此重放安装。尚未开始业务写入的准备阶段可核对原目标后结束补偿。补偿不依赖源暂存、离线解密材料或快照密钥；已接受的 Nginx 补偿也不读取原 `nginx.json`。原接入过期后仍可继续原补偿。补偿完成或最终激活成功后才允许受控清理接入副本，原安装意图、原件和执行历史继续保留。

## 恢复 Nginx 运行配置

文件安装完成后，通过本机 root 命令批准并推进原计划的 Nginx 应用；标准输入沿用安装的 `adoption_sha256`、`plan_id`、`plan_sha256` 与当前 `epoch`，必须明确提供原计划标识和摘要：

```sh
/PANEL_RUNTIME/current/nginxpanel backup-restore-apply --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
/PANEL_RUNTIME/current/nginxpanel backup-restore-runtime-status --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
```

root 在原恢复目录保存不可变 `runtime-apply.json`，绑定安装意图、计划摘要、批准时间和首次批准 epoch；既有批准不覆盖或续期。新运行操作仍受原安装期限约束。固定非 root 助手只向本机 Agent 传递原操作、计划摘要、当前 epoch 与方向；私有端点复用统一 Agent 返回封装，不接受配置原文、材料路径、私钥或新的执行选项。Agent 重新核对持久批准、原停机、当前程序、维护授权、写入屏障、已装文件散列及原运行部署；首次提交还要求目标能力与原计划一致。

执行复用已有 Nginx 候选生成、证书/预置模块核对、真实 `nginx -t`、原子切换、运行观察及回滚。子操作与新物理部署使用计划 UUID，独立记录关联原完整恢复 UUID；重复调用只推进或核对该子操作，不生成新候选。父阶段经过 `runtime_preparing`、`runtime_applying`，确认逻辑修订与物理部署均匹配后进入 `runtime_confirmed`；父状态始终为 `recovery_required`。查询只读取最后持久记录，不发起执行或宣称当前运行仍然匹配。Agent 重启先按已有执行记录处理未确认候选，不重新提交源请求；无法证明结果时保留恢复状态。

运行应用后仍使用 `backup-restore-rollback`，先持久保存 `runtime-rollback.json`；此后任何安装或应用重试均被拒绝。在途子操作未退出时返回待补偿状态，须以同一原操作和当前 epoch 再次调用。补偿经过 `runtime_compensating`，复用原 Nginx 回滚并观察原逻辑修订及物理部署；子操作确认 `rolled_back` 后，父阶段才能保存 `runtime_compensated` 并继续文件补偿。运行补偿失败或结果不明时不恢复业务文件、不解除屏障，允许继续原补偿。

运行应用阶段不更新数据库已生效修订、不重放源任务、不恢复外部授权或启动组件；原停机、root 写入屏障与数据库恢复屏障继续保留。须继续下节的数据对账，不能据 `runtime_confirmed` 启动业务。

## 恢复数据对账

确认原 Nginx 修订及物理部署后，使用本机 root 命令对账源任务与数据库生效状态。原维护、持久停机和写入屏障须保持有效：

```sh
/PANEL_RUNTIME/current/nginxpanel backup-restore-reconcile --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
```

标准输入最多 8 KiB，沿用原安装依据，并明确批准源任务的处理方式：

```json
{
  "adoption_sha256": "原接入摘要",
  "plan_id": "原计划UUID",
  "plan_sha256": "原计划摘要",
  "epoch": "当前维护epoch",
  "review": {
    "abandon_source_tasks": true,
    "preserve_target_access": true,
    "keep_automation_disabled": true,
    "external_effects_require_review": true
  }
}
```

源在途任务转为 `cancelled/restore_abandoned`，原任务、隔离表中的原状态/阶段/错误、源审计及执行材料继续保留。此结果只终止本地旧流程，不代表远端操作未执行或已补偿。未结束的源 ACME 注册/签发与迁移流程转为失败，并记录外部结果待核对；CA 账户、订单、证书和被阻止的 DNS 挑战记录不伪造撤销或清理。源凭据继续撤销、源节点连接与配对继续隔离，通知、续期、自动部署及定期备份继续停用；不发送远程请求、不清理第三方记录、不恢复源网络设置。

固定非 root 助手从原发布数据库生成独立副本，在同一事务内完成上述处理、写入计划对应的已生效修订、保存处理报告及独立审计；数据库内部恢复屏障仅转为 `reconciling`。生成前后均核对原 Nginx 成功记录与实际逻辑修订、物理部署。root 将对账意图、数据库及二次只读核对证明固定为原恢复目录中的 `reconcile.json`、`reconciled.db`、`reconciled-proof.json`，均为 root 0400；root 不解析 SQL。

二次核对通过两份 root 只读数据库投影，以内置变更规则逐表、按主键逐行核对全部记录；源历史、密钥、配置、授权隔离、审计和其他未批准字段须保持一致。表最多 128 张、每表最多 64 列，使用受限缓存和现有助手期限；单份对账数据库仍不超过 512 MiB，副本计入原件保留区的 2 GiB 配额及磁盘预留。未核对的副本不能成为业务文件。

独立执行记录先保存 `data_reconciling/recovery_required`，再以固定散列原子替换数据库，全部目标文件匹配后保存 `data_reconciled/recovery_required`。新的对账意图和核对批准须在原安装期限内保存；重复调用使用原意图和固定副本，不修改处理策略或延长期限。复制中断优先续用原暂存或已固定副本；两者均缺失时停止并保留原批准，不重新猜测产物。已批准的安装可按原事务续办。

`backup-restore-runtime-status` 同时返回对账摘要和 `reconciliation_approved`；该字段只表示核对证明已保存，不表示副本已安装、当前运行仍匹配或完整恢复已经成功。补偿继续使用 `backup-restore-rollback`，先恢复原 Nginx，再恢复数据库/WAL/SHM/密钥/TLS 原件；原始安装与对账后的数据库都必须匹配已批准散列，外部变化阻止覆盖。补偿不依赖源数据库、对账副本内容或原归档重新解密，意图、证明与审计仍保留。

对账完成仍不能直接启动业务或释放维护。root 写入屏障、持久停机和数据库 `reconciling` 屏障继续保留，须显式执行下节激活；外部结果的人工复核继续保留。


## 最终激活

对账完成后，以原维护的当前 epoch 调用本机 root 入口：

```sh
/PANEL_RUNTIME/current/nginxpanel backup-restore-activate --data-dir /var/lib/nginxpanel --restore-operation <原接入UUID>
```

标准输入最多 8 KiB，必须指定对账摘要并接受不可回退提交：

```json
{
  "adoption_sha256": "原接入摘要",
  "plan_id": "原计划UUID",
  "plan_sha256": "原计划摘要",
  "epoch": "原维护当前epoch",
  "reconciliation_sha256": "原对账规范JSON的SHA256",
  "accept_activation_commit": true
}
```

`backup-restore-runtime-status` 增加 `reconciliation_sha256`、`activation`、`activation_approved`；查询沿用持久材料，不启动执行。激活前须核对目标地址、映射、证书及对账报告；高风险网络变更、第三方结果和源授权仍须独立复核。

固定非 root 助手从原发布副本重建已批准对账，再仅将原恢复屏障标记为 completed、加入目标原维护会话及维护任务、保存激活报告和审计。第二次非 root 只读核对复用逐表主键比较，源历史及其他字段须完全匹配。目标维护 UUID 若与源记录冲突则失败，不覆盖源历史。源自动化、授权、任务及外部流程仍保持对账后的隔离状态。

root 先固定 `activate.json`、`activated.db` 和 `activated-proof.json`，存入原 `DATA/agent/disaster-restores/<恢复UUID>`；文件 root 0400、目录 root 0700，数据库最多 512 MiB，计入原 2 GiB 配额及磁盘预留。新增意图和证明不得越过原安装期限；重试沿用原启动 UUID、摘要和副本，不能修改策略或延长期限。已批准的副本在提交前仍重新只读核对运行状态。

父事务持久保存 `activation_committed/recovery_required` 后，才能原子安装完成数据库。**这是允许恢复数据进入写入阶段的不可回退边界**：此后所有重试只续办原激活，`backup-restore`、运行重新应用及 `backup-restore-rollback` 均拒绝；不得用旧快照覆盖可能出现的新数据。激活提交之前仍可沿原补偿路径恢复目标。提交后安装、启动或就绪失败保留 `recovery_required` 和原维护授权，修复真实故障后续办原命令，不伪造整体成功。

安装完成后，启动子记录嵌入父事务，沿用原停机、运行绑定及批准程序；先保存启动意图，再仅解除本操作的 root 写入屏障和原停机标记，通过已有 native/systemd 或 Docker launcher 控制面板。完成数据库自带目标原维护会话，业务写入保持关闭；原 Nginx 运行与自动化停用状态不因面板启动而重放。启动边界之后不重新安装数据库或按旧固定数据库散列覆盖 WAL。

就绪检查核对原进程、数据库节点/版本、期望和已生效修订、Nginx 实际逻辑修订及物理部署、密钥/TLS、真实管理 HTTPS 和前端资源。全部通过后保存 `committed/waiting_confirmation`，只为原维护会话发布完成授权。应用维护服务仍须完成 Agent 锁释放及自身数据库会话/任务的持久释放；root 经专用只读 socket 核验应用释放与受信进程后，才保存 `committed/succeeded` 和释放证据。等待超时不回滚、不另建操作，查询或续办同一激活命令即可。

最终成功是已完成恢复的历史回执，不代表未来实时健康。原件、意图、核对证明、进程就绪及释放证据继续保留；清理源接入或原发布材料须使用已有受控清理命令，不删除独立 Agent 审计。真实恢复、故障中断与重启续办尚待 P5 集中验证。
