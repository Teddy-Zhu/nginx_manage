# Docker 部署产物

完整安装步骤见[部署指南](../../docs/deployment.md#5b-docker-安装)，首次登录与业务操作见[使用手册](../../docs/user-guide.md)，日常服务和恢复见[运维文档](../../docs/operations.md)。本文保留镜像、来源和维护事务的详细约束；当前完成状态及暂缓事项以[进度清单](../../docs/progress.md)为准。

## 签名镜像下载

首次部署可由目标主机 root 使用已批准程序、固定发行信任和独立核对的清单 SHA-256 下载镜像：

```sh
/opt/approved/nginxpanel release-image-pull \
  --component panel-launcher \
  --release-manifest /root/offline/release-manifest.json \
  --release-signature /root/offline/release-manifest.sig \
  --release-manifest-sha256 <manifest-sha256>
```

配套 Nginx 镜像将 `--component` 改为 `nginx`。只从签名清单推导固定 GHCR 摘要及当前架构，当前支持公开发行包；不接受任意镜像或 Registry 凭据。固定信任为 `/etc/nginxpanel/release-trust.json`，预发布须显式 `--release-prerelease`。下载后核对实际镜像和签名启动器，不启动容器。中断不会切换运行版本；再次显式执行时先核对本地镜像，核对通过则复用。已有面板可在组件页完成签名面板准备后分别拉取镜像，再进入配置维护执行运行镜像替换。镜像下载、安装与运行切换分别授权，安装器和日常启动仍不隐式拉取。

## Nginx 固定模块镜像

```sh
docker build -f deploy/docker/nginx.Dockerfile --build-arg TARGETARCH=amd64 -t nginxpanel-nginx:1.30.6 .
```

基础镜像固定为官方 `nginx:1.30.6-alpine-slim` 的多架构摘要；构建时检查静态 HTTP/TLS/HTTP2/realip、Stream/TLS/realip/SSL preread，以及 ACL、基础 WAF、JSON 日志和 HTTP-01 依赖的默认模块。能力清单分别声明 HTTP proxy/cache/access/log/headers/geo/split_clients/charset/gzip、upstream hash/ip_hash/least_conn/keepalive/zone，以及 Stream map/access/log/geo/split_clients/连接限制/return/set、upstream hash/least_conn/zone；构建检查同步拒绝关闭对应默认模块的参数。校验脚本发现版本、必需参数或默认模块不满足时中止镜像构建。

镜像构建前由发行流程准备 `.release/binaries/nginxpanel-amd64`、`nginxpanel-arm64` 静态程序，以及对应的 `licenses-amd64/`、`licenses-arm64/` 项目和第三方许可文本；`TARGETARCH` 应与目标平台一致。镜像提供 `/usr/share/nginxpanel/capabilities.json`、完整 `nginx -V` 输出，以及 Nginx 和固定启动器的 SHA-256。清除官方配置模板入口；固定启动器核对宿主机登记后降权并 exec Nginx，启动时不下载、安装或编译模块。迁移执行仍以目标 Agent 的实际能力与 `nginx -t` 为准，不能把静态清单当作运行确认。

修改模块集合须重新构建并发布镜像；运行环境缺失模块时更换包含对应能力的受信镜像，重新生成迁移计划。镜像不携带源节点二进制、动态模块或业务秘密。

镜像构建、代理、防护、固定启动器及各系统部署的已运行范围见[运行矩阵](../../docs/support-matrix.md)和[验证记录](../../docs/validation.md)。固定实例执行适配、镜像摘要/OCI 证据签名发布及安装验签的流程见[固定镜像发行](../../docs/publishing.md#固定镜像发行)。本机管理员先使用上述签名镜像下载命令或按签名清单准备镜像；已有面板可从组件页显式拉取。安装器验证来源与本地内容，不隐式拉取镜像。

上游构建及模块参数参见 [Nginx 官方镜像源码](https://github.com/nginx/docker-nginx) 和 [Nginx 构建选项](https://nginx.org/en/docs/configure.html)。


## 固定 launcher 与持久面板版本

`panel.Dockerfile` 使用已有的静态 Go 发行程序作为固定 launcher，只从与 Nginx 相同摘要的基础阶段复制 CA 根证书，最终镜像不包含 shell、包管理器、Python 或 Nginx。构建上下文为 `.release/binaries`，包含发行流程生成的 `nginxpanel-amd64`、`nginxpanel-arm64`；镜像内 launcher 必须与宿主机批准的初始程序具有相同 SHA-256。程序必须为匹配架构的静态 ELF，Go 构建信息明确声明 `CGO_ENABLED=0`。

例如为 amd64 构建本地配方（正式发布仍须使用真实仓库和摘要）：

```sh
docker build -f deploy/docker/panel.Dockerfile --build-arg TARGETARCH=amd64 -t nginxpanel-runtime:0.1.0 .release/binaries
```

在宿主机使用[安装器](../native/README.md)首次部署：

```sh
sudo deploy/native/install.sh \
  --binary /root/nginxpanel-release/nginxpanel \
  --web-dir /root/nginxpanel-release/web \
  --without-nginx \
  --panel-mode docker \
  --panel-image 'ghcr.io/<owner>/<repo>/panel@sha256:<image-digest>' \
  --release-trust /etc/nginxpanel/release-trust.json \
  --release-manifest /opt/nginxpanel/offline/release-manifest.json \
  --release-signature /opt/nginxpanel/offline/release-manifest.sig \
  --start
```

该模式初始化专用用户、业务数据及权限，部署宿主机 Agent 和原生 Nginx 首次安装执行器，生成 `/etc/nginxpanel/docker/compose.yaml`，不登记原生 Web 服务。`--start` 只启用、启动宿主机服务；容器由管理员另行启动：

```sh
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml up -d
```

`--without-nginx` 可替换为原生安装器支持的本机程序或签名资产选择，以管理宿主机专用 Nginx。使用配套 Nginx 容器时，替换为 `--nginx-image 'ghcr.io/<owner>/<repo>/nginx@sha256:<image-digest>'`；镜像须由本机 root 预先准备到 Docker，不在安装器或普通运行中拉取。该分支生成同时包含 panel/nginx 的完整 Compose 和容器专用 Agent 参数，不登记原生 Nginx 或原生首次安装服务。没有安装 Nginx 时，迁移按原预检及显式授权首次安装流程处理。

管理入口默认监听全部网卡并随机选择空闲端口，使用机器公网或内网 IP 访问。`manage.sh info` 显示当前地址，`manage.sh set-port 23456` 修改并保存端口；运行中的面板容器会重启，已停止的保持停止，宿主机 Agent 与 Nginx 不重启。端口直接属于 host network，无需修改 Compose 端口映射。云安全组和防火墙需允许对应 TCP 端口。

## 安装来源与批准记录

Docker 安装必须提供 root 持有的发行清单和签名信封，以及独立配置的本机信任根。只接受签名清单中的完整 `repository@sha256:...` 引用，不接受标签别名或另一仓库中的相同摘要。预发布另需明确 `--release-prerelease`。

安装器在写入安装意图、创建账户或复制程序前调用 `panel-runtime-verify` 和按需 `nginx-container-verify`。它们与绑定入口复用验签逻辑，核对签名摘要引用、当前架构、镜像内容身份、实际镜像启动器内容和本机程序散列；面板还逐项核对签名发行中的前端文件，拒绝遗漏和额外文件。镜像读取通过无主机挂载、无网络且从不启动的临时元数据容器进行，清理失败不会报告验证成功。预检执行已认证程序的固定 `version` 命令，不启动服务。

安装意图 v9 固定发行清单散列，并通过 `--release-manifest-sha256` 绑定后续准入，防止预检与登记使用不同清单。`panel-runtime-bind`、`nginx-container-bind` 仍会重新核对实际材料并保存 root 只读的签名批准记录，包括仓库、版本、提交、签名 Key ID、清单/初始信任散列、平台摘要、程序散列和批准时间。普通 Web/API 不能提交镜像地址、信任根或批准时间。

镜像内容身份允许经典存储返回的签名平台 config 摘要，或 containerd 存储返回的签名引用目标摘要；同时仍须核对精确仓库引用、平台和启动器内容。运行绑定保存 Docker 实际返回的镜像 ID，后续运行、替换及恢复均须精确匹配该固定 ID。

新登记按当前时间检查清单有效期。已发布绑定的同计划续装按原批准时间重新验签，并使用当前本机公钥；增补无关公钥不改变原计划，撤销原签名公钥会阻止续装。未保存批准记录前已过期的材料不能作为新登记继续使用。续装仍需原始清单与签名，运行已有批准版本则不依赖离线输入文件或在线仓库。批准记录不替代实际启动、Nginx 生效确认和 P5 部署验收。

固定 Nginx 容器要求支持 API v1.47 的本机 rootful Docker、标准 `/run/docker.sock` 和不重映射的宿主机 UID/GID；具体 Engine/API 对应关系见 [Docker 官方版本矩阵](https://docs.docker.com/reference/api/engine/)。首次登记只检查本地不可变镜像，通过一个从未启动、随后删除的临时容器读取元数据；核对平台、镜像摘要、静态能力、程序及启动器散列后发布 root 只读 `bin/components/nginx-container.json`。与原生安装共用绑定锁，不能直接转换已有实例或替换已登记镜像。

Nginx 镜像的短期 root 启动器仅为切换身份获得 SETUID/SETGID/SETPCAP 和 NET_BIND_SERVICE；exec 前删除 root 身份及转换权限，只保留 NET_BIND_SERVICE 的 bounding/permitted/effective/inheritable/ambient 集合。实际 master/worker 使用独立宿主机 Nginx UID/GID；不修改宿主机低端口 sysctl。面板容器仍删除全部 capabilities。Nginx 的配置和证书只读挂载；私钥仅向独立 Nginx 组开放只读，Web 用户不加入该组；日志、临时目录及 `run/nginx` 单独可写，未挂载业务数据库或 Web 秘密目录。

宿主机 Agent 仅访问固定名称 `nginxpanel-nginx`，逐次核对镜像 ID、入口/参数、命名空间、挂载、只读根和权限；实际 master 必须为该容器 PID 1、专用非 root 身份、允许范围内的 capabilities 和已登记的 Nginx 程序散列。配置校验只在该实例经固定 `nginx-container-test` 启动器完成身份和能力切换，再以专用非 root 用户及 NET_BIND_SERVICE 执行固定 `nginx -t`，能力探测只执行 `nginx -V` 并与构建输出比较；中断诊断会尝试通过原 exec 回执、命名空间和 pidfd 确认结束。重载和日志 reopen 使用宿主机 pidfd，生效继续核对修订探针、监听归属及 TLS。容器在诊断期间重启或重建时校验失败；配置发布仍以完整的修订及监听/TLS 生效确认作为成功条件。Docker API 不暴露给 Web，两个容器都不挂载 Docker Socket。接口语义参见 [Docker Engine API v1.47](https://docs.docker.com/reference/api/engine/version/v1.47/)。

诊断前将原 exec ID、容器 ID、宿主机 boot ID、master 启动标识、Nginx 命令及按需启动器命令散列持久化到 `agent/nginx-container-exec.json`。恢复只查询/终止原诊断，不重新提交；终止前按降权阶段核对原进程的程序散列、UID/GID、能力范围、命名空间及固定命令。只有原 exec 终结或原 PID 1 命名空间已结束才清理回执。未确认开始、断连后状态不明或原回执无法取得时保持阻塞，不能继续配置校验或确认旧日志可清理。必要时须由本机管理员显式停止并重建该受管容器，以结束原命名空间后恢复，不能手工将超时标成成功。

持久卷内 `runtime/releases/<内容标识>/` 保存程序、前端逐文件清单及版本信息，`runtime/current` 指向已批准版本，`runtime/launcher.json` 固定镜像、launcher 散列、宿主机 UID/GID、IPC 组及初始监听。以上目录、清单和指针均由 root 持有；Web 仅写自己的业务目录及独立 launcher 运行目录。首次发布先完整复制、核对和同步，再发布指针；重试复核同一记录，不覆盖当前版本或改换部署意图。

launcher 仅以非 root 的容器 PID 1 运行，要求删除全部 capabilities，继承禁止提权策略，并关闭同 UID 的进程调试。每次启动或重启前核对当前程序、静态 ELF、协议及全部前端文件；不回退到镜像中另一份业务程序。serve 退出时 launcher 结束，由容器重启策略处理；停止先发送 TERM、等待最多 45 秒，再以 KILL 确认回收，旧进程未确认结束时不启动第二个业务写者。PID 1 统一回收包含孤儿在内的子进程。`started` 仅表示子进程已启动，应用健康、数据库迁移及升级成功仍须独立确认。

Compose 从程序内嵌的 `panel.compose.yaml` 模板生成，固定镜像摘要、host network、数字身份及 IPC 组，绑定整个数据目录和只读配置目录，不挂载 Docker Socket、不使用 privileged，也不单独绑定会被替换的 Socket inode。镜像根只读，临时目录有容量限制。当前要求 rootful Docker、保持宿主机 UID/GID 映射的独立 PID 命名空间；rootless 或用户命名空间重映射不满足本机 root 文件与对端身份合同。SELinux/AppArmor 的实际验收范围见[运行矩阵](../../docs/support-matrix.md)，其他组合仍待验收；模板不自动重标整个数据根或关闭安全策略。

SELinux 启用时，统一安装器登记共享数据的文件标签及 Agent 监听器的专用 socket 安全类型，使容器能够连接该监听器；策略来源、权限范围与重放检查见[SELinux 部署说明](../native/README.md#selinux-文件标签)。

## 宿主机固定控制接口

launcher 只在 `DATA/run/launcher/launcher.sock` 提供状态查询、原操作查询及固定的停止、启动和重启控制；控制协议为 2，更新流程通过独立 root 进程记录和维护授权调用。只接受 UID 0 的 Unix 对端；宿主机客户端同时核对对端 UID、容器 PID 1 和执行文件散列。Web 无权调用控制接口；客户端不能选择可执行文件、前端目录、命令或进程号。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-runtime-status --data-dir /srv/nginxpanel
sudo /opt/nginxpanel/current/nginxpanel launcher-status --data-dir /srv/nginxpanel
sudo /opt/nginxpanel/current/nginxpanel launcher-restart --data-dir /srv/nginxpanel \
  --launcher-operation <new-uuid> --launcher-boot <observed-boot-uuid> \
  --launcher-release <approved-current-release-id> --launcher-instance <observed-live-instance-uuid>
sudo /opt/nginxpanel/current/nginxpanel launcher-operation --data-dir /srv/nginxpanel \
  --launcher-operation <original-uuid>
```

一次启动保留最多 64 个操作回执，同一操作 ID 的不同请求被拒绝。同一 boot ID 内重试返回原记录，容器重建改变 boot ID，原请求不能原样派发到新启动；独立进程维护记录先查询实际状态，再记录新的启动身份，并保留最多四次派发。运行实例另有 UUID，停止或重启须匹配观测的实例。root 持久停机标记存在时 launcher 保持控制入口在线并不启动 serve，容器重建也保留停机状态。标记及维护释放由独立 root 事务核对，生命周期入口见 [发行说明](../../docs/releases.md#面板进程维护)。控制客户端需要宿主机 root 的进程检查权限。持久版本选择、面板进程维护、独立更新/回滚 worker、readiness、维护释放与恢复材料清理及网页/API 更新任务均通过对应维护入口执行。

已运行的镜像、部署和维护事务范围以[验证记录](../../docs/validation.md)为准，未覆盖组合及暂缓事项以[进度清单](../../docs/progress.md)为准。

## 面板容器与 launcher 对端核对

每次宿主机 launcher 查询或控制均通过固定 `/run/docker.sock` 的 Docker API v1.47 读取 `nginxpanel` 容器，核对签名批准中的实际镜像 ID、完整摘要引用、固定入口/参数、数字身份、IPC 附加组及数据工作目录；Compose 显式设置工作目录，不依赖镜像默认目录。容器必须保持 host network、独立 PID/挂载命名空间、只读根、全部 capabilities 删除、禁止提权、固定进程及临时空间限制和 `unless-stopped` 重启策略。只接受同路径的业务数据可写 bind 与 `/etc/nginxpanel` 只读 bind，拒绝额外挂载、设备、容器共享、特权、交互入口或健康检查进程。

实际容器主 PID 必须等于 Unix Socket 内核给出的对端 PID。客户端继续从宿主机核对进程完整 UID/GID、附加组、capabilities、禁止提权、PID 1、用户映射、命名空间、实际参数和签名程序散列。响应读取后再次核对容器 ID、启动时间、重启计数、进程及程序 inode/元数据；连接期间发生重启、重建、程序或运行绑定变化时拒绝响应，结果不明的动作继续按原操作查询。核对只读取容器和内核信息，不创建容器、不执行诊断进程或拉取镜像；Docker Socket 仍只供宿主机 root 使用。字段语义见 [Docker Engine API v1.47](https://docs.docker.com/reference/api/engine/version/v1.47/)。

固定 launcher 镜像支持宿主机 root 发起的独立替换事务。先持有原维护会话、完成同一签名发行的面板资源准备，并将新旧镜像按摘要保留在目标主机；命令不拉取镜像。替换只改变容器镜像和 launcher 批准，当前应用、前端选择、数据库、身份、数据目录及监听地址保持原值。该事务可先更新 launcher 协议，原应用继续运行；需要更新应用和 Agent 时，再使用面板协调更新。Nginx 镜像由独立入口替换。

```sh
# 以下命令只在实际部署的目标主机执行。UUID、epoch、准备计划和摘要均须使用实际值。
/opt/nginxpanel/current/nginxpanel panel-image --data-dir /srv/nginxpanel \
  --panel-image <operation-uuid> --maintenance-id <maintenance-uuid> --maintenance-epoch <epoch> \
  --release-plan <signed-panel-plan-sha256> --allow-downtime \
  --image ghcr.io/<owner>/nginxpanel-runtime@sha256:<digest> \
  --image-manifest /root/offline/release-manifest.json \
  --image-signature /root/offline/release-manifest.sig \
  --image-manifest-sha256 <manifest-sha256>
/opt/nginxpanel/current/nginxpanel panel-image-status --data-dir /srv/nginxpanel --panel-image <operation-uuid>
```

固定发布信任为 `/etc/nginxpanel/release-trust.json`，预发布需显式添加 `--release-prerelease`。普通应用更新与镜像替换分别管理。网页“运行镜像”及 `/api/v1/panel/images/upgrades` 已接入同一独立 worker，创建仅引用已完成的面板准备任务与原维护会话，镜像摘要和离线文件位置从 root 签名计划推导，不能在请求中指定任意镜像地址、路径或信任。安装器登记 `nginxpanel-image@.service`；独立 root worker 在持久意图发布后停止、删除原固定实例，切换 root 只读绑定与生成的 Compose，再按固定权限策略重建并检查实际容器、应用、HTTPS、原配置和维护身份。Compose 项目标签及容器标签随事务保留；以后运行 Compose 可能按其配置散列再次重建，仍须使用生成的摘要引用。禁止强制删除、删除原镜像、指定任意 Docker 地址或接管同名未知容器。

前进期限固定为授权后十分钟。失败先持久记录恢复方向，再使用保留的原镜像恢复；恢复不依赖目标签名文件或目标公钥继续可用，不恢复或覆盖业务数据库。若原容器尚未改变且仍就绪，直接确认原实例。未确认的结果保留 `recovery_required`，继续阻止维护释放。进程停止后只能使用原 UUID 显式续办，不重新创建任务；续办不延长期限，也不反转恢复方向。Agent 重启后，可通过 `panel-image-probe --data-dir /srv/nginxpanel --maintenance-id <maintenance-uuid>` 以登记账户重新确认原维护会话，再将返回的 epoch 传给 `panel-image-resume --data-dir /srv/nginxpanel --panel-image <operation-uuid> --maintenance-epoch <epoch>`。若主机重启使原容器产生新的运行代次，只有显式续办能够登记该代次，并转为确认或恢复原镜像。事务成功或完整恢复后，仍由原维护流程显式释放维护会话。

网页/API 创建持久任务并在 IPC 前记录派发；断连后仅查询原事务，服务停止须以新幂等键显式续办。root 启动授权按连续序号保存且只领取一次，普通 CLI 不能绕过托管任务续办。若容器不可用导致网页无法访问，先用 `panel-image-probe` 核对原维护会话，再执行 `panel-image-rescue --data-dir /srv/nginxpanel --panel-image <operation-uuid> --maintenance-epoch <epoch>`，以 `local-root` 记录追加同一事务的救援授权；页面恢复后会对账该结果，不新建或重放任务。

本轮仅完成实现与源码审阅，未在开发主机调用 Docker、launcher 或修改部署环境；实际容器字段、权限、重建与恢复故障场景待 P5 隔离集中验证。


## Nginx 容器镜像切换

目标主机首次安装时登记独立 `nginxpanel-nginx-image@.service`。本机 root 使用以下入口切换已运行的固定 Nginx 容器；网页“Nginx 镜像”与 API 通过同一独立事务管理切换。

```sh
/opt/nginxpanel/current/nginxpanel nginx-image --data-dir /srv/nginxpanel \
  --nginx-image-operation <operation-uuid> --maintenance-id <maintenance-uuid> \
  --maintenance-epoch <epoch> --allow-downtime \
  --release-plan <signed-panel-plan-sha256> \
  --image ghcr.io/<owner>/<repository>/nginx@sha256:<digest> \
  --image-manifest /root/offline/release-manifest.json \
  --image-signature /root/offline/release-manifest.sig \
  --image-manifest-sha256 <manifest-sha256>
/opt/nginxpanel/current/nginxpanel nginx-image-status --data-dir /srv/nginxpanel \
  --nginx-image-operation <operation-uuid>
/opt/nginxpanel/current/nginxpanel nginx-image-resume --data-dir /srv/nginxpanel \
  --nginx-image-operation <operation-uuid> --maintenance-epoch <epoch>
```

准备计划和 Nginx 镜像须属于同一签名发行，新旧镜像都须保留在本地；该命令不拉取镜像，不编译或增装模块。必须持有原维护会话并明确允许中断。独立任务先由候选镜像的固定启动器完成同样的降权，再用非 root Nginx 程序对冻结的完整发布执行 `nginx -t`，通过后才停止 Agent 和原 Nginx。之后切换 root 只读 Compose 与 Nginx 绑定、按固定权限重建容器，并在重启 Agent 前释放 Nginx 执行锁。完成确认覆盖容器代次、实际 Nginx 程序、原配置/监听/TLS 探针、Agent 实际进程、组件镜像来源和原维护会话；应用、前端、数据目录和业务数据库保持原选择。

前进期限自原授权起十分钟，失败先持久确定恢复方向，再核对并恢复保留的原镜像；恢复不依赖目标离线文件或目标公钥。候选配置未通过且尚未停机时，只清理本次校验容器并确认原服务。未知实例、外部修改、失联或未确认结果保留 `recovery_required` 并阻止维护释放，不能强制接管同名容器。创建和启动意图在 Docker 调用前持久保存，已派发但未确认的动作不重复执行；续办只能使用原 UUID、输入和期限。主机重启后的原容器新代次仅能通过显式续办登记，并永久转为原镜像恢复。Agent 运行时可用 `panel-image-probe` 核对原维护会话的当前 epoch；Agent 尚未恢复时沿用该事务最后持有的维护 epoch。只有成功或完整恢复并确认后，才由原维护流程释放会话。


网页/API 创建仅引用已完成的签名面板准备任务和原维护会话：`POST /api/v1/nginx/images/upgrades` 的请求为 `{ "maintenance_id": "<uuid>", "prepare_task_id": "<uuid>", "allow_downtime": true }`。请求须具备组件管理、系统写权限、重新认证与幂等键；镜像地址、签名路径、平台和信任配置由目标节点的 root 准备计划确定。列表、单项查询和原任务续办分别使用同一路径的 GET、`/{id}` 和 `/{id}/resume`，远程节点提供对应显式路由。应用更新、Agent 升级及两种镜像切换共用活动任务约束。

派发前持久保存加密任务、启动授权和审计，断连后只查询原操作；续办须使用新幂等键并追加连续授权。每项 root 授权只领取一次，最多 32 项，Agent 重启后按原维护会话核对新的 epoch。普通本机续办不能绕过托管授权；网页或 Agent 不可用时，root 可执行 `nginx-image-rescue --data-dir /srv/nginxpanel --nginx-image-operation <operation-uuid> --maintenance-epoch <epoch>`，以 `local-root` 为原事务追加救援授权。网页恢复后对账实际结果，不重放已提交动作。从备份恢复的源任务保持隔离，不在目标节点启动或续办。

## 面板与宿主 Agent 协调更新

目标 Agent 协议变化时，可在面板更新页选择“同时更新 Agent”并确认停机；API 沿用 `POST /api/v1/panel/updates`，增加 `coordinate_agent: true` 和 `allow_downtime: true`。必须先完成签名面板准备、进入维护，并满足已安装 launcher 与目标准备协议一致及发布允许自动回滚的条件。原生部署无需 launcher 镜像。镜像和 Nginx 不随此操作替换。

本机 root 可使用同一独立 systemd 更新服务。初次受理指定新 UUID；恢复只引用原 UUID，不修改目标、不延长原前进期限。省略 epoch 时读取原维护记录的当前 epoch。服务结果不明时先查询，不重复初次命令。

```sh
sudo /opt/nginxpanel/current/nginxpanel deployment-upgrade --data-dir /srv/nginxpanel \
  --operation-id <new-uuid> --release-plan <prepared-plan-sha256> \
  --maintenance-id <held-maintenance-uuid> --allow-downtime
sudo /opt/nginxpanel/current/nginxpanel deployment-upgrade-status --data-dir /srv/nginxpanel \
  --operation-id <original-uuid>
sudo /opt/nginxpanel/current/nginxpanel deployment-upgrade-resume --data-dir /srv/nginxpanel \
  --operation-id <original-uuid>
```

目标程序在停机前只读检查持久日志。切换后通过对应程序自身的非 root 辅助入口核对 Agent 协议、进程和原维护会话，再确认面板数据库、前端及 HTTPS；维护释放前失败沿原快照补偿。Agent 不可用或主机重启后可从本机续办；新 boot 代次的 root 救援只恢复原版本。服务定义、程序或进程身份偏离时保留恢复依据，要求本机核对。跨 launcher 协议先完成上述运行镜像替换。此流程尚待 P5 隔离运行验收。

运行镜像替换前会核对目标签名程序提供的固定桥接契约。新 launcher 就绪后，由对应的已批准程序处理其协议；原面板与原 Agent 无需提前切换。页面更换运行镜像时须确认管理服务中断，跨协议 API 请求须传入 `allow_downtime: true`。镜像事务独立确认原应用、配置及 HTTPS 后结束；随后应用/Agent 更新失败只恢复其原应用与 Agent，已确认的运行镜像保留。两步均完成后再释放原维护会话。
