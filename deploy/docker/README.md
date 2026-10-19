# Docker 部署产物

## Nginx 固定模块镜像

```sh
docker build -f deploy/docker/nginx.Dockerfile --build-arg TARGETARCH=amd64 -t nginxpanel-nginx:1.30.6 .
```

基础镜像固定为官方 `nginx:1.30.6-alpine-slim` 的多架构摘要；构建时检查静态 HTTP/TLS/HTTP2/realip、Stream/TLS/realip/SSL preread，以及 ACL、基础 WAF、JSON 日志和 HTTP-01 依赖的默认模块。能力清单分别声明 HTTP proxy/cache/access/log/headers/geo/split_clients/charset/gzip、upstream hash/ip_hash/least_conn/keepalive/zone，以及 Stream map/access/log/geo/split_clients/连接限制/return/set、upstream hash/least_conn/zone；构建检查同步拒绝关闭对应默认模块的参数。校验脚本发现版本、必需参数或默认模块不满足时中止镜像构建。

镜像构建前由发行流程准备 `.release/binaries/nginxpanel-amd64`、`nginxpanel-arm64` 静态程序，以及对应的 `licenses-amd64/`、`licenses-arm64/` 项目和第三方许可文本；`TARGETARCH` 应与目标平台一致。镜像提供 `/usr/share/nginxpanel/capabilities.json`、完整 `nginx -V` 输出，以及 Nginx 和固定启动器的 SHA-256。清除官方配置模板入口；固定启动器核对宿主机登记后降权并 exec Nginx，启动时不下载、安装或编译模块。迁移执行仍以目标 Agent 的实际能力与 `nginx -t` 为准，不能把静态清单当作运行确认。

修改模块集合须重新构建并发布镜像；运行环境缺失模块时更换包含对应能力的受信镜像，重新生成迁移计划。镜像不携带源节点二进制、动态模块或业务秘密。

Nginx 镜像尚未执行构建、启动或 ABI 验证。固定实例执行适配、镜像摘要/OCI 证据签名发布及安装验签已接入源码，流程见 [固定镜像发行](../../docs/publishing.md#固定镜像发行)；真实构建、发布与系统验证仍待 P5。本机管理员先按签名清单准备镜像，安装器自动验证来源与本地内容，不负责拉取镜像。

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

## 安装来源与批准记录

Docker 安装必须提供 root 持有的发行清单和签名信封，以及独立配置的本机信任根。只接受签名清单中的完整 `repository@sha256:...` 引用，不接受标签别名或另一仓库中的相同摘要。预发布另需明确 `--release-prerelease`。

安装器在写入安装意图、创建账户或复制程序前调用 `panel-runtime-verify` 和按需 `nginx-container-verify`。它们与绑定入口复用验签逻辑，核对当前架构的镜像 config 摘要、实际镜像启动器内容和本机程序散列；面板还逐项核对签名发行中的前端文件，拒绝遗漏和额外文件。镜像读取通过无主机挂载、无网络且从不启动的临时元数据容器进行，清理失败不会报告验证成功。预检执行已认证程序的固定 `version` 命令，不启动服务。

安装意图 v9 固定发行清单散列，并通过 `--release-manifest-sha256` 绑定后续准入，防止预检与登记使用不同清单。`panel-runtime-bind`、`nginx-container-bind` 仍会重新核对实际材料并保存 root 只读的签名批准记录，包括仓库、版本、提交、签名 Key ID、清单/初始信任散列、平台摘要、程序散列和批准时间。普通 Web/API 不能提交镜像地址、信任根或批准时间。

新登记按当前时间检查清单有效期。已发布绑定的同计划续装按原批准时间重新验签，并使用当前本机公钥；增补无关公钥不改变原计划，撤销原签名公钥会阻止续装。未保存批准记录前已过期的材料不能作为新登记继续使用。续装仍需原始清单与签名，运行已有批准版本则不依赖离线输入文件或在线仓库。批准记录不替代实际启动、Nginx 生效确认和 P5 部署验收。

固定 Nginx 容器要求支持 API v1.47 的本机 rootful Docker、标准 `/run/docker.sock` 和不重映射的宿主机 UID/GID；具体 Engine/API 对应关系见 [Docker 官方版本矩阵](https://docs.docker.com/reference/api/engine/)。首次登记只检查本地不可变镜像，通过一个从未启动、随后删除的临时容器读取元数据；核对平台、镜像摘要、静态能力、程序及启动器散列后发布 root 只读 `bin/components/nginx-container.json`。与原生安装共用绑定锁，不能直接转换已有实例或替换已登记镜像。

Nginx 镜像的短期 root 启动器仅为切换身份获得 SETUID/SETGID/SETPCAP 和 NET_BIND_SERVICE；exec 前删除 root 身份及转换权限，只保留 NET_BIND_SERVICE 的 bounding/permitted/effective/inheritable/ambient 集合。实际 master/worker 使用独立宿主机 Nginx UID/GID；不修改宿主机低端口 sysctl。面板容器仍删除全部 capabilities。Nginx 的配置和证书只读挂载；私钥仅向独立 Nginx 组开放只读，Web 用户不加入该组；日志、临时目录及 `run/nginx` 单独可写，未挂载业务数据库或 Web 秘密目录。

宿主机 Agent 仅访问固定名称 `nginxpanel-nginx`，逐次核对镜像 ID、入口/参数、命名空间、挂载、只读根和权限；实际 master 必须为该容器 PID 1、专用非 root 身份、允许范围内的 capabilities 和已登记的 Nginx 程序散列。配置校验只在该实例执行固定 `nginx -t`，能力探测只执行 `nginx -V` 并与构建输出比较；中断诊断会尝试通过原 exec 回执、命名空间和 pidfd 确认结束。重载和日志 reopen 使用宿主机 pidfd，生效继续核对修订探针、监听归属及 TLS。容器在诊断期间重启或重建时校验失败；配置发布仍以完整的修订及监听/TLS 生效确认作为成功条件。Docker API 不暴露给 Web，两个容器都不挂载 Docker Socket。接口语义参见 [Docker Engine API v1.47](https://docs.docker.com/reference/api/engine/version/v1.47/)。

诊断前将原 exec ID、容器 ID、宿主机 boot ID 和 master 启动标识持久化到 `agent/nginx-container-exec.json`。恢复只查询/终止原诊断，不重新提交；只有原 exec 终结或原 PID 1 命名空间已结束才清理回执。未确认开始、断连后状态不明或原回执无法取得时保持阻塞，不能继续配置校验或确认旧日志可清理。必要时须由本机管理员显式停止并重建该受管容器，以结束原命名空间后恢复，不能手工将超时标成成功。

持久卷内 `runtime/releases/<内容标识>/` 保存程序、前端逐文件清单及版本信息，`runtime/current` 指向已批准版本，`runtime/launcher.json` 固定镜像、launcher 散列、宿主机 UID/GID、IPC 组及初始监听。以上目录、清单和指针均由 root 持有；Web 仅写自己的业务目录及独立 launcher 运行目录。首次发布先完整复制、核对和同步，再发布指针；重试复核同一记录，不覆盖当前版本或改换部署意图。

launcher 仅以非 root 的容器 PID 1 运行，要求删除全部 capabilities，继承禁止提权策略，并关闭同 UID 的进程调试。每次启动或重启前核对当前程序、静态 ELF、协议及全部前端文件；不回退到镜像中另一份业务程序。serve 退出时 launcher 结束，由容器重启策略处理；停止先发送 TERM、等待最多 45 秒，再以 KILL 确认回收，旧进程未确认结束时不启动第二个业务写者。PID 1 统一回收包含孤儿在内的子进程。`started` 仅表示子进程已启动，应用健康、数据库迁移及升级成功仍须独立确认。

Compose 从程序内嵌的 `panel.compose.yaml` 模板生成，固定镜像摘要、host network、数字身份及 IPC 组，绑定整个数据目录和只读配置目录，不挂载 Docker Socket、不使用 privileged，也不单独绑定会被替换的 Socket inode。镜像根只读，临时目录有容量限制。当前要求 rootful Docker、保持宿主机 UID/GID 映射的独立 PID 命名空间；rootless 或用户命名空间重映射不满足本机 root 文件与对端身份合同。SELinux/AppArmor 组合仍待集中验收；模板不自动重标整个数据根或关闭安全策略。

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

一次启动保留最多 64 个操作回执，同一操作 ID 的不同请求被拒绝。同一 boot ID 内重试返回原记录，容器重建改变 boot ID，原请求不能原样派发到新启动；独立进程维护记录先查询实际状态，再记录新的启动身份，并保留最多四次派发。运行实例另有 UUID，停止或重启须匹配观测的实例。root 持久停机标记存在时 launcher 保持控制入口在线并不启动 serve，容器重建也保留停机状态。标记及维护释放由独立 root 事务核对，生命周期入口见 [发行说明](../../docs/releases.md#面板进程维护)。控制客户端需要宿主机 root 的进程检查权限。持久版本选择、面板进程维护、独立更新/回滚 worker、readiness、维护释放与恢复材料清理及网页/API 更新任务已接入源码，仍待 P5 集中验证。

本阶段只实施并审阅源码和配置，尚未运行镜像构建、安装器、launcher、Compose、服务、类型检查、lint 或测试，统一留待 P5 集中验证。

## 面板容器与 launcher 对端核对

每次宿主机 launcher 查询或控制均通过固定 `/run/docker.sock` 的 Docker API v1.47 读取 `nginxpanel` 容器，核对签名批准中的实际镜像 ID、完整摘要引用、固定入口/参数、数字身份、IPC 附加组及数据工作目录；Compose 显式设置工作目录，不依赖镜像默认目录。容器必须保持 host network、独立 PID/挂载命名空间、只读根、全部 capabilities 删除、禁止提权、固定进程及临时空间限制和 `unless-stopped` 重启策略。只接受同路径的业务数据可写 bind 与 `/etc/nginxpanel` 只读 bind，拒绝额外挂载、设备、容器共享、特权、交互入口或健康检查进程。

实际容器主 PID 必须等于 Unix Socket 内核给出的对端 PID。客户端继续从宿主机核对进程完整 UID/GID、附加组、capabilities、禁止提权、PID 1、用户映射、命名空间、实际参数和签名程序散列。响应读取后再次核对容器 ID、启动时间、重启计数、进程及程序 inode/元数据；连接期间发生重启、重建、程序或运行绑定变化时拒绝响应，结果不明的动作继续按原操作查询。核对只读取容器和内核信息，不创建容器、不执行诊断进程或拉取镜像；Docker Socket 仍只供宿主机 root 使用。字段语义见 [Docker Engine API v1.47](https://docs.docker.com/reference/api/engine/version/v1.47/)。

固定 launcher 镜像的受控替换及补偿流程尚待接入，不能直接修改已批准绑定或将镜像标签替换视为受管升级完成。本轮仅完成实现与源码审阅，未在开发主机调用 Docker、launcher 或修改部署环境；实际容器字段、权限与重建故障场景待 P5 隔离集中验证。
