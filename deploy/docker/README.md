# Docker 部署产物

## Nginx 固定模块镜像

```sh
docker build -f deploy/docker/nginx.Dockerfile -t nginxpanel-nginx:1.30.6 .
```

基础镜像固定为官方 `nginx:1.30.6-alpine-slim` 的多架构摘要；构建时检查静态 HTTP/TLS/realip、Stream/TLS/realip/SSL preread，以及 ACL、基础 WAF、JSON 日志和 HTTP-01 依赖的默认模块。校验脚本发现版本、必需参数或默认模块不满足时中止镜像构建。

镜像提供 `/usr/share/nginxpanel/capabilities.json`、完整 `nginx -V` 输出及 Nginx 二进制 SHA-256。启动入口直接运行 Nginx，清除官方配置模板入口；启动时不下载、安装或编译模块。迁移执行仍以目标 Agent 的实际能力与 `nginx -t` 为准，不能把静态清单当作运行确认。

修改模块集合须重新构建并发布镜像；运行环境缺失模块时更换包含对应能力的受信镜像，重新生成迁移计划。镜像不携带源节点二进制、动态模块或业务秘密。

Nginx 镜像尚未执行构建、启动或 ABI 验证。容器 Nginx 的固定实例执行适配及镜像签名发布仍待完成；目前面板容器接入宿主机 Agent，可管理其原生专用 Nginx。

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
  --panel-image 'ghcr.io/<owner>/nginxpanel-runtime:0.1.0@sha256:<image-digest>' \
  --start
```

该模式初始化专用用户、业务数据及权限，部署宿主机 Agent 和原生 Nginx 首次安装执行器，生成 `/etc/nginxpanel/docker/compose.yaml`，不登记原生 Web 服务。`--start` 只启用、启动宿主机服务；容器由管理员另行启动：

```sh
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml up -d
```

`--without-nginx` 可替换为原生安装器支持的本机程序或签名资产选择。此处仍是宿主机专用 Nginx；Nginx 容器接入尚未完成。没有安装 Nginx 时，迁移按原预检及显式授权首次安装流程处理。

持久卷内 `runtime/releases/<内容标识>/` 保存程序、前端逐文件清单及版本信息，`runtime/current` 指向已批准版本，`runtime/launcher.json` 固定镜像、launcher 散列、宿主机 UID/GID、IPC 组及初始监听。以上目录、清单和指针均由 root 持有；Web 仅写自己的业务目录及独立 launcher 运行目录。首次发布先完整复制、核对和同步，再发布指针；重试复核同一记录，不覆盖当前版本或改换部署意图。

launcher 仅以非 root 的容器 PID 1 运行，要求删除全部 capabilities，继承禁止提权策略，并关闭同 UID 的进程调试。每次启动或重启前核对当前程序、静态 ELF、协议及全部前端文件；不回退到镜像中另一份业务程序。serve 退出时 launcher 结束，由容器重启策略处理；停止先发送 TERM、等待最多 45 秒，再以 KILL 确认回收，旧进程未确认结束时不启动第二个业务写者。PID 1 统一回收包含孤儿在内的子进程。`started` 仅表示子进程已启动，应用健康、数据库迁移及升级成功仍须独立确认。

Compose 从程序内嵌的 `panel.compose.yaml` 模板生成，固定镜像摘要、host network、数字身份及 IPC 组，绑定整个数据目录和只读配置目录，不挂载 Docker Socket、不使用 privileged，也不单独绑定会被替换的 Socket inode。镜像根只读，临时目录有容量限制。当前要求 rootful Docker、保持宿主机 UID/GID 映射的独立 PID 命名空间；rootless 或用户命名空间重映射不满足本机 root 文件与对端身份合同。SELinux/AppArmor 组合仍待集中验收；模板不自动重标整个数据根或关闭安全策略。

## 宿主机固定控制接口

launcher 只在 `DATA/run/launcher/launcher.sock` 提供状态查询、原操作查询及重启当前 root 批准版本。只接受 UID 0 的 Unix 对端；宿主机客户端同时核对对端 UID、容器 PID 1 和执行文件散列。Web 无权调用控制接口；客户端不能选择可执行文件、前端目录、命令或进程号。

```sh
sudo /opt/nginxpanel/current/nginxpanel panel-runtime-status --data-dir /srv/nginxpanel
sudo /opt/nginxpanel/current/nginxpanel launcher-status --data-dir /srv/nginxpanel
sudo /opt/nginxpanel/current/nginxpanel launcher-restart --data-dir /srv/nginxpanel \
  --launcher-operation <new-uuid> --launcher-boot <observed-boot-uuid> \
  --launcher-release <approved-current-release-id>
sudo /opt/nginxpanel/current/nginxpanel launcher-operation --data-dir /srv/nginxpanel \
  --launcher-operation <original-uuid>
```

一次启动保留最多 64 个操作回执，同一操作 ID 的不同请求被拒绝。同一 boot ID 内重试返回原记录，容器重建改变 boot ID，原请求不可重新提交；调用方须核对真实运行版本，不能将断连、进程启动或回执缺失视为升级成功。控制客户端需要宿主机 root 的进程检查权限。当前尚未接入发布激活、独立更新/回滚 worker，UI 仅显示运行模式及版本。

本阶段只实施并审阅源码和配置，尚未运行镜像构建、安装器、launcher、Compose、服务、类型检查、lint 或测试，统一留待 P5 集中验证。
