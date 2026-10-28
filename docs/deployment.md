# 部署指南

[文档首页](README.md) · [使用手册](user-guide.md) · [运维与故障处理](operations.md)

## 1. 运行组成

宿主机仅运行必要权限的 Agent。管理面板、Nginx、Fail2ban、FRP 和第三方应用均使用 Docker；配置、数据库、证书和日志通过目录挂载持久化。Docker 引擎和操作系统原有网络服务仍由宿主机管理。

默认只安装面板、Agent 和 Nginx。Fail2ban、FRP 及第三方软件需在软件商店手动安装。Nginx 常用模块在镜像构建时预置，安装和运行时不在宿主机编译 Nginx，也不动态安装模块。面板容器不获得 Docker 套接字或宿主机 root 权限；相关操作交给 Agent。

## 2. 环境要求

- 使用 systemd 的 Linux，支持 amd64、arm64，需要部署目标的 root 权限。
- 本机 rootful Docker、Compose 插件，以及常规 GNU 系统工具；不使用远程 Docker context、rootless Docker 或 Swarm。
- 源码安装另需 Git 和 Docker BuildKit；编译不依赖宿主机 Go、Node.js、pnpm 或 Nginx。
- Release 安装需 curl，或已认证的 GitHub CLI，以及 tar/gzip。Release 包已包含运行镜像，不需要访问镜像仓库才能启动面板和 Nginx。

安装器检测不到 Docker 或配套镜像时会明确报错，不回退为宿主机应用部署。开发过程中不要在开发主机执行安装器；需要部署验证时使用独立虚拟机。

## 3. 一键安装

下例 `OWNER/REPO` 替换为实际仓库，在部署目标执行。

### 从源码安装

```sh
git clone https://github.com/OWNER/REPO.git nginxpanel
cd nginxpanel
sudo bash install.sh --yes
```

脚本在 Docker 中构建程序和前端，生成面板、Nginx 镜像及内容清单，自动导入镜像并安装。也可先构建，再把安装包传到目标：

```sh
bash scripts/build.sh --output-dir dist
# 在目标机器解压 dist/nginxpanel-linux-<架构>.tar 后执行：
sudo bash install.sh --yes
```

默认检测当前架构；为其他架构构建时使用 `--arch arm64` 或 `--arch amd64`，构建环境须能执行对应架构的容器。

### 使用 Release 安装

```sh
curl -fL https://github.com/OWNER/REPO/releases/latest/download/setup.sh -o nginxpanel-setup.sh
bash nginxpanel-setup.sh --yes
```

脚本自动选择架构并核对下载校验值。私有仓库使用已认证的 `gh` 或环境中的 `GH_TOKEN` / `GITHUB_TOKEN`。安装包同时包含入口脚本、程序、前端和运行镜像；不完整的旧包会明确拒绝。

如需通过下载脚本拉取源码构建，使用 `bash nginxpanel-setup.sh --source --yes`。入口脚本的首次信任来自选定仓库；后续在线更新继续使用本机批准的发行源和签名校验。

### 安装选项

- `--yes`：按检测结果安装。省略后先核对安装摘要。
- `--port 23456`：指定管理端口；省略时随机选择空闲端口，重启后保持。
- `--protocol http`：使用 HTTP；默认 HTTPS。浏览器调试可选择 HTTP。
- `--advanced`：调整数据目录、监听地址和主机网络管理设置，不改变应用的 Docker 部署方式。

默认监听全部网卡，可使用公网或内网地址访问。数据目录优先 `/srv/nginxpanel`，不可用时尝试 `/var/lib/nginxpanel`；已有数据不会被首次安装覆盖。DNS、防火墙和 SSH 保护自动识别，无法可靠确认的环境保持只读；不接管已有系统 Nginx 服务或清空防火墙规则。

## 4. 数据与开机启动

| 位置 | 用途 |
| --- | --- |
| `/opt/nginxpanel/` | Agent、安装器及恢复材料 |
| `/etc/nginxpanel/` | 安装记录、信任配置及生成的 Compose |
| `/srv/nginxpanel/` | 外部持久化数据，具体位置以安装输出为准 |
| `DATA/app/`、`DATA/secrets/` | 数据库和加密密钥 |
| `DATA/nginx/`、`DATA/certificates/` | 网站配置和证书 |
| `DATA/logs/` | 应用及网站日志 |
| `DATA/runtime/` | 已批准的面板程序、前端及运行绑定 |

Agent 启用 `nginxpanel-agent.service` 开机启动；面板及 Nginx 容器使用 `restart: unless-stopped`。按需安装的软件按自身开机启动设置运行。重建或更新容器保留外部挂载数据；不要删除数据目录或密钥。

## 5. 服务管理与重新安装

```sh
sudo bash /opt/nginxpanel/manage.sh
sudo bash /opt/nginxpanel/manage.sh info
sudo bash /opt/nginxpanel/manage.sh status
sudo bash /opt/nginxpanel/manage.sh restart panel
sudo bash /opt/nginxpanel/manage.sh set-port 23456
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml ps
```

安装中断会保留已批准的安装材料，重新运行入口可续办原安装。源码更新不会自动替换运行程序；已使用环境通过系统更新处理。

`manage.sh uninstall --keep-data` 保留数据卸载，`manage.sh reinstall` 恢复原安装；`uninstall --purge` 完全卸载。软件商店安装的额外软件应先单独卸载，避免留下无人管理的容器。

正式首版之前不提供原生应用部署的兼容模式。旧原生测试安装可在备份后重新安装；保留数据卸载只负责恢复原安装，不能用来切换部署结构。尚未使用且明确允许删除全部旧数据时，在最新源码目录执行 `sudo bash install.sh --fresh`。该操作删除旧账号、密钥、配置及备份，不能用于已有业务数据的更新。

手动受控安装参数见 [Agent 安装器](../deploy/native/README.md)，镜像组成及挂载约束见 [Docker 部署](../deploy/docker/README.md)。

## 6. 首次登录

安装结束后按输出地址访问，例如 `http://服务器地址:端口`。通配地址 `0.0.0.0` 和 `[::]` 不是浏览器访问地址。云安全组和现有防火墙需允许该管理端口；HTTPS 自签证书需先由浏览器用户确认。

使用安装输出中的初始化信息创建管理员，密码至少 6 位。初始化信息丢失时使用 `manage.sh info` 查看提示。登录后在“网站代理”创建网站或反向代理；未安装的可选软件在对应页面跳转软件商店安装。具体操作见[使用手册](user-guide.md)。
