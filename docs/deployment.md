# 部署指南

[文档首页](README.md) · [使用手册](user-guide.md) · [运维与故障处理](operations.md)

## 运行组成

NginxPanel 由一个 Go 核心程序组成，程序内嵌 Agent、管理 API 和前端页面。宿主机通过 `nginxpanel.service` 以 root 运行该程序并设置开机启动；系统操作由同一进程处理，不另运行 Agent 服务或管理面板容器。

默认只安装核心程序。Nginx、Fail2ban 和 FRP 服务端是内置组件，在软件商店按需安装。Nginx 安装后以 Docker 容器运行，网站配置、证书和日志保存在宿主机数据目录。常用 Nginx 模块预置在配套镜像中。

## 环境要求

- 使用 systemd 的 Linux，支持 amd64、arm64，需要部署目标的 root 权限。
- 本机 rootful Docker Engine 和 Compose 插件；不使用远程 Docker context、rootless Docker 或 Swarm。
- 源码安装另需 Git。Go、Node.js、pnpm 和 Nginx 均不需要安装在宿主机，源码编译由 Docker 容器完成。
- Release 安装另需 curl，或已认证的 GitHub CLI。通过 curl 自动查找 dev 版还需要 jq。

开发期间不要在开发主机执行安装或修改宿主机服务。部署和功能验收使用独立虚拟机。

## 安装

默认从 `Teddy-Zhu/nginx_manage` 获取源码和发行包。

### 从源码安装

已有源码目录时，在部署目标执行：

```sh
sudo bash install.sh --yes
```

也可以用引导脚本拉取默认仓库源码、在 Docker 中编译并安装：

```sh
bash setup.sh --source --yes
```

源码包只需提供核心程序与 Nginx 镜像的构建材料，不需要独立 `web/` 发布目录或面板运行镜像。跨架构构建须在能运行对应目标容器的 Docker 环境中完成。

### 使用 Release 安装

从 [GitHub Releases](https://github.com/Teddy-Zhu/nginx_manage/releases) 下载所选核心版本附带的 `setup.sh`，运行 `bash setup.sh` 即可按该发行标签安装。也可使用主分支脚本选择版本：

```sh
curl -fL https://raw.githubusercontent.com/Teddy-Zhu/nginx_manage/main/setup.sh \
  -o nginxpanel-setup.sh
bash nginxpanel-setup.sh --dev
```

`--dev` 在最近 100 条发行中按发布时间选择最新版。候选须为已发布的 `v…-dev` 核心预发布版，并包含本机架构的安装包和校验清单。若已知标签，可直接用 `--version <标签>` 安装。主分支脚本默认查找稳定版，首个稳定版发布前请选择 dev、指定标签或源码安装。

安装脚本校验安装包摘要，安装核心程序并保留配套 Nginx 镜像归档。

### 安装选项

- `--yes`：按检测结果安装；省略后先核对安装摘要。
- `--port 23456`：指定管理端口；省略时随机选择空闲端口，重启后保持。
- `--protocol http`：使用 HTTP；默认 HTTPS。
- `--advanced`：调整数据目录、监听地址和主机网络管理设置。

默认监听全部网卡，可通过机器公网或内网地址访问。数据目录优先使用 `/srv/nginxpanel`，不可用时尝试 `/var/lib/nginxpanel`；已有数据不会被首次安装覆盖。安装过程不会自动清空防火墙规则，也不会接管已有系统 Nginx。

## 数据与开机启动

| 位置 | 用途 |
| --- | --- |
| `/opt/nginxpanel/` | 核心程序、管理脚本和安装材料 |
| `/etc/nginxpanel/` | 安装记录、信任配置和服务设置 |
| `DATA/app/`、`DATA/secrets/` | 数据库和加密密钥 |
| `DATA/nginx/`、`DATA/certificates/` | 网站配置和证书 |
| `DATA/logs/` | 核心程序及 Nginx 日志 |
| `DATA/runtime/current` | 当前已批准的核心程序版本 |

`nginxpanel.service` 开机启动并以 root 运行。Nginx 容器使用 `restart: unless-stopped`。需要时安装的应用按各自设置运行。更新核心程序或重建容器不会删除外部数据目录；请勿删除数据库、密钥和证书目录。

## 服务管理

```sh
sudo systemctl status nginxpanel.service
sudo systemctl restart nginxpanel.service
sudo bash /opt/nginxpanel/manage.sh info
sudo bash /opt/nginxpanel/manage.sh set-port 23456
sudo docker ps
```

系统更新从面板唯一的“系统更新”入口执行：检查版本、准备签名核心包并确认更新。短期独立的 `nginxpanel-core-update@<UUID>.service` 在 root 权限下批准并切换 `DATA/runtime/current`，随后重启核心服务；新程序启动时自动完成数据库迁移。Nginx 和其他应用镜像各自更新，不随核心程序更新。

管理脚本支持 `uninstall --keep-data` 保留数据卸载、`uninstall --purge` 完全卸载和 `reinstall`。源码更新不会自动替换已安装核心程序；已部署环境从系统更新入口更新。

旧双服务或面板容器部署不能通过核心程序更新入口转换为当前结构。切换前先创建备份；需要重新安装时按管理脚本的保留数据卸载及安装流程处理。保留数据不代表旧程序、运行容器或配置格式可直接复用。

## 首次登录

安装结束后按输出地址访问，例如 `http://服务器地址:端口`。`0.0.0.0` 和 `[::]` 是监听地址，不是浏览器访问地址。云安全组及现有防火墙需允许管理端口；使用 HTTPS 自签证书时，浏览器会提示确认。

使用安装输出中的初始化信息创建管理员，密码至少 6 位。初始化信息丢失时运行 `manage.sh info` 查看提示。需要网站服务时，打开「软件商店 → Nginx」并点击「安装 Nginx」。安装完成后，在「网站代理」创建网站或反向代理。具体操作见[使用手册](user-guide.md)。
