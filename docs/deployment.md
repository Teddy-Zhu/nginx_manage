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

安装脚本先检查 Linux、systemd、架构、安装权限和本机 Docker，再下载安装包。校验通过后安装核心程序并保留配套 Nginx 镜像归档。源码安装也会在拉取或构建前检查 Docker。

### 安装选项

默认安装向导会询问管理端口、访问协议和管理员账号。按回车接受随机空闲端口和 HTTPS。默认管理员账号为 `admin`，安装时可修改。自定义密码至少 6 个字符，输入时隐藏。密码留空时，安装器会生成随机初始密码，并在确认后显示一次。

- `--yes` 跳过基本配置提问和确认。未提供密码文件时，安装器会在终端显示随机初始密码。
- `--port 23456` 指定管理端口，`--protocol http` 指定访问协议。
- `--admin-user operator` 指定管理员账号。
- `--admin-password-file /root/nginxpanel-password` 从单行文件读取密码。请使用仅安装账户可读的文件。
- `--advanced` 可调整数据目录、监听地址和主机网络管理设置。

无人值守安装可同时指定端口、协议和账号。

```sh
sudo bash install.sh --yes --port 23456 --protocol https \
  --admin-user operator --admin-password-file /root/nginxpanel-password
```

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

在「系统更新」点击「检查更新」，页面直接显示所选通道的检查结果。发现新版本时，可查看版本和发行说明。确认「下载安装」后，面板创建更新记录，自动下载、校验签名、切换版本并重启。新程序启动时完成数据库迁移，页面恢复连接后显示更新结果。Nginx 和其他应用镜像由各自的页面更新。

面板无法访问时，可以在安装主机使用命令行检查或升级。

```sh
sudo bash /opt/nginxpanel/manage.sh upgrade --check
sudo bash /opt/nginxpanel/manage.sh upgrade --dev
```

命令默认使用稳定通道，`--dev` 选择 Beta，`--version v1.2.3` 指定发行标签。确认后通过独立 systemd 任务重启核心服务。如果当前版本没有 `upgrade` 命令，可以从可信的新发行包中解压 `nginxpanel`，以 root 运行该二进制的 `upgrade --data-dir /srv/nginxpanel`。数据目录使用实际安装路径。

新版发行包包含项目的发行公钥。使用旧安装包或从源码安装时，如果没有预先配置发行信任，需要使用维护者的发布公钥配置 `/etc/nginxpanel/release-trust.json`。已有配置由管理员管理。 [发行签名配置](releases.md)

在已安装的主机上运行 `setup.sh` 或从源码运行 `install.sh`，确认后才下载或构建。脚本随后显示当前版本和目标版本，原地升级或覆盖核心程序，保留现有账号、端口和数据。使用本地发行包的 `install.sh` 时，确认前即可看到版本。发行包会为缺少发行公钥的安装补齐配置。

使用 `sudo bash /opt/nginxpanel/manage.sh logs` 查看服务的纯文本日志。网页的日志下载为 `.log` 文件，首行提供脱敏和导出范围摘要。

运行 `bash setup.sh --dev` 安装开发版，加 `--uninstall` 进入卸载流程。源码入口 `install.sh` 和本机管理脚本 `manage.sh uninstall` 支持相同的数据选择，默认保留数据。可使用 `--keep-data` 或 `--purge` 明确选择。保留数据卸载后可通过 `manage.sh reinstall` 恢复原安装。

旧双服务或面板容器部署不能通过核心程序更新入口转换为当前结构。切换前先创建备份；需要重新安装时按管理脚本的保留数据卸载及安装流程处理。保留数据不代表旧程序、运行容器或配置格式可直接复用。

## 首次登录

安装结束后按输出地址访问，例如 `http://服务器地址:端口`。`0.0.0.0` 和 `[::]` 是监听地址，不是浏览器访问地址。云安全组及现有防火墙需允许管理端口；使用 HTTPS 自签证书时，浏览器会提示确认。

使用安装时创建的管理员账号和密码直接登录。登录后，可在「面板设置」修改管理员账号、密码、端口和访问协议。

需要网站服务时，打开「软件商店 → Nginx」并点击「安装 Nginx」。安装完成后，在「网站代理」创建网站或反向代理。具体操作见[使用手册](user-guide.md)。
