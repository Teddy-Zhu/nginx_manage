# NginxPanel

NginxPanel 是一个开源的 Linux Nginx 管理面板。你可以在浏览器里配置网站反向代理和 HTTPS，管理访问规则，并把配置备份或迁移到另一台服务器。

[快速开始](#快速开始) · [使用手册](docs/user-guide.md) · [Releases](https://github.com/Teddy-Zhu/nginx_manage/releases) · [问题反馈](https://github.com/Teddy-Zhu/nginx_manage/issues)

## 主要功能

- **网站代理**支持可视化配置域名、反向代理和上游服务器组，以及 WebSocket 和 TCP/UDP 转发。应用前会检查配置，需要时可编辑 Nginx 源文件。
- **HTTPS**支持导入证书或通过 ACME 申请和续期，再绑定到网站。
- **访问控制**支持按 IP、网段或国家和地区配置网站黑白名单，并管理主机防火墙。
- **容器与应用**支持启停、重启和查看日志。可按需安装 Nginx、Fail2ban 和 FRP 服务端，并切换组件版本。
- **服务器运维**提供系统监控、操作记录、远程节点管理、备份恢复和配置迁移。

## 快速开始

准备一台使用 systemd 的 Linux 服务器（amd64 或 arm64），预装本机 Docker Engine（rootful）和 Docker Compose 插件，并确保安装账户可使用 `sudo` 或 root。适用环境和网络要求见[部署指南](docs/deployment.md#环境要求)。

### 从源码安装

在部署目标上用 Git 下载源码，然后运行安装脚本。编译在 Docker 中完成。

```sh
git clone --depth 1 https://github.com/Teddy-Zhu/nginx_manage.git
cd nginx_manage
sudo bash install.sh
```

安装器会检测环境并显示安装摘要供确认。要在安装时指定管理端口，可用 `sudo bash install.sh --port 23456`。

### 安装预编译版本

项目尚未发布首个稳定版，目前可试用 [Beta 发行](https://github.com/Teddy-Zhu/nginx_manage/releases)。在部署目标上使用主分支的安装脚本，自动选择适合本机架构的最新 dev 版：

```sh
curl -fL https://raw.githubusercontent.com/Teddy-Zhu/nginx_manage/main/setup.sh -o setup.sh
bash setup.sh --dev
```

自动查找 dev 版需要已认证的 GitHub CLI，或 `curl` 和 `jq`。也可从 Release 下载所选版本附带的 `setup.sh` 后运行 `bash setup.sh`，或使用 `--version <标签>` 固定版本。脚本会匹配本机架构并校验安装包 SHA-256。

### 安装之后

1. 打开安装结束时输出的管理地址，使用输出中的初始化信息创建管理员。
2. 在 **网站管理** 添加反向代理，填写域名、监听端口和上游地址，保存并应用配置。
3. 访问业务域名，确认请求到达预期上游。[创建第一个 HTTP 代理](docs/user-guide.md#创建第一个-http-代理)

默认只安装核心程序。登录后，在「软件商店」打开 Nginx，点击「安装 Nginx」即可使用配套镜像离线安装。Nginx 以 Docker 容器运行，配置、证书、日志和数据库保存在宿主机。

## 文档

| 我想做什么 | 从这里开始 |
| --- | --- |
| 安装、设置管理端口、首次登录 | [部署指南](docs/deployment.md) |
| 配置代理、证书、访问控制 | [使用手册](docs/user-guide.md) |
| 管理服务、排查故障或卸载 | [运维与故障处理](docs/operations.md) |
| 备份数据或迁移到另一台服务器 | [备份与恢复](docs/backups.md) · [配置迁移](docs/migration.md) |
| 安装和更新内置组件 | [组件安装与版本管理](docs/software-sources.md) |
| 查看系统组合和验证记录 | [运行矩阵](docs/support-matrix.md) · [开发进度](docs/progress.md) |

其他专题见[完整文档索引](docs/README.md)。

## 开发与贡献

项目使用 Go、Vue 和 SQLite。核心入口在 [`cmd/nginxpanel`](cmd/nginxpanel)，前端代码在 [`web`](web)，API 以 [OpenAPI 合同](api/openapi.yaml)为准。

在仓库根目录执行 `make build`，通过 Docker 构建安装包并输出到 `dist/`。前后端联调可在隔离开发环境中使用 [`go.mod`](go.mod) 和 [`web/package.json`](web/package.json) 声明的工具链：

```sh
pnpm --dir web install --frozen-lockfile
make dev
```

另开终端执行 `pnpm --dir web dev`，访问 [http://127.0.0.1:5173](http://127.0.0.1:5173)。初始化令牌保存在 `.local/bootstrap/token`。安装、网络和防火墙变更在独立虚拟机中验证。打包和签名见[发布指引](docs/publishing.md)。

欢迎提交 Issue 或 Pull Request。反馈故障时请提供版本、操作系统、复现步骤和必要日志，并移除凭据与私钥。[故障信息提交指南](docs/operations.md#提交故障信息)

## 许可证

项目采用 [MIT 许可证](LICENSE)。
