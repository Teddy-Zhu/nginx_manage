# NginxPanel 文档

NginxPanel 用于管理专用 Nginx 实例及相关主机功能。安装和宿主机授权由本机管理员完成，日常配置通过网页或 API 操作。

## 从部署到使用

| 顺序 | 文档 | 内容 |
| --- | --- | --- |
| 1 | [部署指南](deployment.md) | 准备材料、源码构建、原生或 Docker 安装、首次登录、开放管理入口 |
| 2 | [使用手册](user-guide.md) | 第一个代理、HTTPS、访问控制、主机功能、节点、迁移、备份及 API |
| 3 | [运维与故障处理](operations.md) | 服务管理、更新、配置恢复、完整恢复、常见问题及清理边界 |

首次部署可沿“原生安装 → SSH 转发 → 初始化管理员 → 创建 HTTP 代理 → 保存并应用”的顺序操作。需要容器运行时，在部署指南中选择 Docker 分支，后续网页使用流程相同。

## 按任务查阅

| 任务 | 操作入口与详细说明 |
| --- | --- |
| 原生安装参数、账户、目录和 systemd | [原生安装参考](../deploy/native/README.md) |
| Docker 镜像、Compose 和容器维护 | [Docker 部署参考](../deploy/docker/README.md) |
| 一键安装与 Docker 编译 | [源码安装](deployment.md#从源码安装) · [Release 安装](deployment.md#从-github-release-安装) · [离线构建](deployment.md#离线构建与手动安装材料) |
| 菜单管理、服务启停与日志 | [管理脚本](operations.md#管理脚本) |
| 保留数据卸载、完全卸载与重装 | [卸载与重新安装](operations.md#卸载与重新安装) |
| 创建代理、上游组及 TCP/UDP 转发 | [创建第一个代理](user-guide.md#创建第一个-http-代理) |
| 导入证书、ACME 签发与自动部署 | [配置 HTTPS](user-guide.md#配置-https) |
| 主机 DNS 所有者与限时确认 | [主机 DNS 操作](user-guide.md#主机-dns) |
| 日志查询、通知和任务结果 | [日志、通知与任务](user-guide.md#日志通知与任务) |
| 远程访问面板、来源限制与本机救援 | [管理入口](management-listener.md) |
| 原生 Nginx 动态模块批准 | [模块接入](native-modules.md) |
| 防火墙后端授权、入口保护、应用与回滚 | [防火墙](firewall.md) |
| Fail2ban 接入、jail、服务控制与恢复 | [Fail2ban](fail2ban.md) |
| 本地配置迁到云端、文件或 API 迁移 | [配置迁移](migration.md) |
| 加密备份、离线检查与完整恢复 | [完整备份](backups.md) |
| 连接和管理其他节点 | [多节点](nodes.md) |
| 签名信任、离线/在线组件准备及更新 | [发行资产与准备](releases.md) |

## 功能状态与开发资料

产品操作以本组使用文档为入口；当前完成状态、限制和暂缓事项以[进度清单](progress.md)为准。历史验收结果见[运行矩阵](support-matrix.md)及[验证记录](validation.md)，不表示每个系统和功能组合均已验收。

- [API 合同](../api/openapi.yaml)：接口、输入输出、权限和响应格式。
- [工程合同](contracts.md)：身份、配置保真、执行和资源边界。
- [设计文档](../Linux_Nginx_Manager_Design.md)：设计背景与功能范围。
- [实施记录](implementation.md)：阶段历史。
- [发布流程](publishing.md)：发行维护者使用的打包与签名流程。

文档内的安装、服务和网络命令均面向实际部署目标。开发主机只进行源码与文档工作；需要运行验证时使用隔离 Docker/虚拟机环境。
