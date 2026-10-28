# 宿主机 Agent 安装器

目录名沿用内部安装材料路径，不代表应用原生部署。标准安装方式见[部署指南](../../docs/deployment.md)：仅 Agent 及必要权限操作运行在宿主机，面板和 Nginx 使用 Docker。安装器不创建原生面板、Nginx 或 Fail2ban 应用服务。

完整安装包包含 `nginxpanel`、`web/`、`containers.json` 和 `container-images.tar`。顶层 `install.sh` 自动导入配套镜像、批准内容、生成 Compose、启用 Agent 并启动容器。不要手动拼装不完整材料。

推荐入口：

```sh
cd /完整安装包目录
sudo bash install.sh --yes
```

底层安装参数见 `bash deploy/native/install.sh --help`。导入归档后，安装入口根据当前 Docker 引擎重新读取固定镜像 ID，生成 root 批准的运行清单；源清单里的临时镜像标签只用于导入定位，不用于运行绑定。这样兼容 Docker classic 与 containerd 存储对镜像 ID 的不同表示，容器仍使用不可变内容 ID。

内容清单绑定程序、全部前端文件、当前架构及镜像内容 ID；安装器独立读取实际镜像，核对启动器、Nginx 模块能力和容器约束。本地安装包批准不冒充发布者签名。使用发行仓库镜像时仍可传入固定 `repository@sha256:摘要`、`--release-trust`、`--release-manifest`、`--release-signature`，沿用发布者验签；两种来源不能混用。

主机 DNS、防火墙、SSH 保护和日志所有者沿用自动识别结果；需要调整时参考 `--help`。Agent 通过固定的本地 Docker 套接字执行操作，Web 容器不能直接访问 Docker。全部业务数据写入安装时选定的外部数据目录。

管理与卸载使用 `/opt/nginxpanel/manage.sh`，详细范围见[运维说明](../../docs/operations.md)。
