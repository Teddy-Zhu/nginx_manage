# 宿主机安装材料

NginxPanel 的宿主机部分是一个核心二进制，内含 Agent、管理 API 和前端，由 root 权限的 `nginxpanel.service` 启动并设置开机启动。前端不单独部署，管理面板不运行在容器中。

请从源码或完整安装包根目录运行安装入口：

```sh
sudo bash install.sh --yes
```

源码编译由 Docker 完成。安装包包含核心二进制和 Nginx 镜像归档。根目录安装入口部署核心服务，并保留后续安装 Nginx 所需的镜像归档。`deploy/native/install.sh` 是内部安装步骤。

默认只安装核心服务。登录后，在软件商店安装所需的内置组件。Nginx 在 Docker 容器中运行，配置和业务数据保存在宿主机数据目录。

查看核心服务状态和日志：

```sh
sudo systemctl status nginxpanel.service
sudo journalctl -u nginxpanel.service -n 200 --no-pager
```

完整部署、卸载和更新说明见[部署指南](../../docs/deployment.md)及[运维文档](../../docs/operations.md)。
