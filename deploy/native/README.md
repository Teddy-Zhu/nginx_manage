# 宿主机安装材料

NginxPanel 的宿主机部分是一个核心二进制，内含 Agent、管理 API 和前端，由 root 权限的 `nginxpanel.service` 启动并设置开机启动。前端不单独部署，管理面板不运行在容器中。

请从源码或完整安装包根目录运行安装入口：

```sh
sudo bash install.sh --yes
```

源码编译由 Docker 完成。安装包包含核心二进制和 Nginx 镜像归档；不包含独立 `web/` 目录或面板运行镜像。根目录安装入口会校验并导入镜像、写入服务配置并完成首次启动。`deploy/native/install.sh` 是内部安装步骤，不应单独用来拼装发行包。

默认只安装核心服务和 Nginx。Nginx 在 Docker 容器中运行，配置和业务数据保存在宿主机数据目录。Fail2ban、FRPS 和第三方软件默认不安装，用户可在管理界面中按需安装。

查看核心服务状态和日志：

```sh
sudo systemctl status nginxpanel.service
sudo journalctl -u nginxpanel.service -n 200 --no-pager
```

完整部署、卸载和更新说明见[部署指南](../../docs/deployment.md)及[运维文档](../../docs/operations.md)。
