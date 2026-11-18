# Docker 应用

Docker 用于运行 Nginx 和用户按需安装的应用。核心程序不在容器中运行，由宿主机 `nginxpanel.service` 提供 Agent、管理 API 和内嵌前端。

完整安装包附带 Nginx 镜像归档和核心二进制。用户在软件商店点击「安装 Nginx」时，面板导入并校验镜像，确认容器运行后保存 `/etc/nginxpanel/docker/compose.yaml`。镜像已预置常用 HTTP、Stream 等模块。

Fail2ban 和 FRP 服务端从软件商店按需安装，分别使用上游的 Docker 镜像。Nginx 镜像由项目独立发布，可在面板检查并更新。各组件独立运行和更新。

查看 Nginx 容器状态和日志：

```sh
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml ps
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml logs --tail 100 nginx
```

从源码构建时，项目构建入口使用 Docker 编译核心程序并准备 Nginx 镜像；最终安装包仅包含这两项运行材料。不要将旧版面板容器、独立前端目录或 launcher 镜像用于当前部署。

完整安装和运维步骤见[部署指南](../../docs/deployment.md)及[运维文档](../../docs/operations.md)。
