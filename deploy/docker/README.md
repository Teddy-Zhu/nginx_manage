# Docker 应用

Docker 用于运行 Nginx 和用户按需安装的应用。核心程序不在容器中运行，由宿主机 `nginxpanel.service` 提供 Agent、管理 API 和内嵌前端。

完整安装包只附带 Nginx 镜像归档和核心二进制，不包含面板镜像或 `web/` 静态目录。安装器导入并校验 Nginx 镜像后，生成 `/etc/nginxpanel/docker/compose.yaml`；该 Compose 只管理 Nginx。镜像预置常用 HTTP、Stream 等模块，安装或更新时不在宿主机编译或追加模块。

默认不会安装 Fail2ban、FRPS 或第三方应用。用户从软件商店手动安装后，这些应用作为独立 Docker 容器运行并按各自流程更新。组件镜像不随核心程序更新；Nginx 镜像也有独立的检查、准备和更新页面。

查看 Nginx 容器状态和日志：

```sh
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml ps
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml logs --tail 100 nginx
```

从源码构建时，项目构建入口使用 Docker 编译核心程序并准备 Nginx 镜像；最终安装包仅包含这两项运行材料。不要将旧版面板容器、独立前端目录或 launcher 镜像用于当前部署。

完整安装和运维步骤见[部署指南](../../docs/deployment.md)及[运维文档](../../docs/operations.md)。
