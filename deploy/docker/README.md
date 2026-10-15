# Nginx 固定模块镜像

```sh
docker build -f deploy/docker/nginx.Dockerfile -t nginxpanel-nginx:1.30.6 .
```

基础镜像固定为官方 `nginx:1.30.6-alpine-slim` 的多架构摘要；构建时检查静态 HTTP/TLS/realip、Stream/TLS/realip/SSL preread，以及 ACL、基础 WAF、JSON 日志和 HTTP-01 依赖的默认模块。校验脚本发现版本、必需参数或默认模块不满足时中止镜像构建。

镜像提供 `/usr/share/nginxpanel/capabilities.json`、完整 `nginx -V` 输出及 Nginx 二进制 SHA-256。启动入口直接运行 Nginx，清除官方配置模板入口；启动时不下载、安装或编译模块。迁移执行仍以目标 Agent 的实际能力与 `nginx -t` 为准，不能把静态清单当作运行确认。

修改模块集合须重新构建并发布镜像；运行环境缺失模块时更换包含对应能力的受信镜像，重新生成迁移计划。镜像不携带源节点二进制、动态模块或业务秘密。

当前交付为镜像构建配方及能力清单，尚未执行镜像构建、启动或 ABI 验证。面板配套镜像、容器与宿主机 Agent 的完整接入、签名发布、持久卷权限初始化及更新编排仍属于 P4 后续工作；本目录不宣称已完成整套 Docker 部署。

上游构建及模块参数参见 [Nginx 官方镜像源码](https://github.com/nginx/docker-nginx) 和 [Nginx 构建选项](https://nginx.org/en/docs/configure.html)。
