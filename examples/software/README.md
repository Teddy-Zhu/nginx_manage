# 第三方软件接入 Demo

此示例包含三部分：软件源 JSON 只声明操作；`demo/manage.sh` 实现操作；`demo/compose.yaml` 独立保存 Docker 配置。面板只调用约定的操作，不解析或维护 Compose 文件。

`source.json` 是模板，其中下载地址和校验值由 `prepare.py` 填充。不要直接导入模板。先生成可导入文件与软件包：

```sh
docker run --rm -v "$PWD:/workspace" -w /workspace python:3.12-slim-bookworm \
  python3 examples/software/prepare.py https://你的文件服务器/demo.tar.gz
```

输出位于 `examples/software/dist/`：将 `demo.tar.gz` 发布到上面指定的地址，然后在“软件商店 → 第三方商店 → 管理软件源 → 添加软件源”选择生成的 `dist/source.json`。也可发布生成的 JSON，直接填写其 GitHub 或 HTTP/HTTPS 地址。

仅在虚拟机快速体验时，可生成地址为 `http://127.0.0.1:18081/demo.tar.gz` 的文件，再用普通 HTTP 文件服务器提供 `dist/`。地址须能被**安装软件的服务器**访问；文件服务器仅用于演示包下载，不属于面板运行依赖。安装环境需有 Docker Compose、curl、tar、sha256sum。

1. 导入后只增加软件列表，不自动安装。
2. 点击“安装”，在弹窗确认后查看下载及安装日志。
3. “运行中”时点击“打开”，访问演示网站；默认使用服务器 `18080` 端口，防火墙需允许该端口。
4. 点击“管理”体验停止、启动、重启、更新和服务日志，状态会自动变化；直接使用原生 Compose 启停也能同步状态。
5. 卸载调用示例自己的 `compose down`，保留网站文件及 Compose 配置；重新安装继续使用已有数据。

如需改端口或镜像，由软件维护者修改 `demo/compose.yaml`；已安装实例可修改该软件独立工作目录中的 `compose.yaml`，再使用原生 Compose 应用配置。面板 JSON 无需增加任何 Docker 设置。网页入口由状态脚本读取当前实际端口并返回。

对接其他软件时，提供自己的安装、卸载和只读状态操作，再按需要声明启停、重启、更新及日志。应用统一通过 Docker 运行，配置及数据挂载到外部；可使用原生 Compose 或 Docker 命令，无需修改面板代码。完整格式与状态约定见 [第三方软件接入规范](../../docs/software-sources.md)。
