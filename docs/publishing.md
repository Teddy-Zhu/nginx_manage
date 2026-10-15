# 发布产物生成与签名

发布工具 `cmd/nginxpanel-release` 供发布账户和 CI 使用，服务器只使用 [发行资产接收入口](releases.md)。工具不执行输入程序、构建源码、下载依赖或调用包管理器；本轮只完成源码与工作流接入，尚未执行工具、构建、测试或真实发布，待 P5 集中验证。

## 产物和证据

默认发布规格包含 Linux amd64/arm64 面板包及独立 web 包。面板包包含静态 Go 二进制、同版前端、项目许可、第三方许可原文、SPDX 和构建来源；web 包包含构建后的 HTML/CSS/JS 和对应记录，不包含 node_modules 或服务端构建工具。

每个包的 `<asset-id>.spdx.json` 和 `<asset-id>.provenance.json` 同时放在归档与发行根目录。外部副本逐字节匹配签名清单中的文件长度/散列，因此也可以用已验签的文件清单核对。SPDX 2.3 由固定 Syft 生成，范围明确为源码和构建依赖，包括声明的开发依赖，不宣称每项都存在于运行时 JavaScript。许可文件来自实际使用的 Go 模块、Go 标准库及前端生产依赖；缺少许可原文时停止，不能用任意许可证补齐。

构建来源绑定仓库、版本、完整提交、资产、Go/Node/pnpm 版本、go.sum 与 pnpm-lock 散列及 workflow run。面板另核对实际二进制散列、ELF 架构/静态链接、Go 模块和构建设置：干净 VCS 提交、目标平台、CGO=0、注入的 main.version；拒绝模块 replace。数据库目标版本从内嵌 SQL 派生，Agent 协议由 Agent 和发布工具共用单一常量，launcher 使用接收端同一常量。

归档按路径排序，固定 root UID/GID、0644/0755 模式、零时间戳及 USTAR 格式，使用单 gzip 流；不接收链接、特殊文件或自行携带的计算字段。逐文件扫描后在打包时重算散列并核对文件身份，使用与接收端相同的资产/依赖图校验。单文件/归档/展开/清单预算沿用接收合同，整次发布输入与输出最多 2 GiB。SHA-256 清单按文件名排序，包含所有公开记录和归档，不包含其自身。

工具只生成新的输出目录，同文件系统暂存、同步后不覆盖发布；失败只清理自己的暂存。`state=signed` 仅表示本地签名产物已生成，不代表已上传、安装或通过系统矩阵验收。清单当前禁止声明自动回滚能力。

## 本机入口

`make release-tool` 构建工具。准备目录沿用工作流布局：`panel-linux-amd64/`、`panel-linux-arm64/`、`web/`，各目录实际包含上述入口、LICENSE、THIRD_PARTY_NOTICES.txt 及同 ID 的两份 JSON 证据。也可在当前严格 schema 中声明其他已准备组件及其 ABI/运行文件约束；本轮默认构建流程只生产面板和 web，不生产 Nginx/Fail2ban 包。

```sh
bin/nginxpanel-release spec \
  --repository owner/nginxpanel --version 1.2.3 \
  --commit <完整提交> --output .release/input/publication.json

bin/nginxpanel-release bundle \
  --repository owner/nginxpanel --version 1.2.3 --commit <完整提交> \
  --spec .release/input/publication.json --input-root .release/input \
  --key-file /home/publisher/keys/release.seed --key-id release-2026 \
  --public-key <独立确认的Base64公钥> --output .release/output
```

私钥文件为规范 Base64 的 32 字节 Ed25519 seed，可带一个尾随 LF，权限必须 0600。其目录及上层由发布账户或 root 持有且不可被其他账户写入，不允许链接；私钥位于输入和输出树之外。公钥须独立配置并与 seed 派生结果完全一致，不从包内选择信任根。签名采用接收端相同域前缀与完整 manifest 字节，生成后用配置公钥复核。私钥不进入规格、产物、输出和校验清单。

## GitHub Actions

[release.yml](../.github/workflows/release.yml) 在 v 标签推送或指定已有标签的手工触发时运行。所有 action 使用固定 commit，Go 读取 go.mod/toolchain，Node 使用 24.x，pnpm 来自 packageManager；依赖冻结安装。构建任务只授予 contents:read，执行现有 make verify 一轮，然后构建前端和两种静态二进制，生成依赖记录、许可原文和 SBOM。前端直接调用 Vite，复用前序类型检查结果，不重复执行 build 脚本中的同一检查。

发布任务使用 release environment，按构建任务确认的 commit 检出源码，自行构建发布工具；只下载同一工作流的指定 artifact ID，不执行上传的程序。签名 seed 仅在打包签名步骤写入临时 0600 文件，步骤结束清理；上传步骤只持有 GitHub Token。

正式使用需要仓库已有实际 LICENSE，以及 release environment 中的 `RELEASE_ED25519_SEED` secret、`RELEASE_ED25519_PUBLIC_KEY` 和 `RELEASE_KEY_ID` variables。environment 的审批、受信标签限制和私钥保管由仓库维护者配置；代码不假定这些仓库设置已经完成。接收主机仍须由本机 root 独立批准仓库和公钥，普通配置迁移不覆盖它们。

上传前核对当前标签仍指向批准的完整提交。已存在的发行或恢复草稿不会被自动覆盖；新建 draft，上传全部文件并核对资产名称、数量、状态、长度及可用的 GitHub SHA-256 后才公开。失败保留 draft，不自动删除、覆盖或跳过失败。稳定版使用 GitHub legacy 版本选择，预发布不会成为 latest；可配合仓库 immutable releases，但不能替代签名，相关字段见 [GitHub Releases API](https://docs.github.com/en/rest/releases/releases#update-a-release)。

当前仓库缺少项目自身的 LICENSE，正式产物和发布仍需补齐此业务输入。组件构建、安装/切换、更新 worker/回滚及完整 Docker 运行仍在 P4 后续范围，实际发布与系统验收不包含在本轮执行中。
