# GitHub Actions 发布

核心程序和项目自建的 Nginx 镜像分别发布，使用独立版本和流水线。前端内嵌于核心程序，不单独发布。运行架构见[部署指南](deployment.md)，签名和升级流程见[发行与准备](releases.md)。

| 发布内容 | Actions 工作流 | Git 标签 | 产物 |
| --- | --- | --- | --- |
| 核心程序（Agent、API、前端） | `Core binary release` / `release.yml` | `v1.2.3` | Linux amd64、arm64 安装包，签名清单、校验和、依赖及来源证据、`setup.sh` |
| Nginx | `Nginx Docker release` / `nginx-release.yml` | 自动生成，无需手工创建 | Docker Hub 多架构镜像、独立 GitHub Release 的签名镜像清单及 OCI 证据 |
| Fail2ban、FRP 服务端 | 使用软件商店配置的上游镜像 | 不使用项目发行标签 | 拉取各自镜像并重建对应容器 |

核心支持推送版本标签或手动发布；Nginx 在 Actions 中选择分支、组件版本及 stable/dev 通道即可发布，无需事先创建 Git 标签。核心发行不推送组件镜像，Nginx 发行不下载核心 Release，也不编译前端。核心安装包仍在 CI 中组装随包 Nginx 镜像，供首次离线安装；核心更新只切换核心程序，不替换已安装的 Nginx。

核心构建保留 `-trimpath`。amd64、arm64 原生安装包任务分别运行对应程序生成 `containers.json`，记录程序实际版本、架构和二进制 SHA-256；签名打包复用这份清单，同时核对 Go 工具链、源码提交及干净状态，不依赖 Go 在 `-trimpath` 下省略的 `-ldflags` 字段。缺少清单或运行信息不一致时停止发布。

发行版本通过 `-X main.version=<版本>` 写入二进制，`nginxpanel version` 和系统版本接口均读取该值。系统更新将它与所选通道的已验签发行版本进行语义版本比较，仅更高版本提供自动更新；同版本、较旧版本和无效版本分别明确提示。Beta 构建编号、重试编号按数字顺序比较，构建元数据不影响版本先后。

## Actions 页面怎么填写

进入 Actions，按发布内容选择 `Core binary release（核心程序发布）` 或 `Nginx Docker release（Nginx 镜像发布）`，点击 **Run workflow**。

**Use workflow from** 是 GitHub 自带的分支选择，不需要重复填写分支名。核心工作流使用以下输入：

| 发布方式 | `tag`：已有发布标签 | `version`：Beta 基础版本 |
| --- | --- | --- |
| 核心 Beta（无需标签） | 留空 | 例如 `1.2.4-dev`，也可保留默认 `0.1.0-dev` |
| 核心稳定版 | 填已有标签，例如 `v1.2.3` | 忽略，可保留默认值 |

`tag` 有值时，源码和版本都取自该标签，上方分支不决定发布源码；标签必须已推送到仓库，并包含该版本的发行说明和策略。`tag` 留空时，源码取自上方选中的分支，`version` 不带 `v` 前缀且必须以 `-dev` 结尾；实际版本会自动追加构建编号，例如 `1.2.4-123456789.1-dev`。

Nginx 工作流没有 `tag` 输入，使用独立的 `version` 与 `channel`：

| `version` | `channel` | 实际组件版本与发布结果 |
| --- | --- | --- |
| `1.0.0` | `stable` | Docker 标签 `1.0.0`，正式 Release `nginx-v1.0.0` |
| `1.0.1` 或 `1.0.1-dev` | `dev` | Docker 标签 `1.0.1-dev`，预发布 `nginx-v1.0.1-dev` |

组件版本由工作流的 `version` 输入决定。上游 Nginx 引擎版本由组件的基础镜像及能力清单决定，面板核心另有自己的版本。Action 摘要列出计划发布的 Docker 镜像、GitHub Release 标签和实际打包的 Nginx 引擎版本。首次离线安装使用随包镜像时，软件商店显示实际 Nginx 引擎版本，切换到独立发行镜像后可查看组件版本和 Nginx 引擎版本。

分支构建固定使用本次触发时的提交。修改工作流或修复打包脚本后，应先将修复提交推送到所选分支，再发起一次新的运行；发布已有标签时则需创建包含修复的新版本标签。旧运行的 **Re-run failed jobs** 保留原始提交，详见 [GitHub 重跑说明](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)。

## 仓库配置

默认源码仓库为 `Teddy-Zhu/nginx_manage`，工作流使用实际运行仓库的 `github.repository`。Nginx 镜像发布到 Docker Hub，签名清单和 OCI 证据发布到 GitHub Release。部署机器按公开镜像拉取，不持有发布令牌；维护者需要将 Docker Hub 仓库设置为 Public。

在 GitHub 仓库的 **Settings → Environments → release** 添加下表配置。其中 Variable 放入 Environment variables，Secret 放入 Environment secrets。如果私有仓库当前套餐不支持环境级配置，可在 **Settings → Secrets and variables → Actions** 添加同名的仓库级 Variables 和 Secrets。参见 [GitHub 环境配置](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)。

| 名称 | 类型 | 用途 |
| --- | --- | --- |
| `DOCKERHUB_USERNAME` | Variable | Docker Hub 登录用户名 |
| `DOCKERHUB_TOKEN` | Secret | 有目标镜像仓库读写权限的 Docker Hub access token |
| `RELEASE_ED25519_SEED` | Secret | Base64 编码的 32 字节 Ed25519 私钥种子 |
| `RELEASE_ED25519_PUBLIC_KEY` | Variable | 与种子对应的 Base64 公钥 |
| `RELEASE_KEY_ID` | Variable | 签名密钥标识，例如 `release-2026` |
| `NGINX_DOCKERHUB_REPOSITORY` | 可选 Variable | 例如 `myteam/nginxpanel-nginx`，默认 `<DOCKERHUB_USERNAME>/nginxpanel-nginx`。填写 `命名空间/仓库名` |

核心和 Nginx 共用签名配置。已有核心签名配置时，Nginx 只需新增 Docker Hub 用户名和令牌。工作流在开始构建前一次列出缺失项。GitHub Release 通常使用内置 `GITHUB_TOKEN` 和 `contents: write`。

镜像完整地址为 `docker.io/<命名空间>/<仓库名>`。组织仓库需确保登录用户有推送权限。Docker Hub 推送和 OCI 元数据读取默认使用上述凭据。若 blob 下载重定向被拒绝，脚本记录目标域名及原因，并使用匿名拉取令牌重试一次，仍校验摘要和长度。GitHub 内置 Token 用于源码和 Release。参见 [Docker Hub 推送说明](https://docs.docker.com/docker-hub/repos/manage/hub-images/push/)。

手动触发要求工作流已进入默认分支，参见 [GitHub 手动运行工作流说明](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)。首次正式使用前，应确认仓库可使用 `ubuntu-24.04` 与 `ubuntu-24.04-arm` 运行器。

## 发布核心程序

先提交对应版本的发行说明和策略：

```text
deploy/release/notes/1.2.3.md
deploy/release/policies/1.2.3.json
```

说明为非空 UTF-8 文本，最多 8 KiB。策略必须明确版本和自动回滚声明：

```json
{"version":"1.2.3","automatic_rollback":false}
```

然后创建并推送标签，或对已存在的标签手动触发：

```sh
git tag v1.2.3
git push origin v1.2.3
# 也可在 Actions 页面选择 Core binary release，再输入 v1.2.3。
gh workflow run release.yml -f tag=v1.2.3
```

工作流先构建前端并嵌入核心，交叉编译 Linux amd64、arm64 静态程序，执行集中检查，收集依赖许可、SPDX 和构建来源。两个原生架构任务分别组装首次安装所需的本地 Nginx 镜像，不向 GHCR 推送镜像。签名任务核对干净源码提交、版本、二进制构建信息、文件清单和独立策略后，生成两个 `nginxpanel_<版本>_linux_<架构>.tar.gz`。

依赖许可优先读取已安装包中的许可文件。部分 npm 包没有独立许可文件，补充材料存放在 `deploy/release/licenses/`，由 `npm.json` 按精确包名和版本引用并记录来源，打包时无需联网下载。补充材料必须与已安装包的名称、版本及许可声明一致；升级依赖时需同步材料。代理库的许可取自随包 README，vdirs 保留其发布元数据中的作者和 MIT 声明，并明确标注未提供独立版权说明。

发行直接调用 GitHub CLI 上传全部资产并完成发布，不要求手工发布草稿。稳定版发布为正式 Release，Beta 发布为 Prerelease；随后核对公开版本的身份、通道、资产及源码标签。稳定核心版设为仓库 Latest，Beta 与 Nginx 组件发行不替代核心 Latest。`setup.sh` 从核心 Latest 下载与本机架构匹配的安装包。

## 独立发布 Nginx

先配置 Docker Hub 凭据，再选择源码分支和独立组件版本。稳定版与 dev 均不需要 Git 标签或版本说明文件。镜像基础版本和预置模块由 `deploy/docker/nginx.Dockerfile`、`nginx-capabilities.json` 与 `check-nginx-image.sh` 管理；需要调整基础版本或模块时先修改并提交这些文件。

```sh
gh workflow run nginx-release.yml --ref main -f version=1.0.0 -f channel=stable
gh workflow run nginx-release.yml --ref main -f version=1.0.1 -f channel=dev
```

工作流在 amd64、arm64 原生运行器分别构建 Nginx 专用启动器，将其与固定摘要的上游 Nginx 基础镜像和预置模块打包为组件镜像。合并任务只引用推送后的原始摘要，保留 BuildKit SBOM 和 SLSA 来源证据，再由 Go 发布工具独立核对并签名。

正式镜像使用组件版本作为 Docker 标签，例如 `docker.io/myteam/nginxpanel-nginx:1.0.0`。Docker 标签不支持 `+`，组件版本请省略此类构建元数据。每次重新发布不同镜像时都要更换版本号，已有版本标签若指向不同摘要，发布会停止。面板部署使用签名清单中的 `repository@sha256:...`。两个架构的 `build-*` 标签用于构建和校验，发布完成后可在 Action 摘要查看正式镜像。

对应 GitHub Release 自动使用 `nginx-v1.0.0` 等组件标签，包含 `release-manifest.json`、`release-manifest.sig`、`nginx.oci.json` 和 `checksums.txt`，不附带核心二进制或安装脚本，也不会成为仓库 Latest。`make_latest` 行为见 [GitHub Releases API](https://docs.github.com/en/rest/releases/releases#update-a-release)。

核心更新通道由“系统更新”保存。Nginx 在自己的版本选择弹窗切换稳定版或 Beta，可分页查看并选择历史发行。选中确切标签后，面板再下载并验签。稳定版核心使用仓库 Latest，Beta 核心按其保存的通道发现发行。

## 从分支发布 Beta（无需预先创建标签）

版本以 `-dev` 结尾时自动归入 Beta；其他 SemVer 预发布版本也归入 Beta。正式版本归入稳定版。签名清单使用 `stable` / `beta`，GitHub Release 的 Beta 标记为 prerelease，永不替代稳定版 Latest。

在 Actions 手动选择工作流，用上方 **Use workflow from** 选择源码分支，将 `tag` 留空，填写开发基础版本 `version`；默认基础版本为 `0.1.0-dev`。例如：

```sh
# 分支名按实际仓库填写；工作流文件需要已存在于仓库默认分支。
gh workflow run release.yml --ref main -f version=1.2.4-dev
gh workflow run nginx-release.yml --ref main -f version=1.0.1 -f channel=dev
```

核心开发版本增加 GitHub run ID 和 attempt，例如 `1.2.4-123456789.1-dev`。Nginx 开发版使用填写的组件版本，并在需要时补全 `-dev`，例如 `1.0.1-dev`。两个流程都自动生成 GitHub 标签、发行说明及关闭自动回滚的策略。已有发行或失败上传留下的草稿会使同版本发布停止。核心普通手工 `v1.2.4-dev` 标签仍可触发发布，需提交对应说明和策略。

通常使用工作流自带的 `GITHUB_TOKEN`。如果源码分支修改了 `.github/workflows`，GitHub 可能要求额外的 Workflows 写入权限才能创建源码标签；此时在 `release` environment 配置可选的 `RELEASE_GITHUB_TOKEN`，使用具备该仓库 Contents 和 Workflows 写入权限的令牌。签名凭据要求与稳定版相同，参见 [GitHub 创建发行的权限说明](https://docs.github.com/en/rest/releases/releases#create-a-release)。

面板的“系统更新”和“更新 Nginx”均可切换更新通道。切换只改变后续检查来源，不会立即安装、自动降级或修改已运行组件。命令行使用 `--release-channel stable` 或 `--release-channel beta`；指定 Beta 标签或验证离线 Beta 材料时也可使用此参数。

## 本机签名工具

发布工具只用于构建环境，不在接收主机编译或执行下载代码。通过 Docker 构建工具后，可使用：

```sh
nginxpanel-release spec --component panel \
  --repository Teddy-Zhu/nginx_manage --version 1.2.3 --commit <完整提交> \
  --notes-file deploy/release/notes/1.2.3.md \
  --policy-file deploy/release/policies/1.2.3.json --output <新的规格文件>
```

Nginx 规格使用 `--component nginx` 和独立版本的说明、策略文件（工作流在临时目录自动生成），打包时必须提供 `--images <经过核对的镜像 publication.json>`；核心打包不提供镜像输入。两种签名清单不混装核心资产与组件镜像。已有本机信任根继续限制源码仓库、公钥和接收协议，OCI 证据仍核对 GitHub 源码与提交；镜像仓库由签名清单固定，支持 Docker Hub 与原有 GHCR 引用，普通配置迁移不会覆盖信任根。

上传失败可能保留构建镜像或由 GitHub CLI 留下的草稿，流程不自动覆盖发行、删除草稿或忽略上传、校验及验签错误。实际 GitHub Actions、Docker Hub 推送及签名下载尚需在配置了上述凭据的真实仓库执行；本地检查不能代替实际发布结果。

## 内置组件版本目录

Nginx 独立发行完成后，面板版本选择器直接按页读取包含签名材料的 `nginx-v*` 发行记录。工作流把实际引擎版本写入发行说明，面板按该版本筛选组件，准备镜像前再与已验签的发行说明核对。稳定版和 Beta 分开展示，安装继续使用固定镜像摘要。

Fail2ban 和 FRP 服务端从 `internal/componentversions/builtin.json` 读取随核心二进制发布的版本目录。在 `applications` 下增加版本时使用新的组件 SemVer 和不可变 `id`，同时记录实际 `software_version`、目标架构、上游镜像摘要和可选的 `minimum_core`。发布核心程序后，新版本会出现在软件商店。已安装组件由用户按需切换版本。
