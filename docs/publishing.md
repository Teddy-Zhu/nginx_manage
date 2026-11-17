# GitHub Actions 发布

核心程序和项目自建的 Nginx 镜像分别发布，使用独立版本、标签和流水线。前端内嵌于核心程序，不单独发布。运行架构见[部署指南](deployment.md)，签名和升级流程见[发行与准备](releases.md)。

| 发布内容 | Actions 工作流 | Git 标签 | 产物 |
| --- | --- | --- | --- |
| 核心程序（Agent、API、前端） | `Core binary release` / `release.yml` | `v1.2.3` | Linux amd64、arm64 安装包，签名清单、校验和、依赖及来源证据、`setup.sh` |
| Nginx | `Nginx Docker release` / `nginx-release.yml` | `nginx-v1.30.6` | GHCR 多架构镜像、独立 GitHub Release 的签名镜像清单及 OCI 证据 |
| Fail2ban、FRP 服务端 | 使用软件商店配置的上游镜像 | 不使用项目发行标签 | 拉取各自镜像并重建对应容器 |

两个工作流均支持推送相应标签自动触发，以及在 Actions 中手动输入已存在的确切标签。核心发行不会向 GHCR 发布组件镜像，Nginx 发行不下载核心 Release，也不编译前端。核心安装包仍在 CI 中组装随包 Nginx 镜像，供首次离线安装；核心更新只切换核心程序，不替换已安装的 Nginx。

核心构建保留 `-trimpath`。amd64、arm64 原生安装包任务分别运行对应程序生成 `containers.json`，记录程序实际版本、架构和二进制 SHA-256；签名打包复用这份清单，同时核对 Go 工具链、源码提交及干净状态，不依赖 Go 在 `-trimpath` 下省略的 `-ldflags` 字段。缺少清单或运行信息不一致时停止发布。

发行版本通过 `-X main.version=<版本>` 写入二进制，`nginxpanel version` 和系统版本接口均读取该值。系统更新将它与所选通道的已验签发行版本进行语义版本比较，仅更高版本提供自动更新；同版本、较旧版本和无效版本分别明确提示。Beta 构建编号、重试编号按数字顺序比较，构建元数据不影响版本先后。

## Actions 页面怎么填写

进入 Actions，按发布内容选择 `Core binary release（核心程序发布）` 或 `Nginx Docker release（Nginx 镜像发布）`，点击 **Run workflow**。

**Use workflow from** 是 GitHub 自带的分支选择。发布分支上的 Beta 时，直接在这里选择源码分支，不需要再填写分支名。下面只保留两个输入：

| 发布方式 | `tag`：已有发布标签 | `version`：Beta 基础版本 |
| --- | --- | --- |
| 核心 Beta（无需标签） | 留空 | 例如 `1.2.4-dev`，也可保留默认 `0.1.0-dev` |
| 核心稳定版 | 填已有标签，例如 `v1.2.3` | 忽略，可保留默认值 |
| Nginx Beta（无需标签） | 留空 | 例如 `1.30.6-dev` |
| Nginx 稳定版 | 填已有标签，例如 `nginx-v1.30.6` | 忽略，可保留默认值 |

`tag` 有值时，源码和版本都取自该标签，上方分支不决定发布源码；标签必须已推送到仓库，并包含该版本的发行说明和策略。`tag` 留空时，源码取自上方选中的分支，`version` 不带 `v` 前缀且必须以 `-dev` 结尾；实际版本会自动追加构建编号，例如 `1.2.4-123456789.1-dev`。

分支构建固定使用本次触发时的提交。修改工作流或修复打包脚本后，应先将修复提交推送到所选分支，再发起一次新的运行；发布已有标签时则需创建包含修复的新版本标签。旧运行的 **Re-run failed jobs** 保留原始提交，详见 [GitHub 重跑说明](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)。

## 仓库配置

默认仓库为 `Teddy-Zhu/nginx_manage`，工作流使用实际运行仓库的 `github.repository`，镜像地址为 `ghcr.io/<小写 owner/repo>/nginx`。当前代码按公开仓库和公开镜像访问设计；仓库、GHCR 包可见性和访问权限由维护者设置，代码不会自动公开仓库或包。

在 GitHub 的 `release` environment 配置：

- Secret `RELEASE_ED25519_SEED`：Base64 编码的 32 字节 Ed25519 私钥种子。
- Variable `RELEASE_ED25519_PUBLIC_KEY`：与种子对应的 Base64 公钥。
- Variable `RELEASE_KEY_ID`：签名密钥标识，例如 `release-2026`。

私钥、公钥和 Key ID 必须匹配。环境保护和标签限制由仓库维护者配置。核心发布仅需 `contents:write`；Nginx 镜像构建需 `packages:write`，其签名发布任务同时需 `contents:write`。工作流使用 GitHub 提供的 Token，部署服务器不持有发布私钥。

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

发行先建立草稿，上传并核对全部资产，再公开。稳定核心版设为仓库 Latest；Beta 不会替代 Latest。`setup.sh` 从核心 Latest 下载与本机架构匹配的安装包。

## 独立发布 Nginx

Nginx 的发行说明和策略单独存放，版本不要求与核心一致：

```text
deploy/release/notes/nginx/1.30.6.md
deploy/release/policies/nginx/1.30.6.json
```

策略格式相同，`version` 使用 Nginx 组件发行版本。镜像基础版本和预置模块由 `deploy/docker/nginx.Dockerfile`、`nginx-capabilities.json` 与 `check-nginx-image.sh` 管理；需要调整基础版本或模块时先修改并提交这些文件。

```sh
git tag nginx-v1.30.6
git push origin nginx-v1.30.6
# 或对已存在标签手动触发：
gh workflow run nginx-release.yml -f tag=nginx-v1.30.6
```

工作流在 amd64、arm64 原生运行器分别构建镜像内的启动程序与 Nginx 镜像，执行组件检查和镜像模块门禁，推送原始摘要回执。合并任务只引用这些原始摘要，保留 BuildKit SBOM 和 SLSA 来源证据，再由 Go 发布工具独立核对并签名。

镜像同时具有版本标签，例如 `ghcr.io/teddy-zhu/nginx_manage/nginx:v1.30.6`。SemVer 构建元数据中的 `+` 在 Docker 标签中替换为 `_`。已有版本标签若指向不同摘要，发布停止；不覆盖旧版本。面板部署使用签名清单中的 `repository@sha256:...`，不依赖可变标签。

对应 GitHub Release 使用 `nginx-v1.30.6` 标签，包含 `release-manifest.json`、`release-manifest.sig`、`nginx.oci.json` 和 `checksums.txt`，不附带核心二进制或安装脚本，也不会成为仓库 Latest。`make_latest` 行为见 [GitHub Releases API](https://docs.github.com/en/rest/releases/releases#update-a-release)。

面板支持保存“稳定版 / Beta”更新通道，核心和 Nginx 共用此选择，刷新或重新登录后保留。稳定版核心使用仓库 Latest；Beta 核心与 Nginx 镜像按所选通道查询最近 100 个发行，选择最近发布的对应版本，没有匹配项时明确提示。核心/Nginx 与稳定/Beta 分别使用四个固定缓存槽位。指定确切标签仍可下载较早版本，Beta 须明确允许。

## 从分支发布 Beta（无需预先创建标签）

版本以 `-dev` 结尾时自动归入 Beta；其他 SemVer 预发布版本也归入 Beta。正式版本归入稳定版。签名清单使用 `stable` / `beta`，GitHub Release 的 Beta 标记为 prerelease，永不替代稳定版 Latest。

在 Actions 手动选择工作流，用上方 **Use workflow from** 选择源码分支，将 `tag` 留空，填写开发基础版本 `version`；默认基础版本为 `0.1.0-dev`。例如：

```sh
# 分支名按实际仓库填写；工作流文件需要已存在于仓库默认分支。
gh workflow run release.yml --ref main -f version=1.2.4-dev
gh workflow run nginx-release.yml --ref main -f version=1.30.6-dev
```

实际版本增加 GitHub run ID 和 attempt，例如 `1.2.4-123456789.1-dev`，防止不同源码复用同一版本。流程自动生成本次说明及明确关闭自动回滚的策略，发布阶段复用构建时已确定的版本；只重跑失败的发布任务不会改变版本。资产上传核对后自动创建指向构建提交的 GitHub 标签，无需事先手工打标签。核心与 Nginx 仍可分别发布。已有发行或部分草稿不会被覆盖，失败时查看保留的草稿后另行发起新构建。 自动生成的开发标签不再次触发构建，避免使用自定义令牌发布时重复运行；普通手工 `v1.2.4-dev` / `nginx-v1.30.6-dev` 标签仍可触发发布，需提交对应版本的说明和策略。

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

Nginx 规格使用 `--component nginx` 和 `notes/nginx/`、`policies/nginx/` 路径，打包时必须提供 `--images <经过核对的镜像 publication.json>`；核心打包不提供镜像输入。两种签名清单不混装核心资产与组件镜像。已有本机信任根继续限制仓库、公钥和接收协议，普通配置迁移不会覆盖信任根。

失败可能保留构建镜像或恢复草稿，流程不自动覆盖发行、删除草稿、忽略验签失败或发布不完整资产。实际 GitHub Actions、GHCR 推送及签名下载尚需在配置了上述凭据的真实仓库执行；本地检查不能代替实际发布结果。
