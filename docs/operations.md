# 运维与故障处理

[文档首页](README.md) · [部署指南](deployment.md) · [使用手册](user-guide.md)

本文用于已部署节点的日常维护。命令示例在实际目标主机执行，数据目录按实际安装值替换。遇到未完成的维护或恢复任务时，先查询原操作，避免另建相互冲突的变更。

## 目录与需要保管的材料

| 位置 | 用途 |
| --- | --- |
| `/etc/nginxpanel/` | 安装记录、本机发行信任、Docker Compose 等 root 管理配置 |
| `/opt/nginxpanel/current/` | 已批准的宿主机 Agent、安装和本机维护程序 |
| `DATA/runtime/` | 面板不可变版本及当前运行选择 |
| `DATA/app/` | 业务 SQLite 数据及相关业务材料 |
| `DATA/secrets/` | 主密钥和主入口 TLS 等秘密 |
| `DATA/agent/` | root 私有执行、授权和恢复记录 |
| `DATA/nginx/`、`DATA/modules/` | Nginx 配置发布及批准模块 |
| `DATA/logs/` | 受管日志 |
| `DATA/run/` | 锁、通信与运行协调材料 |

`DATA` 在示例中为 `/srv/nginxpanel`。业务数据库和配套密钥必须匹配；迁移、备份和本机恢复材料的用途各不相同。日常使用“完整备份”取得一致性加密备份，保留离线副本及独立的解密材料。

## 日常服务操作

### 管理脚本

引导安装后使用：

```sh
sudo bash /opt/nginxpanel/manage.sh
```

菜单支持部署信息、服务状态、启停/重启、服务日志、初始化令牌、主入口证书指纹、监听端口修改、附加管理入口救援、卸载和重新安装。非引导安装也可从 root 批准的完整安装包运行 `sudo bash manage.sh`，卸载脚本须随包保留；脚本读取现有 root 安装记录，不执行其中的文本。

```sh
sudo bash /opt/nginxpanel/manage.sh info
sudo bash /opt/nginxpanel/manage.sh status
sudo bash /opt/nginxpanel/manage.sh restart panel
sudo bash /opt/nginxpanel/manage.sh logs agent --lines 200
sudo bash /opt/nginxpanel/manage.sh logs panel --follow
sudo bash /opt/nginxpanel/manage.sh fingerprint
sudo bash /opt/nginxpanel/manage.sh set-port 23456
```

`start/stop/restart` 默认仅操作 panel，可选择 `agent`、`nginx` 或 `all`；`all` 跳过明确未安装的 Nginx。非交互变更须加 `--yes`，交互变更先确认影响。原生使用 systemd，容器服务使用已生成的 Compose，宿主机 Agent 始终使用 systemd。Docker 操作固定使用本机 `/run/docker.sock`，不沿用远程 Docker context。

Docker 状态同时显示容器及面板实际进程，容器停止时后者不可查询；容器已运行不等于业务已就绪。宿主机工具版本由 `info` 展示，当前面板程序版本仍按网页核对。

脚本遇到持久停机或恢复屏障时拒绝常规启动/重启面板。维护、更新和完整恢复继续沿原任务处理；日常服务停止不替代持久停机准备。

`set-port` 允许 1024–65535，支持 `--yes`；运行中的面板自动停止、保存并启动，已停止的面板保持停止。新端口绑定失败保留原配置，维护与恢复屏障下拒绝修改。`info` 从当前运行绑定读取端口；初始安装意图用于记录首次安装参数，不表示当前端口。修改前放行新端口对应的云安全组和防火墙规则。

`bootstrap` 只读取原一次性引导令牌，不能重置已有管理员。需停用可选远程入口时，执行 `disable-remote` 并核对返回状态与 Agent 处理结果。

### 原生部署

```sh
sudo systemctl status nginxpanel.service nginxpanel-agent.service
sudo journalctl -u nginxpanel.service -u nginxpanel-agent.service --since '1 hour ago' --no-pager
```

安装了原生 Nginx 时：

```sh
sudo systemctl status nginxpanel-nginx.service
sudo journalctl -u nginxpanel-nginx.service --since '1 hour ago' --no-pager
```

没有在途维护或恢复任务时，常规重启面板和 Agent 可分别执行：

```sh
sudo systemctl restart nginxpanel.service
sudo systemctl restart nginxpanel-agent.service
```

面板、Agent 和 Nginx 是独立服务。配置更新优先使用网页应用流程；重启 Nginx 可能中断业务，需单独安排。

### Docker 部署

```sh
sudo systemctl status nginxpanel-agent.service
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml ps
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml logs --tail 100 panel
```

使用原安装生成的配置启动或重建：

```sh
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml up -d
```

没有在途维护或恢复任务时，只重启 Web 容器：

```sh
sudo docker compose -f /etc/nginxpanel/docker/compose.yaml restart panel
```

Compose 同时包含 Nginx 时，停止整个项目会影响代理流量。镜像和挂载变更使用对应维护流程，保留系统批准记录与实际容器身份的一致性。

## 组件准备与更新

常规面板更新在“设置 → 系统更新”完成：

1. 按需通过“备份恢复”保存完整备份，阅读目标发行说明。
2. 点击“检查更新”，再点击“下载更新”，等待签名校验和准备完成。
3. 点击“立即更新”。宿主 Agent 完成替换及重启，面板启动后自动迁移数据。
4. 短暂断连后重新连接，查看原任务的结果。Docker 部署自动拉取对应镜像并重新创建面板容器，原生部署切换程序并重启服务。

更新失败时保留原任务与日志，根据错误处理；数据库已迁移后不自动强行降级。需要更新宿主 Agent 或安装工具的发行，使用安装脚本完成部署。常规更新不能绕过已有的停机或恢复屏障。

Fail2ban 和第三方软件在“软件商店”独立更新，先拉取镜像，再替换其容器；数据保留，启动失败时尝试恢复原容器。详见[软件源说明](software-sources.md)。

Nginx 的安装与运行替换沿其独立流程处理，不随面板更新更换。缺少模块时使用预置所需能力的完整镜像。需要本机维护或救援时，固定命令及签名输入见[发行与更新参考](releases.md)、[Docker 维护参考](../deploy/docker/README.md)；这些专门接口的维护会话要求不属于日常面板更新步骤。

## 配置应用失败或外部变更

按以下顺序判断：

1. 查看“任务与审计”中的原任务、失败阶段和最终状态。
2. 在“网站与代理”的“更多操作 → 配置差异”中比较当前编辑内容与已生效配置。
3. 配置检查失败时修正指令、依赖、证书或端口条件，再保存配置。
4. 已切换后失败时查看补偿是否完成；`rolled_back` 表示恢复结果，`recovery_required` 表示仍需处理。
5. 检测到运行配置外部变化时，先读取差异，选择将外部内容载入编辑区并保存，或恢复面板中已保存的配置。

受管目录、发布指针和恢复记录由执行器维护。手工覆盖它们会破坏后续核对所需的依据。配置应用不会自动改换二进制、接管另一个 Nginx 实例或修改外部网络。

## 网络变更恢复

### 管理入口失联

运行管理脚本 `info` 查看当前主入口，并使用输出的 SSH 转发命令恢复访问。用新的浏览器连接查看原监听操作，候选未确认时等待其期限或请求回滚。

需要从本机停用所有可选远程入口时：

```sh
sudo /opt/nginxpanel/current/nginxpanel management-listener-disable \
  --data-dir /srv/nginxpanel
```

返回 `requested` 表示救援标记已保存；Agent 运行时处理，未运行则在下次恢复监听前处理。主入口的地址、TLS 与管理员身份保持原有配置；此命令只关闭附加监听，不关闭默认主入口。详细行为见[管理入口参考](management-listener.md)。

### DNS 或防火墙未确认

使用原操作的状态和回滚入口处理。DNS、防火墙和管理监听的限时操作有互斥边界；先完成恢复，再开始新的网络变更。

无法远程访问时，通过 SSH/控制台查看 Agent 日志和对应本机恢复记录。防火墙各后端的 root 恢复入口见[防火墙参考](firewall.md)。保留第三方规则及原始快照，避免整体清空规则或切换系统后端。

## 完整备份恢复

完整恢复会替换目标业务数据，必须按阶段进行。选择灾备或克隆模式，使用与备份匹配的程序、数据版本及目标批准组件；跨环境只搬业务配置时使用[配置迁移](migration.md)。

| 顺序 | 阶段 | 结果与下一步 |
| --- | --- | --- |
| 1 | [离线检查](backups.md#离线检查) | 验证加密文件、配套材料、版本和身份，不写入目标业务数据 |
| 2 | [停机准备](backups.md#停机恢复准备) | 持有原维护会话并取得持久停机边界，解密到固定暂存位置 |
| 3 | [材料接入](backups.md#固定材料接入与目标回退依据) | root 接入固定材料并建立目标原状态的回退依据 |
| 4 | [目标计划](backups.md#目标恢复计划) | 检查目标组件、能力、路径/监听映射及需处理的差异 |
| 5 | [文件安装](backups.md#独立文件安装与补偿) | 按原计划安装固定文件，保留恢复屏障和补偿入口 |
| 6 | [运行应用](backups.md#恢复-nginx-运行配置) | 用目标批准的 Nginx 应用恢复配置并确认运行 |
| 7 | [数据对账](backups.md#恢复数据对账) | 核对数据库、已应用修订和源在途任务的隔离 |
| 8 | [外部结果复核](backups.md#外部结果复核) | 按恢复报告核对业务入口和需要明确处理的外部结果 |
| 9 | [最终激活](backups.md#最终激活) | 明确不可回退边界，完成原维护会话释放与正式启用 |

各阶段命令、输入 JSON 和审批材料在链接章节中给出，操作标识使用实际新建的 UUID。普通停止服务不构成持久停机准备。文件已复制或 Nginx 已运行均不代表最终激活完成。

出现中断时查询原恢复状态，根据当前阶段续办或补偿。源主机 root 授权、系统服务和防火墙运行规则不会因完整备份自动取得目标权限。

## 常见问题

| 现象 | 先检查 | 处理方向 |
| --- | --- | --- |
| 无法打开管理入口 | `manage.sh info` 的实际端口、目标服务状态、端口占用及安全组/防火墙 | 默认端口随机并对外监听；使用可达的机器 IP，必要时使用输出的 SSH 转发命令 |
| 浏览器提示证书不可信 | 地址、证书有效期、通过可信 SSH 取得的指纹 | 核对本节点证书后建立信任；管理入口换证书后更新相应节点信任 |
| 显示初始化页面 | 是否连接预期节点、管理员是否尚未创建 | 从目标 `DATA/bootstrap/token` 取得一次性令牌 |
| 忘记管理员密码 | 是否仍有有效登录会话、是否有完整备份 | 可用会话可在设置中修改密码；系统无默认密码和通用的一键重置入口，无法登录时保留数据与密钥并按可用恢复材料处理 |
| Agent 不可用 | Agent 服务、Unix Socket、安装账户/组、组件版本和维护状态 | 使用匹配版本及原安装权限修复，不向普通用户开放 root 目录 |
| 登录成功但代理不通 | 是否已应用、Nginx 是否运行、监听与上游、云安全组及系统规则 | 区分管理入口、客户端到代理、代理到上游三条链路 |
| 应用时端口占用 | 目标监听端口及既有系统服务 | 用 `sudo ss -lntup` 定位，调整监听或安排原服务切换 |
| 报缺模块/未知指令 | 目标 Nginx 实际能力、批准的原生模块、镜像能力 | 原生批准匹配模块，Docker 更换预置所需模块的受信镜像 |
| DNS、防火墙、轮转按钮只读 | 所有者、安装范围、root 登记、模块开关及实时诊断 | 按对应授权流程处理；模块开关本身不授予系统权限 |
| 返回版本冲突 | 其他操作或节点状态是否已变化 | 重新读取、比较变化并生成新计划 |
| 更新、迁移超时 | 原任务是否已受理，是否仍在执行或待恢复 | 查询原任务，核对后按原入口续办 |
| ACME 失败 | CA 错误、域名解析、HTTP-01 公网 80、DNS 权限与传播、残留挑战 | 先处理原订单与清理，再考虑新签发 |
| Telegram/Webhook 投递失败 | 端点、Token、会话权限、出站网络和队列错误 | 查看同一投递的重试/过期状态；修复渠道后按需重新测试 |
| 迁移缺组件 | 目标实际安装状态、发行信任、组件权限、架构与模块 | 明确授权准备/安装，完成后重新预检；保留真实阻塞原因 |
| 备份不能下载 | 原任务是否完成、登录状态与权限、票据及文件身份 | 浏览器重新取得一次性票据并完整下载；保留独立的解密材料 |

## 容量、清理与停用

先通过日志轮转、备份保留策略及“历史维护”的预览处理可清理材料。清理备份文件后，必要的记录和审计仍会保留；达到记录容量上限时以具体错误为准，不能把删除文件等同于减少所有记录。

当前使用、回滚或未完成任务引用的材料不能随意删除。不要递归修改整个数据根的所有权；Web、Agent 和 worker 的目录权限具有不同用途。

### 卸载与重新安装

```sh
# 保留数据卸载，也是 uninstall 的默认方式
sudo bash /opt/nginxpanel/manage.sh uninstall --keep-data
# 恢复卸载前版本；已安装时也可直接执行，自动完成卸载与重装
sudo bash /opt/nginxpanel/manage.sh reinstall
# 完全卸载，永久删除本系统数据
sudo bash /opt/nginxpanel/manage.sh uninstall --purge
```

三种操作均先确认影响；非交互执行需加 `--yes`。卸载会停止代理流量。

若提示 `unknown subcommand "installation-removal-check"`，说明管理脚本与已安装宿主程序版本不同，该检查发生在删除之前。从最新源码或完整安装包执行 `sudo bash install.sh --uninstall --keep-data` 或 `sudo bash install.sh --uninstall --purge`，入口会使用新工具检查旧安装；源码仅在 Docker 中编译。尚未使用、希望清空原数据并安装当前版本时使用 `sudo bash install.sh --fresh`。具体步骤见[旧版本处理](deployment.md#旧版本卸载与未使用环境更新)。

| 操作 | 清理与保留范围 |
| --- | --- |
| 保留数据卸载 | 停止并移除本应用原生服务或容器，移除部署程序、服务 unit、对应 drop-in 和 tmpfiles 配置；原数据根保持不动，保留账号数据、密钥、证书、配置、日志、备份及执行记录。`DATA/.installation/` 保存原版本和主机安装配置的重装材料；保留两个小型管理脚本、最小安装记录、专用账户及数据所需的 SELinux 标签规则 |
| 重新安装 | 校验本机重装材料，恢复卸载前的版本、服务文件和主机安装配置；保留当前数据、节点身份及后来修改的监听端口，恢复原开机设置和运行/停止状态。已停止的可选组件保持停止，不下载软件或拉取镜像 |
| 完全卸载 | 在卸载服务和程序后，删除整个数据根、重装材料、`/opt/nginxpanel`、`/etc/nginxpanel`，清理未被外部改动的专用账户/组及本应用 SELinux 模块；之后使用源码或 Release 安装入口全新安装 |

保留数据卸载后，再次执行 `install.sh` 会接入本机重装流程，恢复卸载前版本；更换版本仍使用更新入口。重装材料只能用于原主机恢复安装，跨机器仍使用[配置迁移或备份恢复](user-guide.md)。材料可能包含秘密，保持 root 私有权限；保留数据卸载需要足够空间保存原程序及主机安装配置。

脚本会拒绝未结束/待恢复任务、维护 worker、持久停机/恢复屏障、未解除的防火墙登记、Fail2ban 宿主机同步及外部 jail 接管，并给出对应处理入口。先完成原任务，按原模块解除授权或移除本应用规则，再卸载；不会自动重置宿主机 DNS、清空整机防火墙、停止系统 Nginx 或外部 Fail2ban。系统包、Docker、Python、共享镜像、系统日志及用户导出到数据根之外的文件不在清理范围。

卸载或重装中断时保留阶段记录，修复具体错误后重复原命令；完全卸载不创建程序重装包，进入清理阶段后只能续办 `uninstall --purge`。清理过程中本机管理脚本已被删除时，可从 root 批准的完整安装包运行相同命令续办。数据根或安装范围内存在挂载点时明确拒绝清理，需管理员先处理挂载。保留数据卸载可跨重启后重新安装；重装失败时原数据不删除，按提示检查服务/容器日志并续办。

## 提交故障信息

提供部署方式、系统/架构、程序版本、目标节点编号、操作步骤、原任务/操作编号、错误码和发生时间。分享前移除 Token、Cookie、私钥、备份口令、DNS 密钥和含业务秘密的完整配置。
