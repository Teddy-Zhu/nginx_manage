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

菜单支持部署信息、服务状态、启停/重启、服务日志、初始化令牌、主入口证书指纹和远程管理入口救援。非引导安装也可从可信安装包运行 `sudo bash manage.sh`，脚本读取现有 root 安装记录，不执行其中的文本。

```sh
sudo bash /opt/nginxpanel/manage.sh info
sudo bash /opt/nginxpanel/manage.sh status
sudo bash /opt/nginxpanel/manage.sh restart panel
sudo bash /opt/nginxpanel/manage.sh logs agent --lines 200
sudo bash /opt/nginxpanel/manage.sh logs panel --follow
sudo bash /opt/nginxpanel/manage.sh fingerprint
```

`start/stop/restart` 默认仅操作 panel，可选择 `agent`、`nginx` 或 `all`；`all` 跳过明确未安装的 Nginx。非交互变更须加 `--yes`，交互变更先确认影响。原生使用 systemd，容器服务使用已生成的 Compose，宿主机 Agent 始终使用 systemd。

Docker 状态同时显示容器及面板实际进程，容器停止时后者不可查询；容器已运行不等于业务已就绪。宿主机工具版本由 `info` 展示，当前面板程序版本仍按网页核对。

脚本遇到持久停机或恢复屏障时拒绝常规启动/重启面板。维护、更新和完整恢复继续沿原任务处理；日常服务停止不替代持久停机准备。

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

1. 下载并离线保存一次完整备份，确认解密材料可取得。
2. 核对当前节点和部署方式，阅读目标发行说明、停机范围、数据库要求及可恢复条件。
3. 在“组件准备”选择在线检查/获取或离线签名上传。材料准备成功只表示资产就绪。
4. 进入“配置维护”，等待已有写入和宿主机操作结束，取得原维护会话。
5. 按实际更新对象进入对应页面，预览并明确提交。
6. 跟随同一任务，核对目标版本及运行结果；完成或补偿确认后释放原维护会话。

| 更新对象 | 页面 |
| --- | --- |
| 尚未安装的原生 Nginx | 组件安装 |
| 已安装的原生 Nginx | 组件切换 |
| 面板程序和前端 | 面板更新 |
| 宿主机 Agent 与固定工具 | Agent 升级 |
| Docker 面板 launcher 运行镜像 | 运行镜像 |
| Docker Nginx 镜像 | Nginx 镜像 |

镜像下载与运行替换分别进行。Docker 更新前保留旧、新两个已批准镜像；Nginx 缺失模块通过准备具有所需能力的完整镜像解决。需要同时变更面板和 Agent 时使用页面提供的协调更新选项；运行镜像协议有独立要求时先按对应流程处理。

断连后查询原任务，结果未知时保留原 UUID、维护会话和恢复材料。明确要求续办时使用原任务入口；“配置维护”释放失败时先处理其报告的活动操作。

固定本机命令、签名输入及 root 救援入口见[发行与更新参考](releases.md)、[Docker 维护参考](../deploy/docker/README.md)。

## 配置应用失败或外部变更

按以下顺序判断：

1. 查看“任务与审计”中的原任务、失败阶段和最终状态。
2. 在“Nginx 配置”比较当前期望修订与已应用修订。
3. 配置检查失败时修正指令、依赖、证书或端口条件，再保存新修订。
4. 已切换后失败时查看补偿是否完成；`rolled_back` 表示恢复结果，`recovery_required` 表示仍需处理。
5. 检测到运行配置外部变化时，先读取差异或捕获为草稿，明确选择保留外部内容或恢复受管配置；使用页面提供的当前快照和恢复入口。

受管目录、发布指针和恢复记录由执行器维护。手工覆盖它们会破坏后续核对所需的依据。配置应用不会自动改换二进制、接管另一个 Nginx 实例或修改外部网络。

## 网络变更恢复

### 管理入口失联

先恢复 SSH 转发到主回环入口。用新的浏览器连接查看原监听操作，候选未确认时等待其期限或请求回滚。

需要从本机停用所有可选远程入口时：

```sh
sudo /opt/nginxpanel/current/nginxpanel management-listener-disable \
  --data-dir /srv/nginxpanel
```

返回 `requested` 表示救援标记已保存；Agent 运行时处理，未运行则在下次恢复监听前处理。主回环 TLS 与管理员身份保持原有配置。详细行为见[管理入口参考](management-listener.md)。

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
| 无法打开 9443 | SSH 转发是否运行、目标 Web 服务/容器是否正常、本地端口是否占用 | 初始入口仅监听目标回环；远程使用 SSH 转发或已确认管理入口 |
| 浏览器提示证书不可信 | 地址、证书有效期、通过可信 SSH 取得的指纹 | 核对本节点证书后建立信任；管理入口换证书后更新相应节点信任 |
| 显示初始化页面 | 是否连接预期节点、管理员是否尚未创建 | 从目标 `DATA/bootstrap/token` 取得一次性令牌 |
| 忘记管理员密码 | 是否仍有可重新认证的会话、是否有完整备份 | 系统无默认密码和通用的一键重置入口；保留数据与密钥，按可用恢复材料处理 |
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
| 备份不能下载 | 原任务是否完成、权限/近期认证、票据及文件身份 | 浏览器重新取得一次性票据并完整下载；保留独立的解密材料 |

## 容量、清理与停用

先通过日志轮转、备份保留策略及“历史维护”的预览处理可清理材料。清理备份文件后，必要的记录和审计仍会保留；达到记录容量上限时以具体错误为准，不能把删除文件等同于减少所有记录。

当前使用、回滚或未完成任务引用的材料不能随意删除。不要递归修改整个数据根的所有权；Web、Agent 和 worker 的目录权限具有不同用途。

当前没有覆盖所有部署和授权对象的通用一键卸载流程。停用系统前，先导出/备份并处理在途任务，按对应模块明确解除本应用规则或授权，再停止对应服务/容器。保留业务数据和恢复记录，账户、unit、镜像及 SELinux 策略按实际安装记录逐项处理。

## 提交故障信息

提供部署方式、系统/架构、程序版本、目标节点编号、操作步骤、原任务/操作编号、错误码和发生时间。分享前移除 Token、Cookie、私钥、备份口令、DNS 密钥和含业务秘密的完整配置。
