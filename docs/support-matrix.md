# 运行验收矩阵

截至 2026-10-22，项目仍处于 P5，尚未正式发布。下表记录实际完成的范围，未验收项继续属于首版交付目标。安装、组件能力探测和单项功能通过分别记录，不据此声明整个系统的全部功能已通过。

## 系统与部署

“原生”指原生 Web 加宿主 Agent；“Docker”指容器 Web 加宿主 Agent。已验收的容器 Nginx 来自项目预置模块镜像；原生静态 Nginx 为 1.30.6/OpenSSL 3.5.9，包含已核对的 36 个必需模块符号。[构建及运行证据](validation.md#原生-nginx-静态构建)不覆盖系统自带 Nginx 包或其他动态模块 ABI。

| 系统 | 架构 | 实际内核 | 原生 | Docker | 已运行 Nginx | 证据 |
| --- | --- | --- | --- | --- | --- | --- |
| Debian 12 | amd64 | 6.1.0-54-cloud-amd64 | 含/不含 Nginx 安装、权限及重启通过 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过 | 原生静态及 Docker 1.30.6 | [原生](validation.md#debian-原生安装与重启)、[Docker](validation.md#debian-12-与-ubuntu-2204amd64-docker-托管部署2026-10-22) |
| Debian 12 | arm64 | 6.1.0-54-cloud-arm64 | 含 Nginx 安装、权限、代理、回滚及重启通过 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过 | 原生静态及 Docker 1.30.6 | [原生](validation.md#debian-12arm64-原生静态-nginx-部署2026-10-21)、[Docker](validation.md#arm64-默认-docker-部署2026-10-22) |
| Debian 13 | amd64 | 6.12.113+deb13-cloud-amd64 | 不含 Nginx 的安装及重启通过 | 含 Nginx 的安装、重建、重启及指定更新恢复通过 | 容器预置 1.30.6 | [原生](validation.md#selinux-文件标签与-v14-原生安装)、[Docker](validation.md#debian-13-默认-docker-部署)、[更新](validation.md#debian-13-docker-签名升级运行路径) |
| Debian 13 | arm64 | 6.12.113+deb13-cloud-arm64 | 含 Nginx 安装、权限、代理、回滚及重启通过 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过 | 原生静态及 Docker 1.30.6 | [原生](validation.md#debian-13arm64-原生静态-nginx-部署2026-10-21)、[Docker](validation.md#arm64-默认-docker-部署2026-10-22) |
| Ubuntu 22.04 | amd64 | 5.15.0-198-generic | 含 Nginx 安装、权限、代理及重启通过；首轮即时断言失败未复现 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过 | 原生静态及 Docker 1.30.6 | [原生](validation.md#ubuntu-2204amd64-原生部署2026-10-21)、[Docker](validation.md#debian-12-与-ubuntu-2204amd64-docker-托管部署2026-10-22) |
| Ubuntu 22.04 | arm64 | 5.15.0-198-generic | 含/不含 Nginx 安装、权限、代理、回滚及重启通过；静态 Nginx 在 Cortex-A53 验收 | 托管 Web/Nginx 安装、代理、回滚、容器重建及整机重启通过，首次安装与续办分轮记录 | 原生静态及 Docker 1.30.6 | [Web/Agent](validation.md#ubuntu-2204arm64-原生-webagent-部署2026-10-21)、[静态 Nginx](validation.md#ubuntu-2204arm64-原生静态-nginx-部署2026-10-21)、[Docker](validation.md#ubuntu-2204arm64-docker-托管部署2026-10-21) |
| Ubuntu 24.04 | amd64 | 6.8.0-147-generic | 含 Nginx 安装、重启及指定升级恢复通过 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过 | 原生静态及 Docker 1.30.6 | [部署](validation.md#2026-10-20-ubuntu-2404-原生部署及探测-socket-恢复p5)、[升级](validation.md#2026-10-20-ubuntu-2404-原生协调升级及异常重启p5)、[Docker](validation.md#ubuntu-2404-与-2604amd64-docker-托管部署2026-10-22) |
| Ubuntu 24.04 | arm64 | 6.8.0-147-generic | 含 Nginx 的分阶段安装、权限、代理、回滚、重放及重启通过 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过 | 原生静态及 Docker 1.30.6 | [原生](validation.md#ubuntu-2404arm64-原生部署续验2026-10-21)、[Docker](validation.md#arm64-默认-docker-部署2026-10-22) |
| Ubuntu 26.04 | amd64 | 7.0.0-38-generic | 含 Nginx 的安装、权限、代理、回滚及重启业务检查与证据复核通过；采证首连失败保留 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过；AppArmor 启动器阻塞修复后完整复验 | 原生静态及 Docker 1.30.6 | [记录](validation.md#ubuntu-2604amd64-原生部署2026-10-21)、[Docker](validation.md#ubuntu-2404-与-2604amd64-docker-托管部署2026-10-22) |
| Ubuntu 26.04 | arm64 | 7.0.0-38-generic | 含 Nginx 的安装、权限、代理、两类回滚、安装重放及重启恢复通过；AppArmor 启用，应用进程 unconfined | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过；AppArmor 信号拒绝修复后完整复验 | 原生静态及 Docker 1.30.6 | [原生](validation.md#ubuntu-2604arm64-原生部署2026-10-21)、[Docker](validation.md#arm64-默认-docker-部署2026-10-22) |
| CentOS Stream 9 | amd64 | 5.14.0-758.el9.x86_64 | 含 Nginx 安装、权限及重启通过 | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过，SELinux Enforcing | 原生静态及 Docker 1.30.6 | [原生](validation.md#centos-stream-9amd64-原生部署与-selinux-续验2026-10-21)、[Docker](validation.md#centos-stream-910amd64-docker-托管部署2026-10-22) |
| CentOS Stream 9 | arm64 | 5.14.0-758.el9.aarch64 | 含 Nginx 安装、权限、代理、回滚及重启通过，SELinux Enforcing | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过，SELinux Enforcing | 原生静态及 Docker 1.30.6 | [原生](validation.md#centos-stream-910arm64-原生部署2026-10-21)、[Docker](validation.md#arm64-默认-docker-部署2026-10-22) |
| CentOS Stream 10 | amd64 | 6.12.0-277.el10.x86_64 | 含/不含 Nginx 安装、标签及重启通过，SELinux Enforcing | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过，SELinux Enforcing | 原生静态及 Docker 1.30.6 | [安装](validation.md#selinux-文件标签与-v14-原生安装)、[Nginx](validation.md#centos-原生-nginx-与身份切换)、[当前安装器](validation.md#centos-stream-10amd64-firewalld-原生生命周期2026-10-21)、[Docker](validation.md#centos-stream-910amd64-docker-托管部署2026-10-22) |
| CentOS Stream 10 | arm64 | 6.12.0-277.el10.aarch64 | 含 Nginx 安装、权限、代理、回滚及重启通过，SELinux Enforcing | 托管 Web/Nginx 安装、预检、回滚、重建及重启通过，SELinux Enforcing | 原生静态及 Docker 1.30.6 | [原生](validation.md#centos-stream-910arm64-原生部署2026-10-21)、[Docker](validation.md#arm64-默认-docker-部署2026-10-22) |

所有已验收部署均使用独立内核虚拟机；普通容器内的后端/接口检查不计作发行版或内核验收。Ubuntu 的 AppArmor 状态及实际进程标签、CentOS 的 Enforcing 和标签边界以对应记录为准；不宣称新增了专用 AppArmor/SELinux 进程策略。

## 网络与安全功能

以下均为 amd64 的具体组合。表内结果只覆盖链接列明的操作、中断点及恢复方式。

| 系统及部署 | 管理器/后端 | 实际流量路径 | 已执行范围 | 证据 |
| --- | --- | --- | --- | --- |
| Debian 12 Docker → Debian 13 原生 | 已预装受管 Nginx | API 配置迁入及映射后的 HTTP | 正常应用、Agent 中断补偿、版本冲突拒绝、目标重启及源端保持 | [迁移](validation.md#docker-到原生节点的配置迁移2026-10-22) |
| Debian 12 原生 | direct nftables | 主机 INPUT，IPv4/IPv6 | 受控管理监听、规则应用/确认及指定独立恢复 | [记录](validation.md#debian-双节点管理监听与-direct-nftables) |
| Ubuntu 24.04 原生 | iptables-nft | 主机 INPUT，IPv4/IPv6 | 应用/确认、独立恢复、移除及活动策略下协调升级 | [规则](validation.md#2026-10-21-iptables-检查时限与首次规则应用p5)、[升级](validation.md#2026-10-21-活动-iptables-策略下的协调升级与独立恢复) |
| Ubuntu 24.04 原生 | iptables-legacy | 主机 INPUT，IPv4/IPv6 | 应用/确认、Web 停止及整机重启恢复、移除 | [记录](validation.md#2026-10-21-原生-iptables-legacy-应用与恢复) |
| Ubuntu 24.04 原生 | UFW/nftables | 主机 INPUT，IPv4/IPv6 | 应用/确认、Web 停止及整机重启恢复、移除 | [记录](validation.md#p5-ubuntu-2404-原生-ufw-生命周期2026-10-21) |
| CentOS Stream 10 原生 | firewalld/nftables | 主机 INPUT，IPv4/IPv6 | 应用/确认、管理器重启、Web 停止及整机重启恢复、移除；原控制器末尾夹具误判，业务证据补充复核通过 | [记录](validation.md#centos-stream-10amd64-firewalld-原生生命周期2026-10-21) |
| Debian 12 原生 | 普通 resolv.conf | IPv4/IPv6/IPv6-only 实际 DNS | 解析、所有权、外部修改及指定独立恢复 | [记录](validation.md#debian-双节点普通文件-dns-与独立恢复) |
| Debian 13 原生 | networkd/resolved、NetworkManager/resolved、两种 netplan renderer | IPv4/IPv6/IPv6-only 实际 DNS | 静态源、分域保持及指定独立恢复 | [networkd](validation.md#debian-13-networkdresolved-与-netplannetworkd-dns)、[NetworkManager](validation.md#debian-13-networkmanagerresolved-与-netplannetworkmanager-dns) |
| Debian 13 原生 | 受管 Fail2ban，固定宿主机动作 | 双栈来源日志与主机封禁 | 官方代码安装、封禁/解封、轮转及指定重启恢复；amd64/Python 3.13/1.1.1 同版本签名资产升级、中断续办、失败补偿和补偿后重启 | [服务](validation.md#debian-13-fail2ban-官方代码与受管服务)、[动作](validation.md#2026-10-20-独立面板-fail2ban-宿主机动作p5)、[重启](validation.md#2026-10-20-fail2ban-同机整机重启与显式停用p5)、[升级](validation.md#fail2ban-升级的启动恢复批准) |

Ubuntu 22.04/arm64 的自定义 Docker bridge、iptables-nft 发布端口及联合规则范围已完成真实双栈 TCP/UDP、Agent 异常退出、整机重启恢复、外部 DOCKER-USER 规则保持和受管规则移除验收，见[记录](validation.md#docker-forward-实际内核准入续验2026-10-21)。结果限于该组合；主机 INPUT 结果不代表覆盖其他容器 FORWARD/DNAT 路径。Docker 原生 nftables 实验组合、其他系统、架构、管理器和故障点仍待验收，未经验收的 DNS 组合保持只读。

## 发布边界

基础监控的计数器重置、接口重建、启动/热插拔/采样中断、缺失值、维度上限及 SQLite 历史保留/容量配额已完成隔离边界验证；已在同一原生运行绑定下完成原生 Web、容器 Web、恢复原生 Web 的真实宿主 Agent 指标对照；Debian 12 与 Ubuntu 22.04/amd64 的正式 Docker 安装已完成重启前后宿主 Agent 指标验收，见[Docker](validation.md#debian-12-与-ubuntu-2204amd64-docker-托管部署2026-10-22)；Ubuntu 24.04 与 26.04/amd64 也已完成修正版的正式 Docker 指标对照，见[记录](validation.md#ubuntu-2404-与-2604amd64-docker-托管部署2026-10-22)；默认 Docker 矩阵已完成 14/14，见[ARM64 补验](validation.md#arm64-默认-docker-部署2026-10-22)；部署模式迁移和其他功能组合继续独立验收。原生绑定下的 Web 隔离见[对照记录](validation.md#同一宿主-agent-的-web-进程隔离指标对照2026-10-21)。预置模块镜像 amd64 已通过 TCP/UDP 双栈加权多上游、共享 UDP 检测、实际 IPv6 模式和双工作进程双栈 `reuseport`/HTTP 监听合并；其他发行包、架构、内核和完整原生发布事务不据此标记通过。见[监控记录](validation.md#监控边界与-stream-双栈权重2026-10-21)和[监听记录](validation.md#nginx-监听冲突ipv6-归属与端口复用2026-10-21)。

- 本地批准资产和隔离测试发行者的签名不替代正式 GitHub 发布链；实际仓库、发布密钥及正式 CI 尚未配置。arm64 预置模块镜像与[真实双架构验证包](validation.md#双架构镜像产物与-arm-执行2026-10-21)已生成，Ubuntu 22.04/arm64 的托管部署、恢复和重启通过，其余六组 ARM Docker 均已完成[部署及重启验收](validation.md#arm64-默认-docker-部署2026-10-22)。[arm64 原生静态 Nginx](validation.md#arm64-原生静态-nginx-构建2026-10-21)构建及 ELF/模块检查、Ubuntu 22.04 Cortex-A53 上的原生部署通过；原始程序和本地验证包不替代正式双架构发行。
- 真实域名 ACME/DNS、通知接收端及跨主机 API 迁移仍待外部集成验收；已有容器内双节点结果见[验证记录](validation.md#双节点-https-迁移与授权)。
- UI 由用户人工验收，未创建或运行 UI 自动化测试。
- 各轮使用的程序、安装器、镜像及证据散列见[验证记录](validation.md)。历史组合通过不代表后续版本已重跑，也不据此扩大已验证范围。
