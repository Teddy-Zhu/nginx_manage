const labels: Record<string, string> = {
  read: "查看状态与日志",
  "config.write": "管理网站配置",
  "config.secrets": "查看配置凭据",
  "security.write": "管理安全规则",
  "system.write": "管理系统设置",
  "host.dns.write": "管理系统 DNS",
  "monitoring.write": "管理监控",
  "components.manage": "安装和更新软件",
  "auth.manage": "管理授权",
  "backup.export": "导出备份",
  "backup.secrets": "备份敏感配置",
  "backup.restore": "恢复备份",
  "update.execute": "执行更新",
  "nodes.manage": "管理远程服务器",
  "notifications.write": "管理通知",
};
export function permissionLabel(scope: string) {
  return labels[scope] ?? "其他权限";
}
