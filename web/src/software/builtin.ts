import { markRaw, type Component } from "vue";
import NginxInstallPanel from "../components/NginxInstallPanel.vue";
import type {
  ComponentOverview,
  ComponentTask,
  Fail2banContainerStatus,
  SoftwareRequest,
} from "../api/client";
import {
  fail2banRuntime,
  softwareStatus,
  standardServiceActions,
  type RuntimeState,
  type SoftwareOperation,
  type SoftwareView,
} from "../utils/software";

export interface SoftwareRuntimeSettings {
  image: string;
  auto_start: boolean;
}
export interface BuiltinSoftwareView extends SoftwareView {
  runtime: RuntimeState;
  scopes: string[];
  actions: SoftwareOperation[];
  task?: ComponentTask;
  error?: string;
  module?: string;
  settings?: SoftwareRuntimeSettings;
  request?: (
    action: SoftwareOperation | "configure",
    settings?: SoftwareRuntimeSettings,
  ) => SoftwareRequest;
  installTo?: string;
  installer?: Component;
  installerProps?: Record<string, unknown>;
}

// Integrations declare lifecycle operations here. Feature editors stay on their own routes.
export function builtinSoftware(
  overview: ComponentOverview | null,
  fail2ban: Fail2banContainerStatus | null,
  tasks: ComponentTask[],
  active: boolean,
): BuiltinSoftwareView[] {
  const frps = overview?.frps;
  const definitions = [
    {
      id: "nginx",
      name: "Nginx",
      category: "网站服务",
      description: "创建网站与反向代理，管理 HTTPS、上游服务和网站访问控制。",
      accent: "green" as const,
      installed: overview?.scope === "host" ? !!overview.installation : null,
      runtime: overview?.running
        ? ("running" as const)
        : overview?.runtime_reason
          ? ("unknown" as const)
          : ("stopped" as const),
      task: tasks.find(
        (task) =>
          task.action !== "software" &&
          (task.result?.input.components?.includes("nginx") ||
            task.result?.release?.assets.some(
              (asset) => asset.component === "nginx",
            )),
      ),
      entry: { to: "/nginx" },
      note: overview?.installation
        ? `版本 ${overview.installation.version}`
        : "系统内置",
      scopes: ["components.manage"],
      actions: ["install", "update"] as SoftwareOperation[],
      error: overview?.runtime_reason,
      installer: markRaw(NginxInstallPanel),
      installerProps: { overview, tasks, active },
    },
    {
      id: "fail2ban",
      name: "Fail2ban",
      category: "安全防护",
      description: "自动封禁反复登录失败的 IP，保护 SSH、管理面板和网站。",
      accent: "blue" as const,
      installed: fail2ban?.installed ?? null,
      runtime: fail2banRuntime(fail2ban),
      task: tasks.find(
        (task) => task.result?.input.software?.action === "fail2ban",
      ),
      entry: { to: "/fail2ban" },
      note: "系统内置",
      scopes: ["components.manage", "system.write", "security.write"],
      actions: standardServiceActions,
      module: "fail2ban",
      error: fail2ban?.error,
      settings: fail2ban?.config,
      request: (
        action: SoftwareOperation | "configure",
        settings?: SoftwareRuntimeSettings,
      ): SoftwareRequest => ({
        action: "fail2ban",
        fail2ban: {
          action,
          ...(["install", "configure"].includes(action) && fail2ban
            ? { config: { ...fail2ban.config, ...settings } }
            : {}),
        },
      }),
    },
    {
      id: "frps",
      name: "FRP 服务端",
      category: "网络连接",
      description:
        "接入内网客户端，提供 TCP、UDP 端口映射和 HTTP、HTTPS 网站转发。",
      accent: "green" as const,
      installed: frps?.installed ?? null,
      runtime: frps?.state ?? ("unknown" as const),
      task: tasks.find(
        (task) => task.result?.input.software?.action === "frps",
      ),
      entry: { to: "/frps" },
      note: frps?.stats?.version ? `版本 ${frps.stats.version}` : "系统内置",
      scopes: ["components.manage", "system.write"],
      actions: standardServiceActions,
      error: frps?.error,
      settings: frps?.config,
      installTo: "/frps?install=1",
      request: (
        action: SoftwareOperation | "configure",
        settings?: SoftwareRuntimeSettings,
      ): SoftwareRequest => ({
        action: "frps",
        frps: {
          action,
          ...(action === "configure" && frps
            ? { config: { ...frps.config, ...settings } }
            : {}),
        },
      }),
    },
  ];
  return definitions.map((item) => ({
    ...item,
    installed: item.installed === true,
    status: softwareStatus(item.installed, item.runtime, item.task),
  }));
}
