import { markRaw } from "vue";
import Fail2banInstallPanel from "../components/Fail2banInstallPanel.vue";
import NginxInstallPanel from "../components/NginxInstallPanel.vue";
import type {
  ComponentOverview,
  ComponentTask,
  Fail2banContainerStatus,
} from "../api/client";
import {
  fail2banRuntime,
  softwareStatus,
  type SoftwareView,
} from "../utils/software";

// Built-in integrations register their state adapter, entry and detail panel here.
// Store templates and third-party sources do not interpret application IDs.
export function builtinSoftware(
  overview: ComponentOverview | null,
  fail2ban: Fail2banContainerStatus | null,
  tasks: ComponentTask[],
  active: boolean,
) {
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
          task.result?.input.components?.includes("nginx"),
      ),
      entry: { to: "/nginx" },
      note: overview?.installation
        ? `版本 ${overview.installation.version}`
        : "系统内置",
      scopes: ["components.manage"],
      panel: markRaw(NginxInstallPanel),
      panelProps: { overview, tasks, active },
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
      panel: markRaw(Fail2banInstallPanel),
      panelProps: { embedded: true },
    },
  ];
  return definitions.map(
    (item) =>
      ({
        ...item,
        installed: item.installed === true,
        status: softwareStatus(item.installed, item.runtime, item.task),
      }) satisfies SoftwareView & object,
  );
}
