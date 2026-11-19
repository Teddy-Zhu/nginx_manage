import type { ComponentOverview, ComponentTask } from "../api/client";
import {
  softwareStatus,
  standardServiceActions,
  type RuntimeState,
  type SoftwareOperation,
  type SoftwareView,
} from "../utils/software";

export interface BuiltinSoftwareView extends SoftwareView {
  id: "nginx" | "fail2ban" | "frps";
  runtime: RuntimeState;
  scopes: string[];
  actions: SoftwareOperation[];
  task?: ComponentTask;
  error?: string;
}

export function builtinSoftware(
  overview: ComponentOverview | null,
  tasks: ComponentTask[],
): BuiltinSoftwareView[] {
  const installed = overview?.scope === "host" ? !!overview.installation : null;
  const runtime: RuntimeState = overview?.running
    ? "running"
    : overview?.runtime_reason
      ? "unknown"
      : "stopped";
  const task = tasks.find(
    (task) =>
      task.result?.input.software?.action === "install-nginx" ||
      (task.action !== "software" &&
        (task.result?.input.components?.includes("nginx") ||
          (task.result?.release?.selected.includes("image-nginx") &&
            task.result.release.images.some((image) => image.id === "nginx")))),
  );
  const version = overview?.versions?.nginx;
  const engineVersion =
    version?.software_version || overview?.installation?.version;
  const nginx: BuiltinSoftwareView = {
    id: "nginx",
    name: "Nginx",
    category: "网站服务",
    description: "创建网站与反向代理，管理 HTTPS、上游服务和网站访问控制。",
    accent: "green",
    installed: installed === true,
    runtime,
    task,
    status: softwareStatus(installed, runtime, task),
    entry: { to: "/nginx" },
    note: engineVersion
      ? `Nginx ${engineVersion}`
      : version
        ? `组件 ${version.version}`
        : "系统内置",
    scopes: ["components.manage", "system.write"],
    actions: ["install", "update"],
    error: installed ? overview?.runtime_reason : undefined,
    versioned: true,
  };
  const services = [
    {
      id: "fail2ban",
      name: "Fail2ban",
      category: "登录防护",
      description: "保护 SSH、面板和网站登录。",
      accent: "amber",
      status: overview?.fail2ban,
    },
    {
      id: "frps",
      name: "FRP 服务端",
      category: "网络转发",
      description: "为内网客户端提供端口映射和网站转发。",
      accent: "blue",
      status: overview?.frps,
    },
  ] as const;
  return [
    nginx,
    ...services.map((service): BuiltinSoftwareView => {
      const installed =
        service.status?.installed ??
        (overview?.scope === "host" ? false : null);
      const runtime = service.status?.state ?? "unknown";
      const task = tasks.find(
        (task) => task.result?.input.software?.app_id === service.id,
      );
      const version = overview?.versions?.[service.id];
      return {
        id: service.id,
        name: service.name,
        category: service.category,
        description: service.description,
        accent: service.accent,
        installed: installed === true,
        runtime,
        task,
        status: softwareStatus(installed, runtime, task),
        entry: { to: "/" + service.id },
        note: version?.image_tag
          ? `镜像标签 ${version.image_tag}`
          : version
            ? `组件 ${version.version} · 软件 ${version.software_version ?? version.version}`
            : "系统内置",
        scopes:
          service.id === "fail2ban"
            ? ["components.manage", "system.write", "security.write"]
            : ["components.manage", "system.write"],
        actions: standardServiceActions,
        error: service.status?.error,
        versioned: true,
      };
    }),
  ];
}
