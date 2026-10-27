import type {
  ComponentOverview,
  Fail2banContainerStatus,
  SoftwareCatalog,
  ComponentTask,
  SoftwareRequest,
} from "../api/client";

export function softwareCatalogEntries(catalog?: SoftwareCatalog) {
  return (catalog?.sources ?? []).flatMap((source) => {
    const installations = (catalog?.installed ?? []).filter(
      (item) => item.source_id === source.id,
    );
    const applications = [
      ...source.applications,
      ...installations
        .filter(
          (item) =>
            !source.applications.some((app) => app.id === item.application.id),
        )
        .map((item) => item.application),
    ];
    return applications.map((application) => ({
      source,
      application,
      listed: source.applications.some((app) => app.id === application.id),
      installation: installations.find(
        (item) => item.application.id === application.id,
      ),
    }));
  });
}

export type SoftwareState =
  "installed" | "missing" | "unbound" | "recovery" | "unavailable";

export function nginxState(view: ComponentOverview | null): SoftwareState {
  if (!view || view.scope !== "host") return "unavailable";
  return view.installation ? "installed" : "missing";
}

export function fail2banState(
  view: Fail2banContainerStatus | null,
): SoftwareState {
  if (!view) return "unavailable";
  return view.installed ? "installed" : "missing";
}

export function fail2banStatusLabel(
  view: Fail2banContainerStatus | null,
): string {
  return softwareStatus(view ? view.installed : null, fail2banRuntime(view))
    .label;
}

export type RuntimeState =
  "running" | "starting" | "stopped" | "unhealthy" | "missing" | "unknown";
export type SoftwareOperation =
  "install" | "start" | "stop" | "restart" | "update" | "uninstall" | "logs";
export type StatusTone = "default" | "success" | "warning" | "error" | "info";
export interface SoftwareStatus {
  state: RuntimeState | "uninstalled" | "busy" | "recovery";
  label: string;
  tone: StatusTone;
}
export interface SoftwareEntry {
  to?: string;
  href?: string;
}
export interface SoftwareView {
  id: string;
  name: string;
  description: string;
  category: string;
  accent: "green" | "blue" | "amber";
  installed: boolean;
  status: SoftwareStatus;
  entry?: SoftwareEntry;
  note: string;
}
export const softwareOperationLabels: Record<SoftwareOperation, string> = {
  install: "安装",
  start: "启动",
  stop: "停止",
  restart: "重启",
  update: "更新",
  uninstall: "卸载",
  logs: "服务日志",
};
const pendingLabels: Record<string, string> = {
  install: "安装中",
  start: "启动中",
  stop: "停止中",
  restart: "重启中",
  update: "更新中",
  uninstall: "卸载中",
  logs: "读取日志中",
  configure: "保存中",
};
export function softwareTaskActive(task?: ComponentTask) {
  return (
    !!task &&
    task.stage !== "restore_isolated" &&
    ["queued", "running", "recovery_required"].includes(task.state)
  );
}
export function softwareTaskLabel(task: ComponentTask) {
  if (task.action !== "software")
    return (
      {
        check: "检查软件版本",
        prepare: "下载软件",
        pull: "下载运行环境",
        activate: "更新面板界面",
      }[task.action] ?? "软件操作"
    );
  const request = task.result?.input.software;
  const action =
    request?.action === "frps"
      ? request.frps?.action
      : request?.action === "fail2ban"
        ? request.fail2ban?.action
        : request?.action;
  if (action && action in softwareOperationLabels)
    return `${softwareOperationLabels[action as SoftwareOperation]}${request?.action === "frps" ? " · FRP 服务端" : request?.action === "fail2ban" ? " · 登录防护" : ""}`;
  const labels: Record<string, string> = {
    import: "添加软件源",
    refresh: "更新软件列表",
    delete: "删除软件源",
    configure: "保存软件设置",
    "update-panel": "系统更新",
  };
  return labels[action ?? ""] ?? "软件操作";
}
export function softwareStatus(
  installed: boolean | null,
  runtime: RuntimeState = "unknown",
  task?: ComponentTask,
): SoftwareStatus {
  if (softwareTaskActive(task)) {
    if (task?.state === "recovery_required")
      return { state: "recovery", label: "需要处理", tone: "warning" };
    const request = task?.result?.input.software;
    const action =
      request?.action === "frps"
        ? request.frps?.action
        : request?.action === "fail2ban"
          ? request.fail2ban?.action
          : request?.action;
    return {
      state: "busy",
      label: pendingLabels[action ?? ""] ?? "处理中",
      tone: "info",
    };
  }
  if (installed === null)
    return { state: "unknown", label: "状态不可用", tone: "warning" };
  if (!installed)
    return { state: "uninstalled", label: "未安装", tone: "default" };
  return {
    running: { state: "running", label: "运行中", tone: "success" },
    starting: { state: "starting", label: "正在启动", tone: "info" },
    stopped: { state: "stopped", label: "已停止", tone: "warning" },
    unhealthy: { state: "unhealthy", label: "运行异常", tone: "error" },
    missing: { state: "missing", label: "需要修复", tone: "error" },
    unknown: { state: "unknown", label: "状态不可用", tone: "warning" },
  }[runtime] as SoftwareStatus;
}
export function fail2banRuntime(
  view: Fail2banContainerStatus | null,
): RuntimeState {
  return view?.state ?? "unknown";
}
export const standardServiceActions: SoftwareOperation[] = [
  "install",
  "start",
  "stop",
  "restart",
  "update",
  "uninstall",
  "logs",
];
export function softwareControls(
  installed: boolean,
  runtime: RuntimeState,
  available: SoftwareOperation[],
) {
  const actions: SoftwareOperation[] = installed ? [] : ["install"];
  if (installed) {
    if (runtime === "stopped") actions.push("start");
    if (["running", "starting", "unhealthy"].includes(runtime))
      actions.push("stop", "restart");
    actions.push("update", "logs", "uninstall");
  }
  return actions
    .filter((id) => available.includes(id))
    .map((id) => ({
      id,
      label: softwareOperationLabels[id],
      danger: id === "uninstall",
    }));
}
export function applicationActions(entry: CatalogEntry): SoftwareOperation[] {
  if (!entry.installation)
    return entry.listed && entry.application.actions.install ? ["install"] : [];
  const actions = standardServiceActions.filter(
    (id) =>
      id !== "install" &&
      id !== "update" &&
      !!entry.installation!.application.actions[id],
  );
  if (entry.listed && entry.application.actions.update) actions.push("update");
  return actions;
}
export function softwareConfirmation(action: SoftwareOperation, name: string) {
  return {
    install: `安装 ${name}？`,
    start: "",
    stop: `停止 ${name}？相关服务将暂时不可用。`,
    restart: `重启 ${name}？相关服务将短暂中断。`,
    update: `更新 ${name}？相关服务可能短暂中断。`,
    uninstall: `卸载 ${name}？相关服务将停止。`,
    logs: "",
  }[action];
}
export function softwareTaskInput(request: SoftwareRequest) {
  return {
    input: {
      action: "software" as const,
      tag: "",
      prerelease: false,
      plan_id: "",
      manifest_sha256: "",
      trust_sha256: "",
      software: request,
    },
  };
}
export type CatalogEntry = ReturnType<typeof softwareCatalogEntries>[number];
export function softwareApplicationTask(
  tasks: ComponentTask[],
  source: string,
  app: string,
) {
  return tasks.find((task) => {
    const request = task.result?.input.software;
    return request?.source_id === source && request.app_id === app;
  });
}
export function applicationEntry(
  entry: CatalogEntry,
  origin: string,
): SoftwareEntry | undefined {
  if (
    !origin ||
    !entry.installation?.entry ||
    entry.installation.state !== "running"
  )
    return;
  try {
    const host = new URL(origin).hostname;
    const url = new URL(entry.installation.entry.replaceAll("{host}", host));
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password
    )
      return;
    return { href: url.href };
  } catch {
    return;
  }
}

export function applicationView(
  entry: CatalogEntry,
  tasks: ComponentTask[],
  origin: string,
): SoftwareView {
  const { application, installation, source } = entry;
  return {
    id: `${source.id}/${application.id}`,
    name: application.name,
    description: application.description || "暂无软件介绍",
    category: "第三方应用",
    accent: "amber",
    installed: !!installation,
    status: softwareStatus(
      !!installation,
      installation?.state ?? "unknown",
      softwareApplicationTask(tasks, source.id, application.id),
    ),
    entry: applicationEntry(entry, origin),
    note: `来自 ${source.name}`,
  };
}
