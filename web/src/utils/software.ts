import type {
  ComponentOverview,
  Fail2banContainerStatus,
  ComponentTask,
  SoftwareRequest,
} from "../api/client";

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
  to: string;
}
export interface SoftwareView {
  versioned?: boolean;
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
  "install-nginx": "安装中",
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
    return `${softwareOperationLabels[action as SoftwareOperation]}${request?.app_id === "frps" || request?.action === "frps" ? " · FRP 服务端" : request?.app_id === "fail2ban" || request?.action === "fail2ban" ? " · 登录防护" : ""}`;
  const labels: Record<string, string> = {
    configure: "保存软件设置",
    "update-panel": "系统更新",
    "install-nginx": "安装 Nginx",
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
