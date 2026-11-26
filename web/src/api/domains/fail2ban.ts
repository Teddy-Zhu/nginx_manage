import type {
  Fail2banTemplateCheck,
  Fail2banPanelLoginStatus,
  Fail2banHostInputPreview,
  Fail2banTemplateCheckInput,
  Fail2banPolicyView,
  Fail2banPolicyInput,
  Fail2banTemplate,
  Fail2banPolicyPreview,
  Fail2banPythonTaskInput,
  Fail2banPythonTask,
  Fail2banPythonTaskStatus,
  Fail2banUpgradeInput,
  Fail2banUpgradeTask,
  Fail2banUpgradeTaskStatus,
  Fail2banLifecyclePreviewInput,
  Fail2banLifecycleInput,
  Fail2banLifecyclePlan,
  Fail2banLifecycleTask,
  Fail2banLifecycleTaskStatus,
  Fail2banAddressInput,
  Fail2banExistingResource,
  Fail2banExistingResourcePolicy,
  Fail2banExistingPolicyInput,
  Fail2banExistingTaskStatus,
  Fail2banExistingPolicyTask,
  Fail2banAddressStatus,
  Fail2banAddressTask,
  Fail2banAddressTaskStatus,
  Fail2banApplyInput,
  Fail2banApplyTask,
  Fail2banApplyTaskStatus,
  Fail2banJailsRuntime,
  Fail2banInstance,
  Fail2banJail,
  Fail2banContainerStatus,
  Fail2banObservation,
} from "../types";
import type { APIRequest } from "../transport";

export function createFail2banAPI(request: APIRequest) {
  return {
    checkFail2banTemplates: (
      data: Fail2banTemplateCheckInput,
      signal?: AbortSignal,
    ) =>
      request<Fail2banTemplateCheck[]>({
        url: "/fail2ban/templates/check",
        method: "POST",
        data,
        signal,
      }),
    fail2banPolicy: (signal?: AbortSignal) =>
      request<Fail2banPolicyView>({ url: "/fail2ban/policy", signal }),
    fail2banTemplates: (signal?: AbortSignal) =>
      request<Fail2banTemplate[]>({ url: "/fail2ban/templates", signal }),
    fail2banPanelLogin: (signal?: AbortSignal) =>
      request<Fail2banPanelLoginStatus>({
        url: "/fail2ban/panel-login",
        signal,
      }),
    fail2banHostInput: (signal?: AbortSignal) =>
      request<Fail2banHostInputPreview>({
        url: "/fail2ban/host-input",
        signal,
      }),
    saveFail2banPolicy: (data: Fail2banPolicyInput, key: string) =>
      request<Fail2banPolicyView>({
        url: "/fail2ban/policy",
        method: "PUT",
        data,
        headers: { "Idempotency-Key": key },
      }),
    previewFail2ban: (version: number, signal?: AbortSignal) =>
      request<Fail2banPolicyPreview>({
        url: "/fail2ban/preview",
        method: "POST",
        data: { version },
        signal,
        timeout: 30_000,
      }),
    fail2banPythonTasks: (signal?: AbortSignal) =>
      request<Fail2banPythonTaskStatus[]>({
        url: "/fail2ban/python/tasks",
        signal,
      }),
    changeFail2banPython: (data: Fail2banPythonTaskInput, key: string) =>
      request<Fail2banPythonTask>({
        activity:
          data.action === "plan"
            ? "检查 Fail2ban 运行依赖"
            : "安装 Fail2ban 运行依赖",
        url: "/fail2ban/python",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    changeFail2banUpgrade: (data: Fail2banUpgradeInput, key: string) =>
      request<Fail2banUpgradeTask>({
        activity: "更新 Fail2ban",
        url: "/fail2ban/upgrade",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    fail2banUpgradeTasks: (signal?: AbortSignal) =>
      request<Fail2banUpgradeTaskStatus[]>({
        url: "/fail2ban/upgrade/tasks",
        signal,
      }),
    previewFail2banLifecycle: (
      data: Fail2banLifecyclePreviewInput,
      signal?: AbortSignal,
    ) =>
      request<Fail2banLifecyclePlan>({
        url: "/fail2ban/lifecycle/preview",
        method: "POST",
        data,
        signal,
      }),
    fail2banLifecycleTasks: (signal?: AbortSignal) =>
      request<Fail2banLifecycleTaskStatus[]>({
        url: "/fail2ban/lifecycle/tasks",
        signal,
      }),
    changeFail2banLifecycle: (data: Fail2banLifecycleInput, key: string) =>
      request<Fail2banLifecycleTask>({
        activity:
          {
            install: "安装 Fail2ban",
            resume: "继续安装 Fail2ban",
            rollback: "撤回 Fail2ban 安装",
            start: "启动 Fail2ban",
            stop: "停止 Fail2ban",
            enable: "开启 Fail2ban 开机启动",
            disable: "关闭 Fail2ban 开机启动",
          }[data.action] ?? "管理 Fail2ban 服务",
        url: "/fail2ban/lifecycle",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    fail2banAddress: (
      query: Pick<
        Fail2banAddressInput,
        "engine_owner" | "adoption_id" | "jail" | "ip"
      >,
      signal?: AbortSignal,
    ) =>
      request<Fail2banAddressStatus>({
        url: "/fail2ban/addresses/status",
        params: query,
        signal,
      }),
    fail2banAddressTasks: (signal?: AbortSignal) =>
      request<Fail2banAddressTaskStatus[]>({
        url: "/fail2ban/addresses/tasks",
        signal,
      }),
    changeFail2banAddress: (data: Fail2banAddressInput, key: string) =>
      request<Fail2banAddressTask>({
        activity: "更新 Fail2ban IP 名单",
        url: "/fail2ban/addresses",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    fail2banExistingResources: (signal?: AbortSignal) =>
      request<Fail2banExistingResource[]>({
        url: "/fail2ban/existing/resources",
        signal,
      }),
    fail2banExistingResource: (name: string, signal?: AbortSignal) =>
      request<Fail2banExistingResourcePolicy>({
        url: `/fail2ban/existing/resources/${encodeURIComponent(name)}`,
        signal,
      }),
    changeFail2banExistingPolicy: (
      data: Fail2banExistingPolicyInput,
      key: string,
    ) =>
      request<Fail2banExistingPolicyTask>({
        activity: "更新 Fail2ban 防护规则",
        url: "/fail2ban/existing/operations",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    fail2banExistingTasks: (signal?: AbortSignal) =>
      request<Fail2banExistingTaskStatus[]>({
        url: "/fail2ban/existing/tasks",
        signal,
      }),
    fail2banExistingTask: (id: string, signal?: AbortSignal) =>
      request<Fail2banExistingTaskStatus>({
        url: `/fail2ban/existing/tasks/${encodeURIComponent(id)}`,
        signal,
      }),
    cancelFail2banExistingPolicy: (id: string, key: string) =>
      request<Fail2banExistingPolicyTask>({
        activity: "更新 Fail2ban 防护规则",
        url: `/fail2ban/existing/tasks/${encodeURIComponent(id)}/cancel`,
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    fail2banRuntime: (signal?: AbortSignal) =>
      request<Fail2banJailsRuntime>({ url: "/fail2ban/runtime", signal }),
    fail2banTasks: (signal?: AbortSignal) =>
      request<Fail2banApplyTaskStatus[]>({ url: "/fail2ban/tasks", signal }),
    applyFail2ban: (data: Fail2banApplyInput, key: string) =>
      request<Fail2banApplyTask>({
        activity: "应用登录防护配置",
        url: "/fail2ban/apply",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    fail2banInstance: (signal?: AbortSignal) =>
      request<Fail2banInstance>({ url: "/fail2ban/instance", signal }),
    fail2banJail: (name: string, signal?: AbortSignal) =>
      request<Fail2banJail>({
        url: `/fail2ban/jails/${encodeURIComponent(name)}`,
        signal,
        timeout: 30_000,
      }),
    fail2banContainer: (signal?: AbortSignal) =>
      request<Fail2banContainerStatus>({
        url: "/fail2ban/container",
        params: { include_logs: false },
        signal,
        timeout: 30_000,
      }),
    fail2ban: (signal?: AbortSignal) =>
      request<Fail2banObservation>({ url: "/fail2ban", signal }),
  };
}
