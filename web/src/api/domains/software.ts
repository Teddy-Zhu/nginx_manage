import type {
  ComponentOfflineInput,
  ComponentOfflineChunk,
  ComponentOfflineUpload,
  SoftwareResult,
  SoftwareRequest,
  ComponentVersionCatalog,
  UpdateChannel,
  ComponentCreateInput,
  ComponentOverview,
  ComponentTask,
  CoreUpdateCheck,
  ImageUpgradeTask,
  NginxImageUpgradeCreateInput,
  PanelUpdateTask,
  PanelUpdateCreateInput,
  NginxSwitchTask,
  NginxSwitchCreateInput,
  NginxInstallTask,
  NginxInstallCreateInput,
} from "../types";
import { type APIRequest, ApiError, apiError, liveData } from "../transport";
import { watchLiveResource } from "../live";
import type { RequestScope } from "../context";

function componentTaskTitle(data: ComponentCreateInput) {
  if (data.input.software?.action === "container")
    return (
      { start: "启动容器", stop: "停止容器", restart: "重启容器" } as const
    )[data.input.software.container!.action];
  return {
    check: "检查可用版本",
    prepare: "下载安装包",
    activate: "启用前端资源",
    pull: "下载运行镜像",
    software:
      data.input.software?.action === "update-panel" ? "更新系统" : "软件操作",
  }[data.input.action];
}

export function createSoftwareAPI(request: APIRequest, scope: RequestScope) {
  return {
    watchServiceLogs: (
      app: "frps" | "fail2ban",
      updated: (value: string) => void,
      failed: (error: ApiError) => void,
    ) =>
      watchLiveResource(
        scope,
        "/components/service-logs?app_id=" + app,
        (value) => {
          try {
            updated(liveData<SoftwareResult>(value, scope).log);
          } catch (error) {
            failed(apiError(error));
          }
        },
      ),
    controlSoftware: (data: SoftwareRequest) =>
      request<SoftwareResult>({
        url: "/components/control",
        method: "POST",
        data,
        timeout: 90_000,
      }).catch((error: unknown) => {
        const failure = apiError(error);
        if (failure.code === "NETWORK_ERROR" && failure.status === 0)
          throw new ApiError(
            failure.code,
            "未收到操作结果，请刷新服务状态确认",
            0,
          );
        throw failure;
      }),
    components: (signal?: AbortSignal) =>
      request<ComponentOverview>({ url: "/components", signal }),
    updateChannel: () =>
      request<UpdateChannel>({ url: "/components/update-channel" }),
    checkCoreUpdate: (
      channel: UpdateChannel["channel"],
      signal?: AbortSignal,
    ) =>
      request<CoreUpdateCheck>({
        url: "/components/core-update",
        params: { channel },
        signal,
      }),
    setUpdateChannel: (channel: UpdateChannel["channel"]) =>
      request<UpdateChannel>({
        url: "/components/update-channel",
        method: "PUT",
        data: { channel },
      }),
    componentOfflineUploads: (signal?: AbortSignal) =>
      request<ComponentOfflineUpload[]>({ url: "/components/offline", signal }),
    createComponentOfflineUpload: (data: ComponentOfflineInput, key: string) =>
      request<ComponentOfflineUpload>({
        url: "/components/offline",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    writeComponentOfflineChunk: (
      id: string,
      asset: string,
      data: ComponentOfflineChunk,
    ) =>
      request<ComponentOfflineUpload>({
        url: `/components/offline/${encodeURIComponent(id)}/assets/${encodeURIComponent(asset)}`,
        method: "PUT",
        data,
      }),
    discardComponentOfflineUpload: (id: string) =>
      request<ComponentOfflineUpload>({
        url: `/components/offline/${encodeURIComponent(id)}`,
        method: "DELETE",
      }),
    pullComponentImage: (data: ComponentCreateInput, key: string) =>
      request<ComponentTask>({
        activity: componentTaskTitle(data),
        url: "/components/images/pull",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    componentTasks: (signal?: AbortSignal) =>
      request<ComponentTask[]>({ url: "/components/tasks", signal }),
    componentVersions: (
      params: {
        app_id: string;
        channel: "stable" | "beta";
        page: number;
        refresh?: boolean;
      },
      signal?: AbortSignal,
    ) =>
      request<ComponentVersionCatalog>({
        url: "/components/versions",
        params,
        signal,
      }),
    nginxImageUpgrades: (signal?: AbortSignal) =>
      request<ImageUpgradeTask[]>({ url: "/nginx/images/upgrades", signal }),
    createNginxImageUpgrade: (
      data: NginxImageUpgradeCreateInput,
      key: string,
    ) =>
      request<ImageUpgradeTask>({
        activity: "更新运行环境",
        url: "/nginx/images/upgrades",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    resumeNginxImageUpgrade: (id: string, key: string) =>
      request<ImageUpgradeTask>({
        activity: "更新运行环境",
        url: `/nginx/images/upgrades/${encodeURIComponent(id)}/resume`,
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    panelUpdates: (signal?: AbortSignal) =>
      request<PanelUpdateTask[]>({ url: "/panel/updates", signal }),
    createPanelUpdate: (data: PanelUpdateCreateInput, key: string) =>
      request<PanelUpdateTask>({
        activity: "更新管理面板",
        url: "/panel/updates",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    resumePanelUpdate: (id: string, key: string) =>
      request<PanelUpdateTask>({
        activity: "更新管理面板",
        url: `/panel/updates/${encodeURIComponent(id)}/resume`,
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    nginxInstallations: (signal?: AbortSignal) =>
      request<NginxInstallTask[]>({ url: "/components/installations", signal }),
    createNginxInstallation: (data: NginxInstallCreateInput, key: string) =>
      request<NginxInstallTask>({
        activity: "安装 Nginx",
        url: "/components/installations",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    controlNginxInstallation: (
      id: string,
      command: "resume" | "cancel",
      key: string,
    ) =>
      request<NginxInstallTask>({
        activity: "安装 Nginx",
        url: `/components/installations/${encodeURIComponent(id)}/${command}`,
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    nginxSwitches: (signal?: AbortSignal) =>
      request<NginxSwitchTask[]>({ url: "/components/switches", signal }),
    createNginxSwitch: (data: NginxSwitchCreateInput, key: string) =>
      request<NginxSwitchTask>({
        activity: "更新 Nginx",
        url: "/components/switches",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    controlNginxSwitch: (
      id: string,
      command: "resume" | "rollback",
      key: string,
    ) =>
      request<NginxSwitchTask>({
        activity: "更新 Nginx",
        url: `/components/switches/${encodeURIComponent(id)}/${command}`,
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    createComponentTask: (
      data: ComponentCreateInput,
      key: string,
      showActivity = true,
    ) =>
      request<ComponentTask>({
        activity: showActivity ? componentTaskTitle(data) : undefined,
        url: "/components/tasks",
        method: "POST",
        headers: { "Idempotency-Key": key },
        data,
      }),
  };
}
