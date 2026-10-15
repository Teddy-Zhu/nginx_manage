import axios, { AxiosError, type AxiosRequestConfig } from "axios";
import type { components } from "./schema";

type ResponseBody<T> = Omit<components["schemas"]["Response"], "data"> & {
  data: T;
};
export type Tree = components["schemas"]["Tree"];
export type ConfigFile = components["schemas"]["File"];
export type Resource = components["schemas"]["Resource"];
export type SaveResult = components["schemas"]["SaveResult"];
export type SaveRequest = components["schemas"]["SaveRequest"];
export type Me = components["schemas"]["Me"];
export type Task = components["schemas"]["Task"];
export type Module = components["schemas"]["Module"];
export type ResourceMetadata = components["schemas"]["ResourceMetadata"];
export type AccessList = components["schemas"]["AccessList"];
export type WAFConfig = components["schemas"]["WAFConfig"];
export type WAFInput = components["schemas"]["WAFInput"];
export type WAFPolicy = components["schemas"]["WAFPolicy"];
export type NginxFeatures = components["schemas"]["NginxFeatures"];
export type Certificate = components["schemas"]["Certificate"];
export type CertificateVersion = components["schemas"]["CertificateVersion"];
export type CertificateInput = components["schemas"]["CertificateInput"];
export type CertificateResult = components["schemas"]["CertificateResult"];
export type ACMEAccount = components["schemas"]["ACMEAccount"];
export type ACMEAccountInput = components["schemas"]["ACMEAccountInput"];
export type ACMEChangeResult = components["schemas"]["ACMEChangeResult"];
export type ACMEProfile = components["schemas"]["ACMEProfile"];
export type ACMEProfileInput = components["schemas"]["ACMEProfileInput"];
export type ACMEIssueInput = components["schemas"]["ACMEIssueInput"];
export type ACMEArchiveInput = components["schemas"]["ACMEArchiveInput"];
export type ACMEPolicyInput = components["schemas"]["ACMEPolicyInput"];
export type CertificateDeployPreview =
  components["schemas"]["CertificateDeployPreview"];
export type CertificateDeployInput =
  components["schemas"]["CertificateDeployInput"];
export type CertificateDeployment =
  components["schemas"]["CertificateDeployment"];
export type CertificateDeploymentStatus =
  components["schemas"]["CertificateDeploymentStatus"];
export type ACMEOrder = components["schemas"]["ACMEOrder"];
export type DNSProvider = components["schemas"]["DNSProvider"];
export type DNSCredential = components["schemas"]["DNSCredential"];
export type DNSCredentialInput = components["schemas"]["DNSCredentialInput"];
export type AccessListInput = components["schemas"]["AccessListInput"];
export type NginxRuntime = components["schemas"]["NginxRuntime"];
export type Difference = components["schemas"]["Difference"];
export type ExternalSnapshot = components["schemas"]["ExternalSnapshot"];
export type CaptureExternalRequest =
  components["schemas"]["CaptureExternalRequest"];
export type RestoreExternalRequest =
  components["schemas"]["RestoreExternalRequest"];
export type NativeModulesRequest =
  components["schemas"]["NativeModulesRequest"];
export type LogSource = components["schemas"]["LogSource"];
export type LogQuery = components["schemas"]["LogQuery"];
export type LogPage = components["schemas"]["LogPage"];
export type LogRow = components["schemas"]["LogRow"];
export type LogPolicyView = components["schemas"]["LogPolicyView"];
export type LogPolicyInput = components["schemas"]["LogPolicyInput"];
export type MonitoringCapability =
  components["schemas"]["MonitoringCapability"];
export type MonitoringThreshold = components["schemas"]["MonitoringThreshold"];
export type MonitoringSettings = components["schemas"]["MonitoringSettings"];
export type MonitoringSettingsView =
  components["schemas"]["MonitoringSettingsView"];
export type MonitoringSettingsInput =
  components["schemas"]["MonitoringSettingsInput"];
export type HostMetric = components["schemas"]["HostMetric"];
export type MonitoredService = components["schemas"]["MonitoredService"];
export type MonitoringSample = components["schemas"]["MonitoringSample"];
export type MonitoringCondition = components["schemas"]["MonitoringCondition"];
export type MonitoringLatest = components["schemas"]["MonitoringLatest"];
export type MonitoringPoint = components["schemas"]["MonitoringPoint"];
export type MonitoringHistory = components["schemas"]["MonitoringHistory"];
export type NotificationKind = components["schemas"]["NotificationKind"];
export type NotificationPolicy = components["schemas"]["NotificationPolicy"];
export type NotificationPolicyView =
  components["schemas"]["NotificationPolicyView"];
export type NotificationPolicyInput =
  components["schemas"]["NotificationPolicyInput"];
export type NotificationVersionInput =
  components["schemas"]["NotificationVersionInput"];
export type NotificationChannelInput =
  components["schemas"]["NotificationChannelInput"];
export type NotificationChannel = components["schemas"]["NotificationChannel"];
export type NotificationEvent = components["schemas"]["NotificationEvent"];
export type NotificationPayload = components["schemas"]["NotificationPayload"];
export type NotificationDelivery =
  components["schemas"]["NotificationDelivery"];
export type NotificationChange = components["schemas"]["NotificationChange"];
export type NotificationHealth = components["schemas"]["NotificationHealth"];
export type NotificationOverview =
  components["schemas"]["NotificationOverview"];
export interface Revision {
  id: string;
  version: number;
  state: string;
  created_at: number;
}

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
    public data: unknown = null,
    public requestId = "",
  ) {
    super(message);
  }
}

const http = axios.create({
  baseURL: "/api/v1",
  timeout: 20_000,
  withCredentials: true,
});
let csrf = "";
let nodeId = "";
let controller = new AbortController();
export function setCSRF(value: string) {
  csrf = value;
}
export function cancelNodeRequests() {
  controller.abort();
  controller = new AbortController();
  nodeId = "";
}

export async function request<T>(config: AxiosRequestConfig): Promise<T> {
  const headers = { ...config.headers, "X-CSRF-Token": csrf };
  try {
    const result = await http.request<ResponseBody<T>>({
      ...config,
      headers,
      signal: config.signal ?? controller.signal,
    });
    return responseData(result.data, result.status);
  } catch (error) {
    throw apiError(error);
  }
}

function responseData<T>(body: ResponseBody<T>, status: number): T {
  if (
    !body ||
    typeof body !== "object" ||
    typeof body.code !== "string" ||
    typeof body.message !== "string" ||
    !("data" in body) ||
    typeof body.request_id !== "string" ||
    !body.request_id ||
    typeof body.node_id !== "string" ||
    !body.node_id
  )
    throw new ApiError("INVALID_RESPONSE", "服务返回格式无效", status);
  checkNode(body.node_id);
  if (body.code !== "OK")
    throw new ApiError(
      body.code,
      body.message,
      status,
      body.data,
      body.request_id,
    );
  return body.data;
}
function checkNode(value: string) {
  if (!value) throw new ApiError("INVALID_RESPONSE", "响应缺少节点身份", 502);
  if (nodeId && nodeId !== value)
    throw new ApiError(
      "NODE_IDENTITY_CHANGED",
      "节点身份已变化，请重新连接",
      409,
    );
  nodeId = value;
}
function apiError(error: unknown): ApiError {
  let normalized: ApiError;
  if (error instanceof ApiError) normalized = error;
  else if (axios.isCancel(error))
    normalized = new ApiError("CANCELLED", "请求已取消", 0);
  else if (error instanceof AxiosError) {
    const body = error.response?.data as ResponseBody<unknown> | undefined;
    normalized = new ApiError(
      body?.code ?? "NETWORK_ERROR",
      body?.message ??
        (error.code === "ECONNABORTED"
          ? "请求超时，请先查询任务状态"
          : "无法连接服务"),
      error.response?.status ?? 0,
      body?.data,
      body?.request_id,
    );
  } else normalized = new ApiError("CLIENT_ERROR", "请求处理失败", 0);
  if (normalized.status === 401 || normalized.code === "UNAUTHENTICATED")
    window.dispatchEvent(new Event("session-expired"));
  if (normalized.code === "REAUTHENTICATION_REQUIRED")
    window.dispatchEvent(new Event("reauthentication-required"));
  return normalized;
}

export async function downloadLogFile(data: LogQuery) {
  try {
    const result = await http.post<Blob>("/logs/download", data, {
      responseType: "blob",
      timeout: 25_000,
      headers: { "X-CSRF-Token": csrf },
      signal: controller.signal,
    });
    checkNode(String(result.headers["x-node-id"] ?? ""));
    if (
      !String(result.headers["content-type"]).startsWith("application/x-ndjson")
    )
      throw new ApiError("INVALID_RESPONSE", "下载返回格式无效", result.status);
    return {
      blob: result.data,
      gap: result.headers["x-log-gap"] === "true",
      truncated: result.headers["x-log-truncated"] === "true",
    };
  } catch (error) {
    if (
      error instanceof AxiosError &&
      error.response?.data instanceof Blob &&
      error.response.data.size <= 65536
    ) {
      try {
        error.response.data = JSON.parse(await error.response.data.text());
      } catch {
        /* Retain the transport error for a non-JSON response. */
      }
    }
    throw apiError(error);
  }
}

export function followLogs(
  query: LogQuery,
  page: (value: LogPage) => void,
  error: (value: ApiError) => void,
) {
  const signal = controller.signal;
  const source = new EventSource(
    `/api/v1/logs/stream?${new URLSearchParams({ query: JSON.stringify(query) })}`,
    { withCredentials: true },
  );
  const aborted = () => {
    close();
    error(new ApiError("CANCELLED", "节点请求已取消", 0));
  };
  const close = () => {
    source.close();
    signal.removeEventListener("abort", aborted);
  };
  signal.addEventListener("abort", aborted, { once: true });
  source.addEventListener("page", (event) => {
    try {
      page(
        responseData<LogPage>(
          JSON.parse((event as MessageEvent<string>).data),
          200,
        ),
      );
    } catch (cause) {
      close();
      error(apiError(cause));
    }
  });
  const failed = (event: Event) => {
    close();
    try {
      if (event instanceof MessageEvent && event.data)
        responseData<unknown>(JSON.parse(event.data), 200);
      throw new ApiError("LOG_STREAM_ENDED", "实时连接已结束，请重新连接", 0);
    } catch (cause) {
      error(apiError(cause));
    }
  };
  source.addEventListener("error", failed);
  source.addEventListener("end", failed);
  return close;
}

export const api = {
  notifications: (signal?: AbortSignal) =>
    request<NotificationOverview>({ url: "/notifications", signal }),
  notificationEvents: (limit = 30, offset = 0, signal?: AbortSignal) =>
    request<NotificationEvent[]>({
      url: "/notifications/events",
      params: { limit, offset },
      signal,
    }),
  notificationDeliveries: (
    channel_id = "",
    limit = 30,
    offset = 0,
    signal?: AbortSignal,
  ) =>
    request<NotificationDelivery[]>({
      url: "/notifications/deliveries",
      params: { channel_id, limit, offset },
      signal,
    }),
  setNotificationPolicy: (data: NotificationPolicyInput, key: string) =>
    request<NotificationChange>({
      method: "PUT",
      url: "/notifications/policy",
      data,
      headers: { "Idempotency-Key": key },
    }),
  saveNotificationChannel: (
    id: string,
    data: NotificationChannelInput,
    key: string,
  ) =>
    request<NotificationChange>({
      method: id ? "PUT" : "POST",
      url: id ? `/notifications/channels/${id}` : "/notifications/channels",
      data,
      headers: { "Idempotency-Key": key },
    }),
  notificationChannelAction: (
    id: string,
    base_version: number,
    action: "delete" | "test",
    key: string,
  ) =>
    request<NotificationChange>({
      method: action === "delete" ? "DELETE" : "POST",
      url: `/notifications/channels/${id}${action === "test" ? "/test" : ""}`,
      data: { base_version },
      headers: { "Idempotency-Key": key },
    }),
  retryNotification: (id: string, key: string) =>
    request<NotificationChange>({
      method: "POST",
      url: `/notifications/deliveries/${id}/retry`,
      headers: { "Idempotency-Key": key },
    }),
  monitoringLatest: (signal?: AbortSignal) =>
    request<MonitoringLatest>({ url: "/monitoring/latest", signal }),
  monitoringSettings: (signal?: AbortSignal) =>
    request<MonitoringSettingsView>({ url: "/monitoring/settings", signal }),
  setMonitoringSettings: (data: MonitoringSettingsInput, key: string) =>
    request<MonitoringSettingsView>({
      method: "PUT",
      url: "/monitoring/settings",
      data,
      headers: { "Idempotency-Key": key },
    }),
  monitoringHistory: (
    params: {
      kind: string;
      id: string;
      value: string;
      from: number;
      until: number;
      points?: number;
    },
    signal?: AbortSignal,
  ) =>
    request<MonitoringHistory>({ url: "/monitoring/history", params, signal }),
  logSources: () => request<LogSource[]>({ url: "/logs/sources" }),
  logPolicy: () => request<LogPolicyView>({ url: "/logs/policy" }),
  setLogPolicy: (data: LogPolicyInput, key: string) =>
    request<{ operation_id: string; version: number }>({
      method: "PUT",
      url: "/logs/policy",
      data,
      headers: { "Idempotency-Key": key },
    }),
  queryLogs: (data: LogQuery, signal?: AbortSignal) =>
    request<LogPage>({
      method: "POST",
      url: "/logs/query",
      data,
      signal: signal
        ? AbortSignal.any([signal, controller.signal])
        : controller.signal,
    }),
  releaseLogCursor: (cursor: string) =>
    request<null>({
      method: "POST",
      url: "/logs/cursors/release",
      data: { cursor },
    }),
  acmeProfiles: (offset = 0) =>
    request<ACMEProfile[]>({
      url: "/acme-profiles",
      params: { limit: 100, offset },
    }),
  acmeOrders: (id: string) =>
    request<ACMEOrder[]>({ url: `/acme-profiles/${id}/orders` }),
  createACMEProfile: (data: ACMEProfileInput, key: string) =>
    request<ACMEChangeResult>({
      method: "POST",
      url: "/acme-profiles",
      data,
      headers: { "Idempotency-Key": key },
    }),
  issueACMEProfile: (id: string, data: ACMEIssueInput, key: string) =>
    request<ACMEChangeResult>({
      method: "POST",
      url: `/acme-profiles/${id}/issue`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  updateACMEPolicy: (id: string, data: ACMEPolicyInput, key: string) =>
    request<ACMEChangeResult>({
      method: "PUT",
      url: `/acme-profiles/${id}/policy`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  archiveACMEProfile: (id: string, data: ACMEArchiveInput, key: string) =>
    request<ACMEChangeResult>({
      method: "POST",
      url: `/acme-profiles/${id}/archive`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  acmeAccounts: () => request<ACMEAccount[]>({ url: "/acme-accounts" }),
  createACMEAccount: (data: ACMEAccountInput, key: string) =>
    request<ACMEChangeResult>({
      method: "POST",
      url: "/acme-accounts",
      data,
      headers: { "Idempotency-Key": key },
    }),
  registerACMEAccount: (id: string, version: number, key: string) =>
    request<ACMEChangeResult>({
      method: "POST",
      url: `/acme-accounts/${id}/register`,
      data: { base_version: version, terms_agreed: true },
      headers: { "Idempotency-Key": key },
    }),
  deleteACMEAccount: (id: string, version: number, key: string) =>
    request<ACMEChangeResult>({
      method: "DELETE",
      url: `/acme-accounts/${id}`,
      data: { base_version: version },
      headers: { "Idempotency-Key": key },
    }),
  dnsProviders: () => request<DNSProvider[]>({ url: "/dns-providers" }),
  dnsCredentials: () => request<DNSCredential[]>({ url: "/dns-credentials" }),
  saveDNSCredential: (
    id: string | null,
    data: DNSCredentialInput,
    key: string,
  ) =>
    request<ACMEChangeResult>({
      method: id ? "PUT" : "POST",
      url: id ? `/dns-credentials/${id}` : "/dns-credentials",
      data,
      headers: { "Idempotency-Key": key },
    }),
  deleteDNSCredential: (id: string, version: number, key: string) =>
    request<ACMEChangeResult>({
      method: "DELETE",
      url: `/dns-credentials/${id}`,
      data: { base_version: version },
      headers: { "Idempotency-Key": key },
    }),
  me: () => request<Me>({ url: "/me" }),
  login: (username: string, password: string) =>
    request<Me>({
      method: "POST",
      url: "/session",
      data: { username, password },
    }),
  bootstrap: (token: string, username: string, password: string) =>
    request<null>({
      method: "POST",
      url: "/bootstrap",
      data: { token, username, password },
    }),
  logout: () => request<null>({ method: "DELETE", url: "/session" }),
  reauthenticate: (password: string) =>
    request<null>({
      method: "POST",
      url: "/session/reauthenticate",
      data: { password },
    }),
  tree: () => request<Tree>({ url: "/nginx/config-tree" }),
  preview: (data: SaveRequest) =>
    request<Tree>({ method: "POST", url: "/nginx/config-tree/preview", data }),
  save: (data: SaveRequest, key: string) =>
    request<SaveResult>({
      method: "PUT",
      url: "/nginx/config-tree",
      data,
      headers: { "Idempotency-Key": key },
    }),
  patch: (
    id: string,
    base_version: number,
    changes: Record<string, string[]>,
    key: string,
    metadata?: ResourceMetadata,
  ) =>
    request<SaveResult>({
      method: "PATCH",
      url: `/nginx/resources/${encodeURIComponent(id)}`,
      data: { base_version, changes, metadata },
      headers: { "Idempotency-Key": key },
    }),
  createResource: (
    data: components["schemas"]["CreateResource"],
    key: string,
  ) =>
    request<SaveResult>({
      method: "POST",
      url: "/nginx/resources",
      data,
      headers: { "Idempotency-Key": key },
    }),
  resourceAction: (
    id: string,
    action: "copy" | "delete",
    base_version: number,
    key: string,
  ) =>
    request<SaveResult>({
      method: action === "copy" ? "POST" : "DELETE",
      url: `/nginx/resources/${encodeURIComponent(id)}${action === "copy" ? "/copy" : ""}`,
      data: { base_version },
      headers: { "Idempotency-Key": key },
    }),
  saveAccessList: (id: string | null, data: AccessListInput, key: string) =>
    request<SaveResult>({
      method: id ? "PUT" : "POST",
      url: `/nginx/access-lists${id ? "/" + encodeURIComponent(id) : ""}`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  deleteAccessList: (id: string, base_version: number, key: string) =>
    request<SaveResult>({
      method: "DELETE",
      url: `/nginx/access-lists/${encodeURIComponent(id)}`,
      data: { base_version },
      headers: { "Idempotency-Key": key },
    }),
  nginxFeatures: () => request<NginxFeatures>({ url: "/nginx/features" }),
  certificates: () => request<Certificate[]>({ url: "/certificates" }),
  certificate: (id: string) =>
    request<Certificate>({ url: `/certificates/${encodeURIComponent(id)}` }),
  certificateDeployments: (id: string) =>
    request<CertificateDeploymentStatus>({
      url: `/certificates/${encodeURIComponent(id)}/deployments`,
    }),
  previewCertificateDeploy: (id: string) =>
    request<CertificateDeployPreview>({
      url: `/certificates/${encodeURIComponent(id)}/deploy-preview`,
    }),
  deployCertificate: (id: string, data: CertificateDeployInput, key: string) =>
    request<CertificateDeployment>({
      method: "POST",
      url: `/certificates/${encodeURIComponent(id)}/deploy`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  importCertificate: (id: string | null, data: CertificateInput, key: string) =>
    request<CertificateResult>({
      method: id ? "PUT" : "POST",
      url: `/certificates${id ? "/" + encodeURIComponent(id) + "/versions" : ""}`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  deleteCertificate: (id: string, base_version: number, key: string) =>
    request<CertificateResult>({
      method: "DELETE",
      url: `/certificates/${encodeURIComponent(id)}`,
      data: { base_version },
      headers: { "Idempotency-Key": key },
    }),
  saveWAF: (id: string | null, data: WAFInput, key: string) =>
    request<SaveResult>({
      method: id ? "PUT" : "POST",
      url: `/nginx/waf-policies${id ? "/" + encodeURIComponent(id) : ""}`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  deleteWAF: (id: string, base_version: number, key: string) =>
    request<SaveResult>({
      method: "DELETE",
      url: `/nginx/waf-policies/${encodeURIComponent(id)}`,
      data: { base_version },
      headers: { "Idempotency-Key": key },
    }),
  apply: (base_version: number, key: string) =>
    request<SaveResult>({
      method: "POST",
      url: "/nginx/apply",
      data: { base_version },
      headers: { "Idempotency-Key": key },
    }),
  nginxRuntime: () => request<NginxRuntime>({ url: "/nginx/runtime" }),
  revisions: () =>
    request<Revision[]>({ url: "/nginx/revisions", params: { limit: 100 } }),
  revision: (id: string) =>
    request<Tree>({ url: `/nginx/revisions/${encodeURIComponent(id)}` }),
  diff: (base_revision: string, files: ConfigFile[]) =>
    request<Difference>({
      method: "POST",
      url: "/nginx/config-tree/diff",
      data: { base_revision, files },
    }),
  external: (path?: string) =>
    request<ExternalSnapshot>({
      url: "/nginx/external",
      params: path ? { path } : undefined,
    }),
  captureExternal: (data: CaptureExternalRequest, key: string) =>
    request<SaveResult>({
      method: "POST",
      url: "/nginx/external/capture",
      data,
      headers: { "Idempotency-Key": key },
    }),
  restoreExternal: (data: RestoreExternalRequest, key: string) =>
    request<SaveResult>({
      method: "POST",
      url: "/nginx/external/restore",
      data,
      headers: { "Idempotency-Key": key },
    }),
  setNativeModules: (data: NativeModulesRequest, key: string) =>
    request<SaveResult>({
      method: "PUT",
      url: "/nginx/native-modules",
      data,
      headers: { "Idempotency-Key": key },
    }),
  tasks: () => request<Task[]>({ url: "/tasks" }),
  modules: () => request<Module[]>({ url: "/system/modules" }),
  setModule: (id: string, enabled: boolean) =>
    request<null>({
      method: "PUT",
      url: `/system/modules/${encodeURIComponent(id)}`,
      data: { enabled },
    }),
};
