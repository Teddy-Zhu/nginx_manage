import { sha256Hex } from "../utils/crypto";
import axios, { AxiosError, type AxiosRequestConfig } from "axios";
import type { components, operations } from "./schema";
import { onScopeDispose } from "vue";
import { useRoute } from "vue-router";
import { invalidateNodeScope, nodeGeneration, nodeRequestError, pageScope, scopeSignal, selectedTarget, sourceNodeId, type RequestScope } from "./context";

type ResponseBody<T> = Omit<components["schemas"]["Response"], "data"> & {
  data: T;
};
type RequestConfig = Omit<AxiosRequestConfig, "signal"> & { signal?: AbortSignal };
const FIREWALL_REQUEST_TIMEOUT = 85_000;
export type GeoIPSource = components["schemas"]["GeoIPSource"];
export type GeoIPState = components["schemas"]["GeoIPState"];
export type GeoIPSourceInput = components["schemas"]["GeoIPSourceInput"];
export type GeoIPUpdateInput = components["schemas"]["GeoIPUpdateInput"];
export type GeoIPResolveInput = components["schemas"]["GeoIPResolveInput"];
export type GeoIPResolved = components["schemas"]["GeoIPResolved"];
export type RuntimeHistoryFilter = components["schemas"]["RuntimeHistoryFilter"];
export type RuntimeHistoryExecuteInput = components["schemas"]["RuntimeHistoryExecuteInput"];
export type RuntimeHistoryPreview = components["schemas"]["RuntimeHistoryPreview"];
export type RuntimeHistoryStatus = components["schemas"]["RuntimeHistoryStatus"];
export type HistoryFilter = components["schemas"]["HistoryFilter"];
export type HistoryItem = components["schemas"]["HistoryItem"];
export type HistoryScope = components["schemas"]["HistoryScope"];
export type HistoryPreview = components["schemas"]["HistoryPreview"];
export type HistoryExecuteInput = components["schemas"]["HistoryExecuteInput"];
export type HistoryResult = components["schemas"]["HistoryResult"];
export type AuditFilter = components["schemas"]["AuditFilter"];
export type AuditRow = components["schemas"]["AuditRow"];
export type AuditPage = components["schemas"]["AuditPage"];
export type AuditQuery = operations["listAudit"]["parameters"]["query"];
export type BackupInput = components["schemas"]["BackupInput"];
export type BackupPolicyInput = components["schemas"]["BackupPolicyInput"];
export type BackupPolicy = components["schemas"]["BackupPolicy"];
export type BackupRecord = components["schemas"]["BackupRecord"];
export type BackupOverview = components["schemas"]["BackupOverview"];
export type BackupDownloadTicket = components["schemas"]["BackupDownloadTicket"];
export type MaintenanceView = components["schemas"]["MaintenanceView"];
export type MaintenanceSession = components["schemas"]["MaintenanceSession"];
export type MaintenanceStartInput =
  components["schemas"]["MaintenanceStartInput"];
export type ComponentOfflineInput = components["schemas"]["ComponentOfflineInput"];
export type ComponentOfflineChunk = components["schemas"]["ComponentOfflineChunk"];
export type ComponentOfflineAsset = components["schemas"]["ComponentOfflineAsset"];
export type ComponentOfflineUpload = components["schemas"]["ComponentOfflineUpload"];
export type ComponentInput = components["schemas"]["ComponentInput"];
export type ComponentCreateInput =
  components["schemas"]["ComponentCreateInput"];
export type ComponentOverview = components["schemas"]["ComponentOverview"];
export type ComponentAsset = components["schemas"]["ComponentAsset"];
export type ComponentRelease = components["schemas"]["ComponentRelease"];
export type ComponentOperation = components["schemas"]["ComponentOperation"];
export type ComponentTask = components["schemas"]["ComponentTask"];
export type ImageUpgradeTask = components["schemas"]["ImageUpgradeTask"];
export type PanelImageUpgradeCreateInput = components["schemas"]["PanelImageUpgradeCreateInput"];
export type NginxImageUpgradeCreateInput = components["schemas"]["NginxImageUpgradeCreateInput"];
export type AgentUpgradeTask = components["schemas"]["AgentUpgradeTask"];
export type AgentUpgradeCreateInput = components["schemas"]["AgentUpgradeCreateInput"];
export type PanelUpdateTask = components["schemas"]["PanelUpdateTask"];
export type PanelUpdateCreateInput = components["schemas"]["PanelUpdateCreateInput"];
export type NginxSwitchTask = components["schemas"]["NginxSwitchTask"];
export type NginxSwitchCreateInput = components["schemas"]["NginxSwitchCreateInput"];
export type NginxInstallTask = components["schemas"]["NginxInstallTask"];
export type NginxInstallCreateInput =
  components["schemas"]["NginxInstallCreateInput"];
export type Tree = components["schemas"]["Tree"];
export type ConfigFile = components["schemas"]["File"];
export type Resource = components["schemas"]["Resource"];
export type SaveResult = components["schemas"]["SaveResult"];
export type SaveRequest = components["schemas"]["SaveRequest"];
export type Me = components["schemas"]["Me"];
export type NodeConnection = components["schemas"]["NodeConnection"];
export type NodeCreateInput = components["schemas"]["NodeCreateInput"];
export type PairingInput = components["schemas"]["PairingInput"];
export type Pairing = components["schemas"]["Pairing"];
export type PairingOffer = components["schemas"]["PairingOffer"];
export type PairingJobInput = components["schemas"]["PairingJobInput"];
export type PairingJob = components["schemas"]["PairingJob"];
export type ManagementListenerInput = components["schemas"]["ManagementListenerInput"];
export type ManagementListenerOperation = components["schemas"]["ManagementListenerOperation"];
export type ManagementListenerView = components["schemas"]["ManagementListenerView"];
export type Task = components["schemas"]["Task"];
export type Module = components["schemas"]["Module"];
export type SystemVersion = components["schemas"]["SystemVersion"];
export type HostLinkDNS = components["schemas"]["HostLinkDNS"];
export type HostNetplanSource = components["schemas"]["HostNetplanSource"];
export type HostDNSOverview = components["schemas"]["HostDNSOverview"];
export type Fail2banTemplateCheck = components["schemas"]["Fail2banTemplateCheck"];
export type Fail2banPanelLoginEvent = components["schemas"]["Fail2banPanelLoginEvent"];
export type Fail2banPanelLoginStatus = components["schemas"]["Fail2banPanelLoginStatus"];
export type Fail2banHostInputPreview = components["schemas"]["Fail2banHostInputPreview"];
export type Fail2banTemplateCheckInput = components["schemas"]["Fail2banTemplateCheckInput"];
export type Fail2banDesiredJail = components["schemas"]["Fail2banDesiredJail"];
export type Fail2banPolicyView = components["schemas"]["Fail2banPolicyView"];
export type Fail2banPolicyInput = components["schemas"]["Fail2banPolicyInput"];
export type Fail2banTemplate = components["schemas"]["Fail2banTemplate"];
export type Fail2banPolicyPreview = components["schemas"]["Fail2banPolicyPreview"];
export type Fail2banPython = components["schemas"]["Fail2banPython"];
export type Fail2banPythonPackage = components["schemas"]["Fail2banPythonPackage"];
export type Fail2banPythonPlan = components["schemas"]["Fail2banPythonPlan"];
export type Fail2banPythonTaskInput = components["schemas"]["Fail2banPythonTaskInput"];
export type Fail2banPythonTaskOperation = components["schemas"]["Fail2banPythonTaskOperation"];
export type Fail2banPythonTask = components["schemas"]["Fail2banPythonTask"];
export type Fail2banPythonTaskStatus = components["schemas"]["Fail2banPythonTaskStatus"];
export type Fail2banManaged = components["schemas"]["Fail2banManaged"];
export type Fail2banService = components["schemas"]["Fail2banService"];
export type Fail2banUpgradeInput = components["schemas"]["Fail2banUpgradeInput"];
export type Fail2banUpgradeBans = components["schemas"]["Fail2banUpgradeBans"];
export type Fail2banUpgradePlan = components["schemas"]["Fail2banUpgradePlan"];
export type Fail2banUpgradePreparation = components["schemas"]["Fail2banUpgradePreparation"];
export type Fail2banUpgradeRunResult = components["schemas"]["Fail2banUpgradeRunResult"];
export type Fail2banUpgradeOperation = components["schemas"]["Fail2banUpgradeOperation"];
export type Fail2banUpgradeTask = components["schemas"]["Fail2banUpgradeTask"];
export type Fail2banUpgradeTaskStatus = components["schemas"]["Fail2banUpgradeTaskStatus"];
export type Fail2banLifecyclePreviewInput = components["schemas"]["Fail2banLifecyclePreviewInput"];
export type Fail2banLifecycleInput = components["schemas"]["Fail2banLifecycleInput"];
export type Fail2banLifecyclePlan = components["schemas"]["Fail2banLifecyclePlan"];
export type Fail2banLifecycleOperation = components["schemas"]["Fail2banLifecycleOperation"];
export type Fail2banLifecycleTask = components["schemas"]["Fail2banLifecycleTask"];
export type Fail2banLifecycleTaskStatus = components["schemas"]["Fail2banLifecycleTaskStatus"];
export type Fail2banAddressInput =
  components["schemas"]["Fail2banAddressInput"];
export type Fail2banExistingResource =
  components["schemas"]["Fail2banExistingResource"];
export type Fail2banExistingResourcePolicy =
  components["schemas"]["Fail2banExistingResourcePolicy"];
export type Fail2banExistingPolicy =
  components["schemas"]["Fail2banExistingPolicy"];
export type Fail2banExistingPolicyInput =
  components["schemas"]["Fail2banExistingPolicyInput"];
export type Fail2banExistingPlan =
  components["schemas"]["Fail2banExistingPlan"];
export type Fail2banExistingTaskStatus =
  components["schemas"]["Fail2banExistingTaskStatus"];
export type Fail2banExistingPolicyTask =
  components["schemas"]["Fail2banExistingPolicyTask"];
export type Fail2banAddressStatus =
  components["schemas"]["Fail2banAddressStatus"];
export type Fail2banAddressOperation =
  components["schemas"]["Fail2banAddressOperation"];
export type Fail2banAddressTask = components["schemas"]["Fail2banAddressTask"];
export type Fail2banAddressTaskStatus =
  components["schemas"]["Fail2banAddressTaskStatus"];
export type Fail2banApplyInput = components["schemas"]["Fail2banApplyInput"];
export type Fail2banApplyTask = components["schemas"]["Fail2banApplyTask"];
export type Fail2banApplyTaskStatus = components["schemas"]["Fail2banApplyTaskStatus"];
export type Fail2banJailsRuntime = components["schemas"]["Fail2banJailsRuntime"];
export type MigrationHostDNSInput = components["schemas"]["MigrationHostDNSInput"];
export type MigrationHostDNSPlan = components["schemas"]["MigrationHostDNSPlan"];
export type MigrationHostDNSItem = components["schemas"]["MigrationHostDNSItem"];
export type MigrationMonitoringInput = components["schemas"]["MigrationMonitoringInput"];
export type MigrationMonitoringPlan = components["schemas"]["MigrationMonitoringPlan"];
export type MigrationFail2banInput = components["schemas"]["MigrationFail2banInput"];
export type MigrationFail2banPlan = components["schemas"]["MigrationFail2banPlan"];
export type Fail2banInstance = components["schemas"]["Fail2banInstance"];
export type Fail2banJail = components["schemas"]["Fail2banJail"];
export type Fail2banObservation = components["schemas"]["Fail2banObservation"];
export type FirewallObservation = components["schemas"]["FirewallObservation"];
export type FirewallRule = components["schemas"]["FirewallRule"];
export type FirewallPolicy = components["schemas"]["FirewallPolicy"];
export type FirewallPolicyView = components["schemas"]["FirewallPolicyView"];
export type FirewallPolicyInput = components["schemas"]["FirewallPolicyInput"];
export type FirewallPlanInput = components["schemas"]["FirewallPlanInput"];
export type FirewallPlan = components["schemas"]["FirewallPlan"];
export type FirewallOperation = components["schemas"]["FirewallOperation"];
export type FirewallRuntime = components["schemas"]["FirewallRuntime"];
export type FirewallApplyInput = components["schemas"]["FirewallApplyInput"];
export type FirewallPreview = components["schemas"]["FirewallPreview"];
export type HostDNSPlan = components["schemas"]["HostDNSPlan"];
export type HostDNSPlanInput = components["schemas"]["HostDNSPlanInput"];
export type HostDNSChange = components["schemas"]["HostDNSChange"];
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
  pruned_at: number;
}

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
    public data: unknown = null,
    public requestId = "",
    public originNodeId = "",
  ) {
    super(message);
  }
}

export type MigrationDependencyStatus =
  components["schemas"]["MigrationDependencyStatus"];
export type MigrationDependencyInput =
  components["schemas"]["MigrationDependencyInput"];
export type MigrationPushInput = components["schemas"]["MigrationPushInput"];
export type MigrationPushTask = components["schemas"]["MigrationPushTask"];
export type MigrationPushResumeInput =
  components["schemas"]["MigrationPushResumeInput"];
export type MigrationSelection = components["schemas"]["MigrationSelection"];
export type MigrationExportInput =
  components["schemas"]["MigrationExportInput"];
export type MigrationImportInput =
  components["schemas"]["MigrationImportInput"];
export type MigrationPullInput = components["schemas"]["MigrationPullInput"];
export type MigrationExecuteInput =
  components["schemas"]["MigrationExecuteInput"];
export type MigrationFirewallInput =
  components["schemas"]["MigrationFirewallInput"];
export type MigrationFirewallPlan =
  components["schemas"]["MigrationFirewallPlan"];
export type MigrationPlan = components["schemas"]["MigrationPlan"];
export type MigrationPackage = components["schemas"]["MigrationPackage"];

const http = axios.create({
  baseURL: "/api/v1",
  timeout: 20_000,
  withCredentials: true,
});
let csrf = "";
const controlScope: RequestScope = { target: null, generation: null };
export function setCSRF(value: string) { csrf = value; }
export function cancelNodeRequests() { invalidateNodeScope(); }
function assertScope(scope: RequestScope) {
  if (scopeSignal(scope).aborted || (scope.generation !== null && scope.generation !== nodeGeneration.value)) throw new ApiError("CANCELLED", "节点请求已取消", 0);
}
function endpoint(url: string, scope: RequestScope) {
  assertScope(scope);
  if (!url.startsWith("/") || url.startsWith("//")) throw new ApiError("INVALID_REQUEST", "接口路径无效", 0);
  return scope.target ? `/nodes/connections/${scope.target.connection}${url}` : url;
}
export function request<T>(config: RequestConfig): Promise<T> { return scopedRequest<T>(config, controlScope); }
async function scopedRequest<T>(config: RequestConfig, scope: RequestScope): Promise<T> {
	 scope = { ...scope, signal: scopeSignal(scope) };
  assertScope(scope);
  try {
    const result = await http.request<ResponseBody<T>>({ ...config, baseURL: "/api/v1", url: endpoint(String(config.url ?? ""), scope), headers: { ...config.headers, "X-CSRF-Token": csrf }, signal: config.signal ? AbortSignal.any([config.signal, scopeSignal(scope)]) : scopeSignal(scope) });
    return responseData(result.data, result.status, scope);
  } catch (cause) {
    assertScope(scope);
    if (cause instanceof AxiosError && cause.response?.data && !(cause.response.data instanceof Blob)) {
      try { responseData(cause.response.data, cause.response.status, scope); } catch (validated) { throw apiError(validated); }
    }
    throw apiError(cause);
  }
}
function responseData<T>(body: ResponseBody<T>, status: number, scope: RequestScope): T {
  assertScope(scope);
  if (!body || typeof body !== "object" || typeof body.code !== "string" || typeof body.message !== "string" || !("data" in body) || typeof body.request_id !== "string" || !body.request_id || typeof body.node_id !== "string" || !body.node_id) throw new ApiError("INVALID_RESPONSE", "服务返回格式无效", status);
  if ((status >= 200 && status < 300) !== (body.code === "OK")) throw new ApiError("INVALID_RESPONSE", "响应状态与结果不一致", status);
  checkNode(body.node_id, scope, status, body.code);
  if (body.code !== "OK") throw new ApiError(body.code, body.message, status, body.data, body.request_id, body.node_id);
  return body.data;
}
function checkNode(value: string, scope: RequestScope, status = 200, code = "OK") {
  assertScope(scope);
  if (!value) throw new ApiError("INVALID_RESPONSE", "响应缺少节点身份", 502);
  if (scope.target) {
    if (value !== scope.target.nodeId && !(status >= 400 && code !== "OK" && value === sourceNodeId.value)) throw new ApiError("NODE_IDENTITY_CHANGED", "目标节点身份已变化，请重新检查连接", 409);
  } else {
    if (sourceNodeId.value && sourceNodeId.value !== value) throw new ApiError("NODE_IDENTITY_CHANGED", "本机节点身份已变化，请重新连接", 409);
    sourceNodeId.value = value;
  }
}

export function apiError(error: unknown): ApiError {
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
      body?.node_id,
    );
  } else normalized = new ApiError("CLIENT_ERROR", "请求处理失败", 0);
  if ((normalized.status === 401 || normalized.code === "UNAUTHENTICATED") && (!normalized.originNodeId || normalized.originNodeId === sourceNodeId.value)) window.dispatchEvent(new Event("session-expired"));
  const targetUnauthorized = !!selectedTarget.value && normalized.originNodeId === selectedTarget.value.nodeId && (normalized.status === 401 || normalized.code === "UNAUTHENTICATED");
  if (selectedTarget.value && normalized.code !== "CANCELLED" && (normalized.code.startsWith("REMOTE_") || normalized.code === "NODE_IDENTITY_CHANGED" || targetUnauthorized)) nodeRequestError.value = targetUnauthorized ? "目标节点授权不可用，请检查节点连接" : normalized.message;
  if (normalized.code === "REAUTHENTICATION_REQUIRED")
    window.dispatchEvent(new Event("reauthentication-required"));
  return normalized;
}

async function downloadJSONLinesFor(path: string, data: unknown, scope: RequestScope) {
  scope = { ...scope, signal: scopeSignal(scope) };
  assertScope(scope);
  try {
    const result = await http.post<Blob>(endpoint(path, scope), data, {
      responseType: "blob",
      timeout: 25_000,
      headers: { "X-CSRF-Token": csrf },
      signal: scopeSignal(scope),
    });
    checkNode(String(result.headers["x-node-id"] ?? ""), scope);
    if (
      !String(result.headers["content-type"]).startsWith("application/x-ndjson")
    )
      throw new ApiError("INVALID_RESPONSE", "下载返回格式无效", result.status);
    return result;
  } catch (error) {
    assertScope(scope);
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
    if (error instanceof AxiosError && error.response?.data && !(error.response.data instanceof Blob)) {
      try { responseData(error.response.data, error.response.status, scope); } catch (validated) { throw apiError(validated); }
    }
    throw apiError(error);
  }
}

async function downloadLogFileFor(data: LogQuery, scope: RequestScope) {
  const result = await downloadJSONLinesFor("/logs/download", data, scope);
  return {
    blob: result.data,
    gap: result.headers["x-log-gap"] === "true",
    truncated: result.headers["x-log-truncated"] === "true",
  };
}

async function exportAuditFor(data: AuditFilter, scope: RequestScope) {
  const result = await downloadJSONLinesFor("/audit/export", data, scope);
  const expected = String(result.headers["x-archive-sha256"] ?? "");
  if (result.data.size > 8 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(expected))
    throw new ApiError("INVALID_RESPONSE", "审计归档大小或摘要无效", result.status);
  const actual = sha256Hex(new Uint8Array(await result.data.arrayBuffer()));
  assertScope(scope);
  if (actual !== expected)
    throw new ApiError("INVALID_RESPONSE", "审计归档摘要不匹配，请重新下载", result.status);
  return result.data;
}

function followLogsFor(
  scope: RequestScope,
  query: LogQuery,
  page: (value: LogPage) => void,
  error: (value: ApiError) => void,
) {
  scope = { ...scope, signal: scopeSignal(scope) };
  assertScope(scope);
  const signal = scopeSignal(scope);
  const source = new EventSource(
    `/api/v1${endpoint("/logs/stream", scope)}?${new URLSearchParams({ query: JSON.stringify(query) })}`,
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
          200, scope,
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
        responseData<unknown>(JSON.parse(event.data), 400, scope);
      throw new ApiError("LOG_STREAM_ENDED", "实时连接已结束，请重新连接", 0);
    } catch (cause) {
      error(apiError(cause));
    }
  };
  source.addEventListener("error", failed);
  source.addEventListener("end", failed);
  return close;
}

function createAPI(scope: RequestScope) {
  const request = <T>(config: RequestConfig) => scopedRequest<T>(config, scope);
  return {
  request,
  downloadLogFile: (data: LogQuery) => downloadLogFileFor(data, scope),
  runtimeHistory: () => request<RuntimeHistoryStatus[]>({ url: "/history/runtime" }),
  previewRuntimeHistory: (data: RuntimeHistoryFilter) => request<RuntimeHistoryPreview>({ url: "/history/runtime/preview", method: "POST", data }),
  executeRuntimeHistory: (data: RuntimeHistoryExecuteInput) => request<RuntimeHistoryStatus>({ url: "/history/runtime/execute", method: "POST", data, headers: { "Idempotency-Key": data.operation_id } }),
  previewHistory: (data: HistoryFilter) => request<HistoryPreview>({ url: "/history/preview", method: "POST", data }),
  executeHistory: (data: HistoryExecuteInput, key: string) => request<HistoryResult>({ url: "/history/execute", method: "POST", data, headers: { "Idempotency-Key": key } }),
  audit: (params: AuditQuery) => request<AuditPage>({ url: "/audit", params }),
  exportAudit: (data: AuditFilter) => exportAuditFor(data, scope),
  followLogs: (query: LogQuery, page: (value: LogPage) => void, error: (value: ApiError) => void) => followLogsFor(scope, query, page, error),
  nodes: (signal?: AbortSignal) => request<NodeConnection[]>({ url: "/nodes", signal }),
  pairings: () => request<Pairing[]>({ url: "/remote/pairings" }),
  backups: () => request<BackupOverview>({ url: "/backups" }),
  backup: (id: string) => request<BackupRecord>({ url: `/backups/${id}` }),
  createBackup: (data: BackupInput, key: string) => request<BackupRecord>({ url: "/backups", method: "POST", data, headers: { "Idempotency-Key": key } }),
  deleteBackup: (id: string) => request<BackupRecord>({ url: `/backups/${id}`, method: "DELETE" }),
  backupPolicy: () => request<BackupPolicy>({ url: "/backups/policy" }),
  saveBackupPolicy: (data: BackupPolicyInput) => request<BackupPolicy>({ url: "/backups/policy", method: "PUT", data }),
  backupDownload: (id: string) => request<BackupDownloadTicket>({ url: `/backups/${id}/download`, method: "POST" }),
  managementListener: () => request<ManagementListenerView>({ url: "/management/listener" }),
  listenerOperation: (id: string) => request<ManagementListenerOperation>({ url: `/management/listener/operations/${id}` }),
  applyManagementListener: (data: ManagementListenerInput, key: string) => request<ManagementListenerOperation>({ url: "/management/listener", method: "POST", data, headers: { "Idempotency-Key": key } }),
  decideManagementListener: (id: string, action: "confirm" | "rollback") => request<ManagementListenerOperation>({ url: `/management/listener/operations/${id}/${action}`, method: "POST" }),
  createPairing: (data: PairingInput, key: string) => request<PairingOffer>({ url: "/remote/pairings", method: "POST", data, headers: { "Idempotency-Key": key } }),
  revokePairing: (id: string) => request<Pairing>({ url: `/remote/pairings/${id}`, method: "DELETE" }),
  pairingJobs: () => request<PairingJob[]>({ url: "/nodes/pairings" }),
  startPairing: (data: PairingJobInput, key: string) => request<PairingJob>({ url: "/nodes/pairings", method: "POST", data, timeout: 30_000, headers: { "Idempotency-Key": key } }),
  resumePairing: (id: string) => request<PairingJob>({ url: `/nodes/pairings/${id}/resume`, method: "POST", timeout: 30_000 }),
  abandonPairing: (id: string) => request<PairingJob>({ url: `/nodes/pairings/${id}/abandon`, method: "POST", timeout: 25_000 }),
  createNode: (data: NodeCreateInput, key: string) => request<NodeConnection>({ url: "/nodes", method: "POST", data, timeout: 30_000, headers: { "Idempotency-Key": key } }),
  refreshNode: (id: string, key: string) => request<NodeConnection>({ url: `/nodes/${id}/refresh`, method: "POST", timeout: 30_000, headers: { "Idempotency-Key": key } }),
  deleteNode: (id: string, key: string) => request<NodeConnection>({ url: `/nodes/${id}`, method: "DELETE", timeout: 30_000, headers: { "Idempotency-Key": key } }),
  systemVersion: (signal?: AbortSignal) =>
    request<SystemVersion>({ url: "/system/version", signal }),
  exportMigration: (data: MigrationExportInput) =>
    request<MigrationPackage>({
      method: "POST",
      url: "/migrations/export",
      data,
      timeout: 45_000,
    }),
  prepareMigration: (data: MigrationImportInput) =>
    request<MigrationPlan>({
      method: "POST",
      url: "/migrations/plan",
      data,
      timeout: 45_000,
    }),
  preflightMigration: (id: string) =>
    request<MigrationPlan>({
      url: `/migrations/${id}/preflight`,
      method: "POST",
    }),
  prepareMigrationDependencies: (
    id: string,
    data: MigrationDependencyInput,
    key: string,
  ) =>
    request<MigrationPlan>({
      url: `/migrations/${id}/dependencies`,
      method: "POST",
      data,
      headers: { "Idempotency-Key": key },
    }),
  executeMigration: (id: string, data: MigrationExecuteInput, key: string) =>
    request<MigrationPlan>({
      method: "POST",
      url: `/migrations/${encodeURIComponent(id)}/execute`,
      data,
      headers: { "Idempotency-Key": key },
      timeout: 45_000,
    }),
  startMigrationPush: (data: MigrationPushInput, key: string) =>
    request<MigrationPushTask>({
      method: "POST",
      url: "/migrations/push",
      data,
      headers: { "Idempotency-Key": key },
      timeout: 45_000,
    }),
  migrationPushes: (signal?: AbortSignal) =>
    request<MigrationPushTask[]>({ url: "/migrations/push", signal }),
  migrationPush: (id: string, signal?: AbortSignal) =>
    request<MigrationPushTask>({
      url: `/migrations/push/${encodeURIComponent(id)}`,
      signal,
    }),
  resumeMigrationPush: (
    id: string,
    data: MigrationPushResumeInput,
    key: string,
  ) =>
    request<MigrationPushTask>({
      method: "POST",
      url: `/migrations/push/${encodeURIComponent(id)}/resume`,
      data,
      headers: { "Idempotency-Key": key },
    }),
  pullMigration: (data: MigrationPullInput, key: string) =>
    request<MigrationPlan>({
      method: "POST",
      url: "/migrations/pull",
      data,
      headers: { "Idempotency-Key": key },
      timeout: 45_000,
    }),
  maintenance: (signal?: AbortSignal) =>
    request<MaintenanceView>({ url: "/maintenance", signal }),
  enterMaintenance: (data: MaintenanceStartInput, key: string) =>
    request<MaintenanceSession>({
      url: "/maintenance",
      method: "POST",
      data,
      headers: { "Idempotency-Key": key },
    }),
  releaseMaintenance: (id: string) =>
    request<MaintenanceSession>({
      url: `/maintenance/${encodeURIComponent(id)}/release`,
      method: "POST",
    }),
  components: (signal?: AbortSignal) =>
    request<ComponentOverview>({ url: "/components", signal }),
  componentOfflineUploads: (signal?: AbortSignal) =>
    request<ComponentOfflineUpload[]>({ url: "/components/offline", signal }),
  createComponentOfflineUpload: (data: ComponentOfflineInput, key: string) =>
    request<ComponentOfflineUpload>({ url: "/components/offline", method: "POST", data, headers: { "Idempotency-Key": key } }),
  writeComponentOfflineChunk: (id: string, asset: string, data: ComponentOfflineChunk) =>
    request<ComponentOfflineUpload>({ url: `/components/offline/${encodeURIComponent(id)}/assets/${encodeURIComponent(asset)}`, method: "PUT", data }),
  discardComponentOfflineUpload: (id: string) =>
    request<ComponentOfflineUpload>({ url: `/components/offline/${encodeURIComponent(id)}`, method: "DELETE" }),
  pullComponentImage: (data: ComponentCreateInput, key: string) =>
    request<ComponentTask>({ url: "/components/images/pull", method: "POST", data, headers: { "Idempotency-Key": key } }),
  activateFrontend: (data: ComponentCreateInput, key: string) =>
    request<ComponentTask>({ url: "/components/frontend/activate", method: "POST", data, headers: { "Idempotency-Key": key } }),
  componentTasks: (signal?: AbortSignal) =>
    request<ComponentTask[]>({ url: "/components/tasks", signal }),
  panelImageUpgrades: (signal?: AbortSignal) =>
    request<ImageUpgradeTask[]>({ url: "/panel/images/upgrades", signal }),
  createPanelImageUpgrade: (data: PanelImageUpgradeCreateInput, key: string) =>
    request<ImageUpgradeTask>({
      url: "/panel/images/upgrades",
      method: "POST",
      data,
      headers: { "Idempotency-Key": key },
    }),
  resumePanelImageUpgrade: (id: string, key: string) =>
    request<ImageUpgradeTask>({
      url: `/panel/images/upgrades/${encodeURIComponent(id)}/resume`,
      method: "POST",
      headers: { "Idempotency-Key": key },
    }),
  nginxImageUpgrades: (signal?: AbortSignal) =>
    request<ImageUpgradeTask[]>({ url: "/nginx/images/upgrades", signal }),
  createNginxImageUpgrade: (data: NginxImageUpgradeCreateInput, key: string) =>
    request<ImageUpgradeTask>({
      url: "/nginx/images/upgrades",
      method: "POST",
      data,
      headers: { "Idempotency-Key": key },
    }),
  resumeNginxImageUpgrade: (id: string, key: string) =>
    request<ImageUpgradeTask>({
      url: `/nginx/images/upgrades/${encodeURIComponent(id)}/resume`,
      method: "POST",
      headers: { "Idempotency-Key": key },
    }),
  agentUpgrades: (signal?: AbortSignal) =>
    request<AgentUpgradeTask[]>({ url: "/agent/upgrades", signal }),
  createAgentUpgrade: (data: AgentUpgradeCreateInput, key: string) =>
    request<AgentUpgradeTask>({
      url: "/agent/upgrades",
      method: "POST",
      data,
      headers: { "Idempotency-Key": key },
    }),
  resumeAgentUpgrade: (id: string, key: string) =>
    request<AgentUpgradeTask>({
      url: `/agent/upgrades/${encodeURIComponent(id)}/resume`,
      method: "POST",
      headers: { "Idempotency-Key": key },
    }),
  panelUpdates: (signal?: AbortSignal) =>
    request<PanelUpdateTask[]>({ url: "/panel/updates", signal }),
  createPanelUpdate: (data: PanelUpdateCreateInput, key: string) =>
    request<PanelUpdateTask>({
      url: "/panel/updates",
      method: "POST",
      data,
      headers: { "Idempotency-Key": key },
    }),
  resumePanelUpdate: (id: string, key: string) =>
    request<PanelUpdateTask>({
      url: `/panel/updates/${encodeURIComponent(id)}/resume`,
      method: "POST",
      headers: { "Idempotency-Key": key },
    }),
  nginxInstallations: (signal?: AbortSignal) =>
    request<NginxInstallTask[]>({ url: "/components/installations", signal }),
  createNginxInstallation: (data: NginxInstallCreateInput, key: string) =>
    request<NginxInstallTask>({
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
      url: `/components/installations/${encodeURIComponent(id)}/${command}`,
      method: "POST",
      headers: { "Idempotency-Key": key },
    }),
  nginxSwitches: (signal?: AbortSignal) =>
    request<NginxSwitchTask[]>({ url: "/components/switches", signal }),
  createNginxSwitch: (data: NginxSwitchCreateInput, key: string) =>
    request<NginxSwitchTask>({
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
      url: `/components/switches/${encodeURIComponent(id)}/${command}`,
      method: "POST",
      headers: { "Idempotency-Key": key },
    }),
  createComponentTask: (data: ComponentCreateInput, key: string) =>
    request<ComponentTask>({
      url: "/components/tasks",
      method: "POST",
      headers: { "Idempotency-Key": key },
      data,
    }),

  migrations: (signal?: AbortSignal) =>
    request<MigrationPlan[]>({ url: "/migrations", signal }),
  migration: (id: string, signal?: AbortSignal) =>
    request<MigrationPlan>({
      url: `/migrations/${encodeURIComponent(id)}`,
      signal,
    }),
  notifications: (signal?: AbortSignal) =>
    request<NotificationOverview>({ url: "/notifications", signal }),
  hostDNS: (signal?: AbortSignal) =>
    request<HostDNSOverview>({ url: "/host/dns", signal }),
  firewallRuntime: (signal?: AbortSignal) =>
    request<FirewallRuntime>({ url: "/firewall/runtime", signal, timeout: FIREWALL_REQUEST_TIMEOUT }),
  firewallOperation: (id: string, signal?: AbortSignal) =>
    request<FirewallOperation>({ url: `/firewall/operations/${id}`, signal, timeout: FIREWALL_REQUEST_TIMEOUT }),
  planFirewall: (data: FirewallPlanInput, signal?: AbortSignal) =>
    request<FirewallPlan>({
      url: "/firewall/plan",
      method: "POST",
      timeout: FIREWALL_REQUEST_TIMEOUT,
      data,
      signal,
    }),
  applyFirewall: (data: FirewallApplyInput, key: string) =>
    request<FirewallOperation>({
      url: "/firewall/apply",
      method: "POST",
      timeout: FIREWALL_REQUEST_TIMEOUT,
      data,
      headers: { "Idempotency-Key": key },
    }),
  decideFirewall: (id: string, action: "confirm" | "rollback") =>
    request<FirewallOperation>({
      url: `/firewall/operations/${id}/${action}`,
      method: "POST",
      timeout: FIREWALL_REQUEST_TIMEOUT,
    }),
  checkFail2banTemplates: (data: Fail2banTemplateCheckInput, signal?: AbortSignal) => request<Fail2banTemplateCheck[]>({url:"/fail2ban/templates/check",method:"POST",data,signal}),
  fail2banPolicy: (signal?: AbortSignal) => request<Fail2banPolicyView>({url:"/fail2ban/policy",signal}),
  fail2banTemplates: (signal?: AbortSignal) => request<Fail2banTemplate[]>({url:"/fail2ban/templates",signal}),
  fail2banPanelLogin: (signal?: AbortSignal) => request<Fail2banPanelLoginStatus>({url:"/fail2ban/panel-login",signal}),
  fail2banHostInput: (signal?: AbortSignal) => request<Fail2banHostInputPreview>({url:"/fail2ban/host-input",signal}),
  saveFail2banPolicy: (data:Fail2banPolicyInput,key:string) => request<Fail2banPolicyView>({url:"/fail2ban/policy",method:"PUT",data,headers:{"Idempotency-Key":key}}),
  previewFail2ban: (version:number,signal?:AbortSignal) => request<Fail2banPolicyPreview>({url:"/fail2ban/preview",method:"POST",data:{version},signal,timeout:30_000}),
  fail2banPythonTasks: (signal?: AbortSignal) =>
    request<Fail2banPythonTaskStatus[]>({ url: "/fail2ban/python/tasks", signal }),
  changeFail2banPython: (data: Fail2banPythonTaskInput, key: string) =>
    request<Fail2banPythonTask>({ url: "/fail2ban/python", method: "POST", data, headers: { "Idempotency-Key": key } }),
  changeFail2banUpgrade: (data: Fail2banUpgradeInput, key: string) =>
    request<Fail2banUpgradeTask>({ url: "/fail2ban/upgrade", method: "POST", data, headers: { "Idempotency-Key": key } }),
  fail2banUpgradeTasks: (signal?: AbortSignal) =>
    request<Fail2banUpgradeTaskStatus[]>({ url: "/fail2ban/upgrade/tasks", signal }),
  previewFail2banLifecycle: (data: Fail2banLifecyclePreviewInput, signal?: AbortSignal) =>
    request<Fail2banLifecyclePlan>({ url: "/fail2ban/lifecycle/preview", method: "POST", data, signal }),
  fail2banLifecycleTasks: (signal?: AbortSignal) =>
    request<Fail2banLifecycleTaskStatus[]>({ url: "/fail2ban/lifecycle/tasks", signal }),
  changeFail2banLifecycle: (data: Fail2banLifecycleInput, key: string) =>
    request<Fail2banLifecycleTask>({ url: "/fail2ban/lifecycle", method: "POST", data, headers: { "Idempotency-Key": key } }),
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
        url: `/fail2ban/existing/tasks/${encodeURIComponent(id)}/cancel`,
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    fail2banRuntime: (signal?:AbortSignal) => request<Fail2banJailsRuntime>({url:"/fail2ban/runtime",signal}),
  fail2banTasks: (signal?:AbortSignal) => request<Fail2banApplyTaskStatus[]>({url:"/fail2ban/tasks",signal}),
  applyFail2ban: (data:Fail2banApplyInput,key:string) => request<Fail2banApplyTask>({url:"/fail2ban/apply",method:"POST",data,headers:{"Idempotency-Key":key}}),
  fail2banInstance: (signal?: AbortSignal) => request<Fail2banInstance>({ url: "/fail2ban/instance", signal }),
  fail2banJail: (name: string, signal?: AbortSignal) => request<Fail2banJail>({ url: `/fail2ban/jails/${encodeURIComponent(name)}`, signal, timeout: 30_000 }),
  fail2ban: (signal?: AbortSignal) =>
    request<Fail2banObservation>({ url: "/fail2ban", signal }),
  firewall: (signal?: AbortSignal) =>
    request<FirewallObservation>({ url: "/firewall", signal }),
  firewallGeoIP: (signal?: AbortSignal) => request<GeoIPState>({url:"/firewall/geoip",signal}),
  saveFirewallGeoIP: (data: GeoIPSourceInput,key:string) => request<GeoIPState>({url:"/firewall/geoip",method:"PUT",data,headers:{"Idempotency-Key":key}}),
  updateFirewallGeoIP: (data: GeoIPUpdateInput,key:string) => request<GeoIPState>({url:"/firewall/geoip/update",method:"POST",data,headers:{"Idempotency-Key":key},timeout:125_000}),
  resolveFirewallGeoIP: (data:GeoIPResolveInput) => request<GeoIPResolved>({url:"/firewall/geoip/resolve",method:"POST",data,timeout:30_000}),
  firewallPolicy: (signal?: AbortSignal) =>
    request<FirewallPolicyView>({ url: "/firewall/policy", signal }),
  saveFirewallPolicy: (data: FirewallPolicyInput, key: string) =>
    request<FirewallPolicyView>({ url: "/firewall/policy", method: "PUT", data, headers: { "Idempotency-Key": key } }),
  previewFirewall: (version: number, signal?: AbortSignal) =>
    request<FirewallPreview>({ url: "/firewall/preview", method: "POST", data: { version }, signal }),
  planHostDNS: (data: HostDNSPlanInput, key: string) =>
    request<HostDNSPlan>({
      url: "/host/dns/plan",
      method: "POST",
      data,
      headers: { "Idempotency-Key": key },
    }),
  applyHostDNS: (plan_id: string, key: string) =>
    request<HostDNSChange>({
      url: "/host/dns/apply",
      method: "POST",
      data: { plan_id },
      headers: { "Idempotency-Key": key },
    }),
  decideHostDNS: (id: string, action: "confirm" | "rollback", key: string) =>
    request<HostDNSChange>({
      url: `/host/dns/tasks/${id}/${action}`,
      method: "POST",
      headers: { "Idempotency-Key": key },
    }),
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
  logSources: (signal?: AbortSignal) => request<LogSource[]>({ url: "/logs/sources", signal }),
  logPolicies: () => request<LogPolicyView[]>({ url: "/logs/policy" }),
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
        ? AbortSignal.any([signal, scopeSignal(scope)])
        : scopeSignal(scope),
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
  nginxRuntime: (signal?: AbortSignal) =>
    request<NginxRuntime>({ url: "/nginx/runtime", signal }),
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
  modules: (signal?: AbortSignal) =>
    request<Module[]>({ url: "/system/modules", signal }),
  setModule: (
    id: string,
    enabled: boolean,
    options: {
      firewall_rules?: "keep" | "remove";
      firewall_operation_id?: string;
    } = {},
  ) =>
    request<null>({
      method: "PUT",
      url: `/system/modules/${encodeURIComponent(id)}`,
      timeout: id === "firewall" ? FIREWALL_REQUEST_TIMEOUT : undefined,
      data: { enabled, ...options },
    }),
  };
}
export const api = createAPI(controlScope);
export function useNodeAPI() {
  const route = useRoute();
  const controller = new AbortController();
  const scope = pageScope(!!route.meta.localOnly || !!route.meta.public, controller.signal);
  onScopeDispose(() => controller.abort());
  return createAPI(scope);
}
