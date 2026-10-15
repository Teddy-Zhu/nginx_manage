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
    const body = result.data;
    if (
      !body ||
      typeof body.code !== "string" ||
      typeof body.message !== "string" ||
      !("data" in body) ||
      !body.request_id ||
      !body.node_id
    ) {
      throw new ApiError("INVALID_RESPONSE", "服务返回格式无效", result.status);
    }
    if (nodeId && nodeId !== body.node_id)
      throw new ApiError(
        "NODE_IDENTITY_CHANGED",
        "节点身份已变化，请重新连接",
        409,
      );
    nodeId = body.node_id;
    if (body.code !== "OK")
      throw new ApiError(
        body.code,
        body.message,
        result.status,
        body.data,
        body.request_id,
      );
    return body.data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (axios.isCancel(error)) throw new ApiError("CANCELLED", "请求已取消", 0);
    if (error instanceof AxiosError) {
      const body = error.response?.data as ResponseBody<unknown> | undefined;
      const normalized = new ApiError(
        body?.code ?? "NETWORK_ERROR",
        body?.message ??
          (error.code === "ECONNABORTED"
            ? "请求超时，请先查询任务状态"
            : "无法连接服务"),
        error.response?.status ?? 0,
        body?.data,
        body?.request_id,
      );
      if (normalized.status === 401)
        window.dispatchEvent(new Event("session-expired"));
      if (normalized.code === "REAUTHENTICATION_REQUIRED")
        window.dispatchEvent(new Event("reauthentication-required"));
      throw normalized;
    }
    throw new ApiError("CLIENT_ERROR", "请求处理失败", 0);
  }
}

export const api = {
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
