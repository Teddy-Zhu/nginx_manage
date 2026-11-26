import {
  LiveError,
  isLiveResource,
  liveSessionActive,
  readLive,
  refreshLive,
} from "./live";
import type { LiveResult } from "./live";
import axios, { AxiosError, type AxiosRequestConfig } from "axios";
import type { components } from "./schema";
import {
  acceptOperation,
  beginOperation,
  rejectOperation,
} from "../stores/operation";
import {
  invalidateNodeScope,
  nodeGeneration,
  nodeRequestError,
  scopeSignal,
  selectedTarget,
  sourceNodeId,
  type RequestScope,
} from "./context";

type ResponseBody<T> = Omit<components["schemas"]["Response"], "data"> & {
  data: T;
};
export type RequestConfig = Omit<AxiosRequestConfig, "signal"> & {
  signal?: AbortSignal;
  activity?: string | { title: string; requestOnly: true };
};
export type APIRequest = <T>(config: RequestConfig) => Promise<T>;

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

const http = axios.create({
  baseURL: "/api/v1",
  timeout: 20_000,
  withCredentials: true,
});
let csrf = "";
export const controlScope: RequestScope = { target: null, generation: null };
export function setCSRF(value: string) {
  csrf = value;
}
export function cancelNodeRequests() {
  invalidateNodeScope();
}
export function assertScope(scope: RequestScope) {
  if (
    scopeSignal(scope).aborted ||
    (scope.generation !== null && scope.generation !== nodeGeneration.value)
  )
    throw new ApiError("CANCELLED", "节点请求已取消", 0);
}
function endpoint(url: string, scope: RequestScope) {
  assertScope(scope);
  if (!url.startsWith("/") || url.startsWith("//"))
    throw new ApiError("INVALID_REQUEST", "接口路径无效", 0);
  return scope.target
    ? `/nodes/connections/${scope.target.connection}${url}`
    : url;
}
export function request<T>(config: RequestConfig): Promise<T> {
  return scopedRequest<T>(config, controlScope);
}
export async function scopedRequest<T>(
  config: RequestConfig,
  scope: RequestScope,
): Promise<T> {
  assertScope(scope);
  const { activity, ...options } = config;
  const operation = activity
    ? beginOperation(
        typeof activity === "string" ? activity : activity.title,
        scope,
        typeof activity !== "string" && activity.requestOnly,
      )
    : null;
  try {
    const data = await sendRequest<T>(options, scope);
    if (operation !== null) acceptOperation(operation, data);
    return data;
  } catch (cause) {
    const error = cause instanceof ApiError ? cause : apiError(cause);
    if (operation !== null)
      rejectOperation(
        operation,
        error.message,
        error.status === 0 || error.status >= 500,
      );
    throw error;
  }
}
async function sendRequest<T>(
  config: RequestConfig,
  scope: RequestScope,
): Promise<T> {
  assertScope(scope);
  const signal = config.signal
    ? AbortSignal.any([config.signal, scopeSignal(scope)])
    : scopeSignal(scope);
  const method = String(config.method ?? "GET").toUpperCase();
  let resource = axios.getUri({
    url: String(config.url ?? ""),
    params: config.params,
  });
  if (
    liveSessionActive() &&
    method === "GET" &&
    resource.startsWith("/monitoring/history?")
  ) {
    const query = new URLSearchParams(resource.split("?")[1]);
    query.set(
      "window",
      String(Number(query.get("until")) - Number(query.get("from"))),
    );
    query.delete("from");
    query.delete("until");
    resource = "/monitoring/history?" + query.toString();
  }
  const preparationRead =
    method === "POST" &&
    config.url === "/firewall/plan" &&
    config.data?.preparation_id &&
    !config.data?.cancel_preparation;
  if (preparationRead)
    resource =
      "/firewall/plan?" +
      new URLSearchParams({ input: JSON.stringify(config.data) });
  if (
    liveSessionActive() &&
    (method === "GET" || preparationRead) &&
    isLiveResource(resource)
  ) {
    try {
      const result = await readLive(
        scope,
        resource,
        signal,
        config.timeout ?? 20_000,
      );
      return liveData<T>(result, scope);
    } catch (cause) {
      throw apiError(cause);
    }
  }
  try {
    const result = await http.request<ResponseBody<T>>({
      ...config,
      baseURL: "/api/v1",
      url: endpoint(String(config.url ?? ""), scope),
      headers: { ...config.headers, "X-CSRF-Token": csrf },
      signal: config.signal
        ? AbortSignal.any([config.signal, scopeSignal(scope)])
        : scopeSignal(scope),
    });
    const data = responseData<T>(result.data, result.status, scope);
    if (
      !["GET", "HEAD", "OPTIONS"].includes(method) &&
      !/\/(preview|plan|query|resolve|check|download|cursors\/release)$/.test(
        String(config.url),
      )
    )
      refreshLive(scope);
    return data;
  } catch (cause) {
    assertScope(scope);
    if (
      cause instanceof AxiosError &&
      cause.response?.data &&
      !(cause.response.data instanceof Blob)
    ) {
      try {
        responseData(cause.response.data, cause.response.status, scope);
      } catch (validated) {
        throw apiError(validated);
      }
    }
    throw apiError(cause);
  }
}
export function liveData<T>(value: LiveResult, scope: RequestScope): T {
  assertScope(scope);
  if (value.code !== "OK")
    throw new ApiError(value.code, value.message, value.status!, value.data);
  return value.data as T;
}
function responseData<T>(
  body: ResponseBody<T>,
  status: number,
  scope: RequestScope,
): T {
  assertScope(scope);
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
  if ((status >= 200 && status < 300) !== (body.code === "OK"))
    throw new ApiError("INVALID_RESPONSE", "响应状态与结果不一致", status);
  checkNode(body.node_id, scope, status, body.code);
  if (body.code !== "OK")
    throw new ApiError(
      body.code,
      body.message,
      status,
      body.data,
      body.request_id,
      body.node_id,
    );
  return body.data;
}
function checkNode(
  value: string,
  scope: RequestScope,
  status = 200,
  code = "OK",
) {
  assertScope(scope);
  if (!value) throw new ApiError("INVALID_RESPONSE", "响应缺少节点身份", 502);
  if (scope.target) {
    if (
      value !== scope.target.nodeId &&
      !(status >= 400 && code !== "OK" && value === sourceNodeId.value)
    )
      throw new ApiError(
        "NODE_IDENTITY_CHANGED",
        "目标节点身份已变化，请重新检查连接",
        409,
      );
  } else {
    if (sourceNodeId.value && sourceNodeId.value !== value)
      throw new ApiError(
        "NODE_IDENTITY_CHANGED",
        "本机节点身份已变化，请重新连接",
        409,
      );
    sourceNodeId.value = value;
  }
}

export function apiError(error: unknown): ApiError {
  let normalized: ApiError;
  if (error instanceof ApiError) normalized = error;
  else if (error instanceof LiveError)
    normalized = new ApiError(error.code, error.message, error.status);
  else if (
    axios.isCancel(error) ||
    (error instanceof DOMException && error.name === "AbortError")
  )
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
  if (
    (normalized.status === 401 || normalized.code === "UNAUTHENTICATED") &&
    (!normalized.originNodeId || normalized.originNodeId === sourceNodeId.value)
  )
    window.dispatchEvent(new Event("session-expired"));
  const targetUnauthorized =
    !!selectedTarget.value &&
    normalized.originNodeId === selectedTarget.value.nodeId &&
    (normalized.status === 401 || normalized.code === "UNAUTHENTICATED");
  if (
    selectedTarget.value &&
    normalized.code !== "CANCELLED" &&
    (normalized.code.startsWith("REMOTE_") ||
      normalized.code === "NODE_IDENTITY_CHANGED" ||
      targetUnauthorized)
  )
    nodeRequestError.value = targetUnauthorized
      ? "目标服务器授权不可用，请在远程服务管理中检查连接"
      : normalized.message;
  return normalized;
}

export async function downloadBlobFor(
  path: string,
  data: unknown,
  scope: RequestScope,
  mediaType: string,
) {
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
    if (String(result.headers["content-type"]).split(";")[0] !== mediaType)
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
    if (
      error instanceof AxiosError &&
      error.response?.data &&
      !(error.response.data instanceof Blob)
    ) {
      try {
        responseData(error.response.data, error.response.status, scope);
      } catch (validated) {
        throw apiError(validated);
      }
    }
    throw apiError(error);
  }
}
