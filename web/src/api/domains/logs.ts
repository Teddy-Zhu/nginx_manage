import type {
  LogSource,
  LogQuery,
  LogPage,
  LogPolicyView,
  LogPolicyInput,
} from "../types";
import {
  type APIRequest,
  ApiError,
  apiError,
  assertScope,
  liveData,
  downloadBlobFor,
} from "../transport";
import { watchLiveResource } from "../live";
import { scopeSignal, type RequestScope } from "../context";

async function downloadLogFileFor(data: LogQuery, scope: RequestScope) {
  const result = await downloadBlobFor(
    "/logs/download",
    data,
    scope,
    "text/plain",
  );
  return {
    blob: result.data,
    gap: result.headers["x-log-gap"] === "true",
    truncated: result.headers["x-log-truncated"] === "true",
  };
}

function followLogsFor(
  scope: RequestScope,
  query: LogQuery,
  page: (value: LogPage, reset?: boolean) => void,
  error: (value: ApiError) => void,
) {
  assertScope(scope);
  const resource =
    "/logs/live?" +
    new URLSearchParams({ query: JSON.stringify({ ...query, cursor: "" }) });
  return watchLiveResource(scope, resource, (value) => {
    try {
      page(liveData<LogPage>(value, scope), value.reset);
    } catch (cause) {
      error(apiError(cause));
    }
  });
}

export function createLogsAPI(request: APIRequest, scope: RequestScope) {
  return {
    downloadLogFile: (data: LogQuery) => downloadLogFileFor(data, scope),
    followLogs: (
      query: LogQuery,
      page: (value: LogPage, reset?: boolean) => void,
      error: (value: ApiError) => void,
    ) => followLogsFor(scope, query, page, error),
    logSources: (signal?: AbortSignal) =>
      request<LogSource[]>({ url: "/logs/sources", signal }),
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
  };
}
