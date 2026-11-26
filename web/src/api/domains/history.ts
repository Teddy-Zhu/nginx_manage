import type {
  AuditFilter,
  RuntimeHistoryFilter,
  RuntimeHistoryExecuteInput,
  RuntimeHistoryPreview,
  RuntimeHistoryStatus,
  HistoryFilter,
  HistoryPreview,
  HistoryExecuteInput,
  HistoryResult,
  AuditPage,
  AuditQuery,
} from "../types";
import {
  type APIRequest,
  ApiError,
  assertScope,
  downloadBlobFor,
} from "../transport";
import type { RequestScope } from "../context";
import { sha256Hex } from "../../utils/crypto";

async function exportAuditFor(data: AuditFilter, scope: RequestScope) {
  const result = await downloadBlobFor(
    "/audit/export",
    data,
    scope,
    "application/x-ndjson",
  );
  const expected = String(result.headers["x-archive-sha256"] ?? "");
  if (result.data.size > 8 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(expected))
    throw new ApiError(
      "INVALID_RESPONSE",
      "审计归档大小或摘要无效",
      result.status,
    );
  const actual = sha256Hex(new Uint8Array(await result.data.arrayBuffer()));
  assertScope(scope);
  if (actual !== expected)
    throw new ApiError(
      "INVALID_RESPONSE",
      "审计归档摘要不匹配，请重新下载",
      result.status,
    );
  return result.data;
}

export function createHistoryAPI(request: APIRequest, scope: RequestScope) {
  return {
    exportAudit: (data: AuditFilter) => exportAuditFor(data, scope),
    runtimeHistory: () =>
      request<RuntimeHistoryStatus[]>({ url: "/history/runtime" }),
    previewRuntimeHistory: (data: RuntimeHistoryFilter) =>
      request<RuntimeHistoryPreview>({
        url: "/history/runtime/preview",
        method: "POST",
        data,
      }),
    executeRuntimeHistory: (data: RuntimeHistoryExecuteInput) =>
      request<RuntimeHistoryStatus>({
        url: "/history/runtime/execute",
        method: "POST",
        data,
        headers: { "Idempotency-Key": data.operation_id },
      }),
    previewHistory: (data: HistoryFilter) =>
      request<HistoryPreview>({
        url: "/history/preview",
        method: "POST",
        data,
      }),
    executeHistory: (data: HistoryExecuteInput, key: string) =>
      request<HistoryResult>({
        url: "/history/execute",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    audit: (params: AuditQuery) =>
      request<AuditPage>({ url: "/audit", params }),
  };
}
