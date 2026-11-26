import type {
  Tree,
  ConfigFile,
  Resource,
  SaveResult,
  SaveRequest,
  ResourceMetadata,
  WAFInput,
  NginxFeatures,
  AccessListInput,
  NginxRuntime,
  Difference,
  ExternalSnapshot,
  CaptureExternalRequest,
  RestoreExternalRequest,
  NativeModulesRequest,
} from "../types";
import type { components } from "../schema";
import type { APIRequest } from "../transport";

export function createNginxAPI(request: APIRequest) {
  return {
    tree: () => request<Tree>({ url: "/nginx/config-tree" }),
    preview: (data: SaveRequest) =>
      request<Tree>({
        method: "POST",
        url: "/nginx/config-tree/preview",
        data,
      }),
    save: (data: SaveRequest, key: string) =>
      request<SaveResult>({
        activity: data.apply
          ? "应用 Nginx 配置"
          : data.validate
            ? "校验 Nginx 配置"
            : undefined,
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
    resourceTemplate: (kind: "http" | "stream") =>
      request<Resource>({ url: "/nginx/resources/template", params: { kind } }),
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
      details?: Pick<
        components["schemas"]["ResourceAction"],
        "changes" | "metadata"
      >,
    ) =>
      request<SaveResult>({
        method: action === "copy" ? "POST" : "DELETE",
        url: `/nginx/resources/${encodeURIComponent(id)}${action === "copy" ? "/copy" : ""}`,
        data: { base_version, ...details },
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
        activity: "应用 Nginx 配置",
        method: "POST",
        url: "/nginx/apply",
        data: { base_version },
        headers: { "Idempotency-Key": key },
      }),
    nginxRuntime: (signal?: AbortSignal) =>
      request<NginxRuntime>({ url: "/nginx/runtime", signal }),
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
        activity: "恢复 Nginx 配置",
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
  };
}
