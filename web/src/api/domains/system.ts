import type {
  Me,
  ManagementListenerInput,
  ManagementListenerOperation,
  ManagementListenerView,
  Task,
  Module,
  SystemVersion,
} from "../types";
import type { APIRequest } from "../transport";
import { FIREWALL_REQUEST_TIMEOUT } from "./firewall";

export function createSystemAPI(request: APIRequest) {
  return {
    managementListener: () =>
      request<ManagementListenerView>({ url: "/management/listener" }),
    listenerOperation: (id: string) =>
      request<ManagementListenerOperation>({
        url: `/management/listener/operations/${id}`,
      }),
    applyManagementListener: (data: ManagementListenerInput, key: string) =>
      request<ManagementListenerOperation>({
        url: "/management/listener",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    decideManagementListener: (id: string, action: "confirm" | "rollback") =>
      request<ManagementListenerOperation>({
        url: `/management/listener/operations/${id}/${action}`,
        method: "POST",
      }),
    systemVersion: (signal?: AbortSignal) =>
      request<SystemVersion>({ url: "/system/version", signal }),
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
    tasks: () => request<Task[]>({ url: "/tasks" }),
    task: (id: string, signal?: AbortSignal) =>
      request<Task>({ url: `/tasks/${encodeURIComponent(id)}`, signal }),
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
