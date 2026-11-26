import type {
  MonitoringSettingsView,
  MonitoringSettingsInput,
  MonitoringLatest,
  MonitoringHistory,
} from "../types";
import type { APIRequest } from "../transport";

export function createMonitoringAPI(request: APIRequest) {
  return {
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
      },
      signal?: AbortSignal,
    ) =>
      request<MonitoringHistory>({
        url: "/monitoring/history",
        params,
        signal,
      }),
  };
}
