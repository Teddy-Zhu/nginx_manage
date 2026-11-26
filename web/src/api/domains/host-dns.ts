import type {
  HostDNSOverview,
  HostDNSPlan,
  HostDNSPlanInput,
  HostDNSChange,
} from "../types";
import type { APIRequest } from "../transport";

export function createHostDNSAPI(request: APIRequest) {
  return {
    hostDNS: (signal?: AbortSignal) =>
      request<HostDNSOverview>({ url: "/host/dns", signal }),
    planHostDNS: (data: HostDNSPlanInput, key: string) =>
      request<HostDNSPlan>({
        url: "/host/dns/plan",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    applyHostDNS: (plan_id: string, key: string) =>
      request<HostDNSChange>({
        activity: "应用 DNS 配置",
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
  };
}
