import type {
  GeoIPState,
  GeoIPSourceInput,
  GeoIPUpdateInput,
  GeoIPResolveInput,
  GeoIPResolved,
  FirewallObservation,
  FirewallPolicyView,
  FirewallPolicyInput,
  FirewallPlanInput,
  FirewallPlan,
  FirewallOperation,
  FirewallRuntime,
  FirewallApplyInput,
  FirewallPreview,
} from "../types";
import type { APIRequest } from "../transport";

export const FIREWALL_REQUEST_TIMEOUT = 85_000;

export function createFirewallAPI(request: APIRequest) {
  return {
    firewallRuntime: (signal?: AbortSignal) =>
      request<FirewallRuntime>({
        url: "/firewall/runtime",
        signal,
        timeout: FIREWALL_REQUEST_TIMEOUT,
      }),
    firewallOperation: (id: string, signal?: AbortSignal) =>
      request<FirewallOperation>({
        url: `/firewall/operations/${id}`,
        signal,
        timeout: FIREWALL_REQUEST_TIMEOUT,
      }),
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
    firewall: (signal?: AbortSignal) =>
      request<FirewallObservation>({ url: "/firewall", signal }),
    firewallGeoIP: (signal?: AbortSignal) =>
      request<GeoIPState>({ url: "/firewall/geoip", signal }),
    saveFirewallGeoIP: (data: GeoIPSourceInput, key: string) =>
      request<GeoIPState>({
        url: "/firewall/geoip",
        method: "PUT",
        data,
        headers: { "Idempotency-Key": key },
      }),
    updateFirewallGeoIP: (data: GeoIPUpdateInput, key: string) =>
      request<GeoIPState>({
        activity: { title: "更新 GeoIP 数据", requestOnly: true },
        url: "/firewall/geoip/update",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
        timeout: 125_000,
      }),
    resolveFirewallGeoIP: (data: GeoIPResolveInput) =>
      request<GeoIPResolved>({
        url: "/firewall/geoip/resolve",
        method: "POST",
        data,
        timeout: 30_000,
      }),
    firewallPolicy: (signal?: AbortSignal) =>
      request<FirewallPolicyView>({ url: "/firewall/policy", signal }),
    saveFirewallPolicy: (data: FirewallPolicyInput, key: string) =>
      request<FirewallPolicyView>({
        url: "/firewall/policy",
        method: "PUT",
        data,
        headers: { "Idempotency-Key": key },
      }),
    previewFirewall: (version: number, signal?: AbortSignal) =>
      request<FirewallPreview>({
        url: "/firewall/preview",
        method: "POST",
        data: { version },
        signal,
      }),
  };
}
