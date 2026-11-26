import { onScopeDispose } from "vue";
import { useRoute } from "vue-router";
import { pageScope, type RequestScope } from "./context";
import { refreshLive, subscribeLive, type LiveTopic } from "./live";
import { controlScope, scopedRequest, type RequestConfig } from "./transport";
import { createContainersAPI } from "./domains/containers";
import { createLogsAPI } from "./domains/logs";
import { createHistoryAPI } from "./domains/history";
import { createNodesAPI } from "./domains/nodes";
import { createBackupsAPI } from "./domains/backups";
import { createSystemAPI } from "./domains/system";
import { createMigrationAPI } from "./domains/migration";
import { createSoftwareAPI } from "./domains/software";
import { createNotificationsAPI } from "./domains/notifications";
import { createHostDNSAPI } from "./domains/host-dns";
import { createFirewallAPI } from "./domains/firewall";
import { createFail2banAPI } from "./domains/fail2ban";
import { createMonitoringAPI } from "./domains/monitoring";
import { createCertificatesAPI } from "./domains/certificates";
import { createNginxAPI } from "./domains/nginx";

export type * from "./types";
export {
  ApiError,
  apiError,
  setCSRF,
  cancelNodeRequests,
  request,
} from "./transport";

export function createAPI(scope: RequestScope) {
  const request = <T>(config: RequestConfig) => scopedRequest<T>(config, scope);
  return {
    reloadLive: () => refreshLive(scope),
    subscribe: (topics: LiveTopic[], changed: () => void) =>
      subscribeLive(scope, topics, changed),
    request,
    ...createContainersAPI(request, scope),
    ...createLogsAPI(request, scope),
    ...createHistoryAPI(request, scope),
    ...createNodesAPI(request),
    ...createBackupsAPI(request),
    ...createSystemAPI(request),
    ...createMigrationAPI(request),
    ...createSoftwareAPI(request, scope),
    ...createNotificationsAPI(request),
    ...createHostDNSAPI(request),
    ...createFirewallAPI(request),
    ...createFail2banAPI(request),
    ...createMonitoringAPI(request),
    ...createCertificatesAPI(request),
    ...createNginxAPI(request),
  };
}
export const api = createAPI(controlScope);
export function useNodeAPI() {
  const route = useRoute();
  const controller = new AbortController();
  const scope = pageScope(
    !!route.meta.localOnly || !!route.meta.public,
    controller.signal,
  );
  onScopeDispose(() => controller.abort());
  return createAPI(scope);
}
