import type { DockerOverview, DockerDetail, DockerLogs } from "../types";
import { type APIRequest, ApiError, apiError, liveData } from "../transport";
import { watchLiveResource } from "../live";
import type { RequestScope } from "../context";

export function createContainersAPI(request: APIRequest, scope: RequestScope) {
  return {
    dockerContainers: () =>
      request<DockerOverview>({ url: "/docker/containers" }),
    watchDockerContainer: (
      id: string,
      updated: (value: DockerDetail) => void,
      failed: (error: ApiError) => void,
    ) =>
      watchLiveResource(
        scope,
        `/docker/containers/${encodeURIComponent(id)}`,
        (value) => {
          try {
            updated(liveData<DockerDetail>(value, scope));
          } catch (error) {
            failed(apiError(error));
          }
        },
      ),
    watchDockerLogs: (
      id: string,
      tail: number,
      updated: (value: DockerLogs) => void,
      failed: (error: ApiError) => void,
    ) =>
      watchLiveResource(
        scope,
        `/docker/containers/${encodeURIComponent(id)}/logs?tail=${tail}`,
        (value) => {
          try {
            updated(liveData<DockerLogs>(value, scope));
          } catch (error) {
            failed(apiError(error));
          }
        },
      ),
  };
}
