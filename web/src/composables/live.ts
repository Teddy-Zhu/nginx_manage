import { onScopeDispose, watch } from "vue";
import { useSession } from "../stores/session";
import type { LiveTopic } from "../api/live";

type LiveAPI = {
  subscribe: (topics: LiveTopic[], changed: () => void) => () => void;
};
export function useLiveRefresh(
  api: LiveAPI,
  topics: LiveTopic[],
  refresh: () => Promise<unknown> | void,
  blocked: () => boolean = () => false,
) {
  const session = useSession();
  const required: Record<LiveTopic, string[]> = {
    tasks: ["read"],
    monitoring: ["read"],
    notifications: ["read"],
    maintenance: ["read", "system.write"],
    backups: ["read", "backup.export"],
    firewall: ["read", "security.write"],
    listener: ["read", "system.write"],
    version: ["read"],
    dns: ["read"],
    fail2ban: ["read"],
  };
  let release: (() => void) | undefined;
  let running = false,
    pending = false,
    disposed = false;
  const ready = () =>
    !disposed && release !== undefined && !document.hidden && !blocked();
  const drain = async () => {
    if (running || !ready()) return;
    running = true;
    try {
      while (pending && ready()) {
        pending = false;
        await refresh();
      }
    } catch (error) {
      // Existing page loaders own user-facing errors. Unexpected errors must not
      // become unhandled socket callback rejections.
      console.error("实时状态刷新失败", error);
    } finally {
      running = false;
    }
  };
  const update = () => {
    if (disposed || !release) return;
    // Keep one refresh queued while a page is loading or editing. A final
    // state change may be the last notification until another user action.
    pending = true;
    void drain();
  };
  const stopBlocked = watch(blocked, (value) => {
    if (!value && pending) void drain();
  });
  const stop = watch(
    () =>
      session.localMe?.authenticated
        ? session.localMe.scopes.slice().sort().join(",")
        : null,
    (authenticated) => {
      release?.();
      release = undefined;
      pending = false;
      if (authenticated !== null) {
        const allowed = topics.filter((topic) =>
          required[topic].every((scope) =>
            session.localMe?.scopes.includes(scope),
          ),
        );
        if (allowed.length)
          release = api.subscribe(allowed, update);
      }
    },
    { immediate: true },
  );
  const visible = () => {
    if (!document.hidden) update();
  };
  document.addEventListener("visibilitychange", visible);
  onScopeDispose(() => {
    disposed = true;
    release?.();
    stop();
    stopBlocked();
    document.removeEventListener("visibilitychange", visible);
  });
}
