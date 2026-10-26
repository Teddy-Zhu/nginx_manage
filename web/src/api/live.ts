import { ref } from "vue";
import {
  nodeGeneration,
  scopeSignal,
  sourceNodeId,
  type RequestScope,
} from "./context";

export type LiveTopic =
  | "tasks"
  | "monitoring"
  | "notifications"
  | "maintenance"
  | "backups"
  | "firewall"
  | "listener"
  | "version";
interface Listener {
  topics: LiveTopic[];
  changed: () => void;
}
interface Channel {
  scope: RequestScope;
  listeners: Set<Listener>;
  socket?: WebSocket;
  retry?: ReturnType<typeof setTimeout>;
  failures: number;
  revision: number;
  topics: string;
}
const channels = new Map<string, Channel>();
export const liveDisconnected = ref(false);
function status() {
  liveDisconnected.value = [...channels.values()].some(
    (channel) => channel.failures > 0,
  );
}
function closeSocket(channel: Channel) {
  channel.revision++;
  if (channel.retry) clearTimeout(channel.retry);
  channel.retry = undefined;
  const socket = channel.socket;
  channel.socket = undefined;
  if (socket) {
    socket.onclose = socket.onerror = socket.onmessage = socket.onopen = null;
    socket.close();
  }
}
function connect(channel: Channel) {
  closeSocket(channel);
  if (!channel.listeners.size) return;
  const revision = channel.revision;
  const url = new URL("/api/v1/events", window.location.origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("topics", channel.topics);
  if (channel.scope.target)
    url.searchParams.set("connection", channel.scope.target.connection);
  const socket = new WebSocket(url);
  channel.socket = socket;
  socket.onopen = () => {
    channel.failures = 0;
    status();
  };
  socket.onmessage = (event) => {
    if (revision !== channel.revision) return;
    let frame: {
      code?: string;
      node_id?: string;
      data?: { topics?: string[] };
    };
    try {
      frame = JSON.parse(String(event.data));
    } catch {
      socket.close();
      return;
    }
    const node = channel.scope.target?.nodeId ?? sourceNodeId.value;
    if (
      frame.code === "UNAUTHENTICATED" &&
      frame.node_id === sourceNodeId.value
    ) {
      window.dispatchEvent(new Event("session-expired"));
      socket.close();
      return;
    }
    if (
      frame.code !== "OK" ||
      !node ||
      frame.node_id !== node ||
      !Array.isArray(frame.data?.topics) ||
      frame.data.topics.some(
        (topic) => !channel.topics.split(",").includes(topic),
      )
    ) {
      socket.close();
      return;
    }
    for (const listener of channel.listeners) {
      if (listener.topics.some((topic) => frame.data!.topics!.includes(topic)))
        listener.changed();
    }
  };
  socket.onerror = () => socket.close();
  socket.onclose = () => {
    if (revision !== channel.revision || !channel.listeners.size) return;
    channel.socket = undefined;
    channel.failures++;
    status();
    channel.retry = setTimeout(
      () => connect(channel),
      Math.min(30_000, 1000 * 2 ** Math.min(channel.failures - 1, 5)) +
        Math.random() * 500,
    );
  };
}
function update(channel: Channel) {
  const topics = [
    ...new Set([...channel.listeners].flatMap((listener) => listener.topics)),
  ]
    .sort()
    .join(",");
  if (topics === channel.topics && channel.socket) return;
  channel.topics = topics;
  connect(channel);
}

// Subscribers share one socket per server. Unmount, logout and node changes
// release their listeners; the final release also cancels reconnect attempts.
export function subscribeLive(
  scope: RequestScope,
  topics: LiveTopic[],
  changed: () => void,
) {
  if (scope.target) {
    topics = topics.filter(
      (topic) =>
        !["backups", "firewall", "listener"].includes(topic) &&
        (topic !== "maintenance" ||
          scope.target!.scopes.includes("system.write")),
    );
  }
  if (!topics.length) return () => {};
  if (
    scopeSignal(scope).aborted ||
    (scope.generation !== null && scope.generation !== nodeGeneration.value)
  )
    return () => {};
  const key = scope.target?.connection ?? "local";
  let channel = channels.get(key);
  if (!channel) {
    channel = {
      scope,
      listeners: new Set(),
      failures: 0,
      revision: 0,
      topics: "",
    };
    channels.set(key, channel);
  }
  const current = channel;
  const listener: Listener = { topics, changed };
  current.listeners.add(listener);
  // Coalesce subscriptions registered during the same Vue render.
  queueMicrotask(() => {
    if (channels.get(key) === current) update(current);
  });
  let released = false;
  const signal = scopeSignal(scope);
  const release = () => {
    if (released) return;
    released = true;
    signal.removeEventListener("abort", release);
    current.listeners.delete(listener);
    if (!current.listeners.size) {
      closeSocket(current);
      if (channels.get(key) === current) channels.delete(key);
      status();
    } else
      queueMicrotask(() => {
        if (channels.get(key) === current) update(current);
      });
  };
  signal.addEventListener("abort", release, { once: true });
  return release;
}
