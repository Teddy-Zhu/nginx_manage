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
  | "version"
  | "dns";
interface Listener {
  topics: LiveTopic[];
  changed: () => void;
}
interface Channel {
  scope: RequestScope;
  listeners: Set<Listener>;
  failures: number;
  retry?: ReturnType<typeof setTimeout>;
}
interface LiveFrame {
  code: string;
  node_id: string;
  data?: { connection: string; topics: LiveTopic[]; revision: number };
}
const channels = new Map<string, Channel>();
let socket: WebSocket | undefined;
let retry: ReturnType<typeof setTimeout> | undefined;
let failures = 0,
  revision = 0,
  signature = "",
  scheduled = false,
  forceUpdate = false;
let intentionalClose = false;
export const liveDisconnected = ref(false);
function status() {
  liveDisconnected.value =
    !!channels.size &&
    (failures > 0 ||
      [...channels.values()].some((channel) => channel.failures > 0));
}
const delay = (attempts: number) =>
  Math.min(30_000, 1000 * 2 ** Math.min(attempts - 1, 5)) + Math.random() * 500;
function subscriptions() {
  return [...channels.entries()]
    .map(([connection, channel]) => ({
      connection,
      topics: [
        ...new Set(
          [...channel.listeners].flatMap((listener) => listener.topics),
        ),
      ].sort(),
    }))
    .sort((a, b) => a.connection.localeCompare(b.connection));
}
function publish(force = false) {
  if (socket?.readyState !== WebSocket.OPEN) return;
  const desired = subscriptions(),
    next = JSON.stringify(desired);
  if (!force && next === signature) return;
  for (const channel of channels.values()) {
    if (channel.retry) clearTimeout(channel.retry);
    channel.retry = undefined;
  }
  signature = next;
  socket.send(
    JSON.stringify({
      type: "subscribe",
      revision: ++revision,
      subscriptions: desired,
    }),
  );
}
function receive(current: WebSocket, event: MessageEvent) {
  if (socket !== current || current.readyState !== WebSocket.OPEN) return;
  let frame: LiveFrame;
  try {
    frame = JSON.parse(String(event.data));
  } catch {
    current.close();
    return;
  }
  if (
    !frame ||
    typeof frame !== "object" ||
    typeof frame.code !== "string" ||
    typeof frame.node_id !== "string"
  ) {
    current.close();
    return;
  }
  if (
    frame.code === "UNAUTHENTICATED" &&
    frame.node_id === sourceNodeId.value
  ) {
    window.dispatchEvent(new Event("session-expired"));
    current.close();
    return;
  }
  if (!frame.data || !Number.isSafeInteger(frame.data.revision)) {
    current.close();
    return;
  }
  // A changed subscription may leave older frames in flight.
  if (frame.data.revision !== revision) return;
  const channel = channels.get(frame.data.connection);
  if (!channel) return;
  if (frame.code === "REMOTE_STREAM_INTERRUPTED" && frame.data.connection) {
    channel.failures++;
    status();
    if (channel.retry) clearTimeout(channel.retry);
    channel.retry = setTimeout(() => {
      channel.retry = undefined;
      schedule(true);
    }, delay(channel.failures));
    return;
  }
  const node = channel.scope.target?.nodeId ?? sourceNodeId.value;
  const topics = new Set(
    [...channel.listeners].flatMap((listener) => listener.topics),
  );
  if (
    frame.code !== "OK" ||
    !node ||
    frame.node_id !== node ||
    !Array.isArray(frame.data.topics) ||
    !frame.data.topics.length ||
    frame.data.topics.some((topic) => !topics.has(topic))
  ) {
    current.close();
    return;
  }
  channel.failures = 0;
  if (channel.retry) clearTimeout(channel.retry);
  channel.retry = undefined;
  status();
  for (const listener of [...channel.listeners]) {
    if (listener.topics.some((topic) => frame.data!.topics.includes(topic))) {
      try {
        listener.changed();
      } catch (error) {
        console.error("实时状态处理失败", error);
      }
    }
  }
}
function connect() {
  if (socket || retry || !channels.size) return;
  const url = new URL("/api/v1/events", window.location.origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  const current = new WebSocket(url);
  socket = current;
  intentionalClose = false;
  signature = "";
  current.onopen = () => {
    if (socket !== current) return;
    failures = 0;
    status();
    publish(true);
  };
  current.onmessage = (event) => receive(current, event);
  current.onerror = () => current.close();
  current.onclose = () => {
    if (socket !== current) return;
    socket = undefined;
    signature = "";
    if (!channels.size) {
      failures = 0;
      status();
      return;
    }
    if (intentionalClose) {
      failures = 0;
      status();
      connect();
      return;
    }
    failures++;
    status();
    retry = setTimeout(() => {
      retry = undefined;
      connect();
    }, delay(failures));
  };
}
function schedule(force = false) {
  forceUpdate ||= force;
  if (scheduled) return;
  scheduled = true;
  queueMicrotask(() => {
    scheduled = false;
    const forced = forceUpdate;
    forceUpdate = false;
    if (!channels.size) {
      if (retry) clearTimeout(retry);
      retry = undefined;
      failures = 0;
      // Keep the closing instance until onclose; another page cannot open a
      // second socket before the previous connection has actually closed.
      intentionalClose = true;
      socket?.close();
      status();
    } else if (!socket) connect();
    else publish(forced);
  });
}

// All pages, operation drawers and servers share this module's single socket.
export function subscribeLive(
  scope: RequestScope,
  topics: LiveTopic[],
  changed: () => void,
) {
  if (scope.target)
    topics = topics.filter(
      (topic) =>
        !["backups", "firewall", "listener"].includes(topic) &&
        (topic !== "maintenance" ||
          scope.target!.scopes.includes("system.write")),
    );
  const signal = scopeSignal(scope);
  if (
    !topics.length ||
    signal.aborted ||
    (scope.generation !== null && scope.generation !== nodeGeneration.value)
  )
    return () => {};
  const key = scope.target?.connection ?? "";
  let channel = channels.get(key);
  if (!channel) {
    channel = { scope, listeners: new Set(), failures: 0 };
    channels.set(key, channel);
  }
  const current = channel,
    listener: Listener = { topics, changed };
  current.listeners.add(listener);
  schedule();
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    signal.removeEventListener("abort", release);
    current.listeners.delete(listener);
    if (!current.listeners.size) {
      if (current.retry) clearTimeout(current.retry);
      channels.delete(key);
    }
    status();
    schedule();
  };
  signal.addEventListener("abort", release, { once: true });
  return release;
}
