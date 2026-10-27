import { ref } from "vue";
import resources from "../../../api/realtime-resources.json";
import {
  nodeGeneration,
  scopeSignal,
  sourceNodeId,
  type RequestScope,
} from "./context";

export type LiveTopic =
  | "nginx"
  | "nodes"
  | "logs"
  | "tasks"
  | "monitoring"
  | "notifications"
  | "maintenance"
  | "backups"
  | "firewall"
  | "listener"
  | "version"
  | "dns"
  | "fail2ban";
interface Listener {
  topics: LiveTopic[];
  changed: () => void;
}
export interface LiveResult {
  status: number;
  response: unknown;
  reset?: boolean;
}
interface Entry {
  resource: string;
  owners: Set<symbol>;
  watchers: Set<(value: LiveResult) => void>;
  waiters: Set<(value: LiveResult) => void>;
  value?: LiveResult;
}
interface Binding {
  entry: Entry;
  release: () => void;
  active: boolean;
}
const bindings = new WeakMap<RequestScope, Map<string, Binding>>();
export const liveTopicScopes: Record<LiveTopic, string[]> = {
  tasks: ["read"],
  monitoring: ["read"],
  logs: ["read"],
  nginx: ["read"],
  nodes: ["read", "nodes.manage"],
  notifications: ["read"],
  maintenance: ["read", "system.write"],
  backups: ["read", "backup.export"],
  firewall: ["read", "security.write"],
  listener: ["read", "system.write"],
  version: ["read"],
  dns: ["read"],
  fail2ban: ["read"],
};
export class LiveError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
let authenticated = false;
let localScopes: string[] = [];
export function setLiveSession(value: boolean, scopes: string[] = []) {
  authenticated = value;
  localScopes = scopes;
}
function topicAllowed(scope: RequestScope, topic: LiveTopic) {
  return liveTopicScopes[topic].every(
    (permission) =>
      localScopes.includes(permission) &&
      (!scope.target || scope.target.scopes.includes(permission)),
  );
}
export function liveSessionActive() {
  return authenticated;
}
function resourceTopic(resource: string): LiveTopic | undefined {
  const path = resource.split("?")[0];
  for (const route of resources)
    if (route.paths.includes(path)) return route.topic as LiveTopic;
  const parts = path.split("/");
  return resources.find((route) =>
    route.paths.some((pattern) => {
      const expected = pattern.split("/");
      return (
        expected.length === parts.length &&
        expected.every((part, i) =>
          part.startsWith("{") ? !!parts[i] : part === parts[i],
        )
      );
    }),
  )?.topic as LiveTopic | undefined;
}
export const isLiveResource = (resource: string) =>
  resourceTopic(resource) !== undefined;
function defaults(channel: Channel) {
  const topics = new Set(
    [...channel.listeners].flatMap((listener) => listener.topics),
  );
  return resources
    .filter((route) => topics.has(route.topic as LiveTopic))
    .map((route) => route.paths[0]);
}
function entryFor(channel: Channel, resource: string) {
  let entry = channel.entries.get(resource);
  if (!entry) {
    entry = {
      resource,
      owners: new Set(),
      watchers: new Set(),
      waiters: new Set(),
    };
    channel.entries.set(resource, entry);
  }
  return entry;
}
function prune(key: string, channel: Channel) {
  const keep = defaults(channel);
  for (const [resource, entry] of channel.entries)
    if (!entry.owners.size && !keep.includes(resource))
      channel.entries.delete(resource);
  if (!channel.listeners.size && !channel.entries.size) {
    if (channel.retry) clearTimeout(channel.retry);
    channels.delete(key);
  }
  status();
  schedule();
}
function channelFor(scope: RequestScope) {
  const key = scope.target?.connection ?? "";
  let channel = channels.get(key);
  if (!channel) {
    channel = { scope, listeners: new Set(), entries: new Map(), failures: 0 };
    channels.set(key, channel);
  }
  return channel;
}
function attach(scope: RequestScope, resource: string): Binding {
  const topic = resourceTopic(resource);
  if (!topic || !topicAllowed(scope, topic))
    throw new LiveError("FORBIDDEN", "权限不足", 403);
  const signal = scopeSignal(scope),
    channel = channelFor(scope),
    entry = entryFor(channel, resource),
    owner = Symbol();
  entry.owners.add(owner);
  const binding: Binding = {
    entry,
    active: true,
    release() {
      if (!binding.active) return;
      binding.active = false;
      signal.removeEventListener("abort", binding.release);
      entry.owners.delete(owner);
      prune(scope.target?.connection ?? "", channel);
    },
  };
  signal.addEventListener("abort", binding.release, { once: true });
  schedule();
  return binding;
}
function cancelled() {
  return new DOMException("请求已取消", "AbortError");
}
export function readLive(
  scope: RequestScope,
  resource: string,
  signal: AbortSignal,
  timeout = 20_000,
): Promise<LiveResult> {
  if (signal.aborted || scopeSignal(scope).aborted)
    return Promise.reject(cancelled());
  const topic = resourceTopic(resource)!;
  if (
    scope.target &&
    (["backups", "firewall", "listener"].includes(topic) ||
      (topic === "maintenance" &&
        !scope.target.scopes.includes("system.write")))
  )
    return Promise.reject(
      new LiveError("FORBIDDEN", "当前服务器不支持此项实时操作", 403),
    );
  let reads = bindings.get(scope);
  if (!reads) {
    reads = new Map();
    bindings.set(scope, reads);
  }
  const slot = resource.split("?")[0];
  let binding = reads.get(slot);
  if (!binding?.active || binding.entry.resource !== resource) {
    binding?.release();
    binding = attach(scope, resource);
    reads.set(slot, binding);
  }
  const entry = binding.entry;
  if (entry.value) return Promise.resolve(entry.value);
  return new Promise((resolve, reject) => {
    const done = (value: LiveResult) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      entry.waiters.delete(done);
      resolve(value);
    };
    const abort = () => {
      clearTimeout(timer);
      entry.waiters.delete(done);
      reject(cancelled());
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      entry.waiters.delete(done);
      reject(new Error("实时连接暂不可用，请稍后重试"));
    }, timeout);
    signal.addEventListener("abort", abort, { once: true });
    entry.waiters.add(done);
  });
}
export function watchLiveResource(
  scope: RequestScope,
  resource: string,
  changed: (value: LiveResult) => void,
) {
  const binding = attach(scope, resource);
  binding.entry.watchers.add(changed);
  if (binding.entry.value)
    queueMicrotask(() => {
      if (binding.active && binding.entry.value) changed(binding.entry.value);
    });
  return () => {
    binding.entry.watchers.delete(changed);
    binding.release();
  };
}
export function refreshLive(scope: RequestScope) {
  const channel = channels.get(scope.target?.connection ?? "");
  if (!channel) return;
  for (const entry of channel.entries.values()) entry.value = undefined;
  schedule(true);
}
interface Channel {
  scope: RequestScope;
  listeners: Set<Listener>;
  entries: Map<string, Entry>;
  failures: number;
  retry?: ReturnType<typeof setTimeout>;
}
interface LiveFrame {
  code: string;
  node_id: string;
  data?: {
    connection: string;
    topics: LiveTopic[];
    revision: number;
    values: Record<string, LiveResult>;
  };
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
    .map(([connection, channel]) => {
      const requested = [
        ...new Set([...defaults(channel), ...channel.entries.keys()]),
      ].sort();
      for (const resource of requested) entryFor(channel, resource);
      return {
        connection,
        resources: requested,
        topics: [
          ...new Set([
            ...[...channel.listeners].flatMap((listener) => listener.topics),
            ...requested.map((resource) => resourceTopic(resource)!),
          ]),
        ].sort(),
      };
    })
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
      refresh: force,
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
  const topics = new Set([
    ...[...channel.listeners].flatMap((listener) => listener.topics),
    ...[...channel.entries.keys()].map((resource) => resourceTopic(resource)!),
  ]);
  if (
    frame.code !== "OK" ||
    !node ||
    frame.node_id !== node ||
    !Array.isArray(frame.data.topics) ||
    !frame.data.topics.length ||
    frame.data.topics.some((topic) => !topics.has(topic)) ||
    !frame.data.values ||
    typeof frame.data.values !== "object" ||
    Array.isArray(frame.data.values) ||
    Object.entries(frame.data.values).some(
      ([resource, value]) =>
        !channel.entries.has(resource) ||
        !frame.data!.topics.includes(resourceTopic(resource)!) ||
        !value ||
        !Number.isInteger(value.status) ||
        value.status < 100 ||
        value.status > 599 ||
        !value.response ||
        typeof value.response !== "object" ||
        (value.response as { node_id?: string }).node_id !== node,
    )
  ) {
    current.close();
    return;
  }
  channel.failures = 0;
  if (channel.retry) clearTimeout(channel.retry);
  channel.retry = undefined;
  status();
  // Install the entire snapshot before invoking loaders. Their reads use this
  // data synchronously; they never trigger HTTP requests for realtime resources.
  for (const [resource, value] of Object.entries(frame.data.values)) {
    const entry = channel.entries.get(resource)!;
    entry.value = value;
    for (const done of [...entry.waiters]) done(value);
    for (const changed of [...entry.watchers]) {
      try {
        changed(value);
      } catch (error) {
        console.error("实时数据处理失败", error);
      }
    }
  }
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
    for (const channel of channels.values())
      for (const entry of channel.entries.values()) entry.value = undefined;
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
  topics = topics.filter((topic) => topicAllowed(scope, topic));
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
  const current = channelFor(scope),
    listener: Listener = { topics, changed };
  current.listeners.add(listener);
  schedule();
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    signal.removeEventListener("abort", release);
    current.listeners.delete(listener);
    prune(key, current);
  };
  signal.addEventListener("abort", release, { once: true });
  return release;
}
