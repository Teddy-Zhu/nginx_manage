import { ref } from "vue";
import resources from "../../../api/realtime-resources.json";
import { nodeGeneration, scopeSignal, type RequestScope } from "./context";

export type LiveTopic =
  | "docker"
  | "nginx"
  | "nodes"
  | "logs"
  | "tasks"
  | "software"
  | "monitoring"
  | "notifications"
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
  code: string;
  message: string;
  data: unknown;
  status?: number;
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
  docker: ["read", "components.manage"],
  tasks: ["read"],
  software: ["read", "components.manage"],
  monitoring: ["read"],
  logs: ["read"],
  nginx: ["read"],
  nodes: ["read", "nodes.manage"],
  notifications: ["read"],
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
  if (scope.target && ["backups", "firewall", "listener"].includes(topic))
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
      reject(
        new LiveError(
          "REALTIME_UNAVAILABLE",
          "实时连接暂不可用，请稍后重试",
          0,
        ),
      );
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
interface LiveFrame extends LiveResult {
  resource?: string;
  connection?: string;
  revision?: number;
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
  // Navigation can dispose and recreate a resource before this batch is sent.
  // An unchanged subscription still needs a snapshot if its cache was released.
  force ||= [...channels.values()].some((channel) =>
    [...channel.entries.values()].some((entry) => !entry.value),
  );
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
    typeof frame.message !== "string" ||
    !("data" in frame)
  ) {
    current.close();
    return;
  }
  if (
    frame.code === "UNAUTHENTICATED" &&
    !frame.connection &&
    !frame.resource
  ) {
    window.dispatchEvent(new Event("session-expired"));
    current.close();
    return;
  }
  if (!Number.isSafeInteger(frame.revision)) {
    current.close();
    return;
  }
  // A changed subscription may leave older frames in flight.
  if (frame.revision !== revision) return;
  const channel = channels.get(frame.connection ?? "");
  if (!channel) return;
  if (
    frame.code === "REMOTE_STREAM_INTERRUPTED" &&
    frame.connection &&
    !frame.resource
  ) {
    channel.failures++;
    status();
    if (channel.retry) clearTimeout(channel.retry);
    channel.retry = setTimeout(() => {
      channel.retry = undefined;
      schedule(true);
    }, delay(channel.failures));
    return;
  }
  const entry = frame.resource
    ? channel.entries.get(frame.resource)
    : undefined;
  if (
    !entry ||
    (frame.reset !== undefined && typeof frame.reset !== "boolean") ||
    (frame.code === "OK"
      ? frame.status !== undefined
      : !Number.isInteger(frame.status) ||
        frame.status! < 400 ||
        frame.status! > 599 ||
        !frame.message)
  ) {
    current.close();
    return;
  }
  channel.failures = 0;
  if (channel.retry) clearTimeout(channel.retry);
  channel.retry = undefined;
  status();
  // Cache the pushed value before notifying readers and page subscriptions.
  entry.value = frame;
  for (const done of [...entry.waiters]) done(frame);
  for (const changed of [...entry.watchers]) {
    try {
      changed(frame);
    } catch (error) {
      console.error("实时数据处理失败", error);
    }
  }
  for (const listener of [...channel.listeners]) {
    if (listener.topics.includes(resourceTopic(frame.resource!)!)) {
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
      (topic) => !["backups", "firewall", "listener"].includes(topic),
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
