<route lang="json">
{
  "meta": {
    "title": "DNS 设置",
    "subtitle": "设置服务器使用的 DNS 地址",
    "nav": true,
    "order": 11,
    "symbol": "◎",
    "group": "服务器管理"
  }
}
</route>
<script setup lang="ts">
import { randomUUID } from "../utils/crypto";

import AdvancedDetails from "../components/AdvancedDetails.vue";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NInput,
  NInputNumber,
  NSelect,
  NSwitch,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  type HostDNSOverview,
  type HostLinkDNS,
  type HostDNSPlan,
  type HostDNSPlanInput,
  type Module,
} from "../api/client";
import { useAction } from "../composables/action";
import { useSession } from "../stores/session";
import HostDNSNetplanSource from "../components/HostDNSNetplanSource.vue";
const api = useNodeAPI();
const route = useRoute();
const migrationNotice = ref("");
const migrationError = ref("");

const session = useSession(),
  { run, busy, message } = useAction();
const overview = ref<HostDNSOverview | null>(null),
  module = ref<Module | null>(null),
  plan = ref<HostDNSPlan | null>(null),
  error = ref(""),
  editing = ref(false),
  reading = ref(false),
  now = ref(Date.now());
const servers = ref(""),
  search = ref(""),
  verifyNames = ref(""),
  takeover = ref(false),
  timeout = ref<number | null>(120);
const target = ref("");
const families = ref([
  {
    label: "IPv4",
    method: "",
    enabled: false,
    servers: "",
    search: "",
    automatic: false,
  },
  {
    label: "IPv6",
    method: "",
    enabled: false,
    servers: "",
    search: "",
    automatic: false,
  },
]);
const networkManager = computed(
  () =>
    observed.value?.owner === "networkmanager" ||
    (observed.value?.owner === "netplan" &&
      !target.value.startsWith("networkd:")),
);
const networkd = computed(
  () =>
    observed.value?.owner === "networkd" ||
    (observed.value?.owner === "netplan" &&
      target.value.startsWith("networkd:")),
);
const connection = computed(() =>
  observed.value?.connections.find((c) => c.target === target.value),
);
const networkLink = computed(() =>
  observed.value?.links.find((link) => link.target === target.value),
);
const sourceHash = computed(() =>
  networkManager.value
    ? connection.value?.source_hash
    : networkd.value
      ? networkLink.value?.source_hash
      : observed.value?.source_hash,
);
const writable = computed(
  () =>
    observed.value?.writable &&
    (!networkManager.value || connection.value?.writable) &&
    (!networkd.value || networkLink.value?.writable),
);
const choices = computed(() => [
  ...(["networkd", "netplan"].includes(observed.value?.owner ?? "")
    ? (observed.value?.links.map((link) => ({
          label: `${link.interface}${link.writable ? "" : "（只读）"}`,
          value: link.target,
        })) ?? [])
    : []),
  ...(["networkmanager", "netplan"].includes(observed.value?.owner ?? "")
    ? (observed.value?.connections.map((c) => ({
          label: `${c.name} · ${c.interface}${c.writable ? "" : "（只读）"}`,
          value: c.target,
        })) ?? [])
    : []),
]);
const configText = (config: HostDNSPlanInput["config"] | null | undefined) => {
  if (!config) return "无法读取";
  if (!config.ipv4 && !config.ipv6)
    return `${config.servers.join("、") || "无"}；搜索域：${config.search.join("、") || "无"}`;
  return [config.ipv4, config.ipv6]
    .map((f, i) =>
      f
        ? `${i === 0 ? "IPv4" : "IPv6"}：${f.servers.join("、") || "无手动地址"}；${f.automatic ? "自动获取 DNS" : "手动 DNS"}；搜索域：${f.search.join("、") || "无"}`
        : "",
    )
    .filter(Boolean)
    .join(" / ");
};
const effectiveText = (
  config: HostDNSPlanInput["config"] | null | undefined,
) =>
  config
    ? [config.ipv4, config.ipv6]
        .map((f, i) =>
          f
            ? `${i === 0 ? "IPv4" : "IPv6"}：${f.servers.join("、") || "无"}；搜索域：${f.search.join("、") || "无"}`
            : "",
        )
        .filter(Boolean)
        .join(" / ") || "无"
    : "无法读取";
const linkServers = (state: HostLinkDNS | null) =>
  state
    ? state.servers
        .map(
          (s) =>
            `${s.address.includes(":") && s.port && s.port !== 53 ? `[${s.address}]` : s.address}${s.port && s.port !== 53 ? `:${s.port}` : ""}${s.server_name ? ` #${s.server_name}` : ""}${s.source && s.source !== "resolved" ? `（${s.source}）` : ""}`,
        )
        .join("、") || "无"
    : "无法读取";
const linkDomains = (state: HostLinkDNS | null) =>
  state
    ? state.domains
        .map(
          (d) =>
            `${d.routing ? "~" : ""}${d.domain}${d.source && d.source !== "resolved" ? `（${d.source}）` : ""}`,
        )
        .join("、") || "无"
    : "无法读取";
const autoPolicy = (value: boolean | null) =>
  value === null ? "未显式设置" : value ? "允许获取" : "忽略";
const dnrPolicy = (value: boolean | null) =>
  value === null ? "继承 DNS 策略" : autoPolicy(value);
const domainPolicyLabels: Record<string, string> = {
  yes: "搜索域",
  no: "忽略",
  route: "路由域",
};
const sourceOwnerLabels: Record<string, string> = {
  networkd: "本机 networkd 源",
  generated: "运行时生成源",
  vendor: "系统提供的源",
  unknown: "未确认",
};
const domainPolicy = (value: string | null) =>
  value === null ? "未显式设置" : (domainPolicyLabels[value] ?? "无法识别");
const sourceOwner = (value: string) => sourceOwnerLabels[value] ?? "未确认";
const controller = new AbortController();
let poll: ReturnType<typeof setInterval> | undefined;
let pendingRead = false,
  lastRead = 0;
let applyKey = "";
let previewAttempt: { digest: string; key: string } | undefined;
const decisionKeys = new Map<string, string>();
const canWrite = computed(
    () => session.me?.scopes.includes("host.dns.write") ?? false,
  ),
  canToggle = computed(
    () => session.me?.scopes.includes("system.write") ?? false,
  );
const observed = computed(() => overview.value?.observed),
  pending = computed(() => observed.value?.pending),
  task = computed(() => overview.value?.task);
const activeTask = computed(
  () =>
    !!task.value &&
    [
      "queued",
      "running",
      "waiting_confirmation",
      "compensating",
      "recovery_required",
    ].includes(task.value.state),
);
const matching = computed(
  () => pending.value?.operation_id === task.value?.operation_id,
);
const canConfirm = computed(
  () =>
    module.value?.enabled &&
    canWrite.value &&
    activeTask.value &&
    matching.value &&
    task.value?.stage === "awaiting_confirmation" &&
    pending.value?.stage === "awaiting_confirmation" &&
    !task.value?.decision,
);
const remaining = computed(() =>
  pending.value
    ? Math.max(0, Math.ceil(pending.value.deadline - now.value / 1000))
    : 0,
);
const drift = computed(() => {
  const desired = overview.value?.desired.find(
    (d) =>
      d.target === (networkManager.value || networkd.value ? target.value : ""),
  );
  const actual = networkManager.value
    ? connection.value?.persistent
    : networkd.value
      ? networkLink.value?.persistent
        ? {
            servers: networkLink.value.persistent.servers,
            search: networkLink.value.persistent.search,
            ipv4: null,
            ipv6: null,
          }
        : null
      : observed.value?.persistent;
  return (
    desired &&
    !pending.value &&
    (networkManager.value || networkd.value
      ? actual && configText(desired.config) !== configText(actual)
      : sourceHash.value && desired.source_hash !== sourceHash.value)
  );
});
const labels: Record<string, string> = {
  queued: "等待执行",
  running: "执行中",
  waiting_confirmation: "待确认",
  compensating: "恢复中",
  recovery_required: "需本机恢复",
  succeeded: "已确认",
  rolled_back: "已恢复",
  failed: "失败",
  cancelled: "已取消",
  applying: "写入中",
  persisting: "保存持久配置",
  verification_pending: "解析核验中",
  awaiting_confirmation: "等待确认",
  confirmed: "已确认",
  rolling_back: "恢复中",
  rollback_unconfirmed: "恢复未确认",
  agent_submit_pending: "提交中",
  plan_unreadable: "计划无法读取",
  plan_invalid: "计划无效",
  operation_missing: "操作记录缺失",
  module_disabled: "管理已停用",
  preflight_rejected: "预检未通过",
  operation_mismatch: "操作身份不一致",
  confirmation_invalid: "确认结果无效",
  unknown_agent_state: "无法识别本机执行状态",
};
const label = (s: string | undefined) => (s ? (labels[s] ?? "状态未知") : "—");
const split = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
async function read() {
  if (reading.value) {
    pendingRead = true;
    return;
  }
  reading.value = true;
  lastRead = Date.now();
  try {
    const [state, modules] = await Promise.all([
      api.hostDNS(controller.signal),
      api.modules(controller.signal),
    ]);
    overview.value = state;
    const targets =
      state.observed.owner === "netplan"
        ? [...state.observed.links, ...state.observed.connections]
        : state.observed.owner === "networkd"
          ? state.observed.links
          : state.observed.connections;
    const needsTarget = ["networkd", "netplan", "networkmanager"].includes(
      state.observed.owner,
    );
    if (
      needsTarget
        ? !targets.some((item) => item.target === target.value)
        : target.value !== ""
    ) {
      target.value =
        (targets.find((item) => item.writable) ?? targets[0])?.target ?? "";
      editing.value = false;
      invalidate();
    }
    module.value = modules.find((m) => m.id === "host-dns") ?? null;
    error.value = "";
    if (
      plan.value &&
      (plan.value.expires_at * 1000 <= Date.now() ||
        plan.value.input.source_hash !==
          (plan.value.input.target
            ? targets.find(
                (c) => c.target === plan.value!.input.target,
              )?.source_hash
            : state.observed.source_hash))
    )
      plan.value = null;
  } catch (cause) {
    const e = apiError(cause);
    if (e.code !== "CANCELLED") error.value = e.message;
  } finally {
    reading.value = false;
    if (pendingRead && !controller.signal.aborted) {
      pendingRead = false;
      void read();
    }
  }
}
function edit() {
  if (!observed.value) return;
  const staticConfig = networkd.value
    ? networkLink.value?.persistent
    : observed.value.current;
  servers.value = staticConfig?.servers.join("\n") ?? "";
  search.value = staticConfig?.search.join("\n") ?? "";
  const c = connection.value;
  for (const [i, f] of families.value.entries()) {
    const value = i === 0 ? c?.applied?.ipv4 : c?.applied?.ipv6;
    f.enabled = !!value;
    f.method = (i === 0 ? c?.method4 : c?.method6) ?? "";
    f.servers = value?.servers.join("\n") ?? "";
    f.search = value?.search.join("\n") ?? "";
    f.automatic = value?.automatic ?? false;
  }
  takeover.value = false;
  plan.value = null;
  editing.value = true;
}
async function loadMigrationCandidate() {
  const id = route.query.migration,
    source = route.query.source;
  if (typeof id !== "string" || typeof source !== "string") return;
  try {
    const migration = await api.migration(id, controller.signal);
    if (migration.pruned_at)
      throw new Error("迁移材料已清理，无法载入目标 DNS 配置");
    const item = migration.host_dns?.entries.find(
      (entry) => entry.source === source,
    );
    if (
      !["draft", "saved", "succeeded", "rolled_back"].includes(
        migration.state,
      ) ||
      migration.host_dns?.mode !== "map" ||
      migration.host_dns.state !== "staged" ||
      !item?.config ||
      item.target === null
    )
      throw new Error("迁移计划中没有已保存的目标 DNS 配置");
    if (
      !observed.value ||
      (["networkmanager", "networkd", "netplan"].includes(observed.value.owner)
        ? ![...observed.value.connections, ...observed.value.links].some(
            (entry) => entry.target === item.target,
          )
        : observed.value.owner !== "regular-file" || item.target !== "")
    )
      throw new Error("迁移映射目标与当前 DNS 所有者不匹配，须重新映射");
    target.value = item.target;
    edit();
    servers.value = item.config.servers.join("\n");
    search.value = item.config.search.join("\n");
    for (const [index, family] of families.value.entries()) {
      const config = index === 0 ? item.config.ipv4 : item.config.ipv6;
      family.enabled = !!config;
      family.servers = config?.servers.join("\n") ?? "";
      family.search = config?.search.join("\n") ?? "";
      family.automatic = config?.automatic ?? false;
    }
    verifyNames.value = "";
    migrationNotice.value =
      "迁移配置已载入，待核对目标和验证域名，再生成 DNS 变更计划。";
  } catch (cause) {
    if (!controller.signal.aborted)
      migrationError.value =
        cause instanceof Error ? cause.message : apiError(cause).message;
  }
}
function invalidate() {
  plan.value = null;
  applyKey = "";
}
async function preview() {
  if (!observed.value) return;
  if (timeout.value === null) {
    message.error("请填写确认期限");
    return;
  }
  const input: HostDNSPlanInput = {
    target: networkManager.value || networkd.value ? target.value : "",
    source_hash: sourceHash.value ?? "",
    config: networkManager.value
      ? {
          servers: [],
          search: [],
          ipv4: families.value[0]!.enabled
            ? {
                servers: split(families.value[0]!.servers),
                search: split(families.value[0]!.search),
                automatic: families.value[0]!.automatic,
              }
            : null,
          ipv6: families.value[1]!.enabled
            ? {
                servers: split(families.value[1]!.servers),
                search: split(families.value[1]!.search),
                automatic: families.value[1]!.automatic,
              }
            : null,
        }
      : {
          servers: split(servers.value),
          search: split(search.value),
          ipv4: null,
          ipv6: null,
        },
    verify_names: split(verifyNames.value),
    timeout_seconds: timeout.value,
    takeover: takeover.value,
  };
  const digest = JSON.stringify(input);
  if (!previewAttempt || previewAttempt.digest !== digest)
    previewAttempt = { digest, key: randomUUID() };
  const key = previewAttempt.key;
  await run(async () => {
    plan.value = await api.planHostDNS(input, key);
    previewAttempt = undefined;
    applyKey = randomUUID();
  });
}
async function apply() {
  const p = plan.value;
  if (!p || p.expires_at * 1000 <= Date.now()) return;
  if (!window.confirm("临时应用主机 DNS？确认期限内未确认将自动恢复原设置。"))
    return;
  await run(async () => {
    await api.applyHostDNS(p.id, applyKey || (applyKey = randomUUID()));
    plan.value = null;
    editing.value = false;
    await read();
  }, "DNS 变更已排队，等待本机核验与确认");
}
async function decide(action: "confirm" | "rollback") {
  const t = task.value;
  if (!t) return;
  if (
    !window.confirm(
      action === "confirm"
        ? "确认保留当前主机 DNS 设置？"
        : "恢复原主机 DNS 设置？",
    )
  )
    return;
  const cacheKey = `${t.id}:${action}`;
  let key = decisionKeys.get(cacheKey);
  if (!key) {
    key = randomUUID();
    decisionKeys.set(cacheKey, key);
  }
  const requestKey = key;
  await run(async () => {
    await api.decideHostDNS(t.id, action, requestKey);
    decisionKeys.delete(cacheKey);
    await read();
    message.success(action === "confirm" ? "确认请求已排队" : "恢复请求已排队");
  });
}
async function toggle(enabled: boolean) {
  await run(
    async () => {
      await api.setModule("host-dns", enabled);
      await read();
    },
    enabled ? "主机 DNS 模块已启用" : "主机 DNS 模块已停用",
  );
}
function visible() {
  if (!document.hidden) void read();
}
onMounted(async () => {
  await read();
  if (controller.signal.aborted) return;
  await loadMigrationCandidate();
  if (controller.signal.aborted) return;
  document.addEventListener("visibilitychange", visible);
  poll = setInterval(() => {
    now.value = Date.now();
    if (
      !document.hidden &&
      Date.now() - lastRead >=
        (pending.value || activeTask.value ? 2000 : 15000)
    )
      void read();
  }, 1000);
});
onUnmounted(() => {
  controller.abort();
  if (poll) clearInterval(poll);
  document.removeEventListener("visibilitychange", visible);
});
</script>
<template>
  <div class="page-toolbar">
    <h2>DNS 设置</h2>
    <div class="actions">
      <span>启用管理</span
      ><n-switch
        :value="module?.enabled ?? false"
        :disabled="!canToggle || busy"
        @update:value="toggle"
      /><n-button :loading="reading" @click="read">刷新</n-button>
    </div>
  </div>
  <NAlert v-if="migrationError" type="error">{{ migrationError }}</NAlert>
  <NAlert v-if="migrationNotice" type="info">{{ migrationNotice }}</NAlert>
  <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>
  <n-alert type="info" :bordered="false" style="margin: 16px 0"
    >主机解析器变更可能影响证书申请、更新、通知和远程连接。未在期限内确认的设置会自动恢复。</n-alert
  >
  <section v-if="observed" class="panel">
    <div class="page-toolbar">
      <h3>当前 DNS</h3>
      <n-tag :type="observed.writable ? 'success' : 'warning'">{{
        observed.writable ? "可管理" : "仅查看"
      }}</n-tag>
    </div>
    <dl class="detail-list"><dt>DNS 地址</dt><dd>{{ observed.current.servers.join("、") || "未配置" }}</dd><dt>搜索域</dt><dd>{{ observed.current.search.join("、") || "无" }}</dd></dl>
    <NAlert v-if="!observed.writable" type="info" :bordered="false">当前网络配置仅支持查看。需要修改时，请查看网络配置详情。</NAlert>
    <AdvancedDetails title="网络配置详情">
    <dl>
      <dt>配置来源/所有者线索</dt>
      <dd>{{ observed.owner }}</dd>
      <dt>解析器入口</dt>
      <dd>
        {{ observed.source
        }}<span v-if="observed.link_target"> → {{ observed.link_target }}</span>
      </dd>
      <dt>入口 DNS 地址</dt>
      <dd>{{ observed.current.servers.join("、") || "未明确配置" }}</dd>
      <dt>入口搜索域</dt>
      <dd>{{ observed.current.search.join("、") || "无" }}</dd>
      <dt>持久配置</dt>
      <dd>
        {{
          observed.persistent
            ? `${observed.persistent.servers.join("、") || "未明确配置"}；搜索域：${observed.persistent.search.join("、") || "无"}`
            : "上游持久配置未确认"
        }}
      </dd>
    </dl>
    <n-alert v-if="observed.reason" type="warning" :bordered="false">{{
      observed.reason
    }}</n-alert>
    </AdvancedDetails>
    <n-alert
      v-if="drift"
      type="warning"
      :bordered="false"
      style="margin-top: 12px"
      >DNS 设置已被其他工具修改，请刷新后重新配置。</n-alert
    >
    <template v-if="networkManager || networkd">
      <n-form-item
        label="网络接口"
        style="margin-top: 16px"
      >
        <n-select
          v-model:value="target"
          :options="choices"
          :disabled="busy || editing || activeTask"
          @update:value="invalidate"
        />
      </n-form-item>
      <dl v-if="networkd && networkLink?.persistent">
        <dt>保留的路由域</dt>
        <dd>{{ networkLink.persistent.routing_domains.join("、") || "无" }}</dd>
      </dl>
      <template v-if="connection">
        <AdvancedDetails title="网卡配置详情"><dl>
          <dt>接口 / IP 方法</dt>
          <dd>
            {{ connection.interface }} · IPv4 {{ connection.method4 || "—" }} /
            IPv6 {{ connection.method6 || "—" }}
          </dd>
          <dt>当前有效 DNS</dt>
          <dd>{{ effectiveText(connection.effective) }}</dd>
          <dt>运行中的设置</dt>
          <dd>{{ configText(connection.applied) }}</dd>
          <dt>持久设置</dt>
          <dd>{{ configText(connection.persistent) }}</dd>
          <dt>保留的路由域</dt>
          <dd>{{ connection.routing_domains.join("、") || "无" }}</dd>
        </dl>
        <HostDNSNetplanSource
          v-if="connection.netplan"
          :source="connection.netplan"
        />
        </AdvancedDetails>
        <n-alert v-if="connection.reason" type="warning" :bordered="false">{{
          connection.reason
        }}</n-alert>
      </template>
    </template>
    <n-button
      v-if="!editing"
      type="primary"
      style="margin-top: 16px"
      :disabled="
        !canWrite || !module?.enabled || !writable || activeTask || busy
      "
      @click="edit"
      >配置 DNS</n-button
    >
  </section>
  <AdvancedDetails title="网卡诊断">
  <section
    v-for="link in observed?.links ?? []"
    :key="link.target"
    class="panel"
  >
    <div class="page-toolbar">
      <h3>{{ link.interface }} · networkd</h3>
      <n-tag :type="link.writable ? 'success' : 'warning'">{{
        link.writable ? "可接管" : "只读"
      }}</n-tag>
    </div>
    <dl>
      <dt>网卡状态</dt>
      <dd>{{ link.state || "无法读取" }}</dd>
      <dt>持久源归属</dt>
      <dd>{{ sourceOwner(link.owner) }}</dd>
      <dt>已加载源文件</dt>
      <dd>{{ link.loaded_sources.join("、") || "未确认" }}</dd>
      <dt>当前磁盘源文件</dt>
      <dd>{{ link.disk_sources.join("、") || "无法读取" }}</dd>
      <dt>networkd 已加载 DNS</dt>
      <dd>{{ linkServers(link.loaded) }}</dd>
      <dt>已加载搜索 / 路由域</dt>
      <dd>{{ linkDomains(link.loaded) }}</dd>
      <dt>resolved 当前 DNS</dt>
      <dd>{{ linkServers(link.effective) }}</dd>
      <dt>resolved 搜索 / 路由域</dt>
      <dd>{{ linkDomains(link.effective) }}</dd>
      <template v-if="link.persistent">
        <dt>磁盘 DNS 字段</dt>
        <dd>{{ link.persistent.servers.join("、") || "无显式地址" }}</dd>
        <dt>磁盘搜索 / 路由域</dt>
        <dd>
          {{
            [
              ...link.persistent.search,
              ...link.persistent.routing_domains,
            ].join("、") || "无"
          }}
        </dd>
        <dt>DHCPv4 DNS 策略</dt>
        <dd>
          {{ autoPolicy(link.persistent.dhcp4) }}；域名：{{
            domainPolicy(link.persistent.domains4)
          }}；加密 DNS：{{ dnrPolicy(link.persistent.dnr4) }}
        </dd>
        <dt>DHCPv6 DNS 策略</dt>
        <dd>
          {{ autoPolicy(link.persistent.dhcp6) }}；域名：{{
            domainPolicy(link.persistent.domains6)
          }}；加密 DNS：{{ dnrPolicy(link.persistent.dnr6) }}
        </dd>
        <dt>IPv6 RA DNS 策略</dt>
        <dd>
          {{ autoPolicy(link.persistent.ipv6_ra) }}；域名：{{
            domainPolicy(link.persistent.domains_ra)
          }}；加密 DNS：{{ dnrPolicy(link.persistent.dnr_ra) }}
        </dd>
      </template>
      <template v-else
        ><dt>磁盘 DNS 字段</dt>
        <dd>无法完整确认</dd></template
      >
    </dl>
    <HostDNSNetplanSource v-if="link.netplan" :source="link.netplan" />
    <n-alert v-if="link.reason" type="warning" :bordered="false">{{
      link.reason
    }}</n-alert>
  </section>
  </AdvancedDetails>
  <section v-if="pending || task" class="panel">
    <div class="page-toolbar">
      <h3>{{ activeTask || pending ? "当前变更" : "最近变更" }}</h3>
      <n-tag
        :type="
          (pending?.state ?? task?.state) === 'recovery_required'
            ? 'error'
            : 'info'
        "
        >{{ label(pending?.state ?? task?.state) }}</n-tag
      >
    </div>
    <p>
      {{ label(pending?.stage ?? task?.stage)
      }}<span v-if="pending && pending.state !== 'recovery_required'">
        · 剩余确认时间 {{ remaining }} 秒</span
      >
    </p>
    <p v-if="task?.decision">
      {{ task.decision === "confirm" ? "确认" : "恢复" }}请求等待执行
    </p>
    <n-alert
      v-if="pending?.error || task?.error"
      type="warning"
      :bordered="false"
      >{{ pending?.error || task?.error }}</n-alert
    >
    <p class="muted">操作 {{ pending?.operation_id ?? task?.operation_id }}</p>
    <div v-if="activeTask" class="actions">
      <n-button
        type="primary"
        :disabled="!canConfirm || busy || remaining === 0"
        @click="decide('confirm')"
        >确认保留</n-button
      ><n-button
        :disabled="!canWrite || busy || !!task?.decision"
        @click="decide('rollback')"
        >{{ task?.state === "queued" ? "取消变更" : "恢复原设置" }}</n-button
      >
    </div>
  </section>
  <section v-if="editing" class="panel">
    <h3>修改 DNS</h3>
    <template v-if="!networkManager">
      <n-form-item label="DNS 服务器（1–3 个 IPv4 / IPv6 地址）"
        ><n-input
          v-model:value="servers"
          :disabled="busy"
          type="textarea"
          placeholder="每行一个地址"
          @update:value="invalidate"
      /></n-form-item>
      <n-form-item label="搜索域（最多 6 个，可留空）"
        ><n-input
          v-model:value="search"
          :disabled="busy"
          type="textarea"
          placeholder="每行一个搜索域"
          @update:value="invalidate"
      /></n-form-item>
    </template>
    <template v-else>
      <NAlert v-if="observed?.owner === 'netplan'" type="info">
        此连接的 IPv4 与 IPv6 共用搜索域。
      </NAlert>
      <template v-for="family in families" :key="family.label">
        <div v-if="family.enabled">
          <h4>{{ family.label }}</h4>
          <n-form-item label="自动获取 DNS">
            <n-switch
              v-model:value="family.automatic"
              :disabled="busy || !['auto', 'dhcp'].includes(family.method)"
              @update:value="invalidate"
            />
          </n-form-item>
          <n-form-item label="手动 DNS 地址（最多 3 个）">
            <n-input
              v-model:value="family.servers"
              :disabled="busy"
              type="textarea"
              placeholder="每行一个地址，可留空"
              @update:value="invalidate"
            />
          </n-form-item>
          <n-form-item label="搜索域（最多 6 个）">
            <n-input
              v-model:value="family.search"
              :disabled="busy"
              type="textarea"
              placeholder="每行一个搜索域"
              @update:value="invalidate"
            />
          </n-form-item>
        </div>
      </template>
    </template>
    <n-form-item label="本机解析验证域名（1–2 个）"
      ><n-input
        v-model:value="verifyNames"
        :disabled="busy"
        type="textarea"
        placeholder="填写本环境中必须可解析的完整域名"
        @update:value="invalidate"
    /></n-form-item>
    <n-form-item label="确认期限（秒）"
      ><n-input-number
        v-model:value="timeout"
        :disabled="busy"
        :min="45"
        :max="180"
        :precision="0"
        :show-button="true"
        :update-value-on-input="false"
        @update:value="invalidate"
    /></n-form-item>
    <n-checkbox
      v-model:checked="takeover"
      :disabled="busy"
      @update:checked="invalidate"
      >{{
        networkManager
          ? "确认接管所选连接的 DNS 设置"
          : networkd
            ? "确认接管所选网卡的静态 DNS 设置"
            : "确认接管该主机的普通 DNS 配置文件"
      }}</n-checkbox
    >
    <div class="actions" style="margin-top: 16px">
      <n-button
        :disabled="
          !canWrite || busy || !takeover || !writable || !module?.enabled
        "
        @click="preview"
        >生成计划</n-button
      ><n-button
        :disabled="busy"
        @click="
          editing = false;
          plan = null;
        "
        >取消</n-button
      >
    </div>
    <template v-if="plan"
      ><n-alert type="warning" :bordered="false" style="margin-top: 16px">{{
        plan.impact
      }}</n-alert>
      <dl>
        <dt>原 DNS</dt>
        <dd>{{ configText(plan.before) }}</dd>
        <dt>新 DNS</dt>
        <dd>{{ configText(plan.input.config) }}</dd>
        <dt v-if="plan.input.target">目标连接</dt>
        <dd v-if="plan.input.target">{{ plan.input.target }}</dd>
        <dt>验证域名</dt>
        <dd>{{ plan.input.verify_names.join("、") }}</dd>
        <dt>自动恢复期限</dt>
        <dd>{{ plan.input.timeout_seconds }} 秒</dd>
      </dl>
      <n-button
        type="primary"
        :disabled="busy || !module?.enabled || !writable || activeTask"
        @click="apply"
        >临时应用</n-button
      ></template
    >
  </section>
</template>
<style scoped>
.panel {
  padding: 24px;
  background: var(--bg-surface, #fff);
  border: 1px solid var(--border, #e5eae7);
  border-radius: 12px;
  margin-top: 16px;
}
.actions {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.page-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
dl {
  display: grid;
  grid-template-columns: 130px minmax(0, 1fr);
  gap: 12px;
}
dt,
.muted {
  color: var(--text-muted, #7b8680);
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
h3 {
  margin-top: 0;
}
@media (max-width: 600px) {
  dl {
    grid-template-columns: 1fr;
    gap: 8px;
  }
}
</style>
