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
import { useLiveRefresh } from "../composables/live";
import ValueListInput from "../components/ValueListInput.vue";
import { cleanList } from "../utils/form";
import { randomUUID } from "../utils/crypto";

import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NSelect,
  NSwitch,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  type HostDNSOverview,
  type HostDNSPlan,
  type HostDNSPlanInput,
  type Module,
} from "../api/client";
import { useAction } from "../composables/action";
import { useSession } from "../stores/session";
import { inspectTask } from "../stores/operation";

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
const servers = ref<string[]>([]),
  search = ref<string[]>([]),
  verifyNames = ref<string[]>([]),
  takeover = ref(false);
const confirmationSeconds = 120;
const target = ref("");
const families = ref([
  {
    label: "IPv4",
    method: "",
    enabled: false,
    servers: [] as string[],
    search: [] as string[],
    automatic: false,
  },
  {
    label: "IPv6",
    method: "",
    enabled: false,
    servers: [] as string[],
    search: [] as string[],
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

const controller = new AbortController();
let poll: ReturnType<typeof setInterval> | undefined;
let pendingRead = false;
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

async function read() {
  if (reading.value) {
    pendingRead = true;
    return;
  }
  reading.value = true;
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
      if (!editing.value && !activeTask.value)
        target.value =
          (targets.find((item) => item.writable) ?? targets[0])?.target ?? "";
      invalidate();
    }
    module.value = modules.find((m) => m.id === "host-dns") ?? null;
    error.value = "";
    if (
      plan.value &&
      (plan.value.expires_at * 1000 <= Date.now() ||
        plan.value.input.source_hash !==
          (plan.value.input.target
            ? targets.find((c) => c.target === plan.value!.input.target)
                ?.source_hash
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
  servers.value = [...(staticConfig?.servers ?? [])];
  search.value = [...(staticConfig?.search ?? [])];
  const c = connection.value;
  for (const [i, f] of families.value.entries()) {
    const config = c?.applied ?? c?.persistent;
    const value = i === 0 ? config?.ipv4 : config?.ipv6;
    f.enabled = !!value;
    f.method = (i === 0 ? c?.method4 : c?.method6) ?? "";
    f.servers = [...(value?.servers ?? [])];
    f.search = [...(value?.search ?? [])];
    f.automatic = value?.automatic ?? false;
  }
  if (sharedSearch.value)
    search.value = [
      ...(families.value.find((family) => family.enabled)?.search ?? []),
    ];
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
      throw new Error("迁移配置对应的网络接口已变化，请重新选择目标后导入");
    target.value = item.target;
    edit();
    servers.value = [...item.config.servers];
    search.value = [...item.config.search];
    for (const [index, family] of families.value.entries()) {
      const config = index === 0 ? item.config.ipv4 : item.config.ipv6;
      family.enabled = !!config;
      family.servers = [...(config?.servers ?? [])];
      family.search = [...(config?.search ?? [])];
      family.automatic = config?.automatic ?? false;
    }
    if (sharedSearch.value)
      search.value = [
        ...(families.value.find((family) => family.enabled)?.search ?? []),
      ];
    verifyNames.value = [];
    migrationNotice.value =
      "迁移配置已载入，请核对 DNS 地址，填写测试域名后检查设置。";
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
  if (!cleanList(verifyNames.value).length) {
    message.error("请填写至少一个测试域名，用于检查新 DNS 是否正常");
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
                servers: cleanList(families.value[0]!.servers),
                search: cleanList(
                  sharedSearch.value ? search.value : families.value[0]!.search,
                ),
                automatic: families.value[0]!.automatic,
              }
            : null,
          ipv6: families.value[1]!.enabled
            ? {
                servers: cleanList(families.value[1]!.servers),
                search: cleanList(
                  sharedSearch.value ? search.value : families.value[1]!.search,
                ),
                automatic: families.value[1]!.automatic,
              }
            : null,
        }
      : {
          servers: cleanList(servers.value),
          search: cleanList(search.value),
          ipv4: null,
          ipv6: null,
        },
    verify_names: cleanList(verifyNames.value),
    timeout_seconds: confirmationSeconds,
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
  if (!p || p.expires_at * 1000 <= Date.now()) {
    invalidate();
    message.warning("检查结果已过期，请重新检查设置");
    return;
  }
  if (!window.confirm("临时应用主机 DNS？确认期限内未确认将自动恢复原设置。"))
    return;
  await run(async () => {
    await api.applyHostDNS(p.id, applyKey || (applyKey = randomUUID()));
    plan.value = null;
    editing.value = false;
    await read();
  }, "DNS 设置已提交，解析检查通过后请确认保留");
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
    enabled ? "已启用 DNS 管理" : "已停用 DNS 管理",
  );
}
onMounted(async () => {
  await read();
  if (controller.signal.aborted) return;
  await loadMigrationCandidate();
  if (controller.signal.aborted) return;
  poll = setInterval(() => {
    now.value = Date.now();
  }, 1000);
});
onUnmounted(() => {
  controller.abort();
  if (poll) clearInterval(poll);
});
useLiveRefresh(api, ["tasks", "dns"], read);
const sharedSearch = computed(
  () => networkManager.value && observed.value?.owner === "netplan",
);
const currentConfig = computed(() =>
  networkManager.value
    ? (connection.value?.applied ?? connection.value?.persistent)
    : networkd.value
      ? networkLink.value?.persistent
        ? {
            servers: networkLink.value.persistent.servers,
            search: networkLink.value.persistent.search,
            ipv4: null,
            ipv6: null,
          }
        : null
      : observed.value?.current,
);
const configRows = (config: HostDNSPlanInput["config"] | null | undefined) => {
  if (!config) return [{ label: "DNS 地址", value: "暂时无法读取" }];
  if (!config.ipv4 && !config.ipv6)
    return [
      { label: "DNS 地址", value: config.servers.join("、") || "尚未设置" },
      { label: "域名后缀", value: config.search.join("、") || "无" },
    ];
  return [config.ipv4, config.ipv6].flatMap((family, index) =>
    family
      ? [
          {
            label: `${index === 0 ? "IPv4" : "IPv6"} DNS`,
            value: [
              family.automatic ? "自动获取" : "手动指定",
              ...family.servers,
            ].join(" · "),
          },
          {
            label: `${index === 0 ? "IPv4" : "IPv6"} 后缀`,
            value: family.search.join("、") || "无",
          },
        ]
      : [],
  );
};
const currentRows = computed(() => configRows(currentConfig.value));
const targetLabel = computed(
  () =>
    choices.value.find((choice) => choice.value === target.value)?.label ??
    "当前服务器",
);
const steps = ["查看配置", "修改设置", "检查并应用", "确认生效"];
const step = computed(() =>
  activeTask.value || pending.value
    ? 3
    : plan.value
      ? 2
      : editing.value
        ? 1
        : 0,
);
const planExpired = computed(
  () => !!plan.value && plan.value.expires_at * 1000 <= now.value,
);
const statusType = computed(() =>
  ["failed", "recovery_required"].includes(
    pending.value?.state ?? task.value?.state ?? "",
  )
    ? ("error" as const)
    : canConfirm.value
      ? ("warning" as const)
      : task.value?.state === "succeeded"
        ? ("success" as const)
        : ("info" as const),
);
function cancelEdit() {
  editing.value = false;
  migrationNotice.value = "";
  invalidate();
  void read();
}
</script>
<template>
  <Teleport defer to="#page-heading-actions">
    <n-button :loading="reading" :disabled="busy" @click="read">刷新</n-button>
  </Teleport>
  <div class="dns-page page-stack">
    <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>
    <n-alert v-if="migrationError" type="error" :bordered="false">{{
      migrationError
    }}</n-alert>
    <n-alert v-if="migrationNotice" type="info" :bordered="false">{{
      migrationNotice
    }}</n-alert>
    <ol class="dns-steps" aria-label="DNS 设置流程">
      <li
        v-for="(item, index) in steps"
        :key="item"
        :class="{ current: step === index, completed: step > index }"
        :aria-current="step === index ? 'step' : undefined"
      >
        <span>{{ index + 1 }}</span
        >{{ item }}
      </li>
    </ol>

    <section v-if="activeTask || pending" class="surface dns-change">
      <div class="section-toolbar">
        <div>
          <h2>当前变更</h2>
          <p class="muted">{{ label(pending?.stage ?? task?.stage) }}</p>
        </div>
        <n-tag :type="statusType" :bordered="false">{{
          label(pending?.state ?? task?.state)
        }}</n-tag>
      </div>
      <n-alert
        v-if="pending?.error || task?.error"
        type="error"
        :bordered="false"
        >{{ pending?.error || task?.error }}</n-alert
      >
      <p v-if="task?.decision">
        {{
          task.decision === "confirm"
            ? "正在保存已确认的设置，请稍候。"
            : "正在恢复原设置，请稍候。"
        }}
      </p>
      <div v-else-if="canConfirm" class="confirmation-notice">
        <div>
          <strong>解析检查已通过</strong>
          <p>
            请确认业务连接正常，并在
            {{ remaining }} 秒内保留设置；超时将自动恢复。
          </p>
        </div>
        <n-button
          type="primary"
          :loading="busy"
          :disabled="remaining === 0"
          @click="decide('confirm')"
          >确认保留</n-button
        >
      </div>
      <p v-else-if="!pending?.error && !task?.error" class="muted">
        正在处理 DNS 设置，请等待检查结果。
      </p>
      <div class="dns-actions">
        <n-button
          v-if="activeTask"
          :disabled="!canWrite || busy || !!task?.decision"
          @click="decide('rollback')"
          >{{ task?.state === "queued" ? "取消变更" : "恢复原设置" }}</n-button
        >
        <n-button
          v-if="task"
          quaternary
          @click="inspectTask(task.id, 'DNS 设置日志')"
          >查看日志</n-button
        >
      </div>
    </section>

    <section v-if="observed" class="surface">
      <div class="section-toolbar">
        <div>
          <h2>当前 DNS</h2>
          <p class="muted">
            {{
              networkManager || networkd
                ? targetLabel
                : "服务器当前使用的解析设置"
            }}
          </p>
        </div>
        <div class="dns-actions">
          <span class="switch-label"
            >DNS 管理<n-switch
              :value="module?.enabled ?? false"
              :disabled="
                !canToggle || busy || editing || activeTask || !!pending
              "
              @update:value="toggle"
          /></span>
          <n-button
            v-if="!editing"
            type="primary"
            :disabled="
              !canWrite ||
              !module?.enabled ||
              !writable ||
              activeTask ||
              !!pending ||
              busy
            "
            @click="edit"
            >修改 DNS</n-button
          >
        </div>
      </div>
      <n-form-item
        v-if="choices.length > 1"
        label="网络接口"
        class="dns-interface"
      >
        <n-select
          v-model:value="target"
          :options="choices"
          :disabled="busy || editing || activeTask || !!pending"
          @update:value="invalidate"
        />
      </n-form-item>
      <dl class="dns-details">
        <template v-for="row in currentRows" :key="row.label"
          ><dt>{{ row.label }}</dt>
          <dd>{{ row.value }}</dd></template
        >
      </dl>
      <n-alert v-if="!writable" type="info" :bordered="false"
        >当前网络配置仅支持查看，无法在此修改 DNS 设置。</n-alert
      >
      <n-alert v-else-if="!module?.enabled" type="info" :bordered="false"
        >启用 DNS 管理后可修改设置。</n-alert
      >
      <n-alert v-if="drift" type="warning" :bordered="false"
        >DNS 设置已在其他位置修改，重新检查后再应用。</n-alert
      >
    </section>

    <section v-if="editing" class="surface dns-editor">
      <div class="section-toolbar">
        <div>
          <h2>修改设置</h2>
          <p class="muted">填写 DNS 地址，再检查并应用变更。</p>
        </div>
        <n-button quaternary :disabled="busy" @click="cancelEdit"
          >取消修改</n-button
        >
      </div>
      <template v-if="!networkManager">
        <n-form-item label="DNS 地址" required>
          <ValueListInput
            v-model:value="servers"
            item-label="DNS 地址"
            :max="3"
            placeholder="输入 DNS 服务器的 IP 地址"
            :disabled="busy"
            @update:value="invalidate"
          />
        </n-form-item>
        <n-form-item label="域名后缀（可选）">
          <ValueListInput
            v-model:value="search"
            item-label="域名后缀"
            :max="6"
            placeholder="例如 corp.example.com"
            :disabled="busy"
            @update:value="invalidate"
          />
        </n-form-item>
      </template>
      <div v-else class="dns-families">
        <template v-for="family in families" :key="family.label">
          <div v-if="family.enabled" class="dns-family">
            <div class="section-toolbar">
              <h3>{{ family.label }}</h3>
              <span class="switch-label"
                >自动获取 DNS<n-switch
                  v-model:value="family.automatic"
                  :disabled="busy || !['auto', 'dhcp'].includes(family.method)"
                  @update:value="invalidate"
              /></span>
            </div>
            <n-form-item
              :label="family.automatic ? '补充 DNS 地址（可选）' : 'DNS 地址'"
              :required="!family.automatic"
            >
              <ValueListInput
                v-model:value="family.servers"
                item-label="DNS 地址"
                :max="3"
                :placeholder="
                  family.label === 'IPv4' ? '输入 IPv4 地址' : '输入 IPv6 地址'
                "
                :disabled="busy"
                @update:value="invalidate"
              />
            </n-form-item>
            <n-form-item v-if="!sharedSearch" label="域名后缀（可选）">
              <ValueListInput
                v-model:value="family.search"
                item-label="域名后缀"
                :max="6"
                placeholder="例如 corp.example.com"
                :disabled="busy"
                @update:value="invalidate"
              />
            </n-form-item>
          </div>
        </template>
      </div>
      <n-form-item
        v-if="sharedSearch"
        label="域名后缀（可选，IPv4 与 IPv6 共用）"
      >
        <ValueListInput
          v-model:value="search"
          item-label="域名后缀"
          :max="6"
          placeholder="例如 corp.example.com"
          :disabled="busy"
          @update:value="invalidate"
        />
      </n-form-item>
      <p class="muted">域名后缀用于补全内网短名称，不需要时可留空。</p>
      <div class="dns-verification">
        <h3>连接检查</h3>
        <n-form-item label="测试域名" required>
          <ValueListInput
            v-model:value="verifyNames"
            item-label="测试域名"
            :max="2"
            placeholder="例如 example.com"
            :disabled="busy"
            @update:value="invalidate"
          />
        </n-form-item>
        <p class="muted">
          填写新 DNS 应能解析的域名。应用后有
          {{ confirmationSeconds }} 秒确认时间，超时自动恢复。
        </p>
      </div>
      <n-checkbox
        v-model:checked="takeover"
        :disabled="busy"
        @update:checked="invalidate"
        >确认用以上设置替换当前 DNS 配置</n-checkbox
      >
      <div class="dns-actions dns-form-footer">
        <n-button
          :type="plan && !planExpired ? 'default' : 'primary'"
          :loading="busy"
          :disabled="
            !canWrite ||
            !takeover ||
            !writable ||
            !module?.enabled ||
            activeTask ||
            !!pending
          "
          @click="preview"
          >{{ plan ? "重新检查" : "检查设置" }}</n-button
        >
        <n-button :disabled="busy" @click="cancelEdit">取消</n-button>
      </div>

      <div v-if="plan" class="dns-review">
        <div class="section-toolbar">
          <h3>确认修改内容</h3>
          <n-tag
            :type="planExpired ? 'warning' : 'success'"
            :bordered="false"
            >{{ planExpired ? "请重新检查" : "检查通过" }}</n-tag
          >
        </div>
        <div class="dns-comparison">
          <div>
            <h4>当前设置</h4>
            <dl class="dns-details">
              <template v-for="row in configRows(plan.before)" :key="row.label"
                ><dt>{{ row.label }}</dt>
                <dd>{{ row.value }}</dd></template
              >
            </dl>
          </div>
          <div>
            <h4>修改后</h4>
            <dl class="dns-details">
              <template
                v-for="row in configRows(plan.input.config)"
                :key="row.label"
                ><dt>{{ row.label }}</dt>
                <dd>{{ row.value }}</dd></template
              >
            </dl>
          </div>
        </div>
        <p class="muted">
          测试域名：{{
            plan.input.verify_names.join("、")
          }}。应用后请确认连接正常，再保留设置。
        </p>
        <n-button
          type="primary"
          :loading="busy"
          :disabled="
            planExpired ||
            !canWrite ||
            !module?.enabled ||
            !writable ||
            activeTask ||
            !!pending
          "
          @click="apply"
          >应用 DNS 设置</n-button
        >
      </div>
    </section>

    <section v-if="task && !activeTask && !pending" class="surface">
      <div class="section-toolbar">
        <h2>最近操作</h2>
        <n-tag :type="statusType" :bordered="false">{{
          label(task.state)
        }}</n-tag>
      </div>
      <p>{{ label(task.stage) }}</p>
      <n-alert v-if="task.error" type="warning" :bordered="false">{{
        task.error
      }}</n-alert>
      <n-button quaternary @click="inspectTask(task.id, 'DNS 设置日志')"
        >查看日志</n-button
      >
    </section>
  </div>
</template>
<style scoped>
.dns-steps {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  padding: 16px 20px;
  margin: 0;
  list-style: none;
  border: 1px solid var(--border-color, #e2e9e5);
  border-radius: 10px;
  background: var(--surface-color, #fff);
}
.dns-steps li {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--text-muted, #7b8680);
  font-size: 14px;
}
.dns-steps li span {
  display: grid;
  place-items: center;
  width: 26px;
  height: 26px;
  flex: 0 0 26px;
  border-radius: 50%;
  background: #edf2ef;
}
.dns-steps li.current {
  color: #087f68;
  font-weight: 600;
}
.dns-steps li.current span,
.dns-steps li.completed span {
  color: #087f68;
  background: #e4f3ec;
}
.dns-actions,
.switch-label {
  display: flex;
  align-items: center;
  gap: 12px;
}
.dns-actions {
  flex-wrap: wrap;
}
.switch-label {
  color: var(--text-muted, #7b8680);
  white-space: nowrap;
}
.dns-details {
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr);
  gap: 12px 20px;
  margin: 20px 0;
}
.dns-details dt {
  color: var(--text-muted, #7b8680);
}
.dns-details dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.dns-interface {
  max-width: 560px;
}
.dns-families,
.dns-comparison {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px;
}
.dns-family,
.dns-comparison > div {
  min-width: 0;
  padding: 20px;
  border: 1px solid var(--border-color, #e2e9e5);
  border-radius: 8px;
}
.dns-family {
  margin-bottom: 20px;
}
.dns-verification,
.dns-review {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid var(--border-color, #e2e9e5);
}
.dns-form-footer {
  margin-top: 20px;
}
.confirmation-notice {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 16px;
  padding: 18px;
  margin: 16px 0;
  border-radius: 8px;
  background: #fff9e9;
}
.confirmation-notice p {
  margin: 6px 0 0;
}
@media (max-width: 760px) {
  .dns-families,
  .dns-comparison {
    grid-template-columns: 1fr;
    gap: 12px;
  }
  .dns-family {
    margin-bottom: 12px;
  }
  .dns-steps {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
    padding: 16px;
  }
}
@media (max-width: 480px) {
  .dns-details {
    grid-template-columns: 1fr;
    gap: 6px;
  }
  .dns-details dd {
    margin-bottom: 8px;
  }
}
</style>
