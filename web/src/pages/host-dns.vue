<route lang="json">
{
  "meta": {
    "title": "主机 DNS",
    "subtitle": "解析器配置与确认恢复",
    "nav": true,
    "order": 0.6,
    "symbol": "◎"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NInput,
  NInputNumber,
  NSwitch,
  NTag,
} from "naive-ui";
import {
  api,
  apiError,
  type HostDNSOverview,
  type HostDNSPlan,
  type HostDNSPlanInput,
  type Module,
} from "../api/client";
import { useAction } from "../composables/action";
import { useSession } from "../stores/session";

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
const drift = computed(
  () =>
    overview.value?.desired &&
    observed.value?.source_hash &&
    overview.value.desired.source_hash !== observed.value.source_hash &&
    !pending.value,
);
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
    module.value = modules.find((m) => m.id === "host-dns") ?? null;
    error.value = "";
    if (
      plan.value &&
      (plan.value.expires_at * 1000 <= Date.now() ||
        plan.value.input.source_hash !== state.observed.source_hash)
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
  servers.value = observed.value.current.servers.join("\n");
  search.value = observed.value.current.search.join("\n");
  takeover.value = false;
  plan.value = null;
  editing.value = true;
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
    source_hash: observed.value.source_hash,
    config: { servers: split(servers.value), search: split(search.value) },
    verify_names: split(verifyNames.value),
    timeout_seconds: timeout.value,
    takeover: takeover.value,
  };
  const digest = JSON.stringify(input);
  if (!previewAttempt || previewAttempt.digest !== digest)
    previewAttempt = { digest, key: crypto.randomUUID() };
  const key = previewAttempt.key;
  await run(async () => {
    plan.value = await api.planHostDNS(input, key);
    previewAttempt = undefined;
    applyKey = crypto.randomUUID();
  });
}
async function apply() {
  const p = plan.value;
  if (!p || p.expires_at * 1000 <= Date.now()) return;
  if (!window.confirm("临时应用主机 DNS？确认期限内未确认将自动恢复原设置。"))
    return;
  await run(async () => {
    await api.applyHostDNS(p.id, applyKey || (applyKey = crypto.randomUUID()));
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
    key = crypto.randomUUID();
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
onMounted(() => {
  void read();
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
    <h2>主机 DNS</h2>
    <div class="actions">
      <span>启用管理</span
      ><n-switch
        :value="module?.enabled ?? false"
        :disabled="!canToggle || busy"
        @update:value="toggle"
      /><n-button :loading="reading" @click="read">刷新</n-button>
    </div>
  </div>
  <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>
  <n-alert type="info" :bordered="false" style="margin: 16px 0"
    >主机解析器变更可能影响证书申请、更新、通知和远程连接。未在期限内确认的设置会自动恢复。</n-alert
  >
  <section v-if="observed" class="panel">
    <div class="page-toolbar">
      <h3>解析器状态</h3>
      <n-tag :type="observed.writable ? 'success' : 'warning'">{{
        observed.writable ? "可接管" : "只读"
      }}</n-tag>
    </div>
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
    <n-alert
      v-if="drift"
      type="warning"
      :bordered="false"
      style="margin-top: 12px"
      >当前源版本与最近确认的期望配置不同，请检查外部修改后重新规划。</n-alert
    >
    <n-button
      v-if="!editing"
      type="primary"
      style="margin-top: 16px"
      :disabled="
        !canWrite ||
        !module?.enabled ||
        !observed.writable ||
        activeTask ||
        busy
      "
      @click="edit"
      >配置 DNS</n-button
    >
  </section>
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
    <h3>DNS 变更计划</h3>
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
      >确认接管该主机的普通 DNS 配置文件</n-checkbox
    >
    <div class="actions" style="margin-top: 16px">
      <n-button
        :disabled="
          !canWrite ||
          busy ||
          !takeover ||
          !observed?.writable ||
          !module?.enabled
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
        <dd>{{ plan.before.servers.join("、") }}</dd>
        <dt>新 DNS</dt>
        <dd>{{ plan.input.config.servers.join("、") }}</dd>
        <dt>搜索域</dt>
        <dd>
          {{ plan.before.search.join("、") || "无" }} →
          {{ plan.input.config.search.join("、") || "无" }}
        </dd>
        <dt>验证域名</dt>
        <dd>{{ plan.input.verify_names.join("、") }}</dd>
        <dt>未确认恢复</dt>
        <dd>{{ plan.input.timeout_seconds }} 秒</dd>
      </dl>
      <n-button
        type="primary"
        :disabled="
          busy || !module?.enabled || !observed?.writable || activeTask
        "
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
