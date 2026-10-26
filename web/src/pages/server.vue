<route lang="json">
{
  "meta": {
    "title": "监控",
    "subtitle": "查看 CPU、内存、磁盘与服务状态",
    "nav": true,
    "order": 10,
    "symbol": "▥",
    "group": "服务器管理"
  }
}
</route>

<script setup lang="ts">
import AdvancedDetails from "../components/AdvancedDetails.vue";
import { computed, onMounted, onUnmounted, ref, watch, toRaw } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NFormItem,
  NInputNumber,
  NModal,
  NSelect,
  NSwitch,
  NTag,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  type HostMetric,
  type MonitoringCapability,
  type MonitoringHistory,
  type MonitoringLatest,
  type MonitoringSettings,
  type MonitoringSettingsView,
  type MonitoringThreshold,
  type MonitoredService,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import MetricTrend from "../components/MetricTrend.vue";
const api = useNodeAPI();
const { request } = api;

const { run, busy } = useAction(),
  session = useSession(),
  idempotency = useIdempotency();
const latest = ref<MonitoringLatest | null>(null),
  settings = ref<MonitoringSettingsView | null>(null),
  capability = ref<MonitoringCapability | null>(null),
  history = ref<MonitoringHistory | null>(null);
const edit = ref<MonitoringSettings | null>(null),
  modal = ref(false),
  selected = ref("cpu:total"),
  field = ref("usage_percent"),
  hours = ref(1),
  error = ref(""),
  historyError = ref("");
const controller = new AbortController();
let poll: ReturnType<typeof setInterval> | undefined,
  reading = false,
  historyController: AbortController | undefined,
  historyMinute = 0;
const metrics = computed(() => latest.value?.sample?.metrics ?? []);
const current = computed(() =>
  metrics.value.find((m) => `${m.kind}:${m.id}` === selected.value),
);
const options = computed(() =>
  metrics.value.map((m) => ({
    label: `${labels[m.kind] ?? m.kind} · ${m.label}`,
    value: `${m.kind}:${m.id}`,
  })),
);
const fields = computed(() =>
  Object.keys(current.value?.values ?? {}).map((key) => ({
    label: fieldLabels[key] ?? key,
    value: key,
  })),
);
const canConfigure = computed(
  () => session.me?.scopes.includes("monitoring.write") ?? false,
);
const canToggle = computed(
  () => session.me?.scopes.includes("system.write") ?? false,
);
const labels: Record<string, string> = {
  cpu: "CPU",
  memory: "内存",
  swap: "Swap",
  load: "负载",
  uptime: "运行时间",
  filesystem: "文件系统",
  network: "网络",
};
const fieldLabels: Record<string, string> = {
  usage_percent: "使用率",
  used_percent: "使用率",
  total_bytes: "总容量",
  available_bytes: "可用容量",
  reserved_bytes: "保留空间",
  free_bytes: "剩余容量",
  total_inodes: "总 inode",
  free_inodes: "剩余 inode",
  used_inode_percent: "inode 使用率",
  one: "1 分钟",
  five: "5 分钟",
  fifteen: "15 分钟",
  seconds: "秒",
  received_bytes: "累计接收",
  sent_bytes: "累计发送",
  rx_bps: "接收速率",
  tx_bps: "发送速率",
};
const unit = computed(() =>
  field.value.endsWith("percent")
    ? "%"
    : field.value.endsWith("bytes")
      ? "B"
      : field.value.endsWith("bps")
        ? "bit/s"
        : field.value === "seconds"
          ? "s"
          : "",
);
const number = (value: number | null | undefined, suffix = "") =>
  value === null || value === undefined
    ? "—"
    : `${value.toLocaleString(undefined, { maximumFractionDigits: 1 })}${suffix}`;
function bytes(value: number | null | undefined) {
  if (value === null || value === undefined) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const power =
    value > 0 ? Math.min(4, Math.floor(Math.log(value) / Math.log(1024))) : 0;
  return `${number(value / 1024 ** power)} ${units[power]}`;
}
const kind = (name: string) => metrics.value.filter((m) => m.kind === name);
const main = (name: string, value: string) =>
  kind(name).find((m) => m.id === "total")?.values[value];
const cards = computed(() => [
  { label: "CPU 使用率", value: number(main("cpu", "usage_percent"), "%") },
  { label: "内存使用率", value: number(main("memory", "used_percent"), "%") },
  { label: "可用内存", value: bytes(main("memory", "available_bytes")) },
  { label: "Swap 使用率", value: number(main("swap", "used_percent"), "%") },
  { label: "1 分钟负载", value: number(main("load", "one")) },
  {
    label: "运行时长",
    value:
      main("uptime", "seconds") == null
        ? "—"
        : `${number((main("uptime", "seconds") ?? 0) / 3600)} 小时`,
  },
]);
const cpuColumns: DataTableColumns<HostMetric> = [
  { title: "核心", key: "label" },
  {
    title: "使用率",
    key: "values",
    render: (r) => number(r.values.usage_percent, "%"),
  },
  { title: "状态", key: "reason" },
];
const fsColumns: DataTableColumns<HostMetric> = [
  { title: "挂载点", key: "label" },
  { title: "容量", key: "total", render: (r) => bytes(r.values.total_bytes) },
  {
    title: "可用",
    key: "available",
    render: (r) => bytes(r.values.available_bytes),
  },
  {
    title: "保留",
    key: "reserved",
    render: (r) => bytes(r.values.reserved_bytes),
  },
  {
    title: "使用率",
    key: "used",
    render: (r) => number(r.values.used_percent, "%"),
  },
  {
    title: "inode 使用率",
    key: "inodes",
    render: (r) => number(r.values.used_inode_percent, "%"),
  },
  { title: "状态", key: "reason" },
];
const networkColumns: DataTableColumns<HostMetric> = [
  { title: "接口", key: "label" },
  {
    title: "接收",
    key: "rx",
    render: (r) => number(r.values.rx_bps, " bit/s"),
  },
  {
    title: "发送",
    key: "tx",
    render: (r) => number(r.values.tx_bps, " bit/s"),
  },
  {
    title: "累计接收",
    key: "received",
    render: (r) => bytes(r.values.received_bytes),
  },
  { title: "累计发送", key: "sent", render: (r) => bytes(r.values.sent_bytes) },
  { title: "状态", key: "reason" },
];
const serviceNames: Record<string, string> = {
  "nginxpanel.service": "管理面板",
  "nginxpanel-agent.service": "系统管理服务",
  "nginxpanel-nginx.service": "Nginx",
  "nginxpanel-fail2ban.service": "Fail2ban 登录防护",
};
const serviceStates: Record<string, string> = {
  active: "运行中",
  inactive: "已停止",
  failed: "运行异常",
  activating: "启动中",
  deactivating: "停止中",
  reloading: "重新加载中",
};
const serviceColumns: DataTableColumns<MonitoredService> = [
  { title: "服务", key: "id", render: (r) => serviceNames[r.id] ?? r.id },
  {
    title: "运行状态",
    key: "active",
    render: (r) =>
      r.load === "not-found"
        ? "未安装"
        : r.active === "active" && r.sub === "exited"
          ? "已完成"
          : (serviceStates[r.active] ?? "状态未知"),
  },
  {
    title: "说明",
    key: "reason",
    render: (r) =>
      r.reason ||
      (serviceStates[r.active] || r.load === "not-found"
        ? "—"
        : `${r.load} / ${r.active} / ${r.sub}`),
  },
];
const thresholdKinds = [
  { key: "cpu", label: "CPU" },
  { key: "memory", label: "内存" },
  { key: "disk", label: "文件系统" },
] as const;
async function readLatest() {
  if (reading || controller.signal.aborted) return;
  reading = true;
  try {
    latest.value = await api.monitoringLatest(controller.signal);
    error.value = "";
  } catch (cause) {
    const e = apiError(cause);
    if (e.code !== "CANCELLED") error.value = e.message;
  } finally {
    reading = false;
  }
}
async function readHistory() {
  if (controller.signal.aborted) return;
  historyController?.abort();
  historyController = new AbortController();
  const active = historyController;
  if (!current.value || !field.value) {
    history.value = null;
    return;
  }
  const until = Math.floor(Date.now() / 1000);
  historyMinute = Math.floor(until / 60);
  try {
    const result = await api.monitoringHistory(
      {
        kind: current.value.kind,
        id: current.value.id,
        value: field.value,
        from: until - hours.value * 3600,
        until,
        points: 180,
      },
      active.signal,
    );
    if (active === historyController) {
      history.value = result;
      historyError.value = "";
    }
  } catch (cause) {
    const e = apiError(cause);
    if (e.code !== "CANCELLED" && active === historyController) {
      history.value = null;
      historyError.value = e.message;
    }
  }
}
async function load() {
  await run(async () => {
    const result = await Promise.all([
      api.monitoringSettings(controller.signal),
      request<{ host: null | { monitoring: MonitoringCapability } }>({
        url: "/system/capabilities",
        signal: controller.signal,
      }),
    ]);
    settings.value = result[0];
    capability.value = result[1].host?.monitoring ?? null;
    await readLatest();
    await readHistory();
  });
}
async function toggle(enabled: boolean) {
  await run(
    async () => {
      await api.setModule("monitoring", enabled);
      await readLatest();
    },
    enabled ? "基础监控已启用" : "基础监控已停用",
  );
}
function configure() {
  if (settings.value) {
    edit.value = structuredClone(toRaw(settings.value.settings));
    modal.value = true;
  }
}
async function save() {
  if (!settings.value || !edit.value) return;
  const data = { base_version: settings.value.version, settings: edit.value };
  await run(async () => {
    settings.value = await api.setMonitoringSettings(data, idempotency(data));
    modal.value = false;
    await readLatest();
  }, "监控设置已保存");
}
function thresholdInvalid(t: MonitoringThreshold) {
  return (
    t.high <= 0 ||
    t.high > 100 ||
    t.recover < 0 ||
    t.recover >= t.high ||
    (t.enabled &&
      !!edit.value &&
      (t.for_seconds < 2 * edit.value.interval_seconds ||
        t.recover_seconds < 2 * edit.value.interval_seconds))
  );
}
watch(selected, () => {
  if (!fields.value.some((f) => f.value === field.value))
    field.value = fields.value[0]?.value ?? "";
  void readHistory();
});
watch([field, hours], () => void readHistory());
function visible() {
  if (!document.hidden) {
    void readLatest();
    void readHistory();
  }
}
onMounted(async () => {
  document.addEventListener("visibilitychange", visible);
  await load();
  if (!controller.signal.aborted)
    poll = setInterval(() => {
      if (!document.hidden && !busy.value) {
        void readLatest();
        if (Math.floor(Date.now() / 60000) !== historyMinute)
          void readHistory();
      }
    }, 15_000);
});
onUnmounted(() => {
  controller.abort();
  historyController?.abort();
  if (poll) clearInterval(poll);
  document.removeEventListener("visibilitychange", visible);
});
</script>

<template>
  <div class="toolbar">
    <div class="monitor-switch">
      <n-switch
        :value="latest?.enabled ?? false"
        :disabled="!canToggle || busy"
        @update:value="toggle"
      /><span>资源监控</span
      ><n-tag size="small" :type="latest?.stale ? 'warning' : 'success'">{{
        !latest?.sample ? "等待数据" : latest.stale ? "数据已过期" : "数据正常"
      }}</n-tag>
    </div>
    <div class="actions">
      <n-button :disabled="!canConfigure || !settings" @click="configure"
        >采样与阈值</n-button
      ><n-button :loading="busy" @click="load">刷新</n-button>
    </div>
  </div>
  <n-alert
    v-if="error || latest?.reason"
    type="warning"
    :bordered="false"
    class="notice"
    >{{ error || latest?.reason }}</n-alert
  >
  <n-alert
    v-if="capability && !capability.available"
    type="info"
    :bordered="false"
    class="notice"
    >{{ capability.reason }}</n-alert
  >
  <p class="muted">{{ latest?.sample ? `更新时间：${new Date(latest.sample.at * 1000).toLocaleString()}` : '暂无监控数据' }}</p>
  <AdvancedDetails title="采样详情">  <p class="muted">
    {{
      latest?.sample
        ? `采样时间：${new Date(latest.sample.at * 1000).toLocaleString()}`
        : "暂无监控数据"
    }}
    · {{ settings?.settings.interval_seconds ?? "—" }} 秒采样 · 保留
    {{ settings?.settings.retention_hours ?? "—" }} 小时 · 历史占用
    {{ bytes(latest?.stored_bytes) }}
  </p>
</AdvancedDetails>
  <div class="stat-grid">
    <div v-for="card in cards" :key="card.label" class="stat-card">
      <span class="stat-label">{{ card.label }}</span
      ><strong>{{ card.value }}</strong>
    </div>
  </div>
  <section class="surface">
    <div class="section-heading">
      <h2>资源趋势</h2>
      <div class="trend-selectors">
        <n-select
          v-model:value="selected"
          :options="options"
          placeholder="指标维度"
        /><n-select
          v-model:value="field"
          :options="fields"
          placeholder="指标"
        /><n-select
          v-model:value="hours"
          :options="[
            { label: '最近 1 小时', value: 1 },
            { label: '最近 6 小时', value: 6 },
            { label: '最近 24 小时', value: 24 },
          ]"
        />
      </div>
    </div>
    <n-alert v-if="historyError" type="warning">{{ historyError }}</n-alert>
    <MetricTrend :history="history" :unit="unit" />
    <p class="muted">
      {{ history?.notice ?? "缺失值显示为空，采样空档不连接。" }}
    </p>
  </section>
  <n-alert
    v-for="warning in latest?.sample?.warnings ?? []"
    :key="warning"
    type="info"
    :bordered="false"
    class="notice"
    >{{ warning }}</n-alert
  >
  <section v-if="latest?.conditions.length" class="surface">
    <h2>资源阈值</h2>
    <div
      v-for="condition in latest.conditions"
      :key="`${condition.kind}:${condition.id}`"
      class="condition"
    >
      <span>{{ labels[condition.kind] }} · {{ condition.label }}</span
      ><n-tag
        :type="
          !condition.available
            ? 'default'
            : condition.active
              ? 'error'
              : 'success'
        "
        >{{
          !condition.available
            ? condition.active
              ? "超限状态保留，等待采样"
              : "等待采样"
            : condition.active
              ? "持续超限"
              : condition.pending_at
                ? "超限观察中"
                : "正常"
        }}</n-tag
      ><span>{{ number(condition.value, "%") }}</span>
    </div>
  </section>
  <section class="surface">
    <h2>本地文件系统</h2>
    <p class="muted">使用率基于普通用户可用空间；保留空间单独展示。</p>
    <n-data-table
      :columns="fsColumns"
      :data="kind('filesystem')"
      :scroll-x="1000"
    />
  </section>
  <section class="surface">
    <h2>网络接口</h2>
    <n-data-table
      :columns="networkColumns"
      :data="kind('network')"
      :scroll-x="1000"
    />
  </section>
  <section class="surface">
    <h2>CPU 核心</h2>
    <n-data-table
      :columns="cpuColumns"
      :data="kind('cpu').filter((m) => m.id !== 'total')"
      :pagination="{ pageSize: 16 }"
    />
  </section>
  <section class="surface">
    <h2>服务状态</h2>
    <n-data-table
      :columns="serviceColumns"
      :data="latest?.sample?.services ?? []"
    />
  </section>
  <n-modal
    v-model:show="modal"
    preset="card"
    title="采样与资源阈值"
    style="width: min(720px, 95vw)"
  >
    <template v-if="edit">
      <div class="two-columns">
        <n-form-item label="采样间隔（秒）"
          ><n-input-number
            v-model:value="edit.interval_seconds"
            :min="15"
            :max="300" /></n-form-item
        ><n-form-item label="保留时间（小时）"
          ><n-input-number
            v-model:value="edit.retention_hours"
            :min="1"
            :max="24"
        /></n-form-item>
      </div>
      <fieldset v-for="item in thresholdKinds" :key="item.key">
        <legend>{{ item.label }}</legend>
        <n-switch v-model:value="edit[item.key].enabled" /><span
          class="threshold-label"
          >启用资源阈值</span
        >
        <div class="threshold-grid">
          <n-form-item label="超限值（%）"
            ><n-input-number
              v-model:value="edit[item.key].high"
              :min="1"
              :max="100" /></n-form-item
          ><n-form-item label="恢复值（%）"
            ><n-input-number
              v-model:value="edit[item.key].recover"
              :min="0"
              :max="99" /></n-form-item
          ><n-form-item label="超限持续（秒）"
            ><n-input-number
              v-model:value="edit[item.key].for_seconds"
              :min="30"
              :max="3600" /></n-form-item
          ><n-form-item label="恢复持续（秒）"
            ><n-input-number
              v-model:value="edit[item.key].recover_seconds"
              :min="30"
              :max="3600"
          /></n-form-item>
        </div>
        <p v-if="thresholdInvalid(edit[item.key])" class="muted">
          恢复值须小于超限值，启用时持续窗口至少为两个采样间隔。
        </p>
      </fieldset>
      <div class="actions">
        <n-button @click="modal = false">取消</n-button
        ><n-button
          type="primary"
          :loading="busy"
          :disabled="thresholdKinds.some((t) => thresholdInvalid(edit![t.key]))"
          @click="save"
          >保存</n-button
        >
      </div>
    </template>
  </n-modal>
</template>

<style scoped>
.monitor-switch,
.actions,
.condition {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.notice {
  margin-bottom: 16px;
}
.stat-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.trend-selectors {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr) 150px;
  gap: 12px;
  max-width: 760px;
  flex: 1 1 500px;
}
.condition {
  padding: 10px 0;
}
.condition > span:first-child {
  min-width: 180px;
}
.threshold-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 24px;
}
fieldset {
  border: 1px solid var(--border-color);
  border-radius: 8px;
  margin: 12px 0;
  padding: 16px;
  min-width: 0;
}
.threshold-label {
  margin-left: 10px;
}
@media (max-width: 760px) {
  .stat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .trend-selectors {
    grid-template-columns: 1fr;
  }
  .section-heading {
    align-items: stretch;
    flex-direction: column;
  }
  .trend-selectors { flex-basis: auto; width: 100%; }
  .threshold-grid { grid-template-columns: minmax(0, 1fr); }
}
</style>
