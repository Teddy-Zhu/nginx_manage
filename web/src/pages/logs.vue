<route lang="json">
{
  "meta": {
    "title": "日志",
    "subtitle": "应用、安全、任务与 Nginx 日志",
    "nav": true,
    "order": 4.5,
    "symbol": "▤"
  }
}
</route>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useRoute } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
  NDataTable,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NSelect,
  NSwitch,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  type LogPage,
  type LogPolicyInput,
  type LogPolicyView,
  type LogQuery,
  type LogRow,
  type LogSource,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
const api = useNodeAPI();
const { downloadLogFile, followLogs } = api;

const route = useRoute(),
  { run, busy, message } = useAction(),
  policyKey = useIdempotency();
const sources = ref<LogSource[]>([]),
  policies = ref<LogPolicyView[]>([]),
  policyScope = ref<"system" | "nginx">("system"),
  selected = ref(""),
  category = ref("all");
const rows = ref<LogRow[]>([]),
  result = ref<LogPage>(),
  error = ref(""),
  following = ref(false),
  queried = ref(false);
const policyOpen = ref(false),
  policyInput = ref<LogPolicyInput>();
function localTime(value: number) {
  const date = new Date(value);
  return new Date(value - date.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16);
}
const filter = reactive({
  mode: "recent" as "recent" | "history",
  from: localTime(Date.now() - 3600_000),
  until: "",
  status: null as number | null,
  ip: "",
  path: "",
  keyword: "",
  policy: typeof route.query.policy === "string" ? route.query.policy : "",
  reason: "",
  events: route.query.events === "1",
});
const policy = computed(() =>
  policies.value.find((item) => item.scope === policyScope.value),
);
const source = computed(() =>
  sources.value.find((item) => item.id === selected.value),
);
const structured = computed(
    () =>
      source.value?.format === "nginxpanel_http" ||
      source.value?.format === "nginxpanel_stream",
  ),
  http = computed(() => source.value?.format === "nginxpanel_http"),
  stream = computed(() => source.value?.format === "nginxpanel_stream");
const sourceOptions = computed(() =>
  sources.value
    .filter(
      (item) =>
        category.value === "all" || item.category.startsWith(category.value),
    )
    .map((item) => ({
      label: `${item.label}${item.active ? "" : "（已停用）"}`,
      value: item.id,
    })),
);
let current: LogQuery | undefined,
  closeStream: (() => void) | undefined,
  pending: AbortController | undefined,
  generation = 0;
function release(cursor?: string) {
  // Agent expiry reclaims the bounded cursor if navigation interrupts cleanup.
  if (cursor) void api.releaseLogCursor(cursor).catch(() => {});
}
function stop() {
  closeStream?.();
  closeStream = undefined;
  following.value = false;
}
function reset() {
  generation++;
  pending?.abort();
  pending = undefined;
  stop();
  release(current?.cursor);
  current = undefined;
  result.value = undefined;
  rows.value = [];
  queried.value = false;
  error.value = "";
}
function query(): LogQuery {
  if (!selected.value) throw new Error("请选择日志来源");
  const from = Math.floor(new Date(filter.from).getTime() / 1000),
    until = filter.until
      ? Math.floor(new Date(filter.until).getTime() / 1000)
      : 0;
  if (!Number.isFinite(from) || !Number.isFinite(until))
    throw new Error("请选择有效的起止时间");
  if (filter.mode === "history" && !until)
    throw new Error("历史查询须指定结束时间，单次范围最多七天");
  return {
    source_id: selected.value,
    mode: filter.mode,
    from,
    until,
    status: structured.value ? (filter.status ?? 0) : 0,
    ip: structured.value ? filter.ip.trim() : "",
    path: http.value ? filter.path.trim() : "",
    keyword: filter.keyword.trim(),
    policy_id: http.value ? filter.policy.trim() : "",
    reason: http.value ? filter.reason.trim() : "",
    events_only: http.value && filter.events,
    limit: 100,
    cursor: "",
  };
}
function accept(page: LogPage, append = false) {
  result.value = page;
  queried.value = true;
  rows.value = append ? [...rows.value, ...page.rows].slice(-200) : page.rows;
  if (current) current.cursor = page.cursor;
}
async function load() {
  const values = await Promise.all([api.logSources(), api.logPolicies()]);
  sources.value = values[0];
  policies.value = values[1];
  if (!policy.value && policies.value.length)
    policyScope.value = policies.value[0]!.scope;
  if (!sources.value.some((item) => item.id === selected.value)) {
    selected.value =
      sources.value.find(
        (item) =>
          item.resource_id === route.query.resource &&
          (!filter.events || item.format === "nginxpanel_http"),
      )?.id ??
      sources.value.find((item) =>
        filter.events ? item.format === "nginxpanel_http" : !item.sensitive,
      )?.id ??
      sources.value[0]?.id ??
      "";
  }
}
async function search(next = false) {
  await run(async () => {
    if (!next) {
      reset();
      current = query();
    }
    if (!current) return;
    const token = generation;
    pending = new AbortController();
    const page = await api.queryLogs({ ...current }, pending.signal);
    if (token !== generation) {
      release(page.cursor);
      return;
    }
    accept(page);
    pending = undefined;
  });
}
function follow() {
  void run(async () => {
    if (!current || current.mode !== "recent" || current.until)
      throw new Error("请先查询无结束时间的最近日志");
    if (following.value) return;
    // Preflight uses the shared API error handling, including reauthentication.
    const token = generation;
    const page = await api.queryLogs({ ...current });
    if (token !== generation) {
      release(page.cursor);
      return;
    }
    accept(page, true);
    following.value = true;
    error.value = "";
    closeStream = followLogs(
      { ...current },
      (page) => {
        if (token === generation) accept(page, true);
      },
      (cause) => {
        if (token !== generation) return;
        stop();
        error.value = cause.message;
      },
    );
  });
}
async function download() {
  await run(async () => {
    const value = await downloadLogFile(query());
    const url = URL.createObjectURL(value.blob),
      link = document.createElement("a");
    link.href = url;
    link.download = "managed-logs.jsonl";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    if (value.gap || value.truncated)
      message.warning("导出存在缺口或达到范围上限，请查看文件首行摘要");
  });
}
function editPolicy() {
  if (!policy.value) return;
  policyInput.value = {
    scope: policy.value.scope,
    base_version: policy.value.version,
    policy: { ...policy.value.policy },
  };
  policyOpen.value = true;
}
async function savePolicy() {
  await run(async () => {
    if (!policyInput.value) return;
    await api.setLogPolicy(policyInput.value, policyKey(policyInput.value));
    policies.value = await api.logPolicies();
    policyOpen.value = false;
    message.success("日志策略已保存，Agent 将独立执行");
  });
}
const policyFields: {
  key: keyof Omit<LogPolicyInput["policy"], "compress">;
  label: string;
  min: number;
  max: number;
}[] = [
  { key: "size_mib", label: "轮转大小（MiB）", min: 1, max: 1024 },
  { key: "interval_hours", label: "轮转间隔（小时）", min: 1, max: 168 },
  {
    key: "access_days",
    label: "访问 / 安全 / 任务保留（天）",
    min: 1,
    max: 90,
  },
  { key: "error_days", label: "错误 / 应用日志保留（天）", min: 1, max: 90 },
  { key: "resource_mib", label: "单资源配额（MiB）", min: 1, max: 16384 },
  { key: "total_mib", label: "总配额（MiB）", min: 1, max: 65536 },
];
function policyNumber(
  key: (typeof policyFields)[number]["key"],
  value: number | null,
) {
  if (value !== null && policyInput.value)
    policyInput.value.policy[key] = value;
}
const columns = computed<DataTableColumns<LogRow>>(() => {
  const out: DataTableColumns<LogRow> = [
    {
      title: "时间",
      key: "time",
      width: 185,
      render: (row) => new Date(row.time * 1000).toLocaleString(),
    },
  ];
  if (structured.value) {
    out.push(
      { title: "来源 IP", key: "ip", width: 150 },
      {
        title: stream.value ? "会话状态" : "HTTP 状态",
        key: "status",
        width: 100,
      },
    );
    if (stream.value)
      out.push(
        { title: "协议", key: "protocol", width: 80 },
        { title: "接收字节", key: "bytes_received", width: 110 },
      );
    else
      out.push(
        { title: "方法", key: "method", width: 90 },
        { title: "主机", key: "host", width: 180 },
        { title: "路径", key: "path", width: 250, ellipsis: { tooltip: true } },
      );
    out.push(
      { title: "耗时（秒）", key: "duration", width: 110 },
      { title: "发送字节", key: "bytes_sent", width: 110 },
      { title: "上游", key: "upstream", width: 180 },
      { title: "上游状态", key: "upstream_status", width: 100 },
    );
    if (http.value)
      out.push(
        { title: "事件", key: "event", width: 180 },
        { title: "策略", key: "policy_id", width: 220 },
        { title: "原因", key: "reason", width: 200 },
      );
  } else
    out.push(
      { title: "级别", key: "level", width: 100 },
      {
        title:
          source.value?.format === "nginxpanel_event"
            ? "事件元数据"
            : "脱敏消息",
        key: "message",
        width: 650,
        ellipsis: { tooltip: true },
      },
    );
  return out;
});
watch([selected, filter], reset, { deep: true, flush: "sync" });
watch(category, () => {
  if (!sourceOptions.value.some((item) => item.value === selected.value))
    selected.value = sourceOptions.value[0]?.value ?? "";
});
onMounted(() => void run(load));
onUnmounted(reset);
</script>

<template>
  <div class="toolbar">
    <n-button :loading="busy" @click="run(load)">刷新来源</n-button
    ><n-select
      v-model:value="policyScope"
      style="width: 180px"
      :options="
        policies.map((item) => ({
          label: item.scope === 'system' ? '系统日志策略' : 'Nginx 日志策略',
          value: item.scope,
        }))
      "
    /><n-button :disabled="!policy" @click="editPolicy">轮转与保留</n-button
    ><span class="muted"
      >{{ sources.length }} 个来源 ·
      {{ Math.round((policy?.bytes ?? 0) / 1048576) }} MiB</span
    >
  </div>
  <n-alert v-if="policy?.warning" type="warning" :bordered="false">{{
    policy.warning
  }}</n-alert>
  <n-empty
    v-if="!sources.length"
    description="暂无可用日志来源，请检查 Agent 状态"
  />
  <template v-else>
    <n-form
      class="log-filters"
      label-placement="top"
      @submit.prevent="search()"
    >
      <n-form-item label="分类"
        ><n-select
          v-model:value="category"
          :options="[
            { label: '全部', value: 'all' },
            { label: 'HTTP', value: 'http' },
            { label: 'Stream', value: 'stream' },
            { label: '全局', value: 'global' },
            { label: '应用', value: 'application' },
            { label: '安全', value: 'security' },
            { label: '任务', value: 'task' },
          ]"
      /></n-form-item>
      <n-form-item label="日志来源"
        ><n-select v-model:value="selected" :options="sourceOptions" filterable
      /></n-form-item>
      <n-form-item label="查询模式"
        ><n-select
          v-model:value="filter.mode"
          :options="[
            { label: '最近', value: 'recent' },
            { label: '历史', value: 'history' },
          ]"
      /></n-form-item>
      <n-form-item label="开始时间"
        ><input v-model="filter.from" type="datetime-local" required
      /></n-form-item>
      <n-form-item label="结束时间"
        ><input v-model="filter.until" type="datetime-local"
      /></n-form-item>
      <n-form-item v-if="structured" :label="stream ? '会话状态' : 'HTTP 状态'"
        ><n-input-number
          v-model:value="filter.status"
          :min="100"
          :max="599"
          :precision="0"
          clearable
      /></n-form-item>
      <n-form-item v-if="structured" label="来源 IP"
        ><n-input v-model:value="filter.ip" placeholder="数值 IP"
      /></n-form-item>
      <n-form-item v-if="http" label="路径前缀"
        ><n-input
          v-model:value="filter.path"
          placeholder="/api/"
          :maxlength="256"
      /></n-form-item>
      <n-form-item label="关键字"
        ><n-input v-model:value="filter.keyword" :maxlength="256"
      /></n-form-item>
      <n-form-item v-if="http" label="防护策略 ID"
        ><n-input v-model:value="filter.policy" :maxlength="128"
      /></n-form-item>
      <n-form-item v-if="http" label="防护原因 / 事件"
        ><n-input v-model:value="filter.reason" :maxlength="256"
      /></n-form-item>
      <n-form-item v-if="http" label="事件范围"
        ><n-checkbox v-model:checked="filter.events"
          >仅防护事件</n-checkbox
        ></n-form-item
      >
    </n-form>
    <n-alert v-if="source?.sensitive" type="warning" :bordered="false"
      >原生日志或历史文件可能包含请求行及查询参数。读取需要敏感配置权限和近期身份确认；页面与下载尽力脱敏，原始文件不保证完全排除敏感信息。</n-alert
    >
    <n-alert v-if="source?.reason" type="warning" :bordered="false">{{
      source.reason
    }}</n-alert>
    <div class="toolbar">
      <n-button
        type="primary"
        :loading="busy"
        :disabled="!selected"
        @click="search()"
        >查询</n-button
      ><n-button
        :disabled="!result?.more || following || busy"
        @click="search(true)"
        >下一页</n-button
      ><n-button
        v-if="!following"
        :disabled="
          !queried || filter.mode !== 'recent' || !!filter.until || busy
        "
        @click="follow"
        >实时跟随</n-button
      ><n-button v-else @click="stop">停止跟随</n-button
      ><n-button :disabled="busy || !selected" @click="download"
        >下载 JSONL</n-button
      >
    </div>
    <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>
    <n-alert
      v-if="result?.gap || result?.notice"
      :type="result?.gap ? 'warning' : 'info'"
      :bordered="false"
      >{{
        result?.notice || "日志范围存在缺口，请缩小时间范围后查询历史。"
      }}</n-alert
    >
    <p v-if="queried" class="muted">
      当前 {{ rows.length }} 行 · 本页扫描
      {{ Math.ceil((result?.scanned_bytes ?? 0) / 1024) }} KiB · 跳过
      {{ result?.skipped ?? 0 }} 行<span v-if="following">
        · 正在跟随，最多保留最近 200 行</span
      >
    </p>
    <n-data-table
      :columns="columns"
      :data="rows"
      :scroll-x="http ? 2200 : stream ? 1250 : 950"
      :bordered="false"
    />
  </template>
  <n-modal
    v-model:show="policyOpen"
    preset="card"
    title="轮转与保留"
    style="width: 620px; max-width: 94vw"
  >
    <template v-if="policy && policyInput">
      <n-alert type="info" :bordered="false"
        >所有者：{{
          policy.owner === "agent"
            ? "Agent"
            : policy.owner === "external"
              ? "外部管理"
              : "尚未确认"
        }}。大小与时间按定时检查触发，属于软阈值；只清理已确认关闭的历史文件，活动文件或
        reopen 失败时可能超过配额。配额须满足：轮转大小 ≤ 单来源 ≤
        总计。</n-alert
      >
      <n-alert v-if="!policy.editable" type="warning" :bordered="false">{{
        policy.scope === "system"
          ? "系统日志存储尚未就绪，请在本机核对 Agent 状态。"
          : "需在本机确认唯一轮转所有者，排除外部规则竞争后才能启用 Agent 管理。"
      }}</n-alert>
      <n-form
        label-placement="top"
        class="log-filters"
        @submit.prevent="savePolicy"
      >
        <n-form-item
          v-for="field in policyFields"
          :key="field.key"
          :label="field.label"
          ><n-input-number
            :value="policyInput.policy[field.key]"
            :disabled="!policy.editable"
            :min="field.min"
            :max="field.max"
            :precision="0"
            @update:value="policyNumber(field.key, $event)"
        /></n-form-item>
        <n-form-item label="压缩已关闭历史文件"
          ><n-switch
            v-model:value="policyInput.policy.compress"
            :disabled="!policy.editable"
        /></n-form-item>
        <n-button
          type="primary"
          attr-type="submit"
          :loading="busy"
          :disabled="!policy.editable"
          >保存策略</n-button
        >
      </n-form>
    </template>
  </n-modal>
</template>

<style scoped>
.log-filters {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0 16px;
  margin-top: 16px;
}
.log-filters input[type="datetime-local"] {
  width: 100%;
  min-width: 0;
  padding: 6px 10px;
  border: 1px solid #d8dee8;
  border-radius: 3px;
  color: inherit;
  background: transparent;
  font: inherit;
  box-sizing: border-box;
}
.n-alert {
  margin: 12px 0;
}
</style>
