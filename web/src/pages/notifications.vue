<route lang="json">
{
  "meta": {
    "title": "通知",
    "subtitle": "设置通知渠道和接收事件",
    "nav": true,
    "order": 23,
    "symbol": "♧",
    "group": "数据与设置"
  }
}
</route>

<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { randomUUID } from "../utils/crypto";

import { computed, h, onMounted, onUnmounted, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NCheckboxGroup,
  NDataTable,
  NFormItem,
  NInput,
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
  type NotificationChannel,
  type NotificationChannelInput,
  type NotificationDelivery,
  type NotificationEvent,
  type NotificationOverview,
  type NotificationPolicy,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();

const { run, busy, message } = useAction(),
  session = useSession(),
  idempotency = useIdempotency();
const overview = ref<NotificationOverview | null>(null),
  events = ref<NotificationEvent[]>([]),
  deliveries = ref<NotificationDelivery[]>([]),
  error = ref("");
const channelFilter = ref(""),
  eventOffset = ref(0),
  deliveryOffset = ref(0),
  channelModal = ref(false),
  policyModal = ref(false),
  policy = ref<NotificationPolicy | null>(null);
const edited = ref<NotificationChannel | null>(null);
const form = ref({
  name: "",
  kind: "webhook",
  enabled: false,
  subscriptions: [] as string[],
  url: "",
  chat_id: "",
  thread_id: null as number | null,
  bot_token: "",
  bearer_token: "",
  signing_secret: "",
  clear_bearer: false,
  clear_signing: false,
});
const controller = new AbortController();
let
  refreshPending = false;
const loading = ref(false);
const testKeys = new Map<string, { version: number; key: string }>();
const canWrite = computed(
    () => session.me?.scopes.includes("notifications.write") ?? false,
  ),
  canToggle = computed(
    () => session.me?.scopes.includes("system.write") ?? false,
  );
const labels = computed(
  () =>
    new Map<string, string>([
      ...(overview.value?.kinds.map((k) => [k.id, k.label] as const) ?? []),
      ["notification.test", "渠道测试"],
    ]),
);
const channelOptions = computed(() => [
  { label: "全部渠道", value: "" },
  ...(overview.value?.channels.map((c) => ({ label: c.name, value: c.id })) ??
    []),
]);
const time = (value: number) =>
  value ? new Date(value * 1000).toLocaleString() : "—";
const severity: Record<string, string> = {
  info: "信息",
  warning: "警告",
  error: "错误",
  critical: "严重",
};
const states: Record<string, string> = {
  pending: "待发送",
  sending: "发送中",
  sent: "端点已接收",
  failed: "发送失败",
  expired: "已过期",
  cancelled: "已取消",
};
const channelColumns: DataTableColumns<NotificationChannel> = [
  { title: "渠道", key: "name" },
  {
    title: "类型",
    key: "kind",
    render: (c) => (c.kind === "telegram" ? "Telegram" : "Webhook"),
  },
  { title: "目标", key: "target", render: (c) => c.target || "未配置" },
  {
    title: "状态",
    key: "enabled",
    render: (c) =>
      h(NTag, { size: "small", type: c.enabled ? "success" : "default" }, () =>
        c.enabled ? "已启用" : "已停用",
      ),
  },
  {
    title: "配置",
    key: "configured",
    render: (c) => (c.configured ? "已配置" : c.reason),
  },
  {
    title: "订阅",
    key: "subscriptions",
    render: (c) => `${c.subscriptions.length} 类事件`,
  },
  {
    title: "操作",
    key: "actions",
    render: (c) =>
      h("div", { class: "actions" }, [
        h(
          NButton,
          {
            size: "small",
            disabled: !canWrite.value,
            onClick: () => editChannel(c),
          },
          () => "编辑",
        ),
        h(
          NButton,
          {
            size: "small",
            disabled:
              !canWrite.value ||
              !c.enabled ||
              !overview.value?.enabled ||
              busy.value,
            onClick: () => void testChannel(c),
          },
          () => "发送测试",
        ),
        h(
          NButton,
          {
            size: "small",
            disabled: !canWrite.value || busy.value,
            onClick: () => void removeChannel(c),
          },
          () => "删除",
        ),
      ]),
  },
];
const eventColumns: DataTableColumns<NotificationEvent> = [
  { title: "时间", key: "created_at", render: (e) => time(e.created_at) },
  {
    title: "类型",
    key: "kind",
    render: (e) => labels.value.get(e.kind) ?? e.kind,
  },
  {
    title: "级别",
    key: "severity",
    render: (e) =>
      h(
        NTag,
        {
          size: "small",
          type:
            e.severity === "critical" || e.severity === "error"
              ? "error"
              : e.severity === "warning"
                ? "warning"
                : "default",
        },
        () => severity[e.severity] ?? e.severity,
      ),
  },
  { title: "资源", key: "resource_id", ellipsis: { tooltip: true } },
  { title: "摘要", key: "summary", ellipsis: { tooltip: true } },
  { title: "合并次数", key: "occurrences" },
  { title: "事件 ID", key: "id", ellipsis: { tooltip: true } },
];
const deliveryColumns: DataTableColumns<NotificationDelivery> = [
  { title: "创建时间", key: "created_at", render: (d) => time(d.created_at) },
  { title: "渠道", key: "channel_name" },
  { title: "状态", key: "state", render: (d) => states[d.state] ?? d.state },
  {
    title: "尝试",
    key: "attempts",
    render: (d) => `${d.attempts}/${d.max_attempts}`,
  },
  {
    title: "下次尝试",
    key: "next_attempt_at",
    render: (d) => (d.state === "pending" ? time(d.next_attempt_at) : "—"),
  },
  {
    title: "最近结果",
    key: "last_error",
    render: (d) =>
      d.last_error || (d.http_status ? `HTTP ${d.http_status}` : "—"),
  },
  { title: "事件 ID", key: "event_id", ellipsis: { tooltip: true } },
  {
    title: "操作",
    key: "action",
    render: (d) =>
      h(
        NButton,
        {
          size: "small",
          disabled:
            !canWrite.value ||
            !overview.value?.enabled ||
            busy.value ||
            !["failed", "pending"].includes(d.state) ||
            d.attempts >= d.max_attempts ||
            d.expires_at <= Date.now() / 1000,
          onClick: () => void retry(d),
        },
        () => "重试",
      ),
  },
];
async function fetchData() {
  if (controller.signal.aborted) return;
  if (loading.value) {
    refreshPending = true;
    return;
  }
  loading.value = true;
  const query = JSON.stringify([
    channelFilter.value,
    eventOffset.value,
    deliveryOffset.value,
  ]);
  try {
    const result = await Promise.all([
      api.notifications(controller.signal),
      api.notificationEvents(30, eventOffset.value, controller.signal),
      api.notificationDeliveries(
        channelFilter.value,
        30,
        deliveryOffset.value,
        controller.signal,
      ),
    ]);
    if (
      query !==
      JSON.stringify([
        channelFilter.value,
        eventOffset.value,
        deliveryOffset.value,
      ])
    ) {
      refreshPending = true;
      return;
    }
    overview.value = result[0];
    for (const id of testKeys.keys()) {
      if (!result[0].channels.some((c) => c.id === id)) testKeys.delete(id);
    }
    events.value = result[1];
    deliveries.value = result[2];
    error.value = "";
  } catch (cause) {
    const e = apiError(cause);
    if (e.code !== "CANCELLED") error.value = e.message;
  } finally {
    loading.value = false;
    if (refreshPending && !controller.signal.aborted) {
      refreshPending = false;
      void fetchData();
    }
  }
}
async function load() {
  await run(fetchData);
}
async function toggle(enabled: boolean) {
  await run(
    async () => {
      await api.setModule("notifications", enabled);
      await fetchData();
    },
    enabled ? "外部通知已启用" : "外部通知已停用",
  );
}
function editChannel(channel: NotificationChannel | null) {
  edited.value = channel;
  form.value = {
    name: channel?.name ?? "",
    kind: channel?.kind ?? "webhook",
    enabled: channel?.enabled ?? false,
    subscriptions: channel
      ? [...channel.subscriptions]
      : (overview.value?.kinds.map((k) => k.id) ?? []),
    url: "",
    chat_id: "",
    thread_id: channel ? null : 0,
    bot_token: "",
    bearer_token: "",
    signing_secret: "",
    clear_bearer: false,
    clear_signing: false,
  };
  channelModal.value = true;
}
async function saveChannel() {
  const f = form.value,
    c = edited.value;
  const input: NotificationChannelInput = {
    base_version: c?.version ?? 0,
    name: f.name,
    kind: f.kind as "webhook" | "telegram",
    enabled: f.enabled,
    subscriptions: [...f.subscriptions],
  };
  if (f.kind === "telegram") {
    if (f.chat_id || !c) input.chat_id = f.chat_id;
    if (f.bot_token || !c) input.bot_token = f.bot_token;
    if (f.thread_id !== null) input.thread_id = f.thread_id;
  } else {
    if (f.url || !c) input.url = f.url;
    if (f.bearer_token || f.clear_bearer || !c)
      input.bearer_token = f.clear_bearer ? "" : f.bearer_token;
    if (f.signing_secret || f.clear_signing || !c)
      input.signing_secret = f.clear_signing ? "" : f.signing_secret;
  }
  await run(async () => {
    await api.saveNotificationChannel(
      c?.id ?? "",
      input,
      idempotency({ id: c?.id ?? "", input }),
    );
    channelModal.value = false;
    await fetchData();
  }, "渠道设置已保存");
}
async function testChannel(c: NotificationChannel) {
  let pending = testKeys.get(c.id);
  if (!pending || pending.version !== c.version) {
    pending = { version: c.version, key: randomUUID() };
    testKeys.set(c.id, pending);
  }
  const key = pending.key;
  await run(async () => {
    const result = await api.notificationChannelAction(
      c.id,
      c.version,
      "test",
      key,
    );
    testKeys.delete(c.id);
    await fetchData();
    message.success(`测试已排队：${result.delivery_id.slice(0, 8)}`);
  });
}
async function removeChannel(c: NotificationChannel) {
  if (!window.confirm(`删除渠道“${c.name}”并取消其待投递项？`)) return;
  await run(async () => {
    await api.notificationChannelAction(
      c.id,
      c.version,
      "delete",
      idempotency({ delete: c.id, version: c.version }),
    );
    if (channelFilter.value === c.id) channelFilter.value = "";
    await fetchData();
  }, "渠道已删除");
}
async function retry(d: NotificationDelivery) {
  await run(async () => {
    await api.retryNotification(
      d.id,
      idempotency({ retry: d.id, attempts: d.attempts }),
    );
    await fetchData();
  }, "已安排重试");
}
function editPolicy() {
  if (overview.value) {
    policy.value = { ...overview.value.policy.policy };
    policyModal.value = true;
  }
}
async function savePolicy() {
  if (!overview.value || !policy.value) return;
  const input = {
    base_version: overview.value.policy.version,
    policy: { ...policy.value },
  };
  await run(async () => {
    await api.setNotificationPolicy(input, idempotency(input));
    policyModal.value = false;
    await fetchData();
  }, "通知策略已保存");
}
function generateSecret() {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  form.value.signing_secret = Array.from(random, (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  form.value.clear_signing = false;
}
watch(channelModal, (show) => {
  if (!show) {
    form.value.bot_token = "";
    form.value.bearer_token = "";
    form.value.signing_secret = "";
    form.value.url = "";
    form.value.chat_id = "";
  }
});
watch(channelFilter, () => {
  deliveryOffset.value = 0;
  void load();
});
watch([eventOffset, deliveryOffset], () => void load());
function visibility() {
  if (!document.hidden) void fetchData();
}
onMounted(async () => {
  document.addEventListener("visibilitychange", visibility);
  await load();

});
onUnmounted(() => {
  controller.abort();
  document.removeEventListener("visibilitychange", visibility);
});
useLiveRefresh(api, ["notifications"], () => { if (!busy.value) return fetchData(); });
</script>

<template>
  <div class="toolbar">
    <div class="actions">
      <n-switch
        :value="overview?.enabled ?? false"
        :disabled="!canToggle || busy"
        @update:value="toggle"
      /><span>外部通知</span>
    </div>
    <div class="actions">
      <n-button :disabled="!canWrite || !overview" @click="editPolicy"
        >通知策略</n-button
      ><n-button :loading="busy" @click="load">刷新</n-button>
    </div>
  </div>
  <n-alert
    v-if="error || overview?.health.reason"
    type="warning"
    :bordered="false"
    class="notice"
    >{{ error || overview?.health.reason }}</n-alert
  >
  <n-alert
    v-if="overview && !overview.enabled"
    type="info"
    :bordered="false"
    class="notice"
    >外部通知已停用。待投递项在有效期内保留，恢复启用后继续处理。</n-alert
  >
  <n-alert
    v-if="
      overview &&
      (overview.health.evicted_events || overview.health.dropped_deliveries)
    "
    type="warning"
    :bordered="false"
    class="notice"
    >已触发存储上限：清理 {{ overview.health.evicted_events }} 条较早事件，丢弃
    {{ overview.health.dropped_deliveries }} 条未完成投递。</n-alert
  >
  <div class="stat-grid">
    <div class="stat-card">
      <span class="stat-label">通知渠道</span
      ><strong>{{ overview?.channels.length ?? "—" }} / 16</strong>
    </div>
    <div class="stat-card">
      <span class="stat-label">等待投递</span
      ><strong>{{ overview?.health.pending ?? "—" }}</strong>
    </div>
    <div class="stat-card">
      <span class="stat-label">投递失败</span
      ><strong>{{ overview?.health.failed ?? "—" }}</strong>
    </div>
    <div class="stat-card">
      <span class="stat-label">投递有效期</span
      ><strong>{{ overview?.policy.policy.ttl_hours ?? "—" }} 小时</strong>
    </div>
  </div>
  <section class="surface">
    <div class="section-heading">
      <h2>通知渠道</h2>
      <n-button
        type="primary"
        :disabled="!canWrite || (overview?.channels.length ?? 16) >= 16"
        @click="editChannel(null)"
        >新增渠道</n-button
      >
    </div>
    <n-data-table
      :columns="channelColumns"
      :data="overview?.channels ?? []"
      :scroll-x="1100"
    />
    <p class="muted">
      目标与凭据仅显示配置状态；发送测试会产生真实投递。修改或停用渠道会取消其待投递项，历史记录保留。
    </p>
  </section>
  <section class="surface">
    <div class="section-heading">
      <h2>投递记录</h2>
      <n-select
        :disabled="loading"
        v-model:value="channelFilter"
        :options="channelOptions"
        style="width: 220px"
      />
    </div>
    <n-data-table
      :loading="loading"
      :columns="deliveryColumns"
      :data="deliveries"
      :scroll-x="1300"
    />
    <div class="pagination">
      <n-button
        :disabled="deliveryOffset === 0 || busy || loading"
        @click="deliveryOffset = Math.max(0, deliveryOffset - 30)"
        >上一页</n-button
      ><span>第 {{ deliveryOffset / 30 + 1 }} 页</span
      ><n-button
        :disabled="
          deliveries.length < 30 ||
          deliveryOffset + 30 > 8192 ||
          busy ||
          loading
        "
        @click="deliveryOffset += 30"
        >下一页</n-button
      >
    </div>
    <p class="muted">
      失败按退避策略重试，达到次数或有效期后停止。接收端应按节点与事件 ID
      去重；请求结果不确定时可能重复送达。
    </p>
  </section>
  <section class="surface">
    <h2>本机事件</h2>
    <n-data-table
      :loading="loading"
      :columns="eventColumns"
      :data="events"
      :scroll-x="1400"
    />
    <div class="pagination">
      <n-button
        :disabled="eventOffset === 0 || busy || loading"
        @click="eventOffset = Math.max(0, eventOffset - 30)"
        >上一页</n-button
      ><span>第 {{ eventOffset / 30 + 1 }} 页</span
      ><n-button
        :disabled="
          events.length < 30 || eventOffset + 30 > 2048 || busy || loading
        "
        @click="eventOffset += 30"
        >下一页</n-button
      >
    </div>
    <p class="muted">
      任务故障按资源和小时合并。证书到期阈值同时参考实际寿命与已保存续期时间；数据目录空间告警独立于宿主机监控。
    </p>
  </section>
  <n-modal
    v-model:show="channelModal"
    preset="card"
    :title="edited ? '编辑通知渠道' : '新增通知渠道'"
    style="width: min(740px, 95vw)"
  >
    <div class="two-columns">
      <n-form-item label="名称"
        ><n-input v-model:value="form.name" maxlength="128" /></n-form-item
      ><n-form-item label="类型"
        ><n-select
          v-model:value="form.kind"
          :disabled="!!edited"
          :options="[
            { label: 'Webhook', value: 'webhook' },
            { label: 'Telegram', value: 'telegram' },
          ]"
      /></n-form-item>
    </div>
    <n-form-item label="启用渠道"
      ><n-switch v-model:value="form.enabled"
    /></n-form-item>
    <p v-if="edited" class="muted">
      当前目标：{{ edited.target || "未配置" }}。地址和凭据留空时保留原值。
    </p>
    <template v-if="form.kind === 'telegram'">
      <n-form-item label="Bot Token"
        ><n-input
          v-model:value="form.bot_token"
          type="password"
          show-password-on="click"
          autocomplete="new-password"
          :placeholder="
            edited?.has_bot_token ? '已配置，留空保留' : '填写 Bot Token'
          "
      /></n-form-item>
      <div class="two-columns">
        <n-form-item label="Chat ID"
          ><n-input
            v-model:value="form.chat_id"
            placeholder="数字 ID 或 @channelname" /></n-form-item
        ><n-form-item label="话题 ID（0 表示不指定）"
          ><n-input-number v-model:value="form.thread_id" :min="0"
        /></n-form-item>
      </div>
    </template>
    <template v-else>
      <n-form-item label="HTTPS 地址"
        ><n-input
          v-model:value="form.url"
          type="password"
          show-password-on="click"
          autocomplete="off"
          placeholder="https://example.com/webhook"
      /></n-form-item>
      <n-form-item label="Bearer Token（可选）"
        ><n-input
          v-model:value="form.bearer_token"
          type="password"
          show-password-on="click"
          autocomplete="new-password"
          :placeholder="
            edited?.has_bearer_token ? '已配置，留空保留' : '未配置'
          " /></n-form-item
      ><n-checkbox
        v-if="edited?.has_bearer_token"
        v-model:checked="form.clear_bearer"
        >清除原 Bearer Token</n-checkbox
      >
      <n-form-item label="HMAC-SHA256 共享密钥（可选，至少 16 字节）"
        ><n-input
          v-model:value="form.signing_secret"
          type="password"
          show-password-on="click"
          autocomplete="new-password"
          :placeholder="
            edited?.has_signing_secret ? '已配置，留空保留' : '未配置'
          "
      /></n-form-item>
      <div class="actions">
        <n-button size="small" @click="generateSecret">生成密钥</n-button
        ><n-checkbox
          v-if="edited?.has_signing_secret"
          v-model:checked="form.clear_signing"
          >清除原签名密钥</n-checkbox
        >
      </div>
    </template>
    <n-form-item label="事件订阅" style="margin-top: 20px"
      ><n-checkbox-group v-model:value="form.subscriptions"
        ><div class="subscriptions">
          <n-checkbox
            v-for="kind in overview?.kinds ?? []"
            :key="kind.id"
            :value="kind.id"
            :label="kind.label"
          /></div></n-checkbox-group
    ></n-form-item>
    <n-alert v-if="form.kind === 'webhook'" type="info" :bordered="false"
      >Webhook 签名为 HMAC-SHA256(共享密钥, 时间戳 + "." + 原始 JSON
      请求体)，使用 X-NginxPanel-Timestamp 和 X-NginxPanel-Signature
      请求头；签名值以 sha256= 开头。</n-alert
    >
    <div class="actions form-actions">
      <n-button @click="channelModal = false">取消</n-button
      ><n-button type="primary" :loading="busy" @click="saveChannel"
        >保存</n-button
      >
    </div>
  </n-modal>
  <n-modal
    v-model:show="policyModal"
    preset="card"
    title="通知策略"
    style="width: min(660px, 95vw)"
  >
    <template v-if="policy"
      ><div class="two-columns">
        <n-form-item label="证书到期提前天数"
          ><n-input-number
            v-model:value="policy.expiry_days"
            :min="1"
            :max="60" /></n-form-item
        ><n-form-item label="投递有效期（小时）"
          ><n-input-number
            v-model:value="policy.ttl_hours"
            :min="1"
            :max="24" /></n-form-item
        ><n-form-item label="最大尝试次数"
          ><n-input-number
            v-model:value="policy.max_attempts"
            :min="1"
            :max="8" /></n-form-item
        ><n-form-item label="数据目录剩余容量阈值（MiB）"
          ><n-input-number
            v-model:value="policy.disk_mib"
            :min="64"
            :max="10240" /></n-form-item
        ><n-form-item label="数据目录剩余比例阈值（%）"
          ><n-input-number
            v-model:value="policy.disk_percent"
            :min="1"
            :max="20"
        /></n-form-item>
      </div>
      <p class="muted">
        任一空间阈值不足时告警，恢复需同时达到容量阈值的 1.2 倍及比例阈值加
        2%。有效期和尝试次数作用于新建投递。
      </p>
      <div class="actions form-actions">
        <n-button @click="policyModal = false">取消</n-button
        ><n-button type="primary" :loading="busy" @click="savePolicy"
          >保存</n-button
        >
      </div></template
    >
  </n-modal>
</template>

<style scoped>
.actions,
.pagination {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
}
.notice {
  margin-bottom: 16px;
}
.pagination {
  justify-content: flex-end;
  margin-top: 20px;
}
.subscriptions {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
@media (max-width: 700px) {
  .subscriptions {
    grid-template-columns: 1fr;
  }
}
</style>
