<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NTag,
  type DataTableColumns,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banPanelLoginEvent,
  type Fail2banPanelLoginStatus,
} from "../api/client";

const api = useNodeAPI(),
  controller = new AbortController();
const view = ref<Fail2banPanelLoginStatus | null>(null),
  busy = ref(false),
  error = ref("");
let closed = false;
const columns: DataTableColumns<Fail2banPanelLoginEvent> = [
  {
    title: "失败时间",
    key: "time_iso8601",
    render: (row) => new Date(row.time_iso8601).toLocaleString(),
  },
  { title: "TCP 对端", key: "peer_addr" },
  { title: "请求标识", key: "request_id", ellipsis: { tooltip: true } },
];
async function load() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  view.value = null;
  try {
    const result = await api.fail2banPanelLogin(controller.signal);
    if (!closed) view.value = result;
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    if (!closed) busy.value = false;
  }
}
onMounted(() => {
  void load();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
});
</script>
<template>
  <section class="panel page-stack">
    <div class="toolbar">
      <h3>面板登录失败记录</h3>
      <NButton :loading="busy" :disabled="busy" @click="load">刷新记录</NButton>
    </div>
    <NAlert type="info"
      >仅记录密码认证拒绝，显示最近 20 条。反向代理后的 TCP
      对端通常为代理地址。日志可用不代表自动封禁已启用。</NAlert
    >
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <template v-if="view">
      <div class="toolbar">
        <NTag :type="view.available ? 'success' : 'warning'">{{
          view.available ? "日志可读取" : "日志不可用"
        }}</NTag>
        <span class="muted"
          >采样 {{ new Date(view.at * 1000).toLocaleString() }} ·
          {{ view.scope === "host" ? "宿主机" : "范围未确认" }} ·
          {{ (view.bytes / 1024 / 1024).toFixed(2) }} /
          {{ (view.limit_bytes / 1024 / 1024).toFixed(0) }} MiB</span
        >
      </div>
      <NAlert v-if="view.reason" type="warning">{{ view.reason }}</NAlert>
      <NDataTable
        v-if="view.available"
        :columns="columns"
        :data="view.events"
        :row-key="(row: Fail2banPanelLoginEvent) => row.request_id"
        :scroll-x="620"
      />
    </template>
  </section>
</template>
