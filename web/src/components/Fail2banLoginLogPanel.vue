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
      <NButton :loading="busy" :disabled="busy" @click="load">
        刷新记录
      </NButton>
    </div>
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <template v-if="view">
      <div class="toolbar">
        <NTag :type="view.available ? 'success' : 'warning'">
          {{
            view.available ? "日志可读取" : "日志不可用"
          }}
        </NTag>
        <span class="muted">更新于 {{ new Date(view.at * 1000).toLocaleString() }}</span>
      </div>
      <NAlert v-if="view.reason" type="warning">
        {{ view.reason }}
      </NAlert>
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
