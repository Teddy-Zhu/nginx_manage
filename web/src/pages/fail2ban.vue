<route lang="json">
{
  "meta": {
    "title": "Fail2ban",
    "subtitle": "宿主机依赖与实例诊断",
    "nav": true,
    "order": 0.75,
    "symbol": "◈"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NTag,
  type DataTableColumns,
} from "naive-ui";
import { apiError, useNodeAPI, type Fail2banObservation } from "../api/client";

const api = useNodeAPI(),
  controller = new AbortController();
const view = ref<Fail2banObservation | null>(null),
  error = ref(""),
  reading = ref(false),
  moduleEnabled = ref<boolean | null>(null);
let closed = false;
const status = (value: boolean | null) =>
  value === null ? "未知" : value ? "是" : "否";
const python = computed(() => view.value?.python);
const tools: DataTableColumns<Fail2banObservation["tools"][number]> = [
  { title: "程序", key: "id" },
  { title: "发现文件", key: "present", render: (row) => status(row.present) },
  {
    title: "路径与权限已核对",
    key: "trusted",
    render: (row) => (row.trusted ? "是" : "未通过"),
  },
  {
    title: "实际路径",
    key: "resolved",
    render: (row) => row.resolved || row.path || "—",
    minWidth: 240,
    ellipsis: { tooltip: true },
  },
  {
    title: "状态说明",
    key: "reason",
    render: (row) => row.reason || "—",
    minWidth: 240,
  },
];
const services: DataTableColumns<Fail2banObservation["services"][number]> = [
  { title: "服务单元", key: "id" },
  {
    title: "加载",
    key: "load",
    render: (row) => (row.available ? row.load : "未知"),
  },
  {
    title: "活动状态",
    key: "active",
    render: (row) => (row.available ? `${row.active} / ${row.sub}` : "未知"),
  },
  {
    title: "开机状态",
    key: "unit_file",
    render: (row) => row.unit_file || "未知",
  },
  {
    title: "主进程 PID",
    key: "main_pid",
    render: (row) => row.main_pid ?? "未知",
  },
  {
    title: "状态说明",
    key: "reason",
    render: (row) => row.reason || "—",
    minWidth: 240,
  },
];
const modules: DataTableColumns<
  Fail2banObservation["python"]["modules"][number]
> = [
  { title: "标准库", key: "name" },
  { title: "可导入", key: "available", render: (row) => status(row.available) },
];
async function load() {
  if (reading.value || closed) return;
  reading.value = true;
  error.value = "";
  const [diagnostic, flags] = await Promise.allSettled([
    api.fail2ban(controller.signal),
    api.modules(controller.signal),
  ]);
  if (closed) return;
  if (diagnostic.status === "fulfilled") view.value = diagnostic.value;
  else {
    view.value = null;
    error.value = apiError(diagnostic.reason).message;
  }
  if (flags.status === "fulfilled") {
    const flag = flags.value.find((item) => item.id === "fail2ban");
    moduleEnabled.value = flag?.enabled ?? null;
  } else moduleEnabled.value = null;
  reading.value = false;
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
  <div class="page-stack">
    <div class="page-toolbar">
      <h2>Fail2ban 诊断</h2>
      <NButton :loading="reading" @click="load">刷新状态</NButton>
    </div>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h3>管理状态</h3>
        <NTag :type="moduleEnabled ? 'info' : 'default'"
          >模块{{
            moduleEnabled === null
              ? "状态未知"
              : moduleEnabled
                ? "已启用"
                : "已停用"
          }}</NTag
        >
      </div>
      <p>
        服务运行独立于面板模块开关。实例尚未接入，jail、当前封禁及保护效果尚不可核对。
      </p>
      <template v-if="view">
        <p>
          观测时间
          {{ view.at ? new Date(view.at * 1000).toLocaleString() : "未知" }} ·
          {{ view.available ? "宿主机诊断" : "宿主机范围未就绪" }}
        </p>
        <NAlert v-if="view.reason" type="warning">{{ view.reason }}</NAlert>
      </template>
    </section>
    <template v-if="view?.available">
      <section class="panel page-stack">
        <h3>已有工具</h3>
        <p>官方客户端版本 {{ view.client_version || "未能读取" }}</p>
        <NDataTable :columns="tools" :data="view.tools" :scroll-x="900" />
        <NAlert v-if="view.missing.length" type="warning"
          >固定系统路径未发现：{{ view.missing.join("、") }}</NAlert
        >
      </section>
      <section v-if="python" class="panel page-stack">
        <h3>系统 Python</h3>
        <p>
          {{
            python.executable.resolved ||
            python.executable.path ||
            "未发现受信解释器"
          }}
          · 版本 {{ python.version || "未知" }}
        </p>
        <p>
          必要标准库可用：{{ status(python.standard_library) }} · SQLite
          {{ python.sqlite_version || "未知" }}
        </p>
        <p v-if="python.package.available">
          软件包归属 {{ python.package.manager }} / {{ python.package.name }} /
          {{ python.package.version }}
        </p>
        <p v-else>{{ python.package.reason }}</p>
        <NAlert
          v-if="python.reason"
          :type="python.standard_library ? 'info' : 'warning'"
          >{{ python.reason }}</NAlert
        >
        <NDataTable
          v-if="python.modules.length"
          :columns="modules"
          :data="python.modules"
          :pagination="{ pageSize: 8 }"
        />
      </section>
      <section class="panel page-stack">
        <h3>服务与默认 Socket</h3>
        <NDataTable
          :columns="services"
          :data="view.services"
          :scroll-x="1000"
        />
        <p>
          {{ view.socket.path }} · 文件存在：{{ status(view.socket.present) }} ·
          root 保护：{{ view.socket.root_protected ? "已核对" : "未核对" }}
        </p>
        <p class="muted">{{ view.socket.reason }}</p>
      </section>
      <NAlert v-for="warning in view.warnings" :key="warning" type="warning">{{
        warning
      }}</NAlert>
    </template>
  </div>
</template>
