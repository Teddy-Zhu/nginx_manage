<route lang="json">
{
  "meta": {
    "title": "任务与审计",
    "subtitle": "查看执行阶段和操作记录",
    "nav": true,
    "order": 2,
    "symbol": "☷"
  }
}
</route>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import {
  NButton,
  NDataTable,
  NTabs,
  NTabPane,
  NAlert,
  type DataTableColumns,
} from "naive-ui";
import { request, type Task } from "../api/client";
import { useAction } from "../composables/action";
const { run, busy } = useAction(),
  tasks = ref<Task[]>([]);
interface Audit {
  id: string;
  action: string;
  principal: string;
  resource_id: string;
  outcome: string;
  created_at: number;
}
const audits = ref<Audit[]>([]),
  offset = ref(0);
const taskColumns: DataTableColumns<Task> = [
  { title: "任务 ID", key: "id", render: (r) => r.id.slice(0, 8) },
  { title: "类型", key: "kind" },
  { title: "状态", key: "state" },
  { title: "阶段", key: "stage" },
  { title: "错误", key: "last_error", render: (r) => r.last_error || "—" },
  {
    title: "创建时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];
const auditColumns: DataTableColumns<Audit> = [
  { title: "操作", key: "action" },
  { title: "操作者", key: "principal" },
  { title: "资源", key: "resource_id" },
  { title: "结果", key: "outcome" },
  {
    title: "时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];
async function load() {
  await run(async () => {
    const result = await Promise.all([
      request<Task[]>({ url: "/tasks", params: { offset: offset.value } }),
      request<Audit[]>({ url: "/audit", params: { offset: offset.value } }),
    ]);
    tasks.value = result[0];
    audits.value = result[1];
  });
}
async function page(delta: number) {
  offset.value = Math.max(0, offset.value + delta);
  await load();
}
onMounted(load);
</script>
<template>
  <div class="toolbar">
    <span class="muted">每页最多 30 条记录</span
    ><n-button :loading="busy" @click="load">刷新</n-button>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >策略复核通过表示 Agent 接受安全策略检查，不表示 Nginx 配置已应用。</n-alert
  >
  <section class="surface">
    <n-tabs type="line"
      ><n-tab-pane name="tasks" tab="执行任务"
        ><n-data-table
          :columns="taskColumns"
          :data="tasks"
          :bordered="false"
          :scroll-x="900" /></n-tab-pane
      ><n-tab-pane name="audit" tab="操作审计"
        ><n-data-table
          :columns="auditColumns"
          :data="audits"
          :bordered="false"
          :scroll-x="800" /></n-tab-pane
    ></n-tabs>
    <div class="pagination">
      <n-button :disabled="!offset || busy" @click="page(-30)">上一页</n-button
      ><span class="muted">第 {{ offset / 30 + 1 }} 页</span
      ><n-button
        :disabled="busy || (tasks.length < 30 && audits.length < 30)"
        @click="page(30)"
        >下一页</n-button
      >
    </div>
  </section>
</template>
