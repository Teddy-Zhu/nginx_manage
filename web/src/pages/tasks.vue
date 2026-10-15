<route lang="json">
{
  "meta": {
    "title": "任务与审计",
    "subtitle": "查看执行阶段和操作记录",
    "nav": true,
    "order": 3,
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
const taskKinds: Record<string, string> = {
  "nginx.validate": "配置校验",
  "nginx.apply": "配置应用",
};
const taskStates: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  compensating: "回滚中",
  succeeded: "已完成",
  failed: "失败",
  rolled_back: "已回滚",
  recovery_required: "需要恢复",
  cancelled: "已取消",
};
const taskStages: Record<string, string> = {
  queued: "等待执行",
  submit_unconfirmed: "提交待确认",
  operation_missing: "执行记录缺失",
  agent_submit_pending: "等待接收",
  preparing: "生成候选配置",
  prepared: "候选配置就绪",
  testing: "校验配置",
  nginx_tested: "校验通过",
  switch_pending: "准备切换",
  switched: "确认运行状态",
  runtime_confirmed: "已确认生效",
  rollback_pending: "恢复上一修订",
  rollback_confirmed: "已确认恢复",
  rollback_unconfirmed: "恢复待确认",
  nginx_test_failed: "配置校验失败",
  external_conflict: "外部修改冲突",
  runtime_unconfirmed: "运行状态待确认",
  runtime_mismatch: "运行修订不一致",
  agent_unreachable: "等待连接",
  reconciling: "核对执行结果",
  agent_rejected: "操作未被接受",
  agent_not_ready: "执行环境未就绪",
  superseded: "修订已被替换",
  interrupted_before_switch: "切换前中断",
  prepare_failed: "候选配置生成失败",
};
const taskColumns: DataTableColumns<Task> = [
  { title: "任务 ID", key: "id", render: (r) => r.id.slice(0, 8) },
  { title: "类型", key: "kind", render: (r) => taskKinds[r.kind] ?? r.kind },
  {
    title: "状态",
    key: "state",
    render: (r) => taskStates[r.state] ?? r.state,
  },
  {
    title: "目标修订",
    key: "revision_id",
    render: (r) => r.revision_id?.slice(0, 8) || "—",
  },
  {
    title: "确认修订",
    key: "observed_revision",
    render: (r) => r.observed_revision?.slice(0, 8) || "—",
  },
  {
    title: "阶段",
    key: "stage",
    render: (r) => taskStages[r.stage] ?? r.stage,
  },
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
    >配置校验不改变运行修订。配置应用通过运行确认后才标记完成，失败时显示回滚或恢复状态。</n-alert
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
