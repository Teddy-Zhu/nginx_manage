<route lang="json">
{
  "meta": {
    "title": "任务与操作记录",
    "subtitle": "查看任务进度与历史操作",
    "nav": true,
    "order": 22,
    "symbol": "☷",
    "group": "数据与设置"
  }
}
</route>

<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { ref, reactive, onMounted, h } from "vue";
import {
  NButton,
  NDataTable,
  NTabs,
  NFormItem,
  NInput,
  NSelect,
  NTabPane,
  NAlert,
  type DataTableColumns,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Task,
  type AuditRow,
  type AuditPage,
  type AuditFilter,
} from "../api/client";
import { useAction } from "../composables/action";
import TaskLogButton from "../components/TaskLogButton.vue";
import { taskKinds, taskStates, taskStageLabel } from "../utils/tasks";
const api = useNodeAPI();
const { request } = api;

const { run, busy } = useAction(),
  tasks = ref<Task[]>([]);
const audits = ref<AuditPage | null>(null),
  offset = ref(0),
  tab = ref("tasks");
const tasksError = ref("");
function localTime(value: number) {
  const date = new Date(value);
  return new Date(value - date.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16);
}
const filter = reactive({
  from: localTime(Date.now() - 24 * 3600_000),
  until: localTime(Date.now()),
  principal: "",
  action: "",
  resource_id: "",
  outcome: "",
  request_id: "",
});
const applied = ref<AuditFilter | null>(null),
  cursors = ref<string[]>([""]),
  auditPage = ref(0);
function queryFilter(): AuditFilter {
  const from = new Date(filter.from).getTime() / 1000;
  const until = new Date(filter.until).getTime() / 1000 + 59;
  if (
    !Number.isFinite(from) ||
    !Number.isFinite(until) ||
    from <= 0 ||
    until < from ||
    until - from > 90 * 24 * 3600 ||
    until > Date.now() / 1000 + 60
  )
    throw new Error("请选择有效起止时间，范围最多九十天");
  return {
    from: Math.floor(from),
    until: Math.floor(until),
    principal: filter.principal,
    action: filter.action,
    resource_id: filter.resource_id,
    outcome: filter.outcome,
    request_id: filter.request_id,
  };
}
const taskColumns: DataTableColumns<Task> = [
  {
    title: "日志",
    key: "logs",
    render: (task) =>
      h(TaskLogButton, {
        taskId: task.id,
        title: taskKinds[task.kind] ?? "操作详情",
      }),
  },

  {
    title: "类型",
    key: "kind",
    render: (r) => taskKinds[r.kind] ?? "后台任务",
  },
  {
    title: "状态",
    key: "state",
    render: (r) => taskStates[r.state] ?? "状态待确认",
  },
  {
    title: "阶段",
    key: "stage",
    render: (r) => taskStageLabel(r.stage, r.kind, r.state),
  },
  { title: "错误", key: "last_error", render: (r) => r.last_error || "—" },
  {
    title: "创建时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];
const auditActions: Record<string, string> = {
  ...taskKinds,
  "auth.login": "登录面板",
  "auth.bootstrap": "初始化管理员",
  "modules.set": "修改功能开关",
  "nginx.save.desired": "保存代理配置",
  "logs.policy": "保存日志策略",
};
const auditOutcomes: Record<string, string> = {
  ...taskStates,
  requested: "已请求",
  queued: "已提交",
  saved: "已保存",
};
const auditColumns: DataTableColumns<AuditRow> = [
  {
    title: "操作",
    key: "action",
    render: (r) => auditActions[r.action] ?? r.action,
  },

  { title: "操作者", key: "principal" },

  {
    title: "结果",
    key: "outcome",
    render: (r) => auditOutcomes[r.outcome] ?? r.outcome,
  },
  {
    title: "时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];
async function loadTasks() {
  await run(async () => {
    try {
      tasks.value = await request<Task[]>({
        url: "/tasks",
        params: { offset: offset.value },
      });
      tasksError.value = "";
    } catch (cause) {
      tasksError.value = apiError(cause).message;
    }
  });
}
async function searchAudit() {
  await run(async () => {
    const input = queryFilter();
    const result = await api.audit({ ...input, limit: 30 });
    applied.value = input;
    audits.value = result;
    cursors.value = [result.start_cursor];
    auditPage.value = 0;
  });
}
async function load() {
  if (tab.value === "audit") await searchAudit();
  else await loadTasks();
}
async function changeTab(value: string) {
  if (busy.value) return;
  tab.value = value;
  if (value === "audit" && !audits.value) await searchAudit();
}
async function page(delta: number) {
  if (tab.value === "tasks") {
    offset.value = Math.max(0, offset.value + delta * 30);
    await loadTasks();
    return;
  }
  if (!applied.value || !audits.value) return;
  await run(async () => {
    const next = auditPage.value + delta;
    if (next < 0 || (delta > 0 && !audits.value?.more)) return;
    const cursor = delta > 0 ? audits.value!.cursor : cursors.value[next];
    const result = await api.audit({ ...applied.value!, limit: 30, cursor });
    if (delta > 0) cursors.value[next] = cursor;
    audits.value = result;
    auditPage.value = next;
  });
}
async function exportAudit() {
  await run(async () => {
    const input = queryFilter();
    const blob = await api.exportAudit(input);
    const url = URL.createObjectURL(blob),
      link = document.createElement("a");
    link.href = url;
    link.download = `audit-${new Date().toISOString().slice(0, 10)}.jsonl`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}
onMounted(loadTasks);
useLiveRefresh(api, ["tasks"], () => {
  if (tab.value === "tasks") return loadTasks();
});
</script>
<template>
  <div class="toolbar">
    <span class="muted">每页最多 30 条记录</span
    ><n-button :loading="busy" @click="load">刷新</n-button>
  </div>
  <NAlert v-if="tab === 'tasks' && tasksError" type="error">{{
    tasksError
  }}</NAlert>
  <section class="surface">
    <n-tabs type="line" :value="tab" @update:value="changeTab"
      ><n-tab-pane name="tasks" tab="执行任务"
        ><n-data-table
          :columns="taskColumns"
          :data="tasks"
          :loading="busy"
          :bordered="false"
          :scroll-x="900" /></n-tab-pane
      ><n-tab-pane name="audit" tab="操作审计">
        <div class="page-stack">
          <div class="grid-2">
            <NFormItem label="开始时间"
              ><input v-model="filter.from" type="datetime-local"
            /></NFormItem>
            <NFormItem label="结束时间"
              ><input v-model="filter.until" type="datetime-local"
            /></NFormItem>
            <NFormItem label="操作者"
              ><NInput
                v-model:value="filter.principal"
                placeholder="精确匹配，留空为全部"
                :maxlength="128"
            /></NFormItem>
            <NFormItem label="操作"
              ><NSelect
                :value="filter.action || null"
                @update:value="filter.action = String($event ?? '')"
                :options="
                  Object.entries(auditActions).map(([value, label]) => ({
                    value,
                    label,
                  }))
                "
                filterable
                clearable
                tag
                placeholder="选择操作"
            /></NFormItem>
            <NFormItem label="执行结果"
              ><NSelect
                :value="filter.outcome || null"
                @update:value="filter.outcome = String($event ?? '')"
                :options="
                  Object.entries(auditOutcomes).map(([value, label]) => ({
                    value,
                    label,
                  }))
                "
                filterable
                clearable
                tag
                placeholder="选择结果"
            /></NFormItem>
          </div>
          <div class="toolbar">
            <NButton type="primary" :disabled="busy" @click="searchAudit"
              >查询</NButton
            >
            <NButton :disabled="busy" @click="exportAudit"
              >导出审计记录</NButton
            >
          </div>
          <p class="muted">
            导出当前查询范围内的操作记录；记录较多时，请缩小时间范围。
          </p>
          <NAlert v-if="audits?.notice" type="info">{{ audits.notice }}</NAlert>
          <n-data-table
            :columns="auditColumns"
            :data="audits?.rows ?? []"
            :bordered="false"
            :scroll-x="1000"
          /></div></n-tab-pane
    ></n-tabs>
    <div class="pagination">
      <NButton
        :disabled="busy || (tab === 'tasks' ? !offset : !auditPage)"
        @click="page(-1)"
        >上一页</NButton
      >
      <span class="muted"
        >第 {{ tab === "tasks" ? offset / 30 + 1 : auditPage + 1 }} 页</span
      >
      <NButton
        :disabled="
          busy || (tab === 'tasks' ? tasks.length < 30 : !audits?.more)
        "
        @click="page(1)"
        >下一页</NButton
      >
    </div>
  </section>
</template>
