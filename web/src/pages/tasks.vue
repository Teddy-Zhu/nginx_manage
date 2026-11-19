<route lang="json">
{
  "meta": {
    "title": "操作记录",
    "nav": true,
    "order": 42,
    "symbol": "☷",
    "group": "系统管理"
  }
}
</route>

<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { ref, reactive, onMounted } from "vue";
import {
  NButton,
  NDataTable,
  NTabs,
  NFormItem,
  NInput,
  NSelect,
  NTabPane,
  NAlert,
  NEmpty,
  NSpin,
  NTag,
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
import { taskKinds, taskStates, taskStageSummary, taskStateLabel, taskStateTone } from "../utils/tasks";
const api = useNodeAPI();
const { request } = api;

const pageSize = 30;
const { run, busy } = useAction(),
  tasks = ref<Task[]>([]);
const audits = ref<AuditPage | null>(null),
  offset = ref(0),
  tab = ref("tasks");
const tasksError = ref("");
const moreTasks = ref(false);
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
async function loadTasks(nextOffset = offset.value) {
  await run(async () => {
    try {
      const result = await request<Task[]>({
        url: "/tasks",
        params: { offset: nextOffset, limit: pageSize + 1 },
      });
      tasks.value = result.slice(0, pageSize);
      moreTasks.value = result.length > pageSize;
      offset.value = nextOffset;
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
    await loadTasks(Math.max(0, offset.value + delta * pageSize));
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
onMounted(() => loadTasks());
useLiveRefresh(api, ["tasks"], loadTasks, () => busy.value || tab.value !== "tasks");
</script>
<template>
  <section class="surface operation-records">
    <n-tabs type="line" :value="tab" @update:value="changeTab">
      <template #suffix>
        <NButton size="small" :loading="busy" @click="load">
          刷新
        </NButton>
      </template>
      <n-tab-pane name="tasks" tab="任务">
        <NAlert v-if="tasksError" type="error">
          {{ tasksError }}
        </NAlert>
        <NSpin :show="busy && !tasks.length">
          <ul v-if="tasks.length" class="task-list">
            <li v-for="task in tasks" :key="task.id" class="task-row">
              <div class="task-description">
                <strong>{{ taskKinds[task.kind] ?? "后台任务" }}</strong>
                <span v-if="task.last_error || taskStageSummary(task.stage, task.kind, task.state)" class="task-detail">
                  {{ task.last_error || taskStageSummary(task.stage, task.kind, task.state) }}
                </span>
              </div>
              <NTag size="small" :type="taskStateTone(task.state)" :bordered="false">
                {{ taskStateLabel(task.state) }}
              </NTag>
              <time class="task-time" :datetime="new Date(task.created_at * 1000).toISOString()">
                {{ new Date(task.created_at * 1000).toLocaleString() }}
              </time>
              <TaskLogButton
                :task-id="task.id"
                :title="taskKinds[task.kind] ?? '任务详情'"
                label="详情"
              />
            </li>
          </ul>
          <NEmpty v-else-if="!tasksError" class="empty-records" description="暂无任务" />
        </NSpin>
      </n-tab-pane>
      <n-tab-pane name="audit" tab="审计记录">
        <div class="page-stack">
          <div class="grid-2">
            <NFormItem label="开始时间">
              <input v-model="filter.from" type="datetime-local" />
            </NFormItem>
            <NFormItem label="结束时间">
              <input v-model="filter.until" type="datetime-local" />
            </NFormItem>
            <NFormItem label="操作者">
              <NInput
                v-model:value="filter.principal"
                placeholder="精确匹配，留空为全部"
                :maxlength="128"
              />
            </NFormItem>
            <NFormItem label="操作">
              <NSelect
                :value="filter.action || null"
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
                @update:value="filter.action = String($event ?? '')"
              />
            </NFormItem>
            <NFormItem label="执行结果">
              <NSelect
                :value="filter.outcome || null"
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
                @update:value="filter.outcome = String($event ?? '')"
              />
            </NFormItem>
          </div>
          <div class="toolbar">
            <NButton type="primary" :disabled="busy" @click="searchAudit">
              查询
            </NButton>
            <NButton :disabled="busy" @click="exportAudit">
              导出审计记录
            </NButton>
          </div>
          <NAlert v-if="audits?.notice" type="info">
            {{ audits.notice }}
          </NAlert>
          <n-data-table
            :columns="auditColumns"
            :data="audits?.rows ?? []"
            :bordered="false"
            :scroll-x="1000"
          />
        </div>
      </n-tab-pane>
    </n-tabs>
    <div class="pagination">
      <NButton
        :disabled="busy || (tab === 'tasks' ? !offset : !auditPage)"
        @click="page(-1)"
      >
        上一页
      </NButton>
      <span class="muted">第 {{ tab === "tasks" ? offset / pageSize + 1 : auditPage + 1 }} 页</span>
      <NButton
        :disabled="
          busy || (tab === 'tasks' ? !moreTasks : !audits?.more)
        "
        @click="page(1)"
      >
        下一页
      </NButton>
    </div>
  </section>
</template>

<style scoped>
.task-list {
  margin: 0;
  padding: 0;
  list-style: none;
}
.task-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 92px minmax(145px, auto) auto;
  align-items: center;
  gap: 16px;
  padding: 14px 2px;
  border-bottom: 1px solid var(--border-color);
}
.task-row > * {
  justify-self: start;
  min-width: 0;
}
.task-description {
  display: grid;
  gap: 4px;
}
.task-detail {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.task-detail,
.task-time {
  color: var(--text-muted);
  font-size: 13px;
}
.task-time {
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}
.empty-records {
  padding: 36px 0;
}
@media (max-width: 680px) {
  .task-row {
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 6px 12px;
  }
  .task-row > :nth-child(even) {
    justify-self: end;
  }
}
</style>
