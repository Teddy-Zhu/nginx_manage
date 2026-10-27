<route lang="json">
{
  "meta": {
    "title": "管理服务更新",
    "subtitle": "更新服务器管理服务",
    "nav": false,
    "order": 7.23,
    "symbol": "◇",
    "parent": "/settings"
  }
}
</route>
<script setup lang="ts">
import TaskLogButton from "../components/TaskLogButton.vue";
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { RouterLink } from "vue-router";
import {
  NAlert,
  NButton,
  NFormItem,
  NPopconfirm,
  NSelect,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  type AgentUpgradeTask,
  type ComponentTask,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const preparations = ref<ComponentTask[]>([]),
  tasks = ref<AgentUpgradeTask[]>([]),
  selected = ref(""),
  error = ref("");
const canWrite = computed(
  () =>
    !!session.me?.scopes.includes("components.manage") &&
    !!session.me?.scopes.includes("system.write"),
);
const prepared = computed(() =>
  preparations.value.filter(
    (t) =>
      t.action === "prepare" &&
      t.state === "succeeded" &&
      t.result?.runtime_ready &&
      t.result.panel &&
      !t.result.panel.requires_coordination &&
      t.result.release,
  ),
);
const chosen = computed(() =>
  prepared.value.find((t) => t.id === selected.value),
);
const active = computed(() =>
  tasks.value.some(
    (t) =>
      t.stage !== "restore_isolated" &&
      !["succeeded", "failed", "rolled_back", "cancelled"].includes(t.state),
  ),
);
const canCreate = computed(
  () => canWrite.value && !!chosen.value && !active.value && !busy.value,
);
const states: Record<string, string> = {
  queued: "排队中",
  running: "升级中",
  compensating: "恢复原版本",
  recovery_required: "待恢复",
  succeeded: "升级完成",
  failed: "升级未完成",
  rolled_back: "已恢复原版本",
  cancelled: "已取消",
};
const stages: Record<string, string> = {
  restore_isolated: "源任务已隔离",
  queued: "等待执行",
  authorized: "已批准升级",
  stopping: "停止原版本",
  stopped: "原版本已停止",
  selecting: "切换版本",
  selected: "版本已选择",
  starting: "启动并确认就绪",
  rollback_stopping: "停止升级进程",
  rollback_selecting: "选择原版本",
  rollback_starting: "启动并确认原版本",
  committed: "升级已提交",
  compensated: "原版本已恢复",
  agent_submit_pending: "提交升级",
  control_pending: "提交续办授权",
  maintenance_unconfirmed: "等待操作准备",
  epoch_changed: "需要重新授权",
  authorization_expired: "启动授权已过期",
  agent_unconfirmed: "等待独立事务确认",
  control_unconfirmed: "等待续办确认",
  control_rejected: "续办未受理",
  preflight_unconfirmed: "等待执行条件确认",
  preflight_rejected: "未通过执行条件检查",
  operation_missing: "独立记录待本机恢复",
  operation_mismatch: "独立记录待本机核对",
  intent_mismatch: "原升级意图待本机核对",
  control_mismatch: "续办记录待本机核对",
};
function date(value: number) {
  return new Date(value * 1000).toLocaleString();
}
function canResume(t: AgentUpgradeTask) {
  const result = t.result;
  return (
    canWrite.value &&
    !busy.value &&
    t.state === "recovery_required" &&
    ![
      "operation_missing",
      "operation_mismatch",
      "intent_mismatch",
      "control_mismatch",
      "restore_isolated",
    ].includes(t.stage) &&
    (result
      ? !result.active && !result.finalized && result.sequence < 32
      : ["epoch_changed", "maintenance_unconfirmed"].includes(t.stage))
  );
}
const reading = ref(false);
let controller: AbortController | null = null,
  closed = false;
async function load() {
  if (reading.value || closed) return;
  reading.value = true;
  controller = new AbortController();
  try {
    const [sources, items] = await Promise.all([
      api.componentTasks(controller.signal),
      api.agentUpgrades(controller.signal),
    ]);
    preparations.value = sources;
    tasks.value = items;
    error.value = "";
    if (!prepared.value.some((t) => t.id === selected.value))
      selected.value = prepared.value[0]?.id ?? "";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    reading.value = false;
  }
}
async function upgrade() {
  if (!canCreate.value) return;
  const input = {
    prepare_task_id: selected.value,
  };
  await run(async () => {
    const t = await api.createAgentUpgrade(input, keyFor(input));
    tasks.value = [t, ...tasks.value.filter((item) => item.id !== t.id)];
    keyFor = useIdempotency();
  }, "管理服务更新已开始");
  await load();
}
async function resume(t: AgentUpgradeTask) {
  if (!canResume(t)) return;
  await run(async () => {
    await api.resumeAgentUpgrade(
      t.id,
      keyFor({
        id: t.id,
        sequence: t.result?.sequence ?? 0,
        command: "resume",
      }),
    );
    keyFor = useIdempotency();
  }, "原升级续办请求已受理");
  await load();
}
onMounted(load);
onUnmounted(() => {
  closed = true;
  controller?.abort();
});
useLiveRefresh(api, ["tasks"], load, () => reading.value);
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>更新管理服务</h2>
        <NButton @click="load">刷新</NButton>
      </div>
      <p class="muted">
        请先在<RouterLink :to="{ path: '/components', query: {} }"
          >软件商店</RouterLink
        >下载所需版本，再开始更新。
      </p>
      <NAlert type="info"
        >升级期间宿主机管理操作暂时不可用。失败时恢复原版本。</NAlert
      >

      <NFormItem label="已准备版本"
        ><NSelect
          v-model:value="selected"
          :options="
            prepared.map((t) => ({
              label: `${t.result?.release?.version} · ${date(t.created_at)}`,
              value: t.id,
            }))
          "
          placeholder="选择已下载版本"
          :disabled="!canWrite || busy"
      /></NFormItem>
      <div v-if="canWrite">
        <NPopconfirm
          :disabled="!canCreate"
          positive-text="开始升级"
          @positive-click="upgrade"
          ><template #trigger
            ><NButton type="primary" :disabled="!canCreate" :loading="busy"
              >开始升级</NButton
            ></template
          >确认将管理服务更新到
          {{ chosen?.result?.release?.version }}？</NPopconfirm
        >
      </div>
    </section>
    <section class="panel page-stack">
      <h2>升级任务</h2>
      <p v-if="!tasks.length" class="muted">暂无升级任务</p>
      <article v-for="task in tasks" :key="task.id" class="panel page-stack">
        <TaskLogButton :task-id="task.id" />
        <div class="toolbar">
          <strong>{{ states[task.state] ?? "状态待确认" }}</strong
          ><NTag
            :type="
              task.state === 'succeeded'
                ? 'success'
                : ['failed', 'recovery_required'].includes(task.state)
                  ? 'warning'
                  : 'info'
            "
            >{{ stages[task.stage] ?? "正在处理" }}</NTag
          >
        </div>
        <p class="muted">{{ date(task.created_at) }}</p>
        <p v-if="task.result">
          目标版本 {{ task.result.target_version }} ·
          {{
            task.result.active
              ? "服务执行中"
              : task.result.finalized
                ? "操作已结束"
                : "服务未运行"
          }}
        </p>
        <NAlert
          v-if="task.error"
          :type="task.state === 'rolled_back' ? 'info' : 'warning'"
          >{{ task.error }}</NAlert
        >
        <div v-if="canResume(task)">
          <NPopconfirm positive-text="续办原升级" @positive-click="resume(task)"
            ><template #trigger
              ><NButton :loading="busy">续办原升级</NButton></template
            >确认继续此更新操作？系统将按原进度完成升级或恢复原版本。</NPopconfirm
          >
        </div>
      </article>
    </section>
  </div>
</template>
