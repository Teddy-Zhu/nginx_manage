<route lang="json">
{
  "meta": {
    "title": "更新 Nginx",
    "subtitle": "更换版本或恢复上一版本",
    "nav": false,
    "order": 7.25,
    "symbol": "◇",
    "parent": "/components",
    "software": "nginx"
  }
}
</route>
<script setup lang="ts">
import TaskLogButton from "../components/TaskLogButton.vue";
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { RouterLink, useRoute } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NPopconfirm,
  NSelect,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  type ImageUpgradeTask,
  type ComponentTask,
  type MaintenanceView,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(),
  route = useRoute(),
  session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const allowDowntime = ref(false);
const preparations = ref<ComponentTask[]>([]),
  tasks = ref<ImageUpgradeTask[]>([]),
  maintenance = ref<MaintenanceView | null>(null),
  selected = ref(
    typeof route.query.prepare === "string" ? route.query.prepare : "",
  ),
  error = ref("");
const canWrite = computed(
  () =>
    !!session.me?.scopes.includes("components.manage") &&
    !!session.me?.scopes.includes("system.write"),
);
const held = computed(
  () =>
    maintenance.value?.phase === "held" &&
    maintenance.value.agent.phase === "held" &&
    maintenance.value.agent.id === maintenance.value.session?.task_id &&
    maintenance.value.agent.epoch === maintenance.value.session?.root_epoch,
);
const prepared = computed(() =>
  preparations.value.filter(
    (t) =>
      t.action === "prepare" &&
      t.state === "succeeded" &&
      t.result?.runtime_ready &&
      t.result.panel &&
      !t.result.panel.requires_coordination &&
      t.result.release?.images?.some((image) => image.id === "nginx"),
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
  () =>
    canWrite.value &&
    held.value &&
    !!chosen.value &&
    !active.value &&
    allowDowntime.value &&
    !busy.value,
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
  queued: "等待受理",
  control_pending: "等待续办",
  agent_submit_pending: "正在提交",
  authorized: "已授权",
  check_creating: "准备配置校验",
  checking: "校验完整配置",
  check_removing: "清理校验环境",
  stopping_agent: "暂停后台服务",
  stopping: "停止原容器",
  removing: "移除原容器",
  selecting: "切换镜像",
  creating: "创建新容器",
  starting: "启动新容器",
  confirming_nginx: "确认 Nginx",
  starting_agent: "启动后台服务",
  confirming_agent: "检查后台服务",
  committed: "镜像替换完成",
  rollback_stopping_agent: "准备恢复",
  rollback_stopping: "停止候选容器",
  rollback_selecting: "恢复原镜像",
  rollback_creating: "创建原镜像容器",
  rollback_starting: "启动原镜像容器",
  rollback_confirming_nginx: "确认原 Nginx",
  rollback_starting_agent: "恢复后台服务",
  rollback_confirming_agent: "确认恢复结果",
  compensated: "原镜像已恢复",
  rejected: "校验未通过",
  authorization_expired: "授权已过期",
  maintenance_unconfirmed: "等待维护确认",
  epoch_changed: "维护授权已变化",
  agent_unconfirmed: "执行状态待确认",
  operation_missing: "原记录缺失",
  operation_mismatch: "回执不一致",
  intent_mismatch: "原意图不一致",
  control_mismatch: "续办授权不一致",
  control_unconfirmed: "续办状态待确认",
  control_rejected: "续办未受理",
  preflight_rejected: "准入未通过",
  preflight_unconfirmed: "准入状态待确认",
  restore_isolated: "备份来源任务已隔离",
};
function date(value: number) {
  return new Date(value * 1000).toLocaleString();
}
function canResume(t: ImageUpgradeTask) {
  const result = t.result;
  return (
    canWrite.value &&
    held.value &&
    maintenance.value?.agent.id === t.input.maintenance_id &&
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
    const [sources, items, view] = await Promise.all([
      api.componentTasks(controller.signal),
      api.nginxImageUpgrades(controller.signal),
      canWrite.value
        ? api.maintenance(controller.signal)
        : Promise.resolve(null),
    ]);
    preparations.value = sources;
    tasks.value = items;
    maintenance.value = view;
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
  if (!canCreate.value || !maintenance.value) return;
  const input = {
    maintenance_id: maintenance.value.agent.id,
    prepare_task_id: selected.value,
    allow_downtime: true as const,
  };
  await run(async () => {
    const t = await api.createNginxImageUpgrade(input, keyFor(input));
    tasks.value = [t, ...tasks.value.filter((item) => item.id !== t.id)];
    keyFor = useIdempotency();
  }, "Nginx 镜像替换任务已受理");
  await load();
}
async function resume(t: ImageUpgradeTask) {
  if (!canResume(t)) return;
  await run(async () => {
    await api.resumeNginxImageUpgrade(
      t.id,
      keyFor({
        id: t.id,
        sequence: t.result?.sequence ?? 0,
        command: "resume",
      }),
    );
    keyFor = useIdempotency();
  }, "原镜像替换续办请求已受理");
  await load();
}
onMounted(() => {
  void load();
});
onUnmounted(() => {
  closed = true;
  controller?.abort();
});
useLiveRefresh(api, ["tasks", "maintenance"], load, () => reading.value);
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>更新 Nginx</h2>
        <NButton @click="load">刷新</NButton>
      </div>
      <p>
        在<RouterLink to="/components">软件商店</RouterLink
        >完成目标发行版的面板准备与镜像拉取，再在<RouterLink to="/maintenance"
          >维护模式</RouterLink
        >进入维护后更新 Nginx。
      </p>
      <NAlert type="info"
        >更新期间网站服务会短暂中断，失败时将尝试恢复原版本。</NAlert
      >
      <p class="muted">更新前请确保已下载所选版本。网站配置与证书会保留。</p>
      <NAlert v-if="canWrite && !held" type="warning"
        >尚未进入维护模式，请先确认维护状态。</NAlert
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
      <NCheckbox
        v-if="canWrite"
        v-model:checked="allowDowntime"
        :disabled="busy"
        >允许 Nginx 服务短暂中断</NCheckbox
      >
      <div v-if="canWrite">
        <NPopconfirm
          :disabled="!canCreate"
          positive-text="更换镜像"
          @positive-click="upgrade"
          ><template #trigger
            ><NButton type="primary" :disabled="!canCreate" :loading="busy"
              >更换镜像</NButton
            ></template
          >确认更换为版本 {{ chosen?.result?.release?.version }}？</NPopconfirm
        >
      </div>
    </section>
    <section class="panel page-stack">
      <h2>替换任务</h2>
      <p v-if="!tasks.length" class="muted">暂无替换任务</p>
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
        <p v-if="task.result?.finalized">
          更新已结束，可前往<RouterLink to="/maintenance">维护模式</RouterLink
          >结束维护。
        </p>
        <div v-if="canResume(task)">
          <NPopconfirm positive-text="继续更换版本" @positive-click="resume(task)"
            ><template #trigger
              ><NButton :loading="busy">继续更换版本</NButton></template
            >确认继续更换版本？系统会继续完成操作，失败时恢复原版本。</NPopconfirm
          >
        </div>
      </article>
    </section>
  </div>
</template>
