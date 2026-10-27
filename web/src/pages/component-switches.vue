<route lang="json">
{
  "meta": {
    "title": "更新 Nginx",
    "subtitle": "更换版本或恢复上一版本",
    "nav": false,
    "order": 7.22,
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
import { RouterLink } from "vue-router";
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
  type ComponentOverview,
  type ComponentTask,
  type MaintenanceView,
  type NginxSwitchTask,
  type NginxRuntime,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();

const session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const overview = ref<ComponentOverview | null>(null),
  maintenance = ref<MaintenanceView | null>(null),
  preparations = ref<ComponentTask[]>([]),
  tasks = ref<NginxSwitchTask[]>([]),
  error = ref("");
const runtime = ref<NginxRuntime | null>(null);
const selected = ref(""),
  asset = ref(""),
  downtime = ref(false),
  clock = ref(Date.now());
const canWrite = computed(
  () =>
    session.me?.scopes.includes("system.write") &&
    session.me.scopes.includes("components.manage"),
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
      t.result.release &&
      t.result.release.expires_at * 1000 > clock.value,
  ),
);
const chosen = computed(() =>
  prepared.value.find((t) => t.id === selected.value),
);
const assets = computed(
  () =>
    chosen.value?.result?.release?.assets.filter(
      (a) =>
        a.component === "nginx" &&
        chosen.value?.result?.release?.selected.includes(a.id),
    ) ?? [],
);
const active = computed(() =>
  tasks.value.some(
    (t) =>
      t.stage !== "restore_isolated" &&
      !["succeeded", "failed", "rolled_back"].includes(t.state),
  ),
);
const canCreate = computed(
  () =>
    canWrite.value &&
    held.value &&
    overview.value?.switch_available &&
    overview.value.installation &&
    runtime.value?.available &&
    runtime.value.integrity &&
    runtime.value.running &&
    !runtime.value.external_change &&
    downtime.value &&
    chosen.value &&
    assets.value.some((a) => a.id === asset.value) &&
    !active.value &&
    !busy.value,
);
const labels: Record<string, string> = {
  queued: "等待执行",
  running: "执行中",
  succeeded: "完成",
  failed: "失败",
  rolled_back: "已恢复原组件",
  compensating: "正在恢复原组件",
  recovery_required: "待恢复",
};
const stages: Record<string, string> = {
  queued: "等待执行",
  validating: "检查切换条件",
  validated: "切换条件已确认",
  stopping_agent: "准备切换",
  stopping_nginx: "停止原组件",
  binding: "选择新组件",
  starting_nginx: "启动新组件",
  confirming_nginx: "确认代理运行",
  starting_agent: "恢复管理服务",
  confirming_agent: "确认管理状态",
  committed: "切换完成",
  rollback_stopping_agent: "准备恢复原组件",
  rollback_stopping_nginx: "停止候选组件",
  rollback_binding: "选择原组件",
  rollback_starting_nginx: "启动原组件",
  rollback_confirming_nginx: "确认原组件运行",
  rollback_starting_agent: "恢复管理服务",
  rollback_confirming_agent: "确认恢复结果",
  rollback_confirmed: "原组件已恢复",
  cancelled_before_switch: "已取消切换",
  control_pending: "等待控制确认",
  authorization_expired: "授权已过期",
  maintenance_unconfirmed: "等待维护确认",
  agent_unconfirmed: "状态未确认",
  operation_missing: "独立记录缺失",
  control_rejected: "控制操作未执行",
  preflight_rejected: "切换条件不满足",
  restore_isolated: "源任务已隔离",
};
function date(n: number) {
  return new Date(n * 1000).toLocaleString();
}
function canControl(t: NginxSwitchTask) {
  return !!(
    canWrite.value &&
    held.value &&
    maintenance.value?.agent.id === t.input.maintenance_id &&
    !busy.value &&
    t.state === "recovery_required" &&
    t.stage !== "restore_isolated" &&
    t.result &&
    !t.result.active &&
    t.sequence < 32 &&
    t.result.sequence <= t.sequence &&
    (t.result.sequence === t.sequence ||
      ["control_rejected", "authorization_expired"].includes(t.stage))
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
    const [source, preparedTasks, items, view, running] = await Promise.all([
      api.components(controller.signal),
      api.componentTasks(controller.signal),
      api.nginxSwitches(controller.signal),
      canWrite.value
        ? api.maintenance(controller.signal)
        : Promise.resolve(null),
      api.nginxRuntime(controller.signal),
    ]);
    overview.value = source;
    runtime.value = running;
    preparations.value = preparedTasks;
    tasks.value = items;
    maintenance.value = view;
    error.value = "";
    if (!prepared.value.some((t) => t.id === selected.value))
      selected.value = prepared.value[0]?.id ?? "";
    if (!assets.value.some((a) => a.id === asset.value))
      asset.value = assets.value[0]?.id ?? "";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    reading.value = false;
  }
}
function choose(id: string) {
  selected.value = id;
  asset.value = assets.value[0]?.id ?? "";
}
async function switchComponent() {
  if (
    !canCreate.value ||
    !maintenance.value ||
    !runtime.value ||
    !overview.value?.installation
  )
    return;
  const input = {
    maintenance_id: maintenance.value.agent.id,
    prepare_task_id: selected.value,
    asset_id: asset.value,
    allow_downtime: downtime.value,
    expected_sha256: overview.value.installation.sha256,
    expected_revision: runtime.value.revision_id,
    expected_deployment: runtime.value.deployment_id,
  };
  await run(async () => {
    const t = await api.createNginxSwitch(input, keyFor(input));
    tasks.value = [t, ...tasks.value.filter((v) => v.id !== t.id)];
    keyFor = useIdempotency();
  }, "切换组件任务已受理");
  await load();
}
async function control(t: NginxSwitchTask, command: "resume" | "rollback") {
  if (!canControl(t)) return;
  await run(async () => {
    await api.controlNginxSwitch(
      t.id,
      command,
      keyFor({ id: t.id, sequence: t.sequence, command }),
    );
    keyFor = useIdempotency();
  }, "原切换控制请求已受理");
  await load();
}
let clockTimer: ReturnType<typeof setInterval> | undefined;
onMounted(() => {
  void load();
  clockTimer = setInterval(() => {
    clock.value = Date.now();
  }, 1000);
});
onUnmounted(() => {
  closed = true;
  if (clockTimer) clearInterval(clockTimer);
  controller?.abort();
});
useLiveRefresh(api, ["tasks", "maintenance"], load, () => reading.value);
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>切换 Nginx 版本</h2>
        <NButton @click="load">刷新</NButton>
      </div>
      <NAlert v-if="overview && !overview.switch_available" type="info">{{
        overview.switch_reason
      }}</NAlert>
      <p>
        选择已准备的 Nginx 组件，切换前须先进入<RouterLink to="/maintenance"
          >维护模式</RouterLink
        >。切换期间代理流量会短暂中断。
      </p>
      <p v-if="overview?.installation">
        当前版本：{{ overview.installation.version }} ·
        {{ runtime?.running ? "运行中" : "运行未确认" }}
      </p>
      <NAlert v-if="canWrite && !held" type="warning"
        >尚未进入维护模式，请先确认维护状态。</NAlert
      >
      <div v-if="canWrite" class="grid-2">
        <NFormItem label="已下载版本"
          ><NSelect
            :value="selected"
            :options="
              prepared.map((t) => ({
                label: `${t.result?.release?.version} · ${date(t.created_at)}`,
                value: t.id,
              }))
            "
            @update:value="choose"
        /></NFormItem>
        <NFormItem label="Nginx 版本"
          ><NSelect
            v-model:value="asset"
            :options="
              assets.map((a) => ({
                label: a.version,
                value: a.id,
              }))
            "
        /></NFormItem>
        <NCheckbox v-model:checked="downtime">允许切换期间短暂停机</NCheckbox>
      </div>
      <p v-if="!prepared.length" class="muted">
        暂无有效准备结果，请先完成<RouterLink to="/components"
          >软件商店</RouterLink
        >。
      </p>
      <div v-if="canWrite" class="toolbar">
        <NPopconfirm @positive-click="switchComponent"
          ><template #trigger
            ><NButton type="primary" :disabled="!canCreate" :loading="busy"
              >切换组件</NButton
            ></template
          >确认切换至所选 Nginx 组件？切换期间代理流量会短暂中断。</NPopconfirm
        >
      </div>
    </section>
    <section class="panel page-stack">
      <h2>切换任务</h2>
      <p v-if="!tasks.length" class="muted">暂无切换任务</p>
      <article v-for="t in tasks" :key="t.id" class="page-stack">
        <TaskLogButton :task-id="t.id" />
        <div class="toolbar">
          <h3>Nginx 更新</h3>
          <NTag
            :type="
              t.state === 'succeeded'
                ? 'success'
                : t.state === 'recovery_required' || t.state === 'failed'
                  ? 'warning'
                  : 'default'
            "
            >{{ labels[t.state] ?? "状态未确认" }}</NTag
          >
        </div>
        <p>
          {{ stages[t.stage] ?? "等待结果确认" }} · {{ date(t.updated_at) }} ·
          Nginx 版本切换
        </p>
        <p v-if="t.result?.candidate">
          原版本：{{ t.result.before?.version }} · 候选版本：{{
            t.result.candidate.version
          }}
          ·
          {{ t.result.confirmation ? "运行已确认" : "运行未确认" }}
        </p>
        <NAlert v-if="t.error" type="warning">{{ t.error }}</NAlert>
        <div v-if="canControl(t)" class="toolbar">
          <NPopconfirm @positive-click="control(t, 'resume')"
            ><template #trigger
              ><NButton :disabled="busy">续办原切换</NButton></template
            >确认继续原切换任务？已进入补偿的任务将继续恢复原组件。</NPopconfirm
          >
          <NPopconfirm @positive-click="control(t, 'rollback')"
            ><template #trigger
              ><NButton :disabled="busy">恢复原组件</NButton></template
            >确认恢复原组件？尚未开始切换时将结束原任务。</NPopconfirm
          >
        </div>
      </article>
    </section>
  </div>
</template>
