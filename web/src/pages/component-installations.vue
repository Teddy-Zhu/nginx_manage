<route lang="json">
{
  "meta": {
    "title": "组件安装",
    "subtitle": "原生 Nginx 首次安装与恢复",
    "nav": true,
    "order": 7.21,
    "symbol": "◇"
  }
}
</route>
<script setup lang="ts">
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
  type NginxInstallTask,
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
  tasks = ref<NginxInstallTask[]>([]),
  error = ref("");
const selected = ref(""),
  asset = ref(""),
  start = ref(false),
  enable = ref(false),
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
    (t) => !["succeeded", "failed", "cancelled"].includes(t.state),
  ),
);
const canCreate = computed(
  () =>
    canWrite.value &&
    held.value &&
    overview.value?.install_available &&
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
  cancelled: "已取消",
  recovery_required: "待恢复",
};
const stages: Record<string, string> = {
  queued: "等待执行",
  validating: "检查安装条件",
  initializing: "准备初始配置",
  binding: "登记安装",
  enabling: "设置开机启动",
  starting: "启动服务",
  restarting_agent: "接入管理",
  confirming: "确认安装",
  installed: "安装完成",
  running: "运行已确认",
  cancelled_before_binding: "已取消安装",
  control_pending: "等待控制确认",
  authorization_expired: "授权已过期",
  maintenance_unconfirmed: "等待维护确认",
  agent_unconfirmed: "状态未确认",
  operation_missing: "独立记录缺失",
  control_rejected: "控制操作未执行",
  preflight_rejected: "安装条件不满足",
};
function date(n: number) {
  return new Date(n * 1000).toLocaleString();
}
function canControl(t: NginxInstallTask) {
  return !!(
    canWrite.value &&
    held.value &&
    maintenance.value?.agent.id === t.input.maintenance_id &&
    !busy.value &&
    t.state === "recovery_required" &&
    t.result &&
    !t.result.active &&
    t.sequence < 32 &&
    t.result.sequence <= t.sequence &&
    (t.result.sequence === t.sequence ||
      ["control_rejected", "authorization_expired"].includes(t.stage))
  );
}
let controller: AbortController | null = null,
  timer: ReturnType<typeof setInterval> | undefined,
  reading = false,
  closed = false;
async function load() {
  if (reading || closed) return;
  reading = true;
  controller = new AbortController();
  try {
    const [source, preparedTasks, items, view] = await Promise.all([
      api.components(controller.signal),
      api.componentTasks(controller.signal),
      api.nginxInstallations(controller.signal),
      canWrite.value
        ? api.maintenance(controller.signal)
        : Promise.resolve(null),
    ]);
    overview.value = source;
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
    reading = false;
  }
}
function choose(id: string) {
  selected.value = id;
  asset.value = assets.value[0]?.id ?? "";
}
async function install() {
  if (!canCreate.value || !maintenance.value) return;
  const input = {
    maintenance_id: maintenance.value.agent.id,
    prepare_task_id: selected.value,
    asset_id: asset.value,
    start: start.value,
    enable: enable.value,
  };
  await run(async () => {
    const t = await api.createNginxInstallation(input, keyFor(input));
    tasks.value = [t, ...tasks.value.filter((v) => v.id !== t.id)];
    keyFor = useIdempotency();
  }, "首次安装任务已受理");
  await load();
}
async function control(t: NginxInstallTask, command: "resume" | "cancel") {
  if (!canControl(t)) return;
  await run(async () => {
    await api.controlNginxInstallation(
      t.id,
      command,
      keyFor({ id: t.id, sequence: t.sequence, command }),
    );
    keyFor = useIdempotency();
  }, "原安装控制请求已受理");
  await load();
}
onMounted(async () => {
  await load();
  if (!closed)
    timer = setInterval(() => {
      clock.value = Date.now();
      if (active.value || maintenance.value?.phase !== "open") void load();
    }, 3000);
});
onUnmounted(() => {
  closed = true;
  controller?.abort();
  if (timer) clearInterval(timer);
});
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>首次安装 Nginx</h2>
        <NButton @click="load">刷新</NButton>
      </div>
      <NAlert v-if="overview && !overview.install_available" type="info">{{
        overview.install_reason
      }}</NAlert>
      <p>
        选择已准备的签名组件，并在<RouterLink to="/maintenance"
          >配置维护</RouterLink
        >进入维护后安装。安装完成后可继续导入和应用业务配置。
      </p>
      <NAlert v-if="canWrite && !held" type="warning"
        >尚未进入配置维护，请先确认维护状态。</NAlert
      >
      <div v-if="canWrite" class="grid-2">
        <NFormItem label="已准备组件"
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
        <NFormItem label="Nginx 资产"
          ><NSelect
            v-model:value="asset"
            :options="
              assets.map((a) => ({
                label: `${a.version} · ${a.id}`,
                value: a.id,
              }))
            "
        /></NFormItem>
        <NCheckbox v-model:checked="enable">设置开机启动</NCheckbox
        ><NCheckbox v-model:checked="start">立即启动专用 Nginx</NCheckbox>
      </div>
      <p v-if="!prepared.length" class="muted">
        暂无有效准备结果，请先完成<RouterLink to="/components"
          >组件准备</RouterLink
        >。
      </p>
      <div v-if="canWrite" class="toolbar">
        <NPopconfirm @positive-click="install"
          ><template #trigger
            ><NButton type="primary" :disabled="!canCreate" :loading="busy"
              >首次安装</NButton
            ></template
          >确认安装所选 Nginx 组件？</NPopconfirm
        >
      </div>
    </section>
    <section class="panel page-stack">
      <h2>安装任务</h2>
      <p v-if="!tasks.length" class="muted">暂无安装任务</p>
      <article v-for="t in tasks" :key="t.id" class="page-stack">
        <div class="toolbar">
          <h3>{{ t.input.asset_id }}</h3>
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
          {{ t.input.start ? "请求立即启动" : "仅安装"
          }}{{ t.input.enable ? " · 开机启动" : "" }}
        </p>
        <p v-if="t.result?.installation">
          版本：{{ t.result.installation.version }} ·
          {{ t.result.running ? "运行已确认" : "运行未确认" }}
        </p>
        <NAlert v-if="t.error" type="warning">{{ t.error }}</NAlert>
        <div v-if="canControl(t)" class="toolbar">
          <NPopconfirm @positive-click="control(t, 'resume')"
            ><template #trigger
              ><NButton :disabled="busy">续办原安装</NButton></template
            >确认按原资产和选项续办安装？</NPopconfirm
          >
          <NPopconfirm @positive-click="control(t, 'cancel')"
            ><template #trigger
              ><NButton :disabled="busy">取消安装</NButton></template
            >确认取消原安装？已完成安装登记时无法取消，已有初始配置会保留。</NPopconfirm
          >
        </div>
      </article>
    </section>
  </div>
</template>
