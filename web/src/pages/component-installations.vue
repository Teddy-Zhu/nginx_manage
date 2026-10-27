<route lang="json">
{
  "meta": {
    "title": "安装 Nginx",
    "subtitle": "安装进度与软件设置",
    "nav": false,
    "order": 7.21,
    "symbol": "◇",
    "parent": "/components"
  }
}
</route>
<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { RouterLink, useRoute } from "vue-router";
import TaskLogButton from "../components/TaskLogButton.vue";
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
  type NginxInstallTask,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI(),
  route = useRoute();
const session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const overview = ref<ComponentOverview | null>(null),
  preparations = ref<ComponentTask[]>([]),
  tasks = ref<NginxInstallTask[]>([]),
  error = ref("");
const selected = ref(
    typeof route.query.prepare === "string" ? route.query.prepare : "",
  ),
  asset = ref(""),
  start = ref(true),
  enable = ref(true),
  clock = ref(Date.now());
const canWrite = computed(
  () =>
    session.me?.scopes.includes("system.write") &&
    session.me.scopes.includes("components.manage"),
);
const prepared = computed(() =>
  preparations.value.filter(
    (t) =>
      t.action === "prepare" &&
      t.state === "succeeded" &&
      t.result?.runtime_ready &&
      t.result.release?.assets.some(
        (item) =>
          item.component === "nginx" &&
          t.result!.release!.selected.includes(item.id),
      ) &&
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
  running: "运行中",
  cancelled_before_binding: "已取消安装",
  control_pending: "等待控制确认",
  authorization_expired: "授权已过期",
  maintenance_unconfirmed: "等待操作准备",
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
  reading = ref(false),
  closed = false;
async function load() {
  if (reading.value || closed) return;
  reading.value = true;
  controller = new AbortController();
  try {
    const [source, preparedTasks, items] = await Promise.all([
      api.components(controller.signal),
      api.componentTasks(controller.signal),
      api.nginxInstallations(controller.signal),
    ]);
    overview.value = source;
    preparations.value = preparedTasks;
    tasks.value = items;
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
watch(
  () => route.query.prepare,
  (id) => choose(typeof id === "string" ? id : ""),
);
async function install() {
  if (!canCreate.value) return;
  const input = {
    prepare_task_id: selected.value,
    asset_id: asset.value,
    start: start.value,
    enable: enable.value,
  };
  await run(async () => {
    const task = await api.createNginxInstallation(input, keyFor(input));
    tasks.value = [task, ...tasks.value.filter((item) => item.id !== task.id)];
    keyFor = useIdempotency();
  }, "已开始安装 Nginx");
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
    }, 1000);
});
onUnmounted(() => {
  closed = true;
  controller?.abort();
  if (timer) clearInterval(timer);
});
useLiveRefresh(api, ["tasks", "software"], load, () => reading.value);
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>安装 Nginx</h2>
        <NButton @click="load">刷新</NButton>
      </div>
      <NAlert v-if="overview?.installation" type="success"
        >Nginx 已安装。<RouterLink to="/nginx"
          >管理网站与代理</RouterLink
        ></NAlert
      >
      <NAlert
        v-else-if="overview && !overview.install_available"
        type="warning"
        title="当前无法安装"
        >请检查软件安装条件。</NAlert
      >
      <div v-if="canWrite" class="grid-2">
        <NFormItem label="安装版本"
          ><NSelect
            :value="selected"
            :disabled="active"
            :options="
              prepared.map((t) => ({
                label: t.result?.release?.tag ?? '已下载版本',
                value: t.id,
              }))
            "
            @update:value="choose"
        /></NFormItem>
        <NFormItem v-if="assets.length > 1" label="安装版本"
          ><NSelect
            v-model:value="asset"
            :disabled="active"
            :options="
              assets.map((a) => ({
                label: a.version,
                value: a.id,
              }))
            "
        /></NFormItem>
        <section>
          <NCheckbox v-model:checked="enable" :disabled="active"
            >开机启动</NCheckbox
          ><NCheckbox v-model:checked="start" :disabled="active"
            >安装后立即启动</NCheckbox
          >
        </section>
      </div>
      <p v-if="!prepared.length" class="muted">
        请先前往<RouterLink
          :to="{ path: '/components', query: { software: 'nginx' } }"
          >软件商店下载安装包</RouterLink
        >。
      </p>
      <div v-if="canWrite" class="toolbar">
        <NPopconfirm @positive-click="install"
          ><template #trigger
            ><NButton type="primary" :disabled="!canCreate" :loading="busy"
              >开始安装</NButton
            ></template
          >确认安装 Nginx？</NPopconfirm
        >
      </div>
    </section>
    <section class="panel page-stack">
      <h2>安装记录</h2>
      <p v-if="!tasks.length" class="muted">暂无安装任务</p>
      <article v-for="t in tasks" :key="t.id" class="page-stack">
        <div class="toolbar">
          <h3>Nginx 安装</h3>
          <TaskLogButton :task-id="t.id" title="Nginx 安装日志" />
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
          {{ t.input.start ? "安装后启动" : "仅安装"
          }}{{ t.input.enable ? " · 开机启动" : "" }}
        </p>
        <p v-if="t.result?.installation">
          版本：{{ t.result.installation.version }} ·
          {{ t.result.running ? "运行中" : "未运行" }}
        </p>
        <NAlert v-if="t.error" type="warning">{{ t.error }}</NAlert>
        <div v-if="canControl(t)" class="toolbar">
          <NPopconfirm @positive-click="control(t, 'resume')"
            ><template #trigger
              ><NButton :disabled="busy">继续安装</NButton></template
            >确认继续上次安装？</NPopconfirm
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
