<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton, NFormItem, NPopconfirm, NSelect } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentTask,
  type Fail2banLifecycleInput,
  type Fail2banLifecyclePlan,
  type Fail2banLifecyclePreviewInput,
  type Fail2banLifecycleTaskStatus,
  type Fail2banManaged,
  type Fail2banService,
} from "../api/client";
import { useSession } from "../stores/session";

const props = defineProps<{
  moduleEnabled: boolean;
  managed: Fail2banManaged | null;
  service: Fail2banService | null;
  observedAt: number;
}>();
const emit = defineEmits<{ changed: [] }>();
const api = useNodeAPI(),
  session = useSession(),
  controller = new AbortController();
type Action = Fail2banLifecyclePreviewInput["action"];
const names: Record<Action, string> = {
  install: "安装独立实例",
  resume: "续办原安装",
  rollback: "撤回独立实例",
  start: "启动服务",
  stop: "停止服务",
  enable: "开机启用",
  disable: "取消开机启用",
};
const states: Record<string, string> = {
  queued: "排队中",
  running: "处理中",
  compensating: "恢复中",
  recovery_required: "等待恢复确认",
  succeeded: "目标状态已确认",
  failed: "未完成",
  cancelled: "已取消",
};
const managedStates: Record<string, string> = {
  absent: "未登记",
  unavailable: "未知",
  reserved: "待安装",
  ready: "已准备",
  installed: "已登记",
  interrupted: "安装未完成",
  "rolling-back": "撤回中",
  "rolled-back": "已撤回",
};
const activeStates = new Set([
  "queued",
  "running",
  "compensating",
  "recovery_required",
]);
const action = ref<Action | null>(null),
  selected = ref("");
const preparations = ref<ComponentTask[]>([]),
  tasks = ref<Fail2banLifecycleTaskStatus[]>([]);
const plan = ref<Fail2banLifecyclePlan | null>(null),
  pending = ref<{ input: Fail2banLifecycleInput; key: string } | null>(null);
const busy = ref(false),
  reading = ref(false),
  loaded = ref(false),
  assetsReading = ref(false);
const error = ref(""),
  historyError = ref(""),
  assetsError = ref(""),
  notice = ref("");
const clock = ref(Date.now());
const active = computed(() =>
  tasks.value.some((task) => activeStates.has(task.state)),
);
function permitted(value: Action) {
  const scopes = session.me?.scopes ?? [];
  return (
    (value === "install" || value === "resume" || value === "rollback"
      ? scopes.includes("components.manage")
      : true) &&
    (value !== "install" ? scopes.includes("security.write") : true)
  );
}
const options = computed(() =>
  Object.entries(names)
    .filter(([value]) => permitted(value as Action))
    .map(([value, label]) => ({ value, label })),
);
const assets = computed(() =>
  preparations.value.flatMap((task) => {
    const release = task.result?.release;
    if (
      task.action !== "prepare" ||
      task.state !== "succeeded" ||
      !task.result?.runtime_ready ||
      !release ||
      release.selected.length !== 1 ||
      release.expires_at * 1000 <= clock.value
    )
      return [];
    return release.assets
      .filter(
        (asset) =>
          asset.component === "fail2ban" && release.selected.includes(asset.id),
      )
      .map((asset) => ({
        value: task.id,
        label: `${release.tag} · ${asset.id}`,
        task,
        asset,
      }));
  }),
);
const chosen = computed(() =>
  assets.value.find((item) => item.value === selected.value),
);
const latest = computed(
  () =>
    tasks.value.find(
      (task) => task.result && task.result.at >= props.observedAt,
    )?.result ?? null,
);
const currentManaged = computed(() => latest.value?.managed ?? props.managed);
const currentService = computed(() => latest.value?.service ?? props.service);
const currentAt = computed(() => latest.value?.at ?? props.observedAt);
const needsEnabled = computed(
  () =>
    !!plan.value &&
    (plan.value.input.action === "start" ||
      plan.value.input.action === "enable" ||
      plan.value.input.start ||
      plan.value.input.enable),
);
const canSubmit = computed(
  () =>
    !!plan.value &&
    permitted(plan.value.input.action) &&
    (!needsEnabled.value || props.moduleEnabled) &&
    loaded.value &&
    !active.value &&
    !pending.value &&
    !busy.value,
);
let closed = false,
  timer: ReturnType<typeof setTimeout> | undefined;
watch([action, selected], () => {
  plan.value = null;
  notice.value = "";
});
async function loadAssets() {
  if (assetsReading.value || !session.me?.scopes.includes("components.manage"))
    return;
  assetsReading.value = true;
  try {
    const result = await api.componentTasks(controller.signal);
    if (!closed) {
      preparations.value = result;
      assetsError.value = "";
      clock.value = Date.now();
    }
  } catch (e) {
    if (!closed) assetsError.value = apiError(e).message;
  } finally {
    if (!closed) assetsReading.value = false;
  }
}
async function refresh() {
  if (closed || reading.value) return;
  if (timer) clearTimeout(timer);
  reading.value = true;
  const before = new Set(
    tasks.value
      .filter((task) => activeStates.has(task.state))
      .map((task) => task.id),
  );
  try {
    const result = await api.fail2banLifecycleTasks(controller.signal);
    if (closed) return;
    tasks.value = result;
    loaded.value = true;
    historyError.value = "";
    if (
      result.some(
        (task) => before.has(task.id) && !activeStates.has(task.state),
      )
    ) {
      plan.value = null;
      emit("changed");
    }
  } catch (e) {
    if (!closed) {
      historyError.value = apiError(e).message;
      loaded.value = false;
    }
  } finally {
    if (!closed) {
      reading.value = false;
      if (active.value || pending.value)
        timer = setTimeout(() => {
          void refresh();
        }, 3000);
    }
  }
}
async function preview() {
  if (
    busy.value ||
    active.value ||
    pending.value ||
    !action.value ||
    !permitted(action.value)
  )
    return;
  const input: Fail2banLifecyclePreviewInput = {
    action: action.value,
    plan_id: "",
    asset_id: "",
    prerelease: false,
  };
  if (input.action === "install") {
    const item = chosen.value;
    if (!item?.task.result?.release) return;
    if (item.task.result.release.expires_at * 1000 <= Date.now()) {
      error.value = "签名准备计划已过期，请重新准备组件";
      return;
    }
    input.plan_id = item.task.result.release.plan_id;
    input.asset_id = item.asset.id;
    input.prerelease = item.task.result.input.prerelease;
  }
  busy.value = true;
  error.value = "";
  plan.value = null;
  try {
    const result = await api.previewFail2banLifecycle(input, controller.signal);
    if (!closed) plan.value = result;
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    if (!closed) busy.value = false;
  }
}
async function submit() {
  if (busy.value || closed) return;
  if (!pending.value) {
    if (!canSubmit.value || !plan.value) return;
    pending.value = {
      input: { ...plan.value.input },
      key: crypto.randomUUID(),
    };
  }
  busy.value = true;
  error.value = "";
  try {
    const result = await api.changeFail2banLifecycle(
      pending.value.input,
      pending.value.key,
    );
    if (closed) return;
    pending.value = null;
    plan.value = null;
    notice.value = `操作任务已创建：${result.task_id}`;
    await refresh();
  } catch (e) {
    if (!closed) {
      const failure = apiError(e);
      error.value = failure.message;
      if (failure.status >= 400 && failure.status < 500) pending.value = null;
    }
  } finally {
    if (!closed) busy.value = false;
  }
}
onMounted(() => {
  void refresh();
  void loadAssets();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
  if (timer) clearTimeout(timer);
});
</script>
<template>
  <section class="panel page-stack">
    <div class="toolbar">
      <h3>独立实例安装与服务控制</h3>
      <NButton size="small" :loading="reading" @click="refresh"
        >刷新任务</NButton
      >
    </div>
    <p>
      安装登记、服务运行、开机设置与 jail
      保护分别核对。以下操作只控制本应用的独立实例。
    </p>
    <p v-if="currentManaged">
      安装：{{ managedStates[currentManaged.state] || "未知" }} ·
      {{ currentManaged.version || "—" }}
    </p>
    <p v-if="currentService?.available">
      服务：{{ currentService.active }} / {{ currentService.sub }} ·
      开机设置：{{ currentService.unit_file || "未知" }}
    </p>
    <p v-else>专用服务状态未知</p>
    <p v-if="currentAt">
      状态快照 {{ new Date(currentAt * 1000).toLocaleString() }}
    </p>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="notice" type="info">{{ notice }}</NAlert>
    <NAlert v-if="pending" type="warning"
      >提交结果待确认，可继续原操作。</NAlert
    >
    <template v-if="options.length">
      <NFormItem label="操作"
        ><NSelect
          v-model:value="action"
          :options="options"
          :disabled="busy || active || !!pending"
          placeholder="选择操作"
      /></NFormItem>
      <template v-if="action === 'install'">
        <NFormItem label="已准备的签名资产"
          ><NSelect
            v-model:value="selected"
            :options="assets"
            :disabled="busy || active || !!pending"
            placeholder="选择单个 Fail2ban 资产的准备记录"
        /></NFormItem>
        <div class="toolbar">
          <NButton size="small" :loading="assetsReading" @click="loadAssets"
            >刷新准备记录</NButton
          ><RouterLink to="/components">组件准备</RouterLink>
        </div>
        <NAlert v-if="assetsError" type="warning">{{ assetsError }}</NAlert>
        <p v-if="!assets.length">
          需要先检查并准备单个 Fail2ban 签名资产，以及兼容的宿主机 Python 和
          SQLite 标准库。
        </p>
      </template>
      <div class="toolbar">
        <NButton
          :loading="busy"
          :disabled="
            !action ||
            active ||
            !!pending ||
            !loaded ||
            (action === 'install' && !chosen)
          "
          @click="preview"
          >预览操作</NButton
        >
        <NButton v-if="pending" :loading="busy" @click="submit"
          >继续原操作</NButton
        >
      </div>
    </template>
    <section v-if="plan" class="surface page-stack">
      <h4>{{ names[plan.input.action] }}</h4>
      <p>
        预览 {{ new Date(plan.at * 1000).toLocaleString() }} · 实例
        {{ plan.input.base_id || "首次安装" }}
      </p>
      <ul>
        <li v-for="impact in plan.impacts" :key="impact">{{ impact }}</li>
      </ul>
      <p v-if="plan.jails.length">受管 jail：{{ plan.jails.join("、") }}</p>
      <NAlert v-if="needsEnabled && !moduleEnabled" type="warning"
        >此操作包含启动或开机启用，需要先启用 Fail2ban 管理模块。</NAlert
      >
      <NPopconfirm :disabled="!canSubmit" @positive-click="submit">
        <template #trigger
          ><NButton type="warning" :disabled="!canSubmit" :loading="busy"
            >确认{{ names[plan.input.action] }}</NButton
          ></template
        >
        确认执行{{ names[plan.input.action] }}？将按以上影响操作独立受管实例。
      </NPopconfirm>
    </section>
    <NAlert v-if="historyError" type="error">{{ historyError }}</NAlert>
    <p v-if="active">存在尚未结束的 Fail2ban 实例任务。</p>
    <p v-if="loaded && !tasks.length">暂无独立实例操作记录。</p>
    <article v-for="task in tasks" :key="task.id" class="surface page-stack">
      <p>
        {{ names[task.input.action] }} ·
        {{ states[task.state] || "状态未知" }} ·
        {{ new Date(task.created_at * 1000).toLocaleString() }}
      </p>
      <p>任务 {{ task.id }}</p>
      <NAlert v-if="task.error" type="warning">{{ task.error }}</NAlert>
      <template v-if="task.result">
        <p>
          {{
            task.result.submission === "acknowledged"
              ? "执行器已返回回执"
              : task.result.submission === "unknown"
                ? "执行器回执未确认"
                : "尚未派发"
          }}
          · {{ managedStates[task.result.managed.state] || "安装状态未知" }}
        </p>
        <p v-if="task.result.service.available">
          服务快照：{{ task.result.service.active }} /
          {{ task.result.service.unit_file || "开机设置未知" }} ·
          {{ new Date(task.result.at * 1000).toLocaleString() }}
        </p>
      </template>
    </article>
    <p>显示最近 16 次实例操作。安装中断后的续办或撤回需要重新预览并确认。</p>
  </section>
</template>
