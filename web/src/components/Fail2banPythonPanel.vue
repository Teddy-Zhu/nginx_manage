<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { randomUUID } from "../utils/crypto";

import TaskLogButton from "./TaskLogButton.vue";
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NPopconfirm,
  NSelect,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banPython,
  type Fail2banPythonTaskInput,
  type Fail2banPythonTaskStatus,
} from "../api/client";
import { useSession } from "../stores/session";

const props = defineProps<{
  moduleEnabled: boolean;
  python: Fail2banPython | null;
  observedAt: number;
}>();
const emit = defineEmits<{ changed: [] }>();
const api = useNodeAPI(),
  session = useSession(),
  controller = new AbortController();
const tasks = ref<Fail2banPythonTaskStatus[]>([]);
const pending = ref<{ input: Fail2banPythonTaskInput; key: string } | null>(
  null,
);
const selected = ref(""),
  refreshIndex = ref(true),
  clock = ref(Date.now());
const reading = ref(false),
  busy = ref(false),
  loaded = ref(false);
const error = ref(""),
  historyError = ref(""),
  notice = ref("");
const accepted = ref(new Set<string>());
const activeStates = new Set([
  "queued",
  "running",
  "compensating",
  "recovery_required",
]);
const states: Record<string, string> = {
  queued: "排队中",
  running: "处理中",
  compensating: "恢复中",
  recovery_required: "等待恢复确认",
  succeeded: "已完成",
  failed: "未完成",
  cancelled: "已取消",
};
const active = computed(
  () =>
    accepted.value.size > 0 ||
    tasks.value.some((task) => activeStates.has(task.state)),
);
const canManage = computed(
  () => session.me?.scopes.includes("components.manage") ?? false,
);
const canSubmit = computed(
  () =>
    canManage.value &&
    props.moduleEnabled &&
    loaded.value &&
    !active.value &&
    !pending.value &&
    !busy.value,
);
const plans = computed(() =>
  tasks.value.flatMap((task) => {
    const plan = task.result?.plan;
    return task.input.action === "plan" &&
      task.state === "succeeded" &&
      plan &&
      plan.expires_at * 1000 > clock.value
      ? [
          {
            value: task.id,
            label: `安装方案 · ${new Date(plan.at * 1000).toLocaleString()}`,
            plan,
          },
        ]
      : [];
  }),
);
const chosen = computed(
  () => plans.value.find((item) => item.value === selected.value)?.plan ?? null,
);
const latest = computed(
  () =>
    tasks.value
      .filter(
        (task) =>
          task.input.action === "install" &&
          task.result &&
          task.result.at >= props.observedAt &&
          task.result.python.standard_library !== null,
      )
      .sort((a, b) => (b.result?.at ?? 0) - (a.result?.at ?? 0))[0]?.result ??
    null,
);
const currentPython = computed(() => latest.value?.python ?? props.python);
const currentAt = computed(() => latest.value?.at ?? props.observedAt);
const bytes = (value: number) => `${(value / 1024 / 1024).toFixed(1)} MiB`;
let closed = false;

async function refresh() {
  if (closed || reading.value) return;
  reading.value = true;
  const before = new Set(
    tasks.value
      .filter((task) => activeStates.has(task.state))
      .map((task) => task.id),
  );
  try {
    const result = await api.fail2banPythonTasks(controller.signal);
    if (closed) return;
    tasks.value = result;
    loaded.value = true;
    historyError.value = "";
    clock.value = Date.now();
    if (!plans.value.some((item) => item.value === selected.value))
      selected.value = plans.value[0]?.value ?? "";
    if (
      result.some(
        (task) =>
          (before.has(task.id) || accepted.value.has(task.id)) &&
          !activeStates.has(task.state),
      )
    )
      emit("changed");
    for (const task of result) accepted.value.delete(task.id);
  } catch (cause) {
    if (!closed) {
      historyError.value = apiError(cause).message;
      loaded.value = false;
    }
  } finally {
    if (!closed) {
      reading.value = false;
    }
  }
}

async function submit(input?: Fail2banPythonTaskInput) {
  if (closed || busy.value) return;
  if (!pending.value) {
    if (!input || !canSubmit.value) return;
    if (
      input.action === "install" &&
      (!chosen.value ||
        chosen.value.id !== input.plan_id ||
        chosen.value.expires_at * 1000 <= Date.now())
    ) {
      clock.value = Date.now();
      error.value = "依赖计划已过期，请重新生成计划";
      return;
    }
    pending.value = { input: { ...input }, key: randomUUID() };
  }
  busy.value = true;
  error.value = "";
  notice.value = "";
  try {
    const result = await api.changeFail2banPython(
      pending.value.input,
      pending.value.key,
    );
    if (closed) return;
    accepted.value.add(result.task_id);
    pending.value = null;
    notice.value = "操作已提交，请查看执行进度。";
    await refresh();
  } catch (cause) {
    if (!closed) {
      const failure = apiError(cause);
      error.value = failure.message;
      if ([400, 409, 413, 422].includes(failure.status)) pending.value = null;
      else await refresh();
    }
  } finally {
    if (!closed) busy.value = false;
  }
}
function plan() {
  void submit({ action: "plan", plan_id: "", refresh: refreshIndex.value });
}
function install() {
  if (chosen.value)
    void submit({
      action: "install",
      plan_id: chosen.value.id,
      refresh: false,
    });
}
onMounted(() => {
  void refresh();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
});
useLiveRefresh(api, ["tasks"], refresh, () => reading.value);
</script>

<template>
  <section class="panel page-stack">
    <div class="toolbar">
      <h3>安装运行依赖</h3>
      <NButton size="small" :loading="reading" @click="refresh">
        刷新任务
      </NButton>
    </div>
    <p v-if="currentPython?.standard_library === true">
      系统 Python {{ currentPython.version || "—" }} · 标准库与 SQLite 可用
    </p>
    <p v-else class="muted">
      Fail2ban 的运行依赖尚未就绪。
    </p>

    <p v-if="currentAt">
      状态快照 {{ new Date(currentAt * 1000).toLocaleString() }}
    </p>
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <NAlert v-if="notice" type="info">
      {{ notice }}
    </NAlert>
    <NAlert v-if="historyError" type="warning">
      任务记录读取失败：{{ historyError }}
    </NAlert>
    <NAlert v-if="pending" type="warning">
      提交结果待确认。
      <NButton size="small" :loading="busy" @click="submit()">
        继续原请求
      </NButton>
    </NAlert>
    <template v-if="canManage">
      <NAlert v-if="!moduleEnabled" type="warning">
        请先开启登录防护。
      </NAlert>
      <NCheckbox v-model:checked="refreshIndex" :disabled="!canSubmit">
        更新软件列表
      </NCheckbox>
      <div class="toolbar">
        <NPopconfirm
          v-if="refreshIndex"
          :disabled="!canSubmit"
          @positive-click="plan"
        >
          <template #trigger>
            <NButton :disabled="!canSubmit" :loading="busy">
              更新软件列表并检查依赖
            </NButton>
          </template>
          刷新系统软件列表并检查依赖？此步骤不会安装软件。
        </NPopconfirm>
        <NButton v-else :disabled="!canSubmit" :loading="busy" @click="plan">
          检查所需依赖
        </NButton>
      </div>
      <NFormItem v-if="plans.length > 1" label="安装方案">
        <NSelect
          v-model:value="selected"
          :options="plans"
          :disabled="busy || !!pending"
          placeholder="选择安装方案"
        />
      </NFormItem>
      <template v-if="chosen">
        <p>
          下载 {{ bytes(chosen.download_bytes) }} · 安装空间
          {{ bytes(chosen.installed_bytes) }}
        </p>

        <NPopconfirm :disabled="!canSubmit" @positive-click="install">
          <template #trigger>
            <NButton type="primary" :disabled="!canSubmit" :loading="busy">
              安装所需依赖
            </NButton>
          </template>
          将从系统软件仓库安装所列依赖，完成后可继续安装 Fail2ban。
        </NPopconfirm>
      </template>
    </template>
    <template v-if="tasks.length">
      <h4>最近的依赖任务</h4>
      <article v-for="task in tasks" :key="task.id">
        <p>
          {{ task.input.action === "plan" ? "生成计划" : "安装依赖" }} ·
          {{ states[task.state] || task.state }} ·
          {{ new Date(task.created_at * 1000).toLocaleString() }}
        </p>
        <TaskLogButton :task-id="task.id" />
        <p>{{ task.id }}</p>
        <p v-if="task.error || task.result?.error">
          {{ task.error || task.result?.error }}
        </p>
      </article>
    </template>
    <p v-else-if="loaded">
      暂无依赖任务
    </p>
  </section>
</template>

<style scoped>
.python-package-table {
  overflow-x: auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}
th,
td {
  padding: 0.6rem;
  border-bottom: 1px solid var(--border-color, #8884);
  vertical-align: top;
}
.package-digest {
  max-width: 14rem;
  overflow-wrap: anywhere;
  font-family: monospace;
}
</style>
