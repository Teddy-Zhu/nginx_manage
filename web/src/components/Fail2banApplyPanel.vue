<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { NAlert, NButton, NPopconfirm } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banApplyInput,
  type Fail2banApplyTaskStatus,
  type Fail2banPolicyPreview,
} from "../api/client";

const props = defineProps<{
  preview: Fail2banPolicyPreview | null;
  disabled: boolean;
}>();
const emit = defineEmits<{ submitted: [] }>();
const api = useNodeAPI(),
  controller = new AbortController();
const tasks = ref<Fail2banApplyTaskStatus[]>([]),
  error = ref(""),
  notice = ref(""),
  busy = ref(false),
  reading = ref(false),
  loaded = ref(false);
const pending = ref<{ input: Fail2banApplyInput; key: string } | null>(null);
const activeStates = new Set([
  "queued",
  "running",
  "compensating",
  "recovery_required",
]);
const active = computed(() =>
  tasks.value.some((task) => activeStates.has(task.state)),
);
const states: Record<string, string> = {
  queued: "排队中",
  running: "应用中",
  compensating: "恢复原配置中",
  recovery_required: "等待恢复确认",
  succeeded: "jail 参数已确认",
  failed: "应用失败",
  cancelled: "已取消",
};
let closed = false,
  timer: ReturnType<typeof setTimeout> | undefined;
async function refresh() {
  if (reading.value || closed) return;
  if (timer) clearTimeout(timer);
  reading.value = true;
  try {
    const result = await api.fail2banTasks(controller.signal);
    if (closed) return;
    tasks.value = result;
    loaded.value = true;
    error.value = "";
  } catch (e) {
    if (!closed) {
      error.value = apiError(e).message;
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
async function apply() {
  if (busy.value || active.value || !loaded.value) return;
  if (!pending.value) {
    const preview = props.preview;
    if (props.disabled || !preview?.can_apply) return;
    pending.value = {
      input: {
        version: preview.version,
        policy_hash: preview.policy_hash,
        base_id: preview.runtime.selected_id,
        target: preview.runtime.target,
      },
      key: crypto.randomUUID(),
    };
  }
  busy.value = true;
  error.value = "";
  try {
    const result = await api.applyFail2ban(
      pending.value.input,
      pending.value.key,
    );
    if (closed) return;
    pending.value = null;
    notice.value = `应用任务已创建：${result.task_id}`;
    emit("submitted");
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
});
onUnmounted(() => {
  closed = true;
  controller.abort();
  if (timer) clearTimeout(timer);
});
</script>
<template>
  <section class="surface page-stack">
    <div class="toolbar">
      <h4>应用与恢复</h4>
      <NButton size="small" :loading="reading" @click="refresh"
        >刷新任务</NButton
      >
    </div>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="notice" type="info">{{ notice }}</NAlert>
    <NAlert v-if="pending" type="warning"
      >上次提交结果待确认，重试将继续核对原任务。</NAlert
    >
    <p v-if="preview?.removed.length">
      将停用：{{ preview.removed.join("、") }}
    </p>
    <NPopconfirm @positive-click="apply">
      <template #trigger>
        <NButton
          type="primary"
          :loading="busy"
          :disabled="
            busy ||
            active ||
            !loaded ||
            (!pending && (disabled || !preview?.can_apply))
          "
          >{{ pending ? "重试原提交" : "应用已保存配置" }}</NButton
        >
      </template>
      应用此版本将更新本应用的受管 jail，并停用本次移除的 jail。确认继续？
    </NPopconfirm>
    <p class="muted">
      jail 参数确认与 Nginx 拒绝集合生效分别核对；应用任务成功不表示每个地址已被
      Nginx 拒绝。
    </p>
    <div v-for="task in tasks" :key="task.id" class="page-stack">
      <strong>{{ states[task.state] || task.state }} · {{ task.id }}</strong>
      <p v-if="task.error" class="muted">{{ task.error }}</p>
    </div>
    <p v-if="loaded && !tasks.length" class="muted">暂无应用任务</p>
  </section>
</template>
