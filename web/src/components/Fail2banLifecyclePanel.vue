<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { NAlert, NButton, NPopconfirm, NSwitch, NTag } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banLifecycleInput,
  type Fail2banLifecyclePreviewInput,
  type Fail2banLifecycleTaskStatus,
  type Fail2banManaged,
  type Fail2banService,
  type Fail2banInstance,
  type Fail2banObservation,
} from "../api/client";
import { useSession } from "../stores/session";
import { useLiveRefresh } from "../composables/live";
import { randomUUID } from "../utils/crypto";
import TaskLogButton from "./TaskLogButton.vue";

const props = defineProps<{
  moduleEnabled: boolean;
  managed: Fail2banManaged | null;
  service: Fail2banService | null;
  observedAt: number;
  binding: Fail2banObservation["binding"] | null;
  instance: Fail2banInstance | null;
}>();
const emit = defineEmits<{ changed: [] }>();
const api = useNodeAPI(),
  session = useSession(),
  controller = new AbortController();
const tasks = ref<Fail2banLifecycleTaskStatus[]>([]),
  busy = ref(false),
  reading = ref(false),
  loaded = ref(false),
  error = ref("");
const pending = ref<{ input: Fail2banLifecycleInput; key: string } | null>(
  null,
);
const accepted = ref(new Set<string>());
const owner = computed(() =>
  props.binding?.engine.owner === "existing" ? "existing" : "managed",
);
const latest = computed(
  () =>
    tasks.value.find(
      (task) =>
        task.input.engine_owner === owner.value &&
        task.result &&
        task.result.at >= props.observedAt &&
        (owner.value !== "existing" ||
          task.input.base_id === props.binding?.id),
    )?.result,
);
const service = computed(
  () =>
    latest.value?.service ??
    (owner.value === "existing" ? props.instance?.service : props.service),
);
const installed = computed(() =>
  owner.value === "existing"
    ? props.binding?.state === "bound"
    : (latest.value?.managed ?? props.managed)?.state === "installed",
);
const activeStates = new Set([
  "queued",
  "running",
  "compensating",
  "recovery_required",
]);
const active = computed(
  () =>
    accepted.value.size > 0 ||
    tasks.value.some((task) => activeStates.has(task.state)),
);
const writable = computed(
  () =>
    session.me?.scopes.includes("security.write") &&
    (owner.value !== "existing" || props.binding?.service_control),
);
const canActivate = computed(
  () => props.moduleEnabled || session.me?.scopes.includes("system.write"),
);
const running = computed(() => service.value?.active === "active");
const enabled = computed(() =>
  ["enabled", "enabled-runtime"].includes(service.value?.unit_file ?? ""),
);
const blocked = computed(
  () =>
    !installed.value ||
    !loaded.value ||
    !writable.value ||
    busy.value ||
    active.value ||
    !!pending.value ||
    !service.value?.available,
);
const names: Record<string, string> = {
  install: "安装 Fail2ban",
  resume: "继续安装",
  rollback: "取消安装",
  start: "启动防护",
  stop: "停止防护",
  enable: "开启开机启动",
  disable: "关闭开机启动",
};
const states: Record<string, string> = {
  queued: "等待执行",
  running: "正在执行",
  compensating: "正在恢复",
  recovery_required: "需要处理",
  succeeded: "已完成",
  failed: "未完成",
  cancelled: "已取消",
};
const status = computed(() => {
  if (!installed.value) return "未安装";
  if (!service.value?.available) return "状态暂不可用";
  const labels: Record<string, string> = {
    active: "运行中",
    inactive: "已停止",
    failed: "启动失败",
    activating: "正在启动",
    deactivating: "正在停止",
    reloading: "正在重载",
  };
  return labels[service.value.active] ?? "状态暂不可用";
});
async function refresh() {
  if (controller.signal.aborted || reading.value) return;
  reading.value = true;
  const before = new Set(
    tasks.value
      .filter((task) => activeStates.has(task.state))
      .map((task) => task.id),
  );
  try {
    const result = await api.fail2banLifecycleTasks(controller.signal);
    if (controller.signal.aborted) return;
    tasks.value = result;
    loaded.value = true;
    if (
      result.some(
        (task) =>
          (before.has(task.id) || accepted.value.has(task.id)) &&
          !activeStates.has(task.state),
      )
    )
      emit("changed");
    for (const task of result) accepted.value.delete(task.id);
  } catch (failure) {
    if (!controller.signal.aborted) {
      error.value = apiError(failure).message;
      loaded.value = false;
    }
  } finally {
    if (!controller.signal.aborted) reading.value = false;
  }
}
async function change(action?: Fail2banLifecyclePreviewInput["action"]) {
  if (busy.value || controller.signal.aborted) return;
  if (
    !pending.value &&
    (blocked.value ||
      !action ||
      (["start", "enable"].includes(action) && !canActivate.value))
  )
    return;
  busy.value = true;
  error.value = "";
  try {
    if (!pending.value) {
      if (!props.moduleEnabled && ["start", "enable"].includes(action!))
        await api.setModule("fail2ban", true);
      const plan = await api.previewFail2banLifecycle(
        {
          engine_owner: owner.value,
          action: action!,
          plan_id: "",
          asset_id: "",
          prerelease: false,
        },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      pending.value = { input: plan.input, key: randomUUID() };
    }
    const result = await api.changeFail2banLifecycle(
      pending.value.input,
      pending.value.key,
    );
    if (controller.signal.aborted) return;
    accepted.value.add(result.task_id);
    pending.value = null;
    await refresh();
  } catch (failure) {
    if (!controller.signal.aborted) {
      error.value = apiError(failure).message;
      const status = apiError(failure).status;
      if (status >= 400 && status < 500 && status !== 408) pending.value = null;
    }
  } finally {
    if (!controller.signal.aborted) busy.value = false;
  }
}
onMounted(refresh);
onUnmounted(() => controller.abort());
useLiveRefresh(api, ["tasks"], refresh, () => reading.value);
</script>

<template>
  <section class="panel page-stack">
    <div class="section-heading">
      <h3>防护服务</h3>
      <NTag :type="running ? 'success' : 'default'">{{ status }}</NTag>
    </div>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="pending" type="warning"
      >暂未确认操作结果，请继续查询。<NButton
        size="small"
        :loading="busy"
        @click="change()"
        >确认操作进度</NButton
      ></NAlert
    >
    <div class="toolbar">
      <NPopconfirm
        v-if="running"
        :disabled="blocked"
        @positive-click="change('stop')"
        ><template #trigger
          ><NButton :disabled="blocked" :loading="busy"
            >停止防护</NButton
          ></template
        >停止后，当前登录防护规则将暂停生效。确认停止？</NPopconfirm
      >
      <NButton
        v-else
        type="primary"
        :disabled="blocked || !canActivate"
        :loading="busy"
        @click="change('start')"
        >启动防护</NButton
      >
      <div class="inline-gap">
        <span>开机启动</span
        ><NSwitch
          :value="enabled"
          :disabled="
            blocked ||
            (!enabled && !canActivate) ||
            !['enabled', 'enabled-runtime', 'disabled'].includes(
              service?.unit_file ?? '',
            )
          "
          :loading="busy"
          @update:value="change($event ? 'enable' : 'disable')"
        />
      </div>
      <NButton
        :loading="reading"
        :disabled="busy"
        @click="
          () => {
            refresh();
            emit('changed');
          }
        "
        >刷新状态</NButton
      >
    </div>
    <p v-if="!canActivate && !running" class="muted">
      请联系管理员开启登录防护。
    </p>
    <p v-if="active" class="muted">正在处理服务操作，请稍候。</p>
    <p v-if="!writable && installed" class="muted">
      当前账户仅可查看防护状态。
    </p>
    <div v-for="item in tasks.slice(0, 5)" :key="item.id" class="record-card">
      <div class="record-heading">
        <strong>{{ names[item.input.action] || "服务操作" }}</strong
        ><NTag
          :type="
            item.state === 'succeeded'
              ? 'success'
              : ['failed', 'recovery_required'].includes(item.state)
                ? 'warning'
                : 'info'
          "
          >{{ states[item.state] || "正在处理" }}</NTag
        ><TaskLogButton :task-id="item.id" />
      </div>
      <p class="muted">
        {{ new Date(item.created_at * 1000).toLocaleString() }}
      </p>
    </div>
  </section>
</template>
