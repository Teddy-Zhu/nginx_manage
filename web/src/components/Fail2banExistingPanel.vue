<script setup lang="ts">
import { randomUUID } from "../utils/crypto";

import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NInput,
  NInputNumber,
  NPopconfirm,
  NSelect,
  NSwitch,
  NTag,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banExistingResource,
  type Fail2banExistingResourcePolicy,
  type Fail2banExistingPolicy,
  type Fail2banExistingPolicyInput,
  type Fail2banExistingTaskStatus,
} from "../api/client";
import { useSession } from "../stores/session";
import Fail2banAddressPanel from "./Fail2banAddressPanel.vue";

const props = defineProps<{ moduleEnabled: boolean }>();
const emit = defineEmits<{ changed: []; resources: [names: string[]] }>();
const api = useNodeAPI(),
  session = useSession(),
  controller = new AbortController();
const resources = ref<Fail2banExistingResource[]>([]),
  resource = ref<Fail2banExistingResourcePolicy | null>(null),
  selected = ref<string | null>(null);
const tasks = ref<Fail2banExistingTaskStatus[]>([]),
  viewedID = ref("");
const enabled = ref(false),
  banTime = ref<number | null>(null),
  findTime = ref<number | null>(null),
  maxRetry = ref<number | null>(null),
  ignoreIPs = ref(""),
  confirmStop = ref(false);
const error = ref(""),
  historyError = ref(""),
  notice = ref(""),
  busy = ref(false),
  reading = ref(false),
  detailReading = ref(false),
  loaded = ref(false);
const pending = ref<{
  input: Fail2banExistingPolicyInput;
  key: string;
  fingerprint: string;
} | null>(null);
const pendingCancel = ref<{ id: string; key: string } | null>(null);
const previewContext = ref<{
  id: string;
  fingerprint: string;
  adoption: string;
} | null>(null);
const now = ref(Date.now());
let closed = false,
  timer: ReturnType<typeof setTimeout> | undefined,
  detailController: AbortController | null = null,
  detailVersion = 0;
const activeStates = new Set([
  "queued",
  "running",
  "compensating",
  "recovery_required",
]);
const active = computed(() =>
  tasks.value.some((t) => activeStates.has(t.state)),
);
const canWrite = computed(
  () => !!session.me?.scopes.includes("security.write"),
);
const editingDisabled = computed(
  () =>
    !canWrite.value ||
    !props.moduleEnabled ||
    active.value ||
    busy.value ||
    !!pending.value ||
    !!pendingCancel.value,
);
const policy = computed<Fail2banExistingPolicy | null>(() => {
  if (
    banTime.value === null ||
    findTime.value === null ||
    maxRetry.value === null
  )
    return null;
  return {
    enabled: enabled.value,
    ban_time: banTime.value,
    find_time: findTime.value,
    max_retry: maxRetry.value,
    ignore_ips: ignoreIPs.value.split(/\s+/).filter(Boolean).sort(),
  };
});
const fingerprint = computed(() =>
  JSON.stringify({
    adoption: resource.value?.adoption_id,
    policy: policy.value,
  }),
);
const viewed = computed(() => tasks.value.find((t) => t.id === viewedID.value));
const plan = computed(() => viewed.value?.result?.plan);
const ready = computed(() => {
  const context = previewContext.value,
    task = viewed.value,
    value = plan.value;
  return (
    !editingDisabled.value &&
    loaded.value &&
    !detailReading.value &&
    !!context &&
    !!task &&
    !!value &&
    context.id === task.id &&
    context.fingerprint === fingerprint.value &&
    context.adoption === resource.value?.adoption_id &&
    task.input.action === "preview" &&
    task.state === "succeeded" &&
    task.result?.stage === "preview_confirmed" &&
    now.value >= value.at * 1000 &&
    now.value - value.at * 1000 <= 300000
  );
});
const stateNames: Record<string, string> = {
  queued: "排队中",
  running: "处理中",
  recovery_required: "等待核对",
  succeeded: "已完成",
  failed: "未完成",
  cancelled: "已取消",
};
const stageNames: Record<string, string> = {
  queued: "排队中",
  preview_confirmed: "预览已确认",
  prepared: "应用准备完成",
  reload_pending: "应用请求已提交",
  reload_observing: "正在核对运行",
  policy_confirmed: "运行参数已确认",
  policy_unconfirmed: "运行结果待核对",
  preview_rejected: "预览未通过",
  apply_rejected: "应用准备未通过",
  expired: "请求已过期",
  authorization_expired: "授权已过期",
  cancelled: "已取消",
  reconciling: "正在核对",
  operation_missing: "原操作记录缺失",
  operation_mismatch: "任务材料不一致",
  module_disabled: "模块已停用",
  migration_pending: "迁移尚未结束",
  payload_invalid: "材料无法核对",
  cancel_unconfirmed: "取消结果未知",
  restore_isolated: "恢复隔离",
  agent_rejected: "执行器拒绝",
  submit_unconfirmed: "提交结果待核对",
  agent_submit_pending: "正在提交",
};
const logs: Record<string, string> = {
  "auth-log": "认证日志",
  "secure-log": "安全日志",
  systemd: "系统日志",
};
watch(fingerprint, () => {
  confirmStop.value = false;
});
function setPolicy(value: Fail2banExistingPolicy) {
  enabled.value = value.enabled;
  banTime.value = value.ban_time;
  findTime.value = value.find_time;
  maxRetry.value = value.max_retry;
  ignoreIPs.value = value.ignore_ips.join("\n");
}
function copyPolicy(value: Fail2banExistingPolicy): Fail2banExistingPolicy {
  return { ...value, ignore_ips: [...value.ignore_ips] };
}
function time(value: number) {
  return new Date(value * 1000).toLocaleString();
}
function duration(value: number) {
  return value === -1 ? "永久" : `${value} 秒`;
}
function schedule() {
  if (timer) clearTimeout(timer);
  if (
    closed ||
    (!active.value &&
      !pending.value &&
      !pendingCancel.value &&
      (!plan.value || now.value - plan.value.at * 1000 > 300000))
  )
    return;
  timer = setTimeout(() => {
    now.value = Date.now();
    if (active.value || pending.value || pendingCancel.value)
      void refreshTasks();
    else schedule();
  }, 3000);
}
async function loadResource(name: string | null) {
  const version = ++detailVersion;
  detailController?.abort();
  resource.value = null;
  previewContext.value = null;
  confirmStop.value = false;
  detailReading.value = false;
  if (!name || closed) return;
  const requestController = new AbortController();
  detailController = requestController;
  detailReading.value = true;
  error.value = "";
  try {
    const value = await api.fail2banExistingResource(
      name,
      requestController.signal,
    );
    if (!closed && version === detailVersion) {
      resource.value = value;
      setPolicy(value.policy);
    }
  } catch (e) {
    if (!closed && version === detailVersion) error.value = apiError(e).message;
  } finally {
    if (!closed && version === detailVersion) detailReading.value = false;
  }
}
watch(selected, (name) => {
  void loadResource(name);
});
async function loadResources() {
  try {
    const value = await api.fail2banExistingResources(controller.signal);
    if (closed) return;
    resources.value = value;
    emit(
      "resources",
      value.map((item) => item.name),
    );
    if (!value.some((item) => item.name === selected.value))
      selected.value = value[0]?.name ?? null;
    else if (
      resource.value &&
      resource.value.adoption_id !==
        value.find((item) => item.name === selected.value)?.adoption_id
    )
      void loadResource(selected.value);
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  }
}
async function refreshTasks() {
  if (closed || reading.value) return;
  reading.value = true;
  const previous = new Map(tasks.value.map((t) => [t.id, t.state]));
  try {
    const value = await api.fail2banExistingTasks(controller.signal);
    if (closed) return;
    tasks.value = value;
    loaded.value = true;
    historyError.value = "";
    now.value = Date.now();
    if (!viewedID.value && value[0]) viewedID.value = value[0].id;
    if (
      value.some(
        (t) =>
          t.input.action === "apply" &&
          t.state === "succeeded" &&
          activeStates.has(previous.get(t.id) ?? ""),
      )
    ) {
      previewContext.value = null;
      emit("changed");
      if (selected.value) void loadResource(selected.value);
    }
  } catch (e) {
    if (!closed) {
      loaded.value = false;
      historyError.value = apiError(e).message;
    }
  } finally {
    if (!closed) {
      reading.value = false;
      schedule();
    }
  }
}
async function submit(action: "preview" | "apply") {
  if (closed || busy.value) return;
  if (!pending.value) {
    if (
      editingDisabled.value ||
      !loaded.value ||
      !resource.value ||
      !policy.value ||
      detailReading.value
    )
      return;
    if (
      action === "apply" &&
      (!ready.value ||
        !plan.value ||
        (plan.value.stop_confirmation && !confirmStop.value))
    )
      return;
    const value = action === "apply" ? plan.value : undefined;
    pending.value = {
      key: randomUUID(),
      fingerprint: fingerprint.value,
      input: {
        action,
        adoption_id: resource.value.adoption_id,
        policy: value ? copyPolicy(value.after) : copyPolicy(policy.value),
        preview_id: value ? viewed.value!.operation_id : "",
        target: value?.target ?? "",
        confirm_stop: !!value?.stop_confirmation,
      },
    };
  }
  const original = pending.value;
  busy.value = true;
  error.value = "";
  notice.value = "";
  try {
    const out = await api.changeFail2banExistingPolicy(
      original.input,
      original.key,
    );
    if (closed) return;
    viewedID.value = out.task_id;
    previewContext.value =
      original.input.action === "preview"
        ? {
            id: out.task_id,
            adoption: original.input.adoption_id,
            fingerprint: original.fingerprint,
          }
        : null;
    pending.value = null;
    confirmStop.value = false;
    notice.value =
      original.input.action === "preview"
        ? "预览任务已创建"
        : "应用任务已创建，等待运行确认";
    await refreshTasks();
  } catch (e) {
    if (!closed) {
      const failure = apiError(e);
      error.value = failure.message;
      if (failure.status >= 400 && failure.status < 500) pending.value = null;
    }
  } finally {
    if (!closed) {
      busy.value = false;
      schedule();
    }
  }
}
async function cancel(id: string) {
  if (closed || busy.value || !canWrite.value) return;
  if (!pendingCancel.value)
    pendingCancel.value = { id, key: randomUUID() };
  busy.value = true;
  error.value = "";
  try {
    await api.cancelFail2banExistingPolicy(
      pendingCancel.value.id,
      pendingCancel.value.key,
    );
    if (closed) return;
    pendingCancel.value = null;
    notice.value = "取消申请已保存，等待核对结果";
    await refreshTasks();
  } catch (e) {
    if (!closed) {
      const failure = apiError(e);
      error.value = failure.message;
      if (failure.status >= 400 && failure.status < 500)
        pendingCancel.value = null;
    }
  } finally {
    if (!closed) {
      busy.value = false;
      schedule();
    }
  }
}
function retrySubmission() {
  if (pending.value) void submit(pending.value.input.action);
}
function retryCancellation() {
  if (pendingCancel.value) void cancel(pendingCancel.value.id);
}
function inspectTask(task: Fail2banExistingTaskStatus) {
  viewedID.value = task.id;
  confirmStop.value = false;
  schedule();
}
function usePreview(task: Fail2banExistingTaskStatus) {
  const value = task.result?.plan;
  if (
    !value ||
    task.input.action !== "preview" ||
    task.state !== "succeeded" ||
    resource.value?.adoption_id !== value.adoption_id ||
    editingDisabled.value
  )
    return;
  setPolicy(value.after);
  viewedID.value = task.id;
  now.value = Date.now();
  previewContext.value = {
    id: task.id,
    adoption: value.adoption_id,
    fingerprint: fingerprint.value,
  };
  confirmStop.value = false;
  schedule();
}
onMounted(() => {
  void loadResources();
  void refreshTasks();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
  detailController?.abort();
  if (timer) clearTimeout(timer);
});
</script>

<template>
  <section class="panel page-stack">
    <div class="actions">
      <h3>已接管的已有 jail</h3>
      <NButton
        :disabled="busy"
        :loading="reading"
        @click="
          loadResources();
          refreshTasks();
        "
        >刷新</NButton
      >
    </div>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="historyError" type="error"
      >任务记录读取失败：{{ historyError }}</NAlert
    >
    <NAlert v-if="notice" type="info">{{ notice }}</NAlert>
    <p v-if="!resources.length" class="muted">暂无本机已接管的 jail。</p>
    <template v-else>
      <NFormItem label="Jail"
        ><NSelect
          v-model:value="selected"
          :options="
            resources.map((item) => ({ label: item.name, value: item.name }))
          "
          :disabled="busy || !!pending || !!pendingCancel"
          :loading="detailReading"
      /></NFormItem>
      <NButton
        :disabled="!selected || busy || active || !!pending"
        :loading="detailReading"
        @click="loadResource(selected)"
        >重新读取保存参数</NButton
      >
      <template v-if="resource">
        <p class="muted">
          SSH ·
          {{ logs[resource.profile.log_source] ?? resource.profile.log_source }}
          · 端口 {{ resource.profile.ports.join("、") }}
        </p>
        <NAlert type="info"
          >下列参数来自已保存记录；运行状态以预览和应用回执为准。</NAlert
        >
        <div class="actions">
          <NFormItem label="启用此 jail"
            ><NSwitch v-model:value="enabled" :disabled="editingDisabled"
          /></NFormItem>
          <NFormItem label="封禁时间（秒，-1 为永久）"
            ><NInputNumber
              v-model:value="banTime"
              :min="-1"
              :max="31536000"
              :precision="0"
              :disabled="editingDisabled"
          /></NFormItem>
          <NFormItem label="统计窗口（秒）"
            ><NInputNumber
              v-model:value="findTime"
              :min="1"
              :max="86400"
              :precision="0"
              :disabled="editingDisabled"
          /></NFormItem>
          <NFormItem label="重试阈值"
            ><NInputNumber
              v-model:value="maxRetry"
              :min="1"
              :max="1000"
              :precision="0"
              :disabled="editingDisabled"
          /></NFormItem>
        </div>
        <NFormItem label="忽略的 IP/CIDR（每行一项）"
          ><NInput
            v-model:value="ignoreIPs"
            type="textarea"
            :disabled="editingDisabled"
        /></NFormItem>
        <div class="actions">
          <NButton
            :loading="busy"
            :disabled="editingDisabled || !loaded || !policy || detailReading"
            @click="submit('preview')"
            >预览参数变更</NButton
          >
        </div>
      </template>
    </template>
    <NAlert v-if="pending" type="warning"
      >提交结果未确认，请重试同一请求。<NButton
        :disabled="busy || !canWrite"
        @click="retrySubmission"
        >重试提交</NButton
      ></NAlert
    >
    <NAlert v-if="pendingCancel" type="warning"
      >取消申请的提交结果未确认。<NButton
        :disabled="busy || !canWrite"
        @click="retryCancellation"
        >重试取消申请</NButton
      ></NAlert
    >
    <template v-if="plan && viewed">
      <h4>
        {{ plan.name }} ·
        {{ viewed.input.action === "preview" ? "参数预览" : "应用结果" }}
      </h4>
      <p>
        采样时间 {{ time(plan.at) }} · 采样时封禁 {{ plan.ban_count }} 个地址
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>参数</th>
              <th>变更前</th>
              <th>期望值</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>启用</td>
              <td>{{ plan.before.enabled ? "是" : "否" }}</td>
              <td>{{ plan.after.enabled ? "是" : "否" }}</td>
            </tr>
            <tr>
              <td>封禁时间</td>
              <td>{{ duration(plan.before.ban_time) }}</td>
              <td>{{ duration(plan.after.ban_time) }}</td>
            </tr>
            <tr>
              <td>统计窗口</td>
              <td>{{ duration(plan.before.find_time) }}</td>
              <td>{{ duration(plan.after.find_time) }}</td>
            </tr>
            <tr>
              <td>重试阈值</td>
              <td>{{ plan.before.max_retry }}</td>
              <td>{{ plan.after.max_retry }}</td>
            </tr>
            <tr>
              <td>忽略 IP/CIDR</td>
              <td>{{ plan.before.ignore_ips.join("、") || "无" }}</td>
              <td>{{ plan.after.ignore_ips.join("、") || "无" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <NAlert v-if="plan.stop_confirmation" type="warning"
        >停用会结束此 SSH jail
        的当前封禁保护；封禁集合变化后须重新预览。</NAlert
      >
      <p v-else class="muted">
        仅调整此 jail。继续启用时，应用须核对原未到期封禁仍被保留。
      </p>
      <template
        v-if="viewed.input.action === 'preview' && viewed.state === 'succeeded'"
      >
        <p class="muted">预览有效期至 {{ time(plan.at + 300) }}。</p>
        <NButton
          v-if="!ready"
          :disabled="
            editingDisabled ||
            resource?.adoption_id !== plan.adoption_id ||
            now - plan.at * 1000 > 300000
          "
          @click="usePreview(viewed)"
          >载入此预览的期望参数</NButton
        >
        <NCheckbox
          v-if="plan.stop_confirmation && ready"
          v-model:checked="confirmStop"
          >确认停用此 SSH jail 并结束其当前保护</NCheckbox
        >
        <NPopconfirm @positive-click="submit('apply')"
          ><template #trigger
            ><NButton
              type="primary"
              :disabled="!ready || (plan.stop_confirmation && !confirmStop)"
              >应用预览参数</NButton
            ></template
          >确认应用此 jail 的参数变更？</NPopconfirm
        >
      </template>
    </template>
    <Fail2banAddressPanel
      v-if="resource"
      :key="resource.adoption_id"
      engine-owner="existing"
      :adoption-id="resource.adoption_id"
      :jail="resource.name"
      :module-enabled="moduleEnabled"
    />
    <h4>最近参数操作</h4>
    <div v-for="task in tasks" :key="task.id" class="page-stack">
      <div class="actions">
        <strong>{{
          task.result?.plan?.name ??
          resources.find((item) => item.adoption_id === task.input.adoption_id)
            ?.name ??
          "原接管登记"
        }}</strong>
        <span
          >{{ task.input.action === "preview" ? "预览" : "应用" }} ·
          {{ time(task.created_at) }}</span
        >
        <NTag>{{
          task.stage === "cancelled"
            ? "已取消"
            : (stageNames[task.stage] ?? stateNames[task.state] ?? "等待核对")
        }}</NTag>
        <NButton
          v-if="task.result?.plan"
          size="small"
          @click="inspectTask(task)"
          >查看参数</NButton
        >
        <NPopconfirm
          v-if="
            activeStates.has(task.state) && task.stage !== 'restore_isolated'
          "
          @positive-click="cancel(task.id)"
          ><template #trigger
            ><NButton
              size="small"
              :disabled="
                !canWrite ||
                busy ||
                !!pending ||
                !!pendingCancel ||
                (task.cancel_requested && !task.cancel_error)
              "
              >申请取消</NButton
            ></template
          >取消结果须核对原运行状态，已完成的变更需另建恢复计划。</NPopconfirm
        >
      </div>
      <NAlert v-if="task.error" type="error">{{ task.error }}</NAlert>
      <NAlert v-if="task.cancel_error" type="warning"
        >取消申请未完成：{{ task.cancel_error }}</NAlert
      >
      <p
        v-else-if="task.cancel_requested && task.stage !== 'cancelled'"
        class="muted"
      >
        {{
          task.cancel_pending
            ? "取消申请等待提交核对"
            : task.result?.cancel_requested
              ? "取消申请已受理，以最终运行回执为准"
              : "取消申请已核对，请查看任务结果"
        }}
      </p>
    </div>
  </section>
</template>
