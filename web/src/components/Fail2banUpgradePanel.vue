<script setup lang="ts">
import { randomUUID } from "../utils/crypto";

import { computed, onMounted, onUnmounted, ref } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton, NFormItem, NPopconfirm, NSelect } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentTask,
  type Fail2banUpgradeInput,
  type Fail2banUpgradeTaskStatus,
} from "../api/client";
import { useSession } from "../stores/session";

const props = defineProps<{ moduleEnabled: boolean }>();
const emit = defineEmits<{ changed: [] }>();
const api = useNodeAPI(),
  session = useSession(),
  controller = new AbortController();
const preparations = ref<ComponentTask[]>([]),
  tasks = ref<Fail2banUpgradeTaskStatus[]>([]);
const selected = ref(""),
  error = ref(""),
  historyError = ref(""),
  assetsError = ref(""),
  notice = ref("");
const reading = ref(false),
  assetsReading = ref(false),
  loaded = ref(false),
  busy = ref(false);
const pending = ref<{ input: Fail2banUpgradeInput; key: string } | null>(null);
const clock = ref(Date.now());
const activeStates = new Set([
  "queued", "running", "compensating", "recovery_required",
]);
const active = computed(() =>
  tasks.value.some((task) => activeStates.has(task.state)),
);
const permitted = computed(() =>
  session.me?.scopes.includes("components.manage") &&
  session.me.scopes.includes("security.write"),
);
const available = computed(() =>
  props.moduleEnabled && permitted.value && loaded.value &&
  !busy.value && !reading.value && !active.value && !pending.value,
);
const assets = computed(() =>
  preparations.value.flatMap((task) => {
    const release = task.result?.release;
    if (
      task.action !== "prepare" || task.state !== "succeeded" ||
      !task.result?.runtime_ready || !release ||
      release.selected.length !== 1 || release.expires_at * 1000 <= clock.value
    ) return [];
    return release.assets
      .filter((asset) =>
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
function sameSource(input: Fail2banUpgradeInput) {
  const item = chosen.value;
  if (!item?.task.result) return false;
  return input.plan_id === item.task.result.release?.plan_id &&
    input.asset_id === item.asset.id &&
    input.prerelease === item.task.result.input.prerelease;
}
const checkTask = computed(() =>
  tasks.value.find((task) => task.input.action === "check" && sameSource(task.input)),
);
const plan = computed(() => checkTask.value?.state === "succeeded"
  ? checkTask.value.result?.plan ?? null : null,
);
const preparationTask = computed(() => plan.value
  ? tasks.value.find((task) =>
      task.input.action === "prepare" && sameSource(task.input) &&
      task.input.target === plan.value?.target,
    )
  : undefined,
);
const preparation = computed(() => preparationTask.value?.state === "succeeded"
  ? preparationTask.value.result?.preparation ?? null : null,
);
const usedPreparation = computed(() => !!preparation.value &&
  tasks.value.some((task) =>
    task.input.action === "run" && task.input.preparation_id === preparation.value?.id,
  ),
);
const canPrepare = computed(() =>
  available.value && !!plan.value?.running &&
  plan.value.scope_verified && plan.value.blockers.length === 0,
);
const canRun = computed(() =>
  available.value && !!preparation.value && !usedPreparation.value,
);
const actions: Record<Fail2banUpgradeInput["action"], string> = {
  check: "候选检查", prepare: "升级准备", run: "升级实例",
};
const states: Record<string, string> = {
  queued: "排队中", running: "处理中", compensating: "恢复中",
  recovery_required: "等待恢复确认", succeeded: "已完成", failed: "未完成",
  cancelled: "已取消",
};
const stages: Record<string, string> = {
  waiting_for_admission: "等待宿主机操作结束",
  candidate_checked: "候选检查完成", upgrade_prepared: "升级材料已准备",
  protection_verified: "新版本保护已确认", original_protection_verified: "升级未完成，原版本保护已恢复",
  queued: "等待执行", executing: "正在执行", child_unconfirmed: "等待原操作恢复确认",
  authorization_expired: "排队授权已过期", request_rejected: "请求未获执行", agent_rejected: "请求未获执行",
  payload_missing: "操作材料缺失", payload_unreadable: "操作材料无法读取", payload_invalid: "操作材料无法核对",
  operation_missing: "原执行记录缺失", operation_mismatch: "原执行记录不匹配",
  reconciling: "正在核对执行结果", submit_unconfirmed: "等待提交结果确认", agent_submit_pending: "等待执行器受理",
  intent_reserved: "升级请求已保留", quiescing_original: "正在停止原实例并保存状态",
  switching_candidate: "正在切换候选", activating_candidate: "正在启动并核对候选保护",
  restoring_original: "正在恢复原版本及状态", activating_original: "正在启动并核对原版本保护",
  completion_unacknowledged: "等待完成结果确认",
};
let closed = false;
let timer: ReturnType<typeof setTimeout> | undefined;
async function loadAssets() {
  if (closed || assetsReading.value || !session.me?.scopes.includes("components.manage")) return;
  assetsReading.value = true;
  try {
    const result = await api.componentTasks(controller.signal);
    if (!closed) {
      preparations.value = result;
      clock.value = Date.now();
      assetsError.value = "";
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
  const before = new Set(tasks.value
    .filter((task) => task.input.action === "run" && activeStates.has(task.state))
    .map((task) => task.id),
  );
  try {
    const result = await api.fail2banUpgradeTasks(controller.signal);
    if (closed) return;
    tasks.value = result;
    loaded.value = true;
    historyError.value = "";
    if (result.some((task) => before.has(task.id) && !activeStates.has(task.state)))
      emit("changed");
  } catch (e) {
    if (!closed) {
      historyError.value = apiError(e).message;
      loaded.value = false;
    }
  } finally {
    if (!closed) {
      reading.value = false;
      if (active.value || pending.value)
        timer = setTimeout(() => { void refresh(); }, 3000);
    }
  }
}
async function submit(input?: Fail2banUpgradeInput) {
  if (closed || busy.value || reading.value) return;
  if (!pending.value) {
    if (!available.value || !input) return;
    pending.value = { input: { ...input }, key: randomUUID() };
  }
  if (timer) clearTimeout(timer);
  busy.value = true;
  error.value = "";
  try {
    const result = await api.changeFail2banUpgrade(pending.value.input, pending.value.key);
    if (closed) return;
    pending.value = null;
    loaded.value = false;
    notice.value = `任务已创建：${result.task_id}`;
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
function sourceInput(action: "check" | "prepare"): Fail2banUpgradeInput | null {
  const item = chosen.value,
    result = item?.task.result;
  if (!item || !result?.release) return null;
  if (result.release.expires_at * 1000 <= Date.now()) {
    error.value = "候选签名计划已过期，请重新准备组件";
    clock.value = Date.now();
    return null;
  }
  return {
    action,
    plan_id: result.release.plan_id,
    asset_id: item.asset.id,
    prerelease: result.input.prerelease,
    target: action === "prepare" ? plan.value?.target ?? "" : "",
    preparation_id: "",
  };
}
function check() {
  if (!available.value) return;
  const input = sourceInput("check");
  if (input) void submit(input);
}
function prepare() {
  if (!canPrepare.value) return;
  const input = sourceInput("prepare");
  if (input) void submit(input);
}
function run() {
  if (!canRun.value || !preparation.value) return;
  void submit({
    action: "run", plan_id: "", asset_id: "", prerelease: false,
    preparation_id: preparation.value.id,
    target: preparation.value.intent_sha256,
  });
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
      <h3>受管实例升级</h3>
      <NButton size="small" :disabled="busy" :loading="reading" @click="refresh">刷新任务</NButton>
    </div>
    <p>选择已准备的签名候选，完成检查和准备后确认升级。仅支持正在运行的独立受管实例。</p>
    <NAlert v-if="!moduleEnabled" type="warning">请先启用 Fail2ban 管理模块。</NAlert>
    <NAlert v-if="!permitted" type="info">升级需要组件管理与安全写入权限。</NAlert>
    <NFormItem label="签名候选">
      <NSelect v-model:value="selected" :options="assets" :disabled="busy || active || !!pending" placeholder="选择已准备的 Fail2ban 候选" />
    </NFormItem>
    <div class="toolbar">
      <NButton :disabled="!available || !chosen" :loading="busy && pending?.input.action === 'check'" @click="check">检查候选</NButton>
      <NButton :loading="assetsReading" @click="loadAssets">刷新候选</NButton>
      <RouterLink to="/components">准备组件</RouterLink>
    </div>
    <NAlert v-if="assetsError" type="error">{{ assetsError }}</NAlert>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="notice" type="info">{{ notice }}</NAlert>
    <NButton v-if="pending" :disabled="reading" :loading="busy" @click="() => submit()">核对并重试原请求</NButton>
    <section v-if="plan" class="surface page-stack">
      <h4>{{ plan.source_version }} → {{ plan.candidate_version }}</h4>
      <p>检查时间：{{ new Date(plan.at * 1000).toLocaleString() }}</p>
      <p>受管 jail：{{ plan.jails.join('、') || '无' }}</p>
      <p v-if="plan.bans">检查时未过期封禁：{{ plan.bans.count }}</p>
      <p>需迁移动作授权：Nginx {{ plan.nginx_grants }} 项<span v-if="plan.host_sources"> · 宿主机来源</span><span v-if="plan.host_sync"> · 持续同步</span></p>
      <NAlert v-if="!plan.running" type="warning">当前实例未运行，不能从此处执行升级。</NAlert>
      <NAlert v-if="!plan.scope_verified" type="warning">动作授权范围尚未核对完成。</NAlert>
      <NAlert v-for="blocker in plan.blockers" :key="blocker" type="warning">{{ blocker }}</NAlert>
      <NButton :disabled="!canPrepare" :loading="busy && pending?.input.action === 'prepare'" @click="prepare">准备此候选</NButton>
    </section>
    <section v-if="preparation" class="surface page-stack">
      <h4>升级材料已准备</h4>
      <p>{{ preparation.source_version }} → {{ preparation.candidate_version }} · {{ new Date(preparation.created_at * 1000).toLocaleString() }}</p>
      <NAlert type="warning">升级期间会停止并重启独立实例，封禁保护可能短暂中断。候选启动或保护核对失败时将尝试恢复原版本；恢复未确认时需保留现场处理。</NAlert>
      <NPopconfirm :disabled="!canRun" @positive-click="run">
        <template #trigger><NButton type="warning" :disabled="!canRun" :loading="busy && pending?.input.action === 'run'">确认升级</NButton></template>
        确认将独立实例从 {{ preparation.source_version }} 升级至 {{ preparation.candidate_version }}？
      </NPopconfirm>
      <p v-if="usedPreparation">此准备已提交升级，再次升级需重新检查并准备。</p>
    </section>
    <NAlert v-if="historyError" type="error">{{ historyError }}</NAlert>
    <p v-if="active">存在尚未结束的升级任务，正在核对原操作。</p>
    <p v-if="loaded && !tasks.length">暂无升级操作记录。</p>
    <article v-for="task in tasks" :key="task.id" class="surface page-stack">
      <p>{{ actions[task.input.action] }} · {{ states[task.state] || '状态未知' }} · {{ new Date(task.created_at * 1000).toLocaleString() }}</p>
      <p>任务 {{ task.id }}</p>
      <p v-if="stages[task.stage]">{{ stages[task.stage] }}</p>
      <NAlert v-if="task.error" type="warning">{{ task.error }}</NAlert>
    </article>
    <p>显示最近 16 次升级操作。</p>
  </section>
</template>
