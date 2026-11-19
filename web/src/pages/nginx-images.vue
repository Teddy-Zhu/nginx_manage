<route lang="json">
{
  "meta": {
    "title": "Nginx 版本管理",
    "nav": false,
    "order": 7.25,
    "symbol": "◇",
    "parent": "/components"
  }
}
</route>
<script setup lang="ts">
import DetailDialog from "../components/DetailDialog.vue";
import TaskLogButton from "../components/TaskLogButton.vue";
import ComponentVersionDialog from "../components/ComponentVersionDialog.vue";
import {
  compareComponentVersions,
  nginxEngineVersion,
} from "../utils/component-version";
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  NAlert,
  NButton,
  NEmpty,
  NFormItem,
  NPopconfirm,
  NSelect,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  type ImageUpgradeTask,
  type ComponentCreateInput,
  type ComponentTask,
  type ComponentVersion,
  type ComponentOverview,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import { taskStateLabel, taskStageSummary, taskStateTone } from "../utils/tasks";

const router = useRouter();
const api = useNodeAPI(),
  route = useRoute(),
  session = useSession(),
  { run, busy } = useAction();
const channel = ref<"stable" | "beta">("stable"),
  prerelease = computed(() => channel.value === "beta");
let keyFor = useIdempotency();
const lastID = ref("");
const choosingVersion = ref(false),
  showRelease = ref(false),
  showPrepared = ref(false),
  workflowError = ref(""),
  overview = ref<ComponentOverview | null>(null),
  targetVersion = ref<ComponentVersion | null>(null),
  currentVersion = ref<ComponentVersion | null>(null),
  currentEngine = ref("");
const preparations = ref<ComponentTask[]>([]),
  tasks = ref<ImageUpgradeTask[]>([]),
  selected = ref(
    typeof route.query.prepare === "string" ? route.query.prepare : "",
  ),
  error = ref("");
const canWrite = computed(
  () =>
    !!session.me?.scopes.includes("components.manage") &&
    !!session.me?.scopes.includes("system.write"),
);
watch(
  () => route.query.prepare,
  (id) => {
    selected.value = typeof id === "string" ? id : "";
  },
);
const canChooseVersion = computed(() =>
  canWrite.value && !!overview.value?.available && !busy.value && !active.value,
);
function containsNginxImage(task: ComponentTask) {
  const release = task.result?.release;
  if (!release) return false;
  return (
    release.selected.includes("image-nginx") &&
    release.images.some((image) => image.id === "nginx")
  );
}
const nginxOperations = computed(() =>
  preparations.value.filter(
    (task) =>
      task.id === lastID.value ||
      task.result?.input.components?.includes("nginx") ||
      containsNginxImage(task),
  ),
);
const checked = computed(
  () =>
    nginxOperations.value
      .filter(
        (task) =>
          task.action === "check" &&
          task.state === "succeeded" &&
          task.result?.input.prerelease === prerelease.value &&
          (!targetVersion.value ||
            task.result?.input.tag === targetVersion.value.id) &&
          containsNginxImage(task),
      )
      .sort((a, b) => b.created_at - a.created_at)[0],
);
const release = computed(() => checked.value?.result?.release);
const engineVersion = computed(() => nginxEngineVersion(release.value?.notes));
const engineMismatch = computed(
  () => !!release.value && !matchesEngine(release.value.notes),
);
function matchesEngine(notes?: string) {
  const expected = targetVersion.value?.software_version;
  return !expected || expected === nginxEngineVersion(notes);
}
const prepared = computed(() =>
  nginxOperations.value
    .filter((task) => {
      const release = task.result?.release;
      return (
        task.action === "prepare" &&
        task.state === "succeeded" &&
        task.result?.runtime_ready &&
        !!release &&
        containsNginxImage(task) &&
        release.expires_at * 1000 > Date.now()
      );
    })
    .sort((a, b) => b.created_at - a.created_at),
);
const chosen = computed(() =>
  prepared.value.find((t) => t.id === selected.value),
);
const downgrade = computed(() => {
  const target = chosen.value?.result?.release;
  if (!target) return false;
  return (
    (compareComponentVersions(
      target.version,
      currentVersion.value?.version ?? "",
    ) ?? 0) < 0 ||
    (compareComponentVersions(
      nginxEngineVersion(target.notes) ?? "",
      currentEngine.value,
    ) ?? 0) < 0
  );
});
const preparedForRelease = computed(() =>
  engineMismatch.value
    ? undefined
    : prepared.value.find(
        (task) => task.result?.release?.plan_id === release.value?.plan_id,
      ),
);
const last = computed(() =>
  preparations.value.find((task) => task.id === lastID.value),
);
const active = computed(
  () =>
    nginxOperations.value.some((task) =>
      ["queued", "running", "recovery_required"].includes(task.state),
    ) ||
    tasks.value.some(
      (task) =>
        task.stage !== "restore_isolated" &&
        !["succeeded", "failed", "rolled_back", "cancelled"].includes(
          task.state,
        ),
    ),
);
const canCreate = computed(
  () =>
    canWrite.value &&
    !!chosen.value &&
    !active.value &&
    !!overview.value?.installation &&
    !busy.value,
);
const states: Record<string, string> = {
  queued: "排队中",
  running: "切换中",
  compensating: "恢复原版本",
  recovery_required: "待恢复",
  succeeded: "切换完成",
  failed: "切换未完成",
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
  maintenance_unconfirmed: "等待操作准备",
  epoch_changed: "操作授权已变化",
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
function preparedLabel(task: ComponentTask) {
  const release = task.result?.release;
  const engine = nginxEngineVersion(release?.notes);
  return [
    engine ? `Nginx ${engine}` : "",
    `组件 ${release?.version ?? ""}`,
    date(task.created_at),
  ]
    .filter(Boolean)
    .join(" · ");
}
let workflowKey = useIdempotency();
async function submit(input: ComponentCreateInput) {
  workflowError.value = "";
  await run(async () => {
    try {
      const task = await api.createComponentTask(input, workflowKey(input), false);
      preparations.value = [
        task,
        ...preparations.value.filter((item) => item.id !== task.id),
      ];
      lastID.value = task.id;
      if (input.input.action === "prepare") selected.value = task.id;
      workflowKey = useIdempotency();
    } catch (cause) {
      workflowError.value = apiError(cause).message;
    }
  });
  await load();
}
async function check() {
  if (!targetVersion.value || busy.value || active.value) return;
  await submit({
    input: {
      action: "check",
      components: ["nginx"],
      tag: targetVersion.value.id,
      prerelease: prerelease.value,
      plan_id: "",
      manifest_sha256: "",
      trust_sha256: "",
    },
  });
}
async function chooseVersion(version: ComponentVersion) {
  channel.value = version.channel;
  selected.value = "";
  lastID.value = "";
  targetVersion.value = version;
  choosingVersion.value = false;
  showRelease.value = true;
  await check();
}
async function prepare() {
  const task = checked.value,
    source = task?.result;
  if (!task || !source?.release || !source.runtime_ready || engineMismatch.value) return;
  await submit({
    check_task_id: task.id,
    input: {
      action: "prepare",
      tag: source.release.tag,
      prerelease: source.input.prerelease,
      assets: source.release.selected,
      plan_id: source.release.plan_id,
      manifest_sha256: source.release.manifest_sha256,
      trust_sha256: source.release.trust_sha256,
      offline_id: source.input.offline_id,
    },
  });
}
async function pullRuntime(item?: ComponentTask) {
  const source = item?.result;
  if (!item || !source?.release || !canWrite.value || active.value || busy.value ||
    !overview.value || overview.value.installation) return;
  const input: ComponentCreateInput = {
    prepare_task_id: item.id,
    input: {
      action: "pull",
      image_id: "nginx",
      tag: source.release.tag,
      prerelease: source.input.prerelease,
      assets: source.release.selected,
      plan_id: source.release.plan_id,
      manifest_sha256: source.release.manifest_sha256,
      trust_sha256: source.release.trust_sha256,
      offline_id: source.input.offline_id,
    },
  };
  showPrepared.value = showRelease.value = false;
  await run(async () => {
    const task = await api.pullComponentImage(input, workflowKey(input));
    preparations.value = [task, ...preparations.value.filter(({ id }) => id !== task.id)];
    lastID.value = task.id;
    workflowKey = useIdempotency();
  });
  await load();
}
function canResume(t: ImageUpgradeTask) {
  const result = t.result;
  return (
    canWrite.value &&
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
async function load(readVersion = false) {
  if (reading.value || closed) return;
  reading.value = true;
  controller = new AbortController();
  try {
    const [sources, items] = await Promise.all([
      api.componentTasks(controller.signal),
      api.nginxImageUpgrades(controller.signal),
    ]);
    preparations.value = sources;
    const settled = tasks.value.some(
      (task) => task.state !== "succeeded" &&
        items.some((item) => item.id === task.id && item.state === "succeeded"),
    );
    tasks.value = items;
    if (readVersion || settled) {
      overview.value = await api.components(controller.signal);
      currentVersion.value = overview.value.versions?.nginx ?? null;
      currentEngine.value = overview.value.installation?.version ?? "";
    }
    error.value = "";
    if (showRelease.value && preparedForRelease.value)
      selected.value = preparedForRelease.value.id;
    else if (!prepared.value.some((t) => t.id === selected.value))
      selected.value = prepared.value[0]?.id ?? "";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    reading.value = false;
  }
}
async function upgrade(item = chosen.value) {
  if (!item || !canWrite.value || active.value || busy.value ||
    !overview.value?.installation) return;
  showPrepared.value = showRelease.value = false;
  const input = {
    prepare_task_id: item.id,
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
function openRelease() {
  showRelease.value = true;
  if (preparedForRelease.value) selected.value = preparedForRelease.value.id;
}
async function openFromStore() {
  if (route.query.choose !== "1") return;
  if (canChooseVersion.value) choosingVersion.value = true;
  await router.replace({ query: { ...route.query, choose: undefined } });
}
onMounted(async () => {
  await load(true);
  if (!closed) await openFromStore();
});
watch(() => route.query.choose, () => {
  if (!reading.value) void openFromStore();
});
onUnmounted(() => {
  closed = true;
  controller?.abort();
});
useLiveRefresh(api, ["tasks"], load, () => reading.value);
</script>
<template>
  <ComponentVersionDialog
    :show="choosingVersion"
    name="Nginx"
    app-id="nginx"
    :busy="busy || active"
    submit-text="继续"
    @choose="chooseVersion"
    @cancel="choosingVersion = false"
  />
  <DetailDialog
    v-model:show="showRelease"
    body-height="300px"
    :title="targetVersion ? 'Nginx ' + (targetVersion.software_version || targetVersion.version) : '版本详情'"
  >
    <div class="page-stack">
      <div class="button-row">
        <strong v-if="release">组件 {{ release.version }}</strong>
        <strong v-if="!targetVersion && engineVersion">Nginx {{ engineVersion }}</strong>
        <NTag v-if="preparedForRelease" type="success">
          镜像已准备
        </NTag>
        <NTag v-else-if="last" :type="taskStateTone(last.state)">
          {{ taskStateLabel(last.state) }}
        </NTag>
        <span v-else-if="busy">正在提交版本检查</span>
      </div>
      <p v-if="last && !preparedForRelease && taskStageSummary(last.stage, 'component.' + last.action, last.state)" class="muted">
        {{ taskStageSummary(last.stage, 'component.' + last.action, last.state) }}
      </p>
      <NAlert v-if="workflowError || last?.error" type="error">
        {{ workflowError || last?.error }}
      </NAlert>
      <NAlert v-if="engineMismatch" type="error">
        发行包中的 Nginx 版本与所选版本不一致。
      </NAlert>
      <NAlert v-else-if="release && !checked?.result?.runtime_ready" type="warning">
        当前服务器不满足此版本的运行条件。
      </NAlert>
      <NAlert v-if="preparedForRelease && downgrade" type="warning">
        目标版本较旧，确认兼容性后再切换。
      </NAlert>
    </div>
    <template #actions>
      <TaskLogButton v-if="last || checked" :task-id="(last ?? checked)!.id" />
      <NButton
        v-if="!release && targetVersion && (workflowError || last?.state === 'failed')"
        :disabled="busy || active"
        @click="check"
      >
        重试检查
      </NButton>
      <NButton
        v-if="release && !preparedForRelease"
        type="primary"
        :loading="busy || last?.action === 'prepare' && active"
        :disabled="!canWrite || busy || active || engineMismatch || !checked?.result?.runtime_ready || release.expires_at * 1000 <= Date.now()"
        @click="prepare"
      >
        准备镜像
      </NButton>
      <NPopconfirm
        v-if="preparedForRelease && overview?.installation"
        positive-text="切换版本"
        @positive-click="upgrade(preparedForRelease)"
      >
        <template #trigger>
          <NButton type="primary" :disabled="!canCreate || chosen?.id !== preparedForRelease.id">
            切换到此版本
          </NButton>
        </template>
        切换会短暂中断 Nginx 服务。确认切换到 {{ release?.version }}？
      </NPopconfirm>
      <NButton
        v-else-if="preparedForRelease && overview"
        type="primary"
        :disabled="!canWrite || busy || active"
        @click="pullRuntime(preparedForRelease)"
      >
        下载运行环境
      </NButton>
    </template>
  </DetailDialog>
  <DetailDialog v-model:show="showPrepared" title="已准备镜像">
    <NFormItem label="版本">
      <NSelect
        v-model:value="selected"
        :options="prepared.map((task) => ({ label: preparedLabel(task), value: task.id }))"
        placeholder="选择镜像版本"
      />
    </NFormItem>
    <NAlert v-if="downgrade" type="warning">
      目标版本较旧，确认兼容性后再切换。
    </NAlert>
    <template #actions>
      <NPopconfirm v-if="overview?.installation" positive-text="切换版本" @positive-click="upgrade()">
        <template #trigger>
          <NButton type="primary" :disabled="!canCreate">
            切换到此版本
          </NButton>
        </template>
        切换会短暂中断 Nginx 服务。确认切换到 {{ chosen?.result?.release?.version }}？
      </NPopconfirm>
      <NButton v-else-if="overview" type="primary" :disabled="!chosen || !canWrite || busy || active" @click="pullRuntime(chosen)">
        下载运行环境
      </NButton>
    </template>
  </DetailDialog>
  <div class="page-stack">
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>Nginx 版本管理</h2>
        <NButton :loading="reading" @click="load(true)">
          刷新
        </NButton>
      </div>
      <div v-if="currentEngine" class="button-row">
        <span class="muted">已安装</span>
        <strong>Nginx {{ currentEngine }}</strong>
        <span v-if="currentVersion" class="muted">
          组件 {{ currentVersion.version }}
        </span>
      </div>
      <NAlert v-if="overview && !overview.available" type="warning">
        {{ overview.reason || "安装源暂不可用" }}
      </NAlert>
      <div class="button-row">
        <NButton type="primary" :disabled="!canChooseVersion" @click="choosingVersion = true">
          选择版本
        </NButton>
        <NButton :disabled="!release && !targetVersion" @click="openRelease">
          版本详情
        </NButton>
        <NButton :disabled="!prepared.length" @click="showPrepared = true">
          已准备镜像
        </NButton>
      </div>
    </section>
    <section class="panel page-stack">
      <h2>更新记录</h2>
      <NEmpty v-if="!tasks.length" description="暂无更新记录" />
      <article v-for="task in tasks" :key="task.id" class="panel page-stack">
        <TaskLogButton :task-id="task.id" />
        <div class="toolbar">
          <strong>{{ states[task.state] ?? "状态待确认" }}</strong><NTag
            :type="
              task.state === 'succeeded'
                ? 'success'
                : ['failed', 'recovery_required'].includes(task.state)
                  ? 'warning'
                  : 'info'
            "
          >
            {{ stages[task.stage] ?? "正在处理" }}
          </NTag>
        </div>
        <p class="muted">
          {{ date(task.created_at) }}
        </p>
        <p v-if="task.result">
          Nginx 引擎 {{ task.result.target_version }} ·
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
        >
          {{ task.error }}
        </NAlert>
        <div v-if="canResume(task)">
          <NPopconfirm positive-text="继续更新" @positive-click="resume(task)">
            <template #trigger>
              <NButton :loading="busy">
                继续更新
              </NButton>
            </template>确认继续更新？失败时将恢复原版本。
          </NPopconfirm>
        </div>
      </article>
    </section>
  </div>
</template>
