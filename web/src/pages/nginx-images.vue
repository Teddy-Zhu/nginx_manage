<route lang="json">
{
  "meta": {
    "title": "更新 Nginx",
    "subtitle": "更新 Nginx 运行镜像",
    "nav": false,
    "order": 7.25,
    "symbol": "◇",
    "parent": "/components",
    "software": "nginx"
  }
}
</route>
<script setup lang="ts">
import TaskLogButton from "../components/TaskLogButton.vue";
import ComponentVersionDialog from "../components/ComponentVersionDialog.vue";
import {
  compareComponentVersions,
  nginxEngineVersion,
} from "../utils/component-version";
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
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
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import { inspectTask } from "../stores/operation";
import { randomUUID } from "../utils/crypto";

const api = useNodeAPI(),
  route = useRoute(),
  session = useSession(),
  { run, busy } = useAction();
const channel = ref<"stable" | "beta">("stable"),
  prerelease = computed(() => channel.value === "beta");
let keyFor = useIdempotency();
const allowDowntime = ref(false),
  lastID = ref("");
const choosingVersion = ref(false),
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
        task.result.input.prerelease === prerelease.value &&
        (!targetVersion.value || release?.tag === targetVersion.value.id) &&
        !!release &&
        matchesEngine(release.notes) &&
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
  prepared.value.find(
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
    allowDowntime.value &&
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
async function submit(input: ComponentCreateInput) {
  await run(async () => {
    const task = await api.createComponentTask(input, randomUUID());
    preparations.value = [
      task,
      ...preparations.value.filter((item) => item.id !== task.id),
    ];
    lastID.value = task.id;
    if (input.input.action === "prepare") selected.value = task.id;
    inspectTask(task.id, "Nginx 镜像准备日志");
  });
  await load();
}
async function check() {
  await submit({
    input: {
      action: "check",
      components: ["nginx"],
      tag: targetVersion.value?.id ?? "",
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
  allowDowntime.value = false;
  targetVersion.value = version;
  choosingVersion.value = false;
  await check();
}
async function prepare() {
  const task = checked.value,
    source = task?.result;
  if (
    !task ||
    !source?.release ||
    !source.runtime_ready ||
    engineMismatch.value
  )
    return;
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
async function load() {
  if (reading.value || closed) return;
  reading.value = true;
  controller = new AbortController();
  try {
    const [sources, items, overview] = await Promise.all([
      api.componentTasks(controller.signal),
      api.nginxImageUpgrades(controller.signal),
      api.components(controller.signal),
    ]);
    preparations.value = sources;
    const requested = sources.find((item) => item.id === selected.value);
    if (requested)
      channel.value = requested.result?.input.prerelease ? "beta" : "stable";
    tasks.value = items;
    currentVersion.value = overview.versions?.nginx ?? null;
    currentEngine.value = overview.installation?.version ?? "";
    error.value = "";
    if (!prepared.value.some((t) => t.id === selected.value))
      selected.value = prepared.value[0]?.id ?? "";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    reading.value = false;
  }
}
async function upgrade() {
  if (!canCreate.value) return;
  const input = {
    prepare_task_id: selected.value,
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
onMounted(() => {
  void load();
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
    submit-text="检查此版本"
    @choose="chooseVersion"
    @cancel="choosingVersion = false"
  />
  <div class="page-stack">
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>Nginx 版本管理</h2>
        <NButton :loading="reading" @click="load"> 刷新 </NButton>
      </div>
      <p class="muted">
        检查并准备签名镜像，确认后即可应用更新。网站配置与证书会保留。
      </p>
      <NAlert type="info">
        更新期间网站服务会短暂中断，失败时将尝试恢复原版本。
      </NAlert>
      <div class="button-row">
        <NButton
          type="primary"
          :loading="busy || active"
          :disabled="!canWrite || active"
          @click="choosingVersion = true"
        >
          {{ active ? "正在处理" : "选择版本" }}
        </NButton>
      </div>
      <p v-if="channel === 'beta'" class="muted">
        Beta 版本用于提前体验新功能，可能存在尚未修复的问题。
      </p>
      <NAlert v-if="last?.error" type="error">
        {{ last.error }}
      </NAlert>
      <NAlert v-if="downgrade" type="warning">
        目标版本较旧，现有配置或数据可能不兼容。确认后仍可切换，失败时将尝试恢复原版本。
      </NAlert>
      <div v-if="last" class="button-row">
        <NTag
          :type="
            last.state === 'succeeded'
              ? 'success'
              : last.state === 'failed'
                ? 'error'
                : 'info'
          "
        >
          {{
            last.state === "succeeded"
              ? "已完成"
              : last.state === "failed"
                ? "未完成"
                : "正在处理"
          }} </NTag
        ><TaskLogButton :task-id="last.id" />
      </div>
      <section v-if="release" class="page-stack">
        <div class="toolbar">
          <strong
            >组件 {{ release.version
            }}<template v-if="engineVersion">
              · Nginx {{ engineVersion }}</template
            ></strong
          >
          <NTag v-if="preparedForRelease" type="success"> 已准备 </NTag>
        </div>
        <NAlert v-if="engineMismatch" type="error">
          发行中的 Nginx 版本与所选版本不一致，请刷新版本列表后重新选择。
        </NAlert>
        <NAlert v-if="!checked?.result?.runtime_ready" type="warning">
          当前环境暂不满足更新条件，请查看检查日志。
        </NAlert>
        <div class="button-row">
          <NButton
            v-if="!preparedForRelease"
            type="primary"
            :loading="busy || active"
            :disabled="
              !canWrite ||
              active ||
              engineMismatch ||
              !checked?.result?.runtime_ready ||
              release.expires_at * 1000 <= Date.now()
            "
            @click="prepare"
          >
            准备镜像 </NButton
          ><TaskLogButton
            v-if="preparedForRelease"
            :task-id="preparedForRelease.id"
          />
        </div>
      </section>
      <NEmpty v-if="!prepared.length" description="尚未准备可用镜像" />
      <NFormItem v-else label="准备好的版本">
        <NSelect
          v-model:value="selected"
          :options="
            prepared.map((task) => ({
              label: preparedLabel(task),
              value: task.id,
            }))
          "
          placeholder="选择镜像版本"
          :disabled="!canWrite || busy || active"
        />
      </NFormItem>
      <NCheckbox
        v-if="canWrite"
        v-model:checked="allowDowntime"
        :disabled="busy || active"
      >
        允许 Nginx 服务短暂中断
      </NCheckbox>
      <div v-if="canWrite">
        <NPopconfirm
          :disabled="!canCreate"
          positive-text="开始更新"
          @positive-click="upgrade"
        >
          <template #trigger>
            <NButton type="primary" :disabled="!canCreate" :loading="busy">
              立即更新
            </NButton> </template
          >确认将 Nginx 更新到 {{ chosen?.result?.release?.version }}？
        </NPopconfirm>
      </div>
    </section>
    <section class="panel page-stack">
      <h2>更新记录</h2>
      <NEmpty v-if="!tasks.length" description="暂无更新记录" />
      <article v-for="task in tasks" :key="task.id" class="panel page-stack">
        <TaskLogButton :task-id="task.id" />
        <div class="toolbar">
          <strong>{{ states[task.state] ?? "状态待确认" }}</strong
          ><NTag
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
              <NButton :loading="busy"> 继续更新 </NButton> </template
            >确认继续更新？失败时将恢复原版本。
          </NPopconfirm>
        </div>
      </article>
    </section>
  </div>
</template>
