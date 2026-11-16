<route lang="json">
{
  "meta": {
    "title": "系统更新",
    "subtitle": "检查版本与更新记录",
    "order": 30,
    "localOnly": true,
    "parent": "/settings"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { NAlert, NButton, NCheckbox, NEmpty, NTag } from "naive-ui";
import {
  useNodeAPI,
  type ComponentCreateInput,
  type ComponentTask,
} from "../api/client";
import { useAction } from "../composables/action";
import { useLiveRefresh } from "../composables/live";
import { useSession } from "../stores/session";
import { inspectTask } from "../stores/operation";
import { taskStates } from "../utils/tasks";
import { randomUUID } from "../utils/crypto";
import TaskLogButton from "../components/TaskLogButton.vue";
const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction();
const tasks = ref<ComponentTask[]>([]),
  version = ref(""),
  prerelease = ref(false),
  lastID = ref("");
const permitted = computed(
  () =>
    session.me?.scopes.includes("components.manage") &&
    session.me.scopes.includes("system.write"),
);
function containsSelectedPanelAsset(task: ComponentTask) {
  const release = task.result?.release;
  return !!release?.assets.some(
    (asset) =>
      asset.component === "panel" && release.selected.includes(asset.id),
  );
}
const panelOperations = computed(() =>
  tasks.value.filter(
    (task) =>
      task.result?.input.components?.includes("panel") ||
      containsSelectedPanelAsset(task) ||
      task.result?.input.software?.action === "update-panel",
  ),
);
const active = computed(() =>
  panelOperations.value.some(
    (task) =>
      ["queued", "running", "recovery_required"].includes(task.state) &&
      task.stage !== "restore_isolated",
  ),
);
const last = computed(() => tasks.value.find((t) => t.id === lastID.value));
const checked = computed(() =>
  tasks.value.find(
    (t) =>
      t.action === "check" &&
      t.state === "succeeded" &&
      t.result?.input.prerelease === prerelease.value &&
      t.result?.release?.assets.some(
        (a) =>
          a.component === "panel" && t.result!.release!.selected.includes(a.id),
      ),
  ),
);
const release = computed(() => checked.value?.result?.release);
const prepared = computed(() =>
  tasks.value.find(
    (t) =>
      t.action === "prepare" &&
      t.state === "succeeded" &&
      t.result?.panel &&
      t.result.input.plan_id === release.value?.plan_id,
  ),
);
const history = computed(() =>
  tasks.value
    .filter((t) => t.result?.input.software?.action === "update-panel")
    .slice(0, 10),
);
async function load() {
  await run(async () => {
    const [items, current] = await Promise.all([
      api.componentTasks(),
      api.systemVersion(),
    ]);
    tasks.value = items;
    version.value = current.version;
  });
}
async function submit(input: ComponentCreateInput) {
  await run(async () => {
    const task = await api.createComponentTask(input, randomUUID());
    lastID.value = task.id;
    tasks.value = [task, ...tasks.value.filter((t) => t.id !== task.id)];
    inspectTask(
      task.id,
      input.input.action === "software" ? "系统更新日志" : "更新准备日志",
    );
  });
}
async function check() {
  await submit({
    input: {
      action: "check",
      components: ["panel"],
      tag: "",
      prerelease: prerelease.value,
      plan_id: "",
      manifest_sha256: "",
      trust_sha256: "",
    },
  });
}
async function download() {
  const r = release.value,
    t = checked.value;
  if (!r || !t) return;
  await submit({
    check_task_id: t.id,
    input: {
      action: "prepare",
      tag: r.tag,
      prerelease: prerelease.value,
      assets: r.selected,
      plan_id: r.plan_id,
      manifest_sha256: r.manifest_sha256,
      trust_sha256: r.trust_sha256,
      offline_id: t.result?.input.offline_id,
    },
  });
}
async function update() {
  const t = prepared.value;
  if (!t?.result?.release) return;
  if (!window.confirm("现在更新系统？面板连接将短暂中断，已有数据会保留。"))
    return;
  await submit({
    input: {
      action: "software",
      tag: "",
      prerelease: false,
      plan_id: "",
      manifest_sha256: "",
      trust_sha256: "",
      software: {
        action: "update-panel",
        plan_id: t.result.release.plan_id,
        prerelease: t.result.input.prerelease,
      },
    },
  });
}
useLiveRefresh(api, ["tasks"], load, () => busy.value);
onMounted(load);
</script>
<template>
  <div class="page-stack">
    <section class="panel page-stack">
      <div class="section-heading">
        <div>
          <h3>当前版本</h3>
          <p class="current-version">{{ version || "正在读取" }}</p>
        </div>
        <NButton :loading="busy" @click="load">刷新</NButton>
      </div>
      <p class="muted">
        检查并下载新版本后，即可更新。更新期间面板会短暂断开，完成后自动恢复连接。
      </p>
      <div class="button-row">
        <NButton
          type="primary"
          :loading="busy || active"
          :disabled="!permitted || active"
          @click="check"
          >{{ active ? "正在处理" : "检查更新" }}</NButton
        ><NCheckbox v-model:checked="prerelease" :disabled="busy || active"
          >包含预览版本</NCheckbox
        >
      </div>
      <NAlert v-if="last?.error" type="error">{{ last.error }}</NAlert>
      <div v-if="last" class="button-row">
        <NTag
          :type="
            last.state === 'succeeded'
              ? 'success'
              : last.state === 'failed'
                ? 'error'
                : 'info'
          "
          >{{ taskStates[last.state] || "正在处理" }}</NTag
        ><TaskLogButton :task-id="last.id" />
      </div>
    </section>
    <section v-if="release" class="panel page-stack">
      <div class="section-heading">
        <h3>可用版本 {{ release.version }}</h3>
        <NTag v-if="prepared" type="success">已下载</NTag>
      </div>
      <p v-if="release.notes">{{ release.notes }}</p>
      <p class="muted">
        下载大小：{{ (release.archive_bytes / 1048576).toFixed(1) }} MB
      </p>
      <NAlert v-if="!checked?.result?.runtime_ready" type="warning"
        >服务器暂不满足此版本的安装条件，请查看检查日志。</NAlert
      >
      <div class="button-row">
        <NButton
          v-if="!prepared"
          type="primary"
          :loading="busy || active"
          :disabled="
            !permitted ||
            active ||
            !checked?.result?.runtime_ready ||
            release.expires_at * 1000 <= Date.now()
          "
          @click="download"
          >下载更新</NButton
        ><NButton
          v-else
          type="primary"
          :loading="busy || active"
          :disabled="
            !permitted ||
            active ||
            prepared.result?.panel?.requires_coordination
          "
          @click="update"
          >立即更新</NButton
        ><TaskLogButton v-if="prepared" :task-id="prepared.id" />
      </div>
      <NAlert
        v-if="prepared?.result?.panel?.requires_coordination"
        type="warning"
        >此版本需要更新安装程序，请使用安装脚本更新。</NAlert
      >
    </section>
    <section class="panel page-stack">
      <h3>更新记录</h3>
      <NEmpty v-if="!history.length" description="暂无更新记录" />
      <article v-for="task in history" :key="task.id" class="update-record">
        <div>
          <strong>{{ taskStates[task.state] || "正在处理" }}</strong>
          <p class="muted">
            {{ new Date(task.created_at * 1000).toLocaleString() }}
          </p>
          <p v-if="task.error">{{ task.error }}</p>
        </div>
        <TaskLogButton :task-id="task.id" />
      </article>
    </section>
  </div>
</template>
<style scoped>
.current-version {
  font-size: 26px;
  font-weight: 600;
  margin: 8px 0 0;
}
.update-record {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding-top: 16px;
  border-top: 1px solid var(--border-color);
}
.update-record p {
  margin: 8px 0 0;
}
</style>
