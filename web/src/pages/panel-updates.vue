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
import { NAlert, NButton, NSelect, NEmpty, NTag, useDialog } from "naive-ui";
import { liveDisconnected } from "../api/live";
import {
  useNodeAPI,
  type ComponentCreateInput,
  type ComponentTask,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useLiveRefresh } from "../composables/live";
import { useSession } from "../stores/session";
import { loadedFrontendEntries } from "../frontend-version";
import { taskStates } from "../utils/tasks";
import { randomUUID } from "../utils/crypto";
import TaskLogButton from "../components/TaskLogButton.vue";
import {
  updateChannels,
  useUpdateChannel,
} from "../composables/update-channel";
const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction(),
  dialog = useDialog();
const upgradeKey = useIdempotency();
const {
  channel,
  prerelease,
  ready: channelReady,
  saving: savingChannel,
  loadChannel,
  saveChannel,
} = useUpdateChannel(api);
const savedCheck = "nginxpanel:update-check";
const savedUpgrade = "nginxpanel:update-task";
const tasks = ref<ComponentTask[]>([]),
  version = ref(""),
  checkID = ref(window.sessionStorage.getItem(savedCheck) ?? ""),
  upgradeID = ref(window.sessionStorage.getItem(savedUpgrade) ?? "");
const permitted = computed(
  () =>
    session.me?.scopes.includes("components.manage") &&
    session.me.scopes.includes("system.write"),
);
function pending(task: ComponentTask | undefined) {
  return task?.state === "queued" || task?.state === "running";
}
const lastCheck = computed(() =>
  tasks.value.find((task) => task.id === checkID.value),
);
const checked = computed(() =>
  tasks.value.find(
    (task) =>
      (!checkID.value || task.id === checkID.value) &&
      task.action === "check" &&
      task.state === "succeeded" &&
      task.result?.input.prerelease === prerelease.value &&
      !!task.core_update,
  ),
);
const release = computed(() => checked.value?.result?.release);
const updateStatus = computed(() => checked.value?.core_update);
const updateAvailable = computed(
  () => updateStatus.value?.state === "available",
);
const history = computed(() =>
  tasks.value
    .filter(
      (task) =>
        task.id === upgradeID.value ||
        task.result?.input.software?.action === "update-panel",
    )
    .slice(0, 10),
);
const updating = computed(() => history.value.some(pending));
const active = computed(() => pending(lastCheck.value) || updating.value);
const canUpgrade = computed(
  () =>
    updateAvailable.value &&
    !!checked.value?.result?.runtime_ready &&
    !!release.value &&
    release.value.expires_at * 1000 > Date.now(),
);
async function load() {
  if (updating.value && liveDisconnected.value) return;
  await run(async () => {
    const [items, current] = await Promise.all([
      api.componentTasks(),
      api.systemVersion(),
      loadChannel(),
    ]);
    tasks.value = items;
    version.value = current.version;
    if (
      upgradeID.value &&
      items.some(
        (item) => item.id === upgradeID.value && item.state === "succeeded",
      ) &&
      current.frontend_id &&
      loadedFrontendEntries.length &&
      JSON.stringify([...current.frontend_entries].sort()) !==
        JSON.stringify(loadedFrontendEntries)
    ) {
      window.location.reload();
    }
  });
}
async function submit(input: ComponentCreateInput, installing: boolean) {
  await run(async () => {
    const key = installing ? upgradeKey(input) : randomUUID();
    const task = await api.createComponentTask(input, key, installing);
    tasks.value = [task, ...tasks.value.filter((item) => item.id !== task.id)];
    if (installing) {
      upgradeID.value = task.id;
      window.sessionStorage.setItem(savedUpgrade, task.id);
    } else {
      checkID.value = task.id;
      window.sessionStorage.setItem(savedCheck, task.id);
    }
  });
}
async function check() {
  if (active.value || liveDisconnected.value) return;
  await submit(
    {
      input: {
        action: "check",
        components: ["panel"],
        tag: "",
        prerelease: prerelease.value,
        plan_id: "",
        manifest_sha256: "",
        trust_sha256: "",
      },
    },
    false,
  );
}
async function changeChannel(value: typeof channel.value) {
  await run(async () => {
    await saveChannel(value);
    checkID.value = "";
    window.sessionStorage.removeItem(savedCheck);
  });
}
function confirmUpdate() {
  const task = checked.value;
  const target = release.value;
  if (!task || !target || !canUpgrade.value || active.value) return;
  dialog.warning({
    title: `更新至 ${target.version}`,
    content:
      "系统将下载安装更新并自动重启。重启期间面板会短暂断开，恢复连接后可查看更新结果。",
    positiveText: "下载安装",
    negativeText: "取消",
    onPositiveClick: () =>
      submit(
        {
          check_task_id: task.id,
          input: {
            action: "software",
            tag: "",
            prerelease: false,
            plan_id: "",
            manifest_sha256: "",
            trust_sha256: "",
            software: {
              action: "update-panel",
              plan_id: target.plan_id,
              prerelease: task.result!.input.prerelease,
            },
          },
        },
        true,
      ),
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
      <p class="muted">检查当前更新通道，确认后下载安装。</p>
      <div class="button-row">
        <NButton
          type="primary"
          :loading="pending(lastCheck)"
          :disabled="
            !permitted ||
            busy ||
            active ||
            savingChannel ||
            !channelReady ||
            liveDisconnected
          "
          @click="check"
          >{{ pending(lastCheck) ? "正在检查" : "检查更新" }}</NButton
        >
        <NSelect
          :value="channel"
          :options="updateChannels"
          aria-label="更新通道"
          style="width: 150px"
          :loading="savingChannel"
          :disabled="
            busy || active || savingChannel || !channelReady || !permitted
          "
          @update:value="changeChannel"
        />
      </div>
      <p v-if="channel === 'beta'" class="muted">
        Beta 版本用于提前体验新功能，可能存在尚未修复的问题。
      </p>
      <NAlert v-if="updating && liveDisconnected" type="info">
        面板正在重启或连接暂时中断，恢复后将继续显示更新结果。
      </NAlert>
      <NAlert v-if="lastCheck?.error && !pending(lastCheck)" type="error">
        {{ lastCheck.error }}
      </NAlert>
      <TaskLogButton v-if="lastCheck" :task-id="lastCheck.id" />
    </section>
    <section v-if="release" class="panel page-stack">
      <div class="section-heading">
        <h3>
          {{ updateAvailable ? "发现新版本" : "所选通道版本" }}
          {{ release.version }}
          <NTag v-if="release.channel === 'beta'" type="warning" size="small"
            >Beta</NTag
          >
        </h3>
      </div>
      <p v-if="release.notes">{{ release.notes }}</p>
      <NAlert v-if="updateStatus?.state === 'current'" type="success"
        >当前已是最新版本。</NAlert
      >
      <NAlert v-else-if="updateStatus?.state === 'older'" type="info"
        >当前安装版本高于所选通道的发布版本，暂无可用更新。</NAlert
      >
      <NAlert v-else-if="!updateAvailable" type="warning">{{
        updateStatus?.message || "正在确认当前程序版本，请刷新后重试。"
      }}</NAlert>
      <p v-if="updateAvailable" class="muted">
        下载大小：{{ (release.archive_bytes / 1048576).toFixed(1) }} MB
      </p>
      <NAlert
        v-if="updateAvailable && !checked?.result?.runtime_ready"
        type="warning"
        >服务器暂不满足此版本的安装条件，请查看检查日志。</NAlert
      >
      <div v-if="updateAvailable" class="button-row">
        <NButton
          type="primary"
          :loading="updating"
          :disabled="
            !permitted || busy || active || liveDisconnected || !canUpgrade
          "
          @click="confirmUpdate"
        >
          下载安装
        </NButton>
      </div>
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
