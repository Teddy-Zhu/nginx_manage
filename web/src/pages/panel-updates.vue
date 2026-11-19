<route lang="json">
{
  "meta": {
    "title": "系统更新",
    "order": 30,
    "localOnly": true,
    "parent": "/settings"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { NAlert, NButton, NSelect, NEmpty, NTag, useDialog } from "naive-ui";
import { liveDisconnected } from "../api/live";
import {
  ApiError,
  useNodeAPI,
  type ComponentCreateInput,
  type ComponentTask,
  type CoreUpdateCheck,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useLiveRefresh } from "../composables/live";
import { useSession } from "../stores/session";
import { loadedFrontendEntries } from "../frontend-version";
import { taskStates } from "../utils/tasks";
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
  ready: channelReady,
  saving: savingChannel,
  loadChannel,
  saveChannel,
} = useUpdateChannel(api);
const savedUpgrade = "nginxpanel:update-task";
const tasks = ref<ComponentTask[]>([]),
  version = ref(""),
  upgradeID = ref(window.sessionStorage.getItem(savedUpgrade) ?? "");
const checked = ref<CoreUpdateCheck>();
const checking = ref(false);
const checkError = ref("");
let checkRequest: AbortController | undefined;
const permitted = computed(
  () =>
    session.me?.scopes.includes("components.manage") &&
    session.me.scopes.includes("system.write"),
);
const canCheck = computed(
  () =>
    session.me?.scopes.includes("read") &&
    session.me.scopes.includes("components.manage"),
);
function pending(task: ComponentTask | undefined) {
  return task?.state === "queued" || task?.state === "running";
}
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
const active = computed(() => checking.value || updating.value);
async function load(initial = false) {
  if (updating.value && liveDisconnected.value) return;
  await run(async () => {
    const [items, current] = await Promise.all([
      api.componentTasks(),
      api.systemVersion(),
      initial ? loadChannel() : undefined,
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
async function submitUpdate(input: ComponentCreateInput) {
  await run(async () => {
    const task = await api.createComponentTask(input, upgradeKey(input));
    tasks.value = [task, ...tasks.value.filter((item) => item.id !== task.id)];
    upgradeID.value = task.id;
    window.sessionStorage.setItem(savedUpgrade, task.id);
    checked.value = undefined;
  });
}
async function check() {
  if (active.value || !channelReady.value) return;
  const request = new AbortController();
  checkRequest = request;
  checking.value = true;
  checked.value = undefined;
  checkError.value = "";
  try {
    const result = await api.checkCoreUpdate(channel.value, request.signal);
    if (!request.signal.aborted) {
      version.value = result.current_version;
      checked.value = result;
    }
  } catch (error) {
    if (!request.signal.aborted) {
      checkError.value =
        error instanceof Error &&
        !(error instanceof ApiError && error.status === 0)
          ? error.message
          : "未能完成更新检查，请稍后重试。";
    }
  } finally {
    if (checkRequest === request) {
      checkRequest = undefined;
      checking.value = false;
    }
  }
}
async function changeChannel(value: typeof channel.value) {
  await run(() => saveChannel(value));
}
watch(channel, () => {
  checkRequest?.abort();
  checked.value = undefined;
  checkError.value = "";
});
onUnmounted(() => checkRequest?.abort());
function confirmUpdate() {
  const target = checked.value;
  if (!target?.confirmation || active.value || liveDisconnected.value) return;
  const confirmation = target.confirmation;
  dialog.warning({
    title: `更新至 ${target.version}`,
    content:
      "系统将下载安装更新并自动重启。重启期间面板会短暂断开，恢复连接后可查看更新结果。",
    positiveText: "下载安装",
    negativeText: "取消",
    onPositiveClick: () => {
      if (checked.value !== target || active.value || liveDisconnected.value)
        return;
      return submitUpdate({
        update_confirmation: confirmation,
        input: {
          action: "software",
          tag: "",
          prerelease: false,
          plan_id: "",
          manifest_sha256: "",
          trust_sha256: "",
          software: {
            action: "update-panel",
          },
        },
      });
    },
  });
}
useLiveRefresh(api, ["tasks"], load, () => busy.value);
onMounted(() => load(true));
</script>
<template>
  <div class="page-stack">
    <section class="panel page-stack">
      <div class="section-heading">
        <div>
          <h3>当前版本</h3>
          <p class="current-version">
            {{ version || "正在读取" }}
          </p>
        </div>
      </div>
      <div class="button-row">
        <NButton
          type="primary"
          :loading="checking"
          :disabled="
            !canCheck || busy || active || savingChannel || !channelReady
          "
          @click="check"
        >
          {{ checking ? "正在检查" : "检查更新" }}
        </NButton>
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
        Beta 版本可能不稳定。
      </p>
      <NAlert v-if="updating && liveDisconnected" type="info">
        更新期间连接已断开，正在重连。
      </NAlert>
      <NAlert v-if="checkError" type="error">
        {{ checkError }}
      </NAlert>
      <NAlert v-else-if="checked?.state === 'current'" type="success">
        当前已是最新版本。
      </NAlert>
      <NAlert v-else-if="checked?.state === 'older'" type="info">
        当前版本高于所选通道的 {{ checked.version }}，暂无可用更新。
      </NAlert>
      <NAlert v-else-if="checked?.state === 'unknown'" type="warning">
        {{ checked.message }}
      </NAlert>
      <div v-else-if="checked?.state === 'available'" class="update-result">
        <h3>
          发现新版本 {{ checked.version }}
          <NTag v-if="checked.channel === 'beta'" type="warning" size="small">
            Beta
          </NTag>
        </h3>
        <p v-if="checked.notes" class="release-notes">
          {{ checked.notes }}
        </p>
        <p class="muted">
          {{ (checked.archive_bytes / 1048576).toFixed(1) }} MB
        </p>
        <NAlert v-if="checked.message" type="warning">
          {{
            checked.message
          }}
        </NAlert>
        <NButton
          v-if="checked.confirmation"
          type="primary"
          :disabled="!permitted || busy || active || liveDisconnected"
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
          <p v-if="task.error">
            {{ task.error }}
          </p>
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
.update-result {
  display: grid;
  justify-items: start;
  gap: 12px;
  padding-top: 16px;
  border-top: 1px solid var(--border-color);
}
.update-result h3,
.update-result p {
  margin: 0;
}
.release-notes {
  white-space: pre-line;
  overflow-wrap: anywhere;
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
