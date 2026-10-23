<route lang="json">
{
  "meta": {
    "title": "维护模式",
    "subtitle": "暂停配置修改，进行系统维护",
    "nav": false,
    "order": 7.3,
    "symbol": "◈",
    "parent": "/settings"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NFormItem,
  NInputNumber,
  NPopconfirm,
  NTag,
} from "naive-ui";
import { useNodeAPI, apiError, type MaintenanceView } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();

const session = useSession(),
  { run, busy } = useAction();
const view = ref<MaintenanceView | null>(null),
  error = ref(""),
  seconds = ref<number | null>(120);
let keyFor = useIdempotency();
const permitted = computed(
  () => session.me?.scopes.includes("system.write") ?? false,
);
const recoverID = computed(
  () => view.value?.session?.task_id || view.value?.agent.id || "",
);
const orphan = computed(() => !!view.value?.agent.id && !view.value?.session);
const canRelease = computed(
  () =>
    !!recoverID.value &&
    (!orphan.value || session.me?.scopes.includes("auth.manage")) &&
    view.value?.phase !== "releasing",
);
const labels: Record<string, string> = {
  open: "正常",
  draining: "等待在途任务",
  root_acquiring: "等待独占确认",
  closing: "等待在途操作",
  held: "维护中",
  releasing: "恢复写入中",
  released: "已恢复写入",
  failed: "维护失败",
  recovery_required: "待恢复",
  unavailable: "状态不可确认",
};
const phase = computed(() => labels[view.value?.phase ?? ""] ?? "读取中");
const rootPhase = computed(
  () => labels[view.value?.agent.phase ?? ""] ?? "未确认",
);
let controller: AbortController | null = null,
  timer: ReturnType<typeof setInterval> | undefined,
  reading = false,
  closed = false;
async function load() {
  if (reading || closed || !permitted.value) return;
  reading = true;
  controller = new AbortController();
  try {
    view.value = await api.maintenance(controller.signal);
    error.value = "";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    reading = false;
  }
}
async function enter() {
  if (seconds.value == null) return;
  const input = { drain_seconds: seconds.value };
  await run(async () => {
    await api.enterMaintenance(input, keyFor(input));
    keyFor = useIdempotency();
  }, "维护请求已受理");
  await load();
}
async function release() {
  const id = recoverID.value;
  if (!id) return;
  await run(() => api.releaseMaintenance(id), "恢复写入请求已受理");
  await load();
}
onMounted(() => {
  void load();
  timer = setInterval(() => void load(), 3000);
});
onUnmounted(() => {
  closed = true;
  controller?.abort();
  if (timer) clearInterval(timer);
});
</script>
<template>
  <div class="stack">
    <NAlert v-if="!permitted" type="warning">需要系统管理权限。</NAlert>
    <template v-else>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <NAlert v-if="view?.reason || view?.session?.error" type="warning">{{
        view.reason || view.session?.error
      }}</NAlert>
      <section class="panel stack">
        <div class="toolbar">
          <NTag
            :type="
              view?.phase === 'open'
                ? 'success'
                : view?.phase === 'held'
                  ? 'warning'
                  : 'default'
            "
            >{{ phase }}</NTag
          >
          <NButton :disabled="reading" @click="load">刷新</NButton>
        </div>
        <p>
          维护期间暂停配置写入、自动续期和部署，已有代理服务继续运行。在途操作完成后进入维护状态。
        </p>
        <dl v-if="view" class="details">
          <dt>在途 Web 操作</dt>
          <dd>{{ view.active }}</dd>
          <dt>Agent 状态</dt>
          <dd>{{ rootPhase }}</dd>
          <dt>在途 Agent 操作</dt>
          <dd>{{ view.agent.busy }}</dd>
          <template v-if="view.session"
            ><dt>维护任务</dt>
            <dd>{{ view.session.task_id }}</dd>
            <dt>等待截止</dt>
            <dd>
              {{ new Date(view.session.deadline * 1000).toLocaleString() }}
            </dd></template
          >
          <template v-if="orphan"
            ><dt>独立维护标识</dt>
            <dd>{{ view.agent.id }}</dd></template
          >
        </dl>
        <NAlert v-if="view && !view.agent.available" type="info">{{
          view.agent.reason || "本机尚未开放维护操作"
        }}</NAlert>
        <NFormItem label="等待在途操作的时限（秒）"
          ><NInputNumber
            v-model:value="seconds"
            :min="30"
            :max="300"
            :disabled="view?.phase !== 'open' || busy"
        /></NFormItem>
        <div class="toolbar">
          <NPopconfirm @positive-click="enter"
            ><template #trigger
              ><NButton
                type="warning"
                :disabled="
                  busy ||
                  view?.phase !== 'open' ||
                  !view.agent.available ||
                  seconds == null
                "
                >进入维护</NButton
              ></template
            >确认暂停新的配置写入并等待在途操作结束？</NPopconfirm
          >
          <NPopconfirm @positive-click="release"
            ><template #trigger
              ><NButton :disabled="busy || !canRelease"
                >恢复写入</NButton
              ></template
            >{{
              orphan
                ? "确认已核对独立维护记录，并释放此维护锁？"
                : "确认结束维护并恢复配置写入？"
            }}</NPopconfirm
          >
        </div>
      </section>
    </template>
  </div>
</template>
