<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from "vue";
import { NAlert, NButton, NModal, NSpin, NTag } from "naive-ui";
import { apiError, createAPI, type LogRow, type Task } from "../api/client";
import { liveTopicScopes } from "../api/live";
import { currentOperation, operationVisible } from "../stores/operation";
import { useSession } from "../stores/session";
import { isTaskActive, taskStageLabel, taskStates } from "../utils/tasks";

const session = useSession();
const task = ref<Task | null>(null);
const rows = ref<LogRow[]>([]);
const softwareLog = ref(""),
  softwareMessage = ref("");
const statusError = ref(""),
  logError = ref(""),
  softwareError = ref(""),
  logNotice = ref("");
const reading = ref(false),
  checkedAt = ref(0),
  clock = ref(Date.now());
const active = computed(() => !!task.value && isTaskActive(task.value.state));
const needsAttention = computed(() =>
  ["recovery_required", "waiting_confirmation"].includes(
    task.value?.state ?? "",
  ),
);
const canReadLogs = computed(() =>
  liveTopicScopes.logs.every(
    (permission) =>
      !!session.localMe?.scopes.includes(permission) &&
      (!currentOperation.value?.scope.target ||
        currentOperation.value.scope.target.scopes.includes(permission)),
  ),
);
const state = computed(
  () => task.value?.state ?? currentOperation.value?.state ?? "queued",
);
const tagType = computed(() =>
  state.value === "succeeded"
    ? "success"
    : state.value === "failed"
      ? "error"
      : needsAttention.value
        ? "warning"
        : "info",
);
const elapsed = computed(() => {
  if (!task.value || !active.value) return "";
  const seconds = Math.max(
    0,
    Math.floor(clock.value / 1000) - task.value.created_at,
  );
  return seconds < 60
    ? `${seconds} 秒`
    : `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
});
const date = (value: number) => new Date(value * 1000).toLocaleString();
function eventLabel(row: LogRow) {
  const [event, , kind = "", eventState = "", stage = ""] =
    row.message.split(" ");
  return event === "task.created"
    ? "任务已创建"
    : `${taskStageLabel(stage, kind, eventState)} · ${taskStates[eventState] ?? "状态待确认"}`;
}

let controller: AbortController | undefined;
let unsubscribe: (() => void) | undefined;
let stopLogs: (() => void) | undefined;
let ticker: ReturnType<typeof setInterval> | undefined;
let refresh: (() => Promise<void>) | undefined;
function stop() {
  controller?.abort();
  stopLogs?.();
  stopLogs = undefined;
  unsubscribe?.();
  unsubscribe = undefined;
  if (ticker) clearInterval(ticker);
  ticker = undefined;
  refresh = undefined;
}

watch(
  () =>
    [currentOperation.value?.sequence, currentOperation.value?.taskId] as const,
  () => {
    stop();
    task.value = null;
    rows.value = [];
    softwareLog.value = softwareMessage.value = "";
    statusError.value =
      logError.value =
      softwareError.value =
      logNotice.value =
        "";
    checkedAt.value = 0;
    reading.value = false;
    const operation = currentOperation.value;
    if (!operation?.taskId) return;
    const current = new AbortController();
    controller = current;
    const api = createAPI({ ...operation.scope, signal: current.signal });
    let sourceId = "",
      pending = false;
    refresh = async () => {
      if (current.signal.aborted || reading.value) return;
      pending = false;
      reading.value = true;
      try {
        const value = await api.task(operation.taskId);
        if (current.signal.aborted) return;
        task.value = value;
        if (isTaskActive(value.state) && !ticker) {
          ticker = setInterval(() => {
            clock.value = Date.now();
          }, 1000);
        } else if (!isTaskActive(value.state) && ticker) {
          clearInterval(ticker);
          ticker = undefined;
        }
        operation.state = value.state;
        checkedAt.value = clock.value = Date.now();
        statusError.value = "";
        if (canReadLogs.value) {
          if (
            value.kind === "component.software" &&
            session.localMe?.scopes.includes("components.manage") &&
            (!operation.scope.target ||
              operation.scope.target.scopes.includes("components.manage"))
          ) {
            try {
              const details = (await api.componentTasks()).find(
                (t) => t.id === value.id,
              );
              if (current.signal.aborted) return;
              softwareLog.value = details?.result?.software?.log ?? "";
              softwareMessage.value =
                details?.result?.runtime_reason ||
                details?.result?.software?.message ||
                "";
              softwareError.value = "";
            } catch (error) {
              softwareError.value = apiError(error).message;
            }
          }
          try {
            if (!sourceId)
              sourceId =
                (await api.logSources()).find(
                  (source) =>
                    source.category === "task" &&
                    source.resource_id === operation.taskId,
                )?.id ?? "";
            if (sourceId && !stopLogs) {
              stopLogs = api.followLogs(
                {
                  source_id: sourceId,
                  mode: "recent",
                  from: Math.max(
                    value.created_at - 1,
                    Math.floor(Date.now() / 1000) - 7 * 86400 + 1,
                  ),
                  until: 0,
                  status: 0,
                  ip: "",
                  path: "",
                  keyword: "",
                  policy_id: "",
                  reason: "",
                  events_only: false,
                  limit: 100,
                  cursor: "",
                },
                (page, reset) => {
                  if (current.signal.aborted) return;
                  rows.value = [...(reset ? [] : rows.value), ...page.rows]
                    .sort((a, b) => a.time - b.time)
                    .slice(-100);
                  logNotice.value =
                    page.notice ||
                    (page.gap
                      ? "部分历史日志缺失，当前任务状态不受影响。"
                      : "");
                  logError.value = "";
                },
                (cause) => {
                  if (!current.signal.aborted) logError.value = cause.message;
                },
              );
            }
            if (!current.signal.aborted) logError.value = "";
          } catch (cause) {
            if (!current.signal.aborted)
              logError.value = apiError(cause).message;
          }
        }
      } catch (cause) {
        if (!current.signal.aborted) {
          const error = apiError(cause);
          statusError.value = error.message;
        }
      } finally {
        if (!current.signal.aborted) {
          reading.value = false;
          if (pending) window.queueMicrotask(() => void refresh?.());
        }
      }
    };
    unsubscribe = api.subscribe(["tasks"], () => {
      pending = true;
      void refresh?.();
    });
    void refresh();
  },
  { immediate: true },
);
onUnmounted(stop);
</script>

<template>
  <NModal
    v-model:show="operationVisible"
    preset="card"
    :title="currentOperation?.title ?? '操作详情'"
    :style="{ width: '880px', maxWidth: 'calc(100vw - 32px)' }"
    :mask-closable="false"
  >
    <div class="operation-dialog-body page-stack">
      <NAlert v-if="currentOperation?.submitting" type="info"
        ><NSpin size="small" /> 正在提交操作，请稍候…</NAlert
      >
      <NAlert
        v-if="currentOperation?.error"
        :type="currentOperation.uncertain ? 'warning' : 'error'"
        :title="currentOperation.uncertain ? '提交结果待确认' : '未能提交操作'"
      >
        {{ currentOperation.error }}
        <p v-if="currentOperation.uncertain">
          请先查看操作记录，确认结果后再操作。
        </p>
      </NAlert>
      <NAlert
        v-if="
          currentOperation?.requestOnly &&
          !currentOperation.submitting &&
          !currentOperation.error
        "
        type="success"
        >操作已完成。</NAlert
      >
      <template v-if="currentOperation?.taskId">
        <div class="toolbar">
          <div class="operation-state">
            <NSpin v-if="active || (!task && reading)" size="small" /><NTag
              :type="tagType"
              >{{
                task ? (taskStates[state] ?? "状态待确认") : "正在查询状态"
              }}</NTag
            >
          </div>
          <NButton size="small" :loading="reading" @click="refresh?.()"
            >刷新</NButton
          >
        </div>
        <div v-if="task" class="surface page-stack">
          <strong>{{
            taskStageLabel(task.stage, task.kind, task.state)
          }}</strong>
          <p class="muted">
            提交时间：{{ date(task.created_at)
            }}<span v-if="elapsed"> · 已用时 {{ elapsed }}</span>
          </p>
          <p v-if="active" class="muted">
            任务正在后台执行，进度和日志将自动更新。
          </p>
          <p v-if="needsAttention">请返回原操作页面确认或恢复任务。</p>
        </div>
        <NAlert v-if="statusError" type="warning" title="暂时无法读取任务状态"
          >{{ statusError }}。任务可能仍在执行，请刷新后确认。</NAlert
        >
        <NAlert
          v-if="task?.last_error"
          :type="task.state === 'failed' ? 'error' : 'warning'"
          title="执行详情"
          >{{ task.last_error }}</NAlert
        >
        <div class="toolbar">
          <h3>执行日志</h3>
          <span v-if="checkedAt" class="muted"
            >更新于 {{ new Date(checkedAt).toLocaleTimeString() }}</span
          >
        </div>
        <NAlert v-if="!canReadLogs" type="info"
          >当前账户没有查看日志的权限。</NAlert
        >
        <NAlert v-else-if="logError" type="warning" title="日志暂不可用">{{
          logError
        }}</NAlert>
        <p
          v-else-if="!rows.length && !softwareLog && !softwareMessage"
          class="muted"
        >
          {{
            active
              ? "等待执行日志，稍后自动更新…"
              : "最近七天内暂无可读取的执行日志。"
          }}
        </p>
        <ol v-if="rows.length" class="operation-log" aria-label="执行日志">
          <li
            v-for="(row, index) in rows"
            :key="`${row.time}-${index}`"
            :class="{ 'log-error': row.level === 'error' }"
          >
            <time>{{ date(row.time) }}</time
            ><span>{{ eventLabel(row) }}</span>
          </li>
        </ol>
        <NAlert v-if="softwareError" type="warning" title="操作详情暂不可用">{{
          softwareError
        }}</NAlert>
        <p v-if="canReadLogs && softwareMessage">{{ softwareMessage }}</p>
        <pre v-if="canReadLogs && softwareLog" class="software-log">{{
          softwareLog
        }}</pre>
        <NAlert v-if="logNotice" type="warning">{{ logNotice }}</NAlert>
      </template>
    </div>
    <template #footer>
      <div class="operation-dialog-footer">
        <NButton @click="operationVisible = false">关闭</NButton>
      </div>
    </template>
  </NModal>
</template>

<style scoped>
.operation-dialog-body {
  max-height: calc(100dvh - 220px);
  overflow-y: auto;
  overscroll-behavior: contain;
  overflow-wrap: anywhere;
  padding-right: 4px;
}
.operation-dialog-footer {
  display: flex;
  justify-content: flex-end;
}
.software-log {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 320px;
  overflow: auto;
  padding: 16px;
  border-radius: 10px;
  background: var(--bg);
  font-size: 12px;
}
.operation-state {
  display: flex;
  align-items: center;
  gap: 10px;
}
.operation-log {
  margin: 0;
  padding: 12px 16px;
  list-style: none;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--surface-soft);
  max-height: 480px;
  overflow: auto;
}
.operation-log li {
  display: grid;
  gap: 4px;
  padding: 10px 0;
  overflow-wrap: anywhere;
}
.operation-log li + li {
  border-top: 1px solid var(--border-color);
}
.operation-log time {
  color: var(--text-muted);
  font-size: 12px;
}
.log-error {
  color: #b42318;
}
</style>
