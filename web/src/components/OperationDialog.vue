<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from "vue";
import { NAlert, NButton, NModal, NSpin, NTag } from "naive-ui";
import { apiError, createAPI, type LogRow, type Task } from "../api/client";
import { liveTopicScopes } from "../api/live";
import { currentOperation, operationVisible } from "../stores/operation";
import { useSession } from "../stores/session";
import { isTaskActive, taskStageSummary, taskStateLabel, taskStateTone } from "../utils/tasks";

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
const stage = computed(() =>
  task.value ? taskStageSummary(task.value.stage, task.value.kind, task.value.state) : "",
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
const time = (value: number) => new Date(value * 1000).toLocaleTimeString();
const progress = computed(() => {
  const events: { at: number; label: string; error: boolean }[] = [];
  for (const row of rows.value) {
    if (row.event === "task.created") continue;
    const [, , kind = "", state = "", stage = ""] = row.message.split(" ");
    const label = taskStageSummary(stage, kind, state) || taskStateLabel(state);
    const error = row.level === "error";
    const previous = events[events.length - 1];
    if (previous?.label !== label || previous.error !== error)
      events.push({ at: row.time, label, error });
  }
  return events;
});

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
    [operationVisible.value, currentOperation.value?.sequence, currentOperation.value?.taskId] as const,
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
    reading.value = false;
    const operation = currentOperation.value;
    if (!operationVisible.value || !operation?.taskId) return;
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
        clock.value = Date.now();
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
              if (current.signal.aborted) return;
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
            if (current.signal.aborted) return;
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
                  logNotice.value = page.notice || (page.gap ? "部分进度记录缺失" : "");
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
    :style="{ width: '720px', maxWidth: 'calc(100vw - 32px)' }"
    :mask-closable="false"
  >
    <div class="operation-dialog-body page-stack">
      <NAlert v-if="currentOperation?.submitting" type="info">
        <NSpin size="small" /> 正在提交
      </NAlert>
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
      >
        操作已完成。
      </NAlert>
      <template v-if="currentOperation?.taskId">
        <section v-if="task" class="task-summary" aria-label="任务状态">
          <div class="summary-state" role="status">
            <NSpin v-if="active" size="small" />
            <NTag :type="taskStateTone(task.state)" :bordered="false">
              {{ taskStateLabel(task.state) }}
            </NTag>
            <strong v-if="stage">{{ stage }}</strong>
          </div>
          <dl class="summary-meta">
            <div>
              <dt>提交时间</dt>
              <dd>{{ date(task.created_at) }}</dd>
            </div>
            <div v-if="elapsed">
              <dt>已用时</dt>
              <dd>{{ elapsed }}</dd>
            </div>
          </dl>
        </section>
        <div v-else-if="reading" class="summary-state" role="status">
          <NSpin size="small" />
          <span>读取任务状态</span>
        </div>
        <NAlert v-if="statusError" type="warning" title="任务状态暂不可用">
          {{ statusError }}
        </NAlert>
        <NAlert
          v-if="task?.last_error"
          :type="task.state === 'failed' ? 'error' : 'warning'"
        >
          {{ task.last_error }}
        </NAlert>
        <p v-if="needsAttention" class="muted action-hint">
          请返回任务来源页面{{ task?.state === "waiting_confirmation" ? "确认" : "恢复" }}。
        </p>
        <p
          v-if="canReadLogs && softwareMessage && softwareMessage !== task?.last_error"
          class="action-hint"
        >
          {{ softwareMessage }}
        </p>
        <section v-if="task && canReadLogs" class="progress-section">
          <h3>进度记录</h3>
          <ol v-if="progress.length" class="operation-log" aria-label="进度记录">
            <li
              v-for="(item, index) in progress"
              :key="index"
              :class="{ 'log-error': item.error }"
            >
              <time :datetime="new Date(item.at * 1000).toISOString()" :title="date(item.at)">
                {{ time(item.at) }}
              </time>
              <span>{{ item.label }}</span>
            </li>
          </ol>
          <p v-else-if="!logError" class="muted">
            暂无进度记录
          </p>
          <NAlert v-if="logError || logNotice" type="warning">
            {{ logError || logNotice }}
          </NAlert>
        </section>
        <details v-if="canReadLogs && softwareLog" class="program-output">
          <summary>程序输出</summary>
          <pre>{{ softwareLog }}</pre>
        </details>
        <p v-if="canReadLogs && softwareError" class="muted">
          程序输出暂不可用 · {{ softwareError }}
        </p>
      </template>
    </div>
    <template #footer>
      <div class="operation-dialog-footer">
        <NButton v-if="currentOperation?.taskId" :loading="reading" @click="refresh?.()">
          刷新
        </NButton>
        <NButton type="primary" @click="operationVisible = false">
          关闭
        </NButton>
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
.task-summary {
  display: grid;
  gap: 12px;
  border: 1px solid var(--border-color);
  border-radius: 10px;
  padding: 14px;
  background: var(--surface-soft);
}
.summary-state,
.summary-meta,
.summary-meta > div,
.operation-dialog-footer {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}
.summary-meta {
  margin: 0;
  gap: 6px 20px;
  font-size: 13px;
}
.summary-meta > div {
  gap: 6px;
}
.summary-meta dt {
  color: var(--text-muted);
}
.summary-meta dd {
  margin: 0;
  font-variant-numeric: tabular-nums;
}
.operation-dialog-footer {
  justify-content: flex-end;
}
.progress-section {
  display: grid;
  gap: 8px;
}
.progress-section > h3,
.progress-section > p,
.action-hint {
  margin: 0;
}
.operation-log {
  margin: 0;
  padding: 0 0 0 2px;
  list-style: none;
  max-height: 280px;
  overflow: auto;
}
.operation-log li {
  position: relative;
  display: grid;
  grid-template-columns: 82px minmax(0, 1fr);
  align-items: baseline;
  gap: 10px;
  margin-left: 5px;
  padding: 7px 0 7px 14px;
  border-left: 1px solid var(--border-color);
}
.operation-log li::before {
  content: "";
  position: absolute;
  top: 13px;
  left: -4px;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--text-muted);
}
.operation-log time {
  color: var(--text-muted);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.log-error {
  color: #b42318;
}
.operation-log li.log-error::before {
  background: currentColor;
}
.program-output {
  border-top: 1px solid var(--border-color);
  padding-top: 12px;
}
.program-output summary {
  cursor: pointer;
  font-weight: 600;
}
.program-output pre {
  max-height: 300px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  margin: 10px 0 0;
  padding: 12px;
  border-radius: 8px;
  background: var(--surface-soft);
  font-size: 12px;
}
</style>
