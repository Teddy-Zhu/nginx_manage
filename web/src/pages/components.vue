<route lang="json">
{
  "meta": {
    "title": "软件商店",
    "nav": true,
    "order": 20,
    "symbol": "◇",
    "group": "应用管理"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  NAlert,
  NButton,
  NEmpty,
  NInput,
  NModal,
  NSelect,
  NSkeleton,
  NTag,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentOverview,
  type ComponentTask,
} from "../api/client";
import { useLiveRefresh } from "../composables/live";
import { useSession } from "../stores/session";
import { softwareTaskActive, softwareTaskLabel } from "../utils/software";
import SoftwareCard from "../components/SoftwareCard.vue";
import SoftwareActions from "../components/SoftwareActions.vue";
import { builtinSoftware } from "../software/builtin";
import BuiltinSoftwarePanel from "../components/BuiltinSoftwarePanel.vue";
import TaskLogButton from "../components/TaskLogButton.vue";

const api = useNodeAPI(),
  route = useRoute(),
  router = useRouter(),
  session = useSession();
const overview = ref<ComponentOverview | null>(null),
  tasks = ref<ComponentTask[]>([]);
const readingOverview = ref(false),
  readingTasks = ref(false),
  loaded = ref(false),
  overviewError = ref(""),
  taskError = ref("");
const reading = computed(() => readingOverview.value || readingTasks.value);
const error = computed(() =>
  [overviewError.value, taskError.value].filter(Boolean).join("、"),
);
const search = ref(""),
  statusFilter = ref("all");
const selected = ref<string | null>(null),
  openVersionPicker = ref(false),
  detailBusy = ref(false),
  showHistory = ref(false);
const controller = new AbortController();
const active = computed(() => tasks.value.some(softwareTaskActive));
const systemSoftware = computed(() =>
  builtinSoftware(overview.value, tasks.value),
);
const querySoftware = computed(() =>
  systemSoftware.value.some((app) => app.id === route.query.software)
    ? String(route.query.software)
    : null,
);
watch(
  querySoftware,
  (value) => {
    selected.value = value;
  },
  { immediate: true },
);
const filteredSystemSoftware = computed(() => {
  const query = search.value.trim().toLocaleLowerCase();
  return systemSoftware.value.filter(
    (app) =>
      (!query ||
        `${app.name} ${app.category} ${app.description}`
          .toLocaleLowerCase()
          .includes(query)) &&
      (statusFilter.value === "all" ||
        (statusFilter.value === "installed" ? app.installed : !app.installed)),
  );
});
const selectedApp = computed(() =>
  systemSoftware.value.find((app) => app.id === selected.value),
);
const stateLabels: Record<string, string> = {
  queued: "等待执行",
  running: "正在执行",
  succeeded: "已完成",
  failed: "未完成",
  recovery_required: "需要处理",
};
function recordTask(task: ComponentTask) {
  tasks.value = [task, ...tasks.value.filter((item) => item.id !== task.id)];
}
let overviewRequest: Promise<void> | undefined;
function loadOverview() {
  if (controller.signal.aborted) return;
  if (overviewRequest) return overviewRequest;
  readingOverview.value = true;
  overviewRequest = api
    .components(controller.signal)
    .then((value) => {
      overview.value = value;
      overviewError.value = "";
    })
    .catch((failure: unknown) => {
      if (!controller.signal.aborted)
        overviewError.value = `软件列表：${apiError(failure).message}`;
    })
    .finally(() => {
      overviewRequest = undefined;
      readingOverview.value = false;
      loaded.value = true;
    });
  return overviewRequest;
}
async function loadTasks() {
  if (readingTasks.value || controller.signal.aborted) return;
  readingTasks.value = true;
  try {
    const items = await api.componentTasks(controller.signal);
    if (controller.signal.aborted) return;
    const previous = new Map(tasks.value.map((task) => [task.id, task]));
    const settled = items.some((task) => {
      const prior = previous.get(task.id);
      const action = task.result?.input.software?.action;
      return (
        task.action === "software" &&
        action !== "logs" &&
        action !== "update-panel" &&
        softwareTaskActive(prior) &&
        task.state !== prior?.state &&
        ["succeeded", "failed", "recovery_required"].includes(task.state)
      );
    });
    for (const task of items) previous.set(task.id, task);
    tasks.value = [...previous.values()].sort(
      (a, b) => b.created_at - a.created_at,
    );
    taskError.value = "";
    if (settled) {
      await overviewRequest;
      await loadOverview();
    }
  } catch (failure) {
    if (!controller.signal.aborted)
      taskError.value = `操作记录：${apiError(failure).message}`;
  } finally {
    readingTasks.value = false;
  }
}
async function load() {
  await Promise.all([loadOverview(), loadTasks()]);
}
function closeDetails() {
  if (detailBusy.value) return;
  selected.value = null;
  openVersionPicker.value = false;
  if (querySoftware.value)
    void router.replace({
      query: { ...route.query, software: undefined, existing: undefined },
    });
}
function openDetails(app: string, install = false) {
  openVersionPicker.value = install && app === "nginx";
  selected.value = app;
}
onMounted(load);
onUnmounted(() => controller.abort());
useLiveRefresh(api, ["tasks"], loadTasks, () => readingTasks.value);
</script>
<template>
  <Teleport defer to="#page-heading-actions">
    <NButton :loading="reading" @click="load">
      刷新
    </NButton>
    <NButton :disabled="!tasks.length" @click="showHistory = true">
      操作记录
    </NButton>
  </Teleport>
  <div class="page-stack">
    <NAlert v-if="error || overview?.component_error" type="error">
      {{ error || overview?.component_error }}
    </NAlert>
    <NAlert v-if="active" type="info" :bordered="false">
      有软件操作正在执行。
    </NAlert>
    <section class="store-workspace">
      <div class="store-filters">
        <NInput
          v-model:value="search"
          clearable
          placeholder="搜索软件名称或用途"
          aria-label="搜索软件"
          class="store-search"
        />
        <NSelect
          v-model:value="statusFilter"
          :options="[
            { label: '全部软件', value: 'all' },
            { label: '已安装', value: 'installed' },
            { label: '未安装', value: 'missing' },
          ]"
          aria-label="安装状态"
          class="store-status-filter"
        />
      </div>
      <template v-if="!loaded && reading">
        <div class="store-grid">
          <NSkeleton
            v-for="item in 3"
            :key="item"
            height="250px"
            :sharp="false"
          />
        </div>
      </template>
      <template v-else>
        <div v-if="filteredSystemSoftware.length" class="store-grid">
          <SoftwareCard
            v-for="app in filteredSystemSoftware"
            :key="app.id"
            :name="app.name"
            :description="app.description"
            :category="app.category"
            :status="app.status.label"
            :accent="app.accent"
            :status-type="app.status.tone"
          >
            <span>{{ app.note }}</span>
            <template #actions>
              <SoftwareActions
                :app="app"
                :permitted="
                  app.scopes.every((scope) =>
                    session.me?.scopes.includes(scope),
                  )
                "
                :active="active"
                @manage="openDetails(app.id)"
                @install="openDetails(app.id, true)"
              />
            </template>
          </SoftwareCard>
        </div>
        <NEmpty v-else class="store-empty" description="没有符合条件的软件">
          <template #extra>
            <NButton
              @click="
                search = '';
                statusFilter = 'all';
              "
            >
              清除筛选
            </NButton>
          </template>
        </NEmpty>
      </template>
    </section>
  </div>
  <NModal
    :show="!!selected"
    preset="card"
    :title="selectedApp ? `软件管理 · ${selectedApp.name}` : '软件管理'"
    style="width: 760px; max-width: calc(100vw - 32px)"
    :mask-closable="false"
    :closable="!detailBusy"
    :close-on-esc="!detailBusy"
    @update:show="
      (value: boolean) => {
        if (!value) closeDetails();
      }
    "
  >
    <div class="software-details page-stack">
      <BuiltinSoftwarePanel
        v-if="selectedApp"
        :key="selectedApp.id"
        :app="selectedApp"
        :overview="overview"
        :tasks="tasks"
        :active="active"
        :open-version-picker="openVersionPicker"
        @busy="detailBusy = $event"
        @task="recordTask"
      />
    </div>
    <template #footer>
      <div class="dialog-footer">
        <NButton :disabled="detailBusy" @click="closeDetails">
          关闭
        </NButton>
      </div>
    </template>
  </NModal>
  <NModal
    v-model:show="showHistory"
    preset="card"
    title="软件操作记录"
    style="width: 760px; max-width: calc(100vw - 32px)"
  >
    <div class="software-history page-stack">
      <article
        v-for="item in tasks.slice(0, 12)"
        :key="item.id"
        class="record-card"
      >
        <div class="section-heading">
          <strong>{{ softwareTaskLabel(item) }}</strong><NTag
            :bordered="false"
            :type="
              item.state === 'succeeded'
                ? 'success'
                : item.state === 'failed'
                  ? 'error'
                  : 'info'
            "
          >
            {{ stateLabels[item.state] || "正在处理" }}
          </NTag>
        </div>
        <div class="history-footer">
          <span class="muted">{{
            new Date(item.created_at * 1000).toLocaleString()
          }}</span><TaskLogButton :task-id="item.id" />
        </div>
        <p v-if="item.error" class="error">
          {{ item.error }}
        </p>
      </article>
    </div>
  </NModal>
</template>
<style scoped>
.store-workspace {
  display: grid;
  gap: 24px;
  min-width: 0;
}
.store-filters {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}
.store-search {
  width: min(100%, 360px);
}
.store-status-filter {
  width: 150px;
}
.store-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 280px), 1fr));
  gap: 20px;
}
.store-empty {
  padding: 64px 20px;
  border: 1px dashed var(--border-color);
  border-radius: 12px;
  background: var(--bg-surface);
}
.software-details,
.software-history {
  max-height: calc(100dvh - 220px);
  overflow-y: auto;
  padding-right: 4px;
}
.dialog-footer {
  display: flex;
  justify-content: flex-end;
}
.history-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
@media (max-width: 560px) {
  .store-search {
    width: 100%;
  }
  .store-status-filter {
    flex: 1;
  }
}
</style>
