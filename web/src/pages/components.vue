<route lang="json">
{
  "meta": {
    "title": "软件商店",
    "subtitle": "安装和管理所需软件",
    "nav": true,
    "order": 13,
    "symbol": "◇",
    "group": "服务器管理"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import {
  NAlert,
  NButton,
  NEmpty,
  NInput,
  NModal,
  NSelect,
  NSkeleton,
  NTabPane,
  NTabs,
  NTag,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentOverview,
  type ComponentTask,
  type Fail2banObservation,
} from "../api/client";
import { useLiveRefresh } from "../composables/live";
import { useSession } from "../stores/session";
import {
  nginxState,
  fail2banState,
  softwareCatalogEntries,
} from "../utils/software";
import SoftwareSourcesPanel from "../components/SoftwareSourcesPanel.vue";
import SoftwareCard from "../components/SoftwareCard.vue";
import Fail2banInstallPanel from "../components/Fail2banInstallPanel.vue";
import NginxInstallPanel from "../components/NginxInstallPanel.vue";
import TaskLogButton from "../components/TaskLogButton.vue";

const api = useNodeAPI(),
  route = useRoute(),
  router = useRouter(),
  session = useSession();
type SystemSoftware = "nginx" | "fail2ban";
const overview = ref<ComponentOverview | null>(null),
  tasks = ref<ComponentTask[]>([]),
  fail2ban = ref<Fail2banObservation | null>(null);
const reading = ref(false),
  loaded = ref(false),
  error = ref("");
const store = ref("system"),
  search = ref(""),
  statusFilter = ref("all");
const selected = ref<SystemSoftware | null>(null),
  detailBusy = ref(false),
  showHistory = ref(false);
const controller = new AbortController();
const querySoftware = computed(() =>
  route.query.software === "nginx" || route.query.software === "fail2ban"
    ? route.query.software
    : null,
);
watch(
  querySoftware,
  (value) => {
    selected.value = value;
    if (value) store.value = "system";
  },
  { immediate: true },
);
const permitted = computed(
  () => !!session.me?.scopes.includes("components.manage"),
);
const active = computed(() =>
  tasks.value.some(
    (task) =>
      task.stage !== "restore_isolated" &&
      ["queued", "running", "recovery_required"].includes(task.state),
  ),
);
const nginxStatus = computed(() => nginxState(overview.value)),
  fail2banStatus = computed(() => fail2banState(fail2ban.value));
const stateNames = {
  installed: "已安装",
  missing: "未安装",
  unbound: "待连接",
  recovery: "安装未完成",
  unavailable: "状态不可用",
};
const systemSoftware = computed(() => [
  {
    id: "nginx" as const,
    name: "Nginx",
    category: "网站服务",
    description: "创建网站与反向代理，管理 HTTPS、上游服务和网站访问控制。",
    state: nginxStatus.value,
    status:
      nginxStatus.value === "installed"
        ? overview.value?.running
          ? "运行中"
          : "已停止"
        : stateNames[nginxStatus.value],
    installed: nginxStatus.value === "installed",
    management: "/nginx",
    action: "管理网站",
    accent: "green" as const,
  },
  {
    id: "fail2ban" as const,
    name: "Fail2ban",
    category: "安全防护",
    description: "自动封禁反复登录失败的 IP，保护 SSH、管理面板和网站。",
    state: fail2banStatus.value,
    status:
      fail2banStatus.value === "installed"
        ? fail2ban.value?.container
          ? fail2ban.value.container.ready
            ? "运行中"
            : fail2ban.value.container.running
              ? "正在启动"
              : "已停止"
          : "已安装"
        : stateNames[fail2banStatus.value],
    installed: fail2banStatus.value === "installed",
    management: "/fail2ban",
    action: "设置防护",
    accent: "blue" as const,
  },
]);
const filteredSystemSoftware = computed(() => {
  const query = search.value.trim().toLocaleLowerCase();
  return systemSoftware.value.filter(
    (app) =>
      (!query ||
        `${app.name} ${app.category} ${app.description}`
          .toLocaleLowerCase()
          .includes(query)) &&
      (statusFilter.value === "all" ||
        (statusFilter.value === "installed"
          ? app.installed
          : app.state === "missing")),
  );
});
const thirdPartyCount = computed(
  () => softwareCatalogEntries(overview.value?.software).length,
);
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
function taskName(task: ComponentTask) {
  const request = task.result?.input.software;
  if (task.action === "software")
    return request?.action === "fail2ban"
      ? "登录防护操作"
      : request?.action === "update-panel"
        ? "系统更新"
        : "第三方软件操作";
  return (
    {
      check: "检查软件版本",
      prepare: "下载软件",
      pull: "下载运行环境",
      activate: "更新面板界面",
    }[task.action] ?? "软件操作"
  );
}
function recordTask(task: ComponentTask) {
  tasks.value = [task, ...tasks.value.filter((item) => item.id !== task.id)];
}
async function load() {
  if (reading.value || controller.signal.aborted) return;
  reading.value = true;
  try {
    const [source, items, observation] = await Promise.all([
      api.components(controller.signal),
      api.componentTasks(controller.signal),
      api.fail2ban(controller.signal),
    ]);
    if (controller.signal.aborted) return;
    overview.value = source;
    tasks.value = [
      ...tasks.value.filter(
        (task) => !items.some((item) => item.id === task.id),
      ),
      ...items,
    ].sort((a, b) => b.created_at - a.created_at);
    fail2ban.value = observation;
    loaded.value = true;
    error.value = "";
  } catch (failure) {
    if (!controller.signal.aborted) error.value = apiError(failure).message;
  } finally {
    if (!controller.signal.aborted) reading.value = false;
  }
}
function closeDetails() {
  if (detailBusy.value) return;
  selected.value = null;
  if (querySoftware.value)
    void router.replace({
      query: { ...route.query, software: undefined, existing: undefined },
    });
}
onMounted(load);
onUnmounted(() => controller.abort());
useLiveRefresh(api, ["tasks", "fail2ban"], load);
</script>
<template>
  <Teleport defer to="#page-heading-actions">
    <NButton :loading="reading" @click="load">刷新</NButton>
    <NButton :disabled="!tasks.length" @click="showHistory = true"
      >操作记录</NButton
    >
  </Teleport>
  <div class="page-stack">
    <NAlert v-if="error" type="error">软件状态读取失败：{{ error }}</NAlert>
    <NAlert v-if="active" type="info" :bordered="false"
      >软件操作正在处理，可在“操作记录”中查看进度和日志。</NAlert
    >
    <section class="store-workspace">
      <NTabs
        v-model:value="store"
        type="line"
        size="large"
        :pane-style="{ paddingTop: '24px' }"
      >
        <NTabPane
          name="system"
          display-directive="show"
          :tab="`系统商店 · ${systemSoftware.length}`"
        >
          <div class="store-intro">
            <div>
              <h2>系统内置软件</h2>
              <p class="muted">
                常用的网站服务与安全工具，安装后可直接在面板中管理。
              </p>
            </div>
          </div>
        </NTabPane>
        <NTabPane
          name="third-party"
          display-directive="show"
          :tab="`第三方商店 · ${thirdPartyCount}`"
        >
          <div class="store-intro">
            <div>
              <h2>第三方软件</h2>
              <p class="muted">
                浏览已添加软件源提供的应用，选择需要的软件安装。
              </p>
            </div>
          </div>
        </NTabPane>
      </NTabs>
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
        <div
          id="software-source-actions"
          v-show="store === 'third-party'"
          class="source-actions"
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
      <template v-else-if="store === 'system'">
        <div v-if="filteredSystemSoftware.length" class="store-grid">
          <SoftwareCard
            v-for="app in filteredSystemSoftware"
            :key="app.id"
            :name="app.name"
            :description="app.description"
            :category="app.category"
            :status="app.status"
            :accent="app.accent"
            :status-type="
              app.installed
                ? app.status === '运行中' || app.status === '已安装'
                  ? 'success'
                  : 'warning'
                : app.state === 'unavailable' || app.state === 'recovery'
                  ? 'warning'
                  : 'default'
            "
          >
            <span v-if="app.id === 'nginx' && overview?.installation"
              >版本 {{ overview.installation.version }}</span
            ><span v-else
              >系统内置 ·
              {{ app.id === "nginx" ? "网站与代理" : "登录防护" }}</span
            >
            <template #actions>
              <RouterLink v-if="app.installed" :to="app.management"
                ><NButton type="primary">{{ app.action }}</NButton></RouterLink
              >
              <NButton
                v-else
                type="primary"
                :disabled="!permitted || app.state === 'unavailable' || active"
                @click="selected = app.id"
                >{{
                  app.state === "recovery"
                    ? "继续安装"
                    : app.state === "unbound"
                      ? "连接软件"
                      : "安装"
                }}</NButton
              >
              <NButton quaternary @click="selected = app.id">{{
                app.installed ? "软件管理" : "详情"
              }}</NButton>
            </template>
          </SoftwareCard>
        </div>
        <NEmpty v-else class="store-empty" description="没有符合条件的软件"
          ><template #extra
            ><NButton
              @click="
                search = '';
                statusFilter = 'all';
              "
              >清除筛选</NButton
            ></template
          ></NEmpty
        >
      </template>
      <SoftwareSourcesPanel
        :visible="store === 'third-party' && (loaded || !reading)"
        :catalog="overview?.software"
        :tasks="tasks"
        :active="active"
        :search="search"
        :status-filter="statusFilter"
        @changed="load"
        @task="recordTask"
      />
    </section>
  </div>
  <NModal
    :show="!!selected"
    preset="card"
    :title="selectedApp?.name ?? '软件详情'"
    style="width: 820px; max-width: calc(100vw - 32px)"
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
      <div v-if="selectedApp" class="detail-intro">
        <NTag
          :bordered="false"
          :type="selectedApp.installed ? 'success' : 'default'"
          >{{ selectedApp.status }}</NTag
        ><span class="muted">{{ selectedApp.description }}</span>
      </div>
      <Fail2banInstallPanel
        v-if="selected === 'fail2ban'"
        embedded
        @busy="detailBusy = $event"
        @changed="load"
      />
      <NginxInstallPanel
        v-if="selected === 'nginx'"
        :overview="overview"
        :tasks="tasks"
        :active="active"
        @task="recordTask"
        @busy="detailBusy = $event"
      />
    </div>
    <template #footer
      ><div class="dialog-footer">
        <NButton :disabled="detailBusy" @click="closeDetails">关闭</NButton>
      </div></template
    >
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
          <strong>{{ taskName(item) }}</strong
          ><NTag
            :bordered="false"
            :type="
              item.state === 'succeeded'
                ? 'success'
                : item.state === 'failed'
                  ? 'error'
                  : 'info'
            "
            >{{ stateLabels[item.state] || "正在处理" }}</NTag
          >
        </div>
        <div class="history-footer">
          <span class="muted">{{
            new Date(item.created_at * 1000).toLocaleString()
          }}</span
          ><TaskLogButton :task-id="item.id" />
        </div>
        <p v-if="item.error" class="error">{{ item.error }}</p>
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
.store-intro {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.store-intro h2 {
  font-size: 17px;
  margin-bottom: 6px;
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
.source-actions {
  flex: 1;
  display: flex;
  justify-content: flex-end;
  min-width: 0;
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
.detail-intro {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  align-items: center;
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
