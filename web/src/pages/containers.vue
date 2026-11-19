<route lang="json">
{
  "meta": {
    "title": "容器管理",
    "nav": true,
    "order": 41,
    "symbol": "▦",
    "group": "系统管理"
  }
}
</route>
<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NDropdown,
  NInput,
  NModal,
  NSelect,
  NSpin,
  NTag,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentTask,
  type DockerContainer,
  type DockerControl,
  type DockerDetail,
  type DockerLogs,
  type DockerOverview,
} from "../api/client";
import { useSession } from "../stores/session";
import { useAction, useIdempotency } from "../composables/action";
import { useLiveRefresh } from "../composables/live";
import { inspectTask } from "../stores/operation";
import { isTaskActive, taskStates } from "../utils/tasks";
import { copyText } from "../utils/copy";
import SettingsSection from "../components/SettingsSection.vue";
const api = useNodeAPI(),
  session = useSession(),
  dialog = useDialog(),
  { run, busy, message } = useAction();
const view = ref<DockerOverview | null>(null),
  tasks = ref<ComponentTask[]>([]),
  error = ref(""),
  loading = ref(true),
  search = ref(""),
  filter = ref("all");
const detailID = ref(""),
  detail = ref<DockerDetail | null>(null),
  detailError = ref("");
const logID = ref(""),
  logs = ref<DockerLogs | null>(null),
  logError = ref(""),
  tail = ref(200),
  paused = ref(false);
const canRead = computed(
  () =>
    session.me?.scopes.includes("read") &&
    session.me?.scopes.includes("components.manage"),
);
const canWrite = computed(
  () => canRead.value && session.me?.scopes.includes("system.write"),
);
let closed = false,
  keyFor = useIdempotency();
const labels: Record<string, string> = {
  running: "运行中",
  created: "未启动",
  exited: "已停止",
  paused: "已暂停",
  restarting: "正在重启",
  removing: "正在移除",
  dead: "运行异常",
};
const stateLabel = (state: string) => labels[state] || "状态未知";
const components: Record<string, string> = {
  panel: "管理面板",
  nginx: "Nginx",
  fail2ban: "登录防护",
  frps: "FRP 服务端",
};
const time = (value: number | string) => {
  if (!value || (typeof value === "string" && value.startsWith("0001-")))
    return "—";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
};
const list = computed(() => view.value?.containers ?? []);
const running = computed(
  () => list.value.filter((c) => c.state === "running").length,
);
const stopped = computed(
  () =>
    list.value.filter((c) => c.state === "created" || c.state === "exited")
      .length,
);
const filtered = computed(() =>
  list.value.filter((c) => {
    const term = search.value.trim().toLowerCase();
    return (
      (!term ||
        [
          c.name,
          c.image,
          c.id,
          c.project,
          c.service,
          components[c.component] ?? "",
        ].some((value) => value.toLowerCase().includes(term))) &&
      (filter.value === "all" ||
        (filter.value === "running" && c.state === "running") ||
        (filter.value === "stopped" &&
          ["exited", "created"].includes(c.state)) ||
        (filter.value === "other" &&
          !["running", "created", "exited"].includes(c.state)))
    );
  }),
);
const active = computed(() => tasks.value.find((t) => isTaskActive(t.state)));
const containerTasks = computed(() =>
  tasks.value.filter((t) => t.result?.input.software?.action === "container"),
);
const selectedLogName = computed(
  () => list.value.find((c) => c.id === logID.value)?.name ?? "容器",
);
const policies: Record<string, string> = {
  no: "不自动重启",
  always: "始终重启",
  "unless-stopped": "除手动停止外自动重启",
  "on-failure": "异常退出时重启",
};
const health: Record<string, string> = {
  healthy: "健康",
  unhealthy: "健康检查未通过",
  starting: "正在检查",
};
function ports(c: DockerContainer) {
  return (
    c.ports
      .map((p) =>
        p.public
          ? `${p.address.includes(":") ? "[" + p.address + "]" : p.address || "全部地址"}:${p.public} → ${p.private}/${p.protocol}`
          : `${p.private}/${p.protocol}（未映射）`,
      )
      .join("\n") || "无端口映射"
  );
}
async function load() {
  if (!canRead.value) {
    loading.value = false;
    return;
  }
  try {
    const [next, records] = await Promise.all([
      api.dockerContainers(),
      api.componentTasks(),
    ]);
    if (closed) return;
    view.value = next;
    tasks.value = records;
    error.value = "";
  } catch (cause) {
    if (!closed) error.value = apiError(cause).message;
  } finally {
    if (!closed) loading.value = false;
  }
}
async function control(c: DockerContainer, action: DockerControl["action"]) {
  if (
    closed ||
    !canWrite.value ||
    busy.value ||
    active.value ||
    error.value ||
    c.protected
  )
    return;
  const input = {
    action: "software" as const,
    tag: "",
    prerelease: false,
    plan_id: "",
    manifest_sha256: "",
    trust_sha256: "",
    software: { action: "container" as const, container: { id: c.id, action } },
  };
  await run(async () => {
    const task = await api.createComponentTask({ input }, keyFor(input));
    if (closed) return;
    tasks.value = [task, ...tasks.value.filter((t) => t.id !== task.id)];
    keyFor = useIdempotency();
  });
}
async function copyLogs() {
  try {
    await copyText(logs.value?.text ?? "");
    message.success("日志已复制");
  } catch {
    message.error("无法复制，请选择日志内容手动复制");
  }
}
function selectControl(c: DockerContainer, action: string) {
  if (action === "stop") {
    dialog.warning({
      title: "停止容器",
      content: `停止 ${c.name} 后，其提供的服务将不可用。确认停止？`,
      positiveText: "停止容器",
      negativeText: "取消",
      onPositiveClick: () => control(c, "stop"),
    });
  } else if (action === "start" || action === "restart") {
    void control(c, action);
  }
}
const columns: DataTableColumns<DockerContainer> = [
  {
    title: "容器",
    key: "name",
    width: 300,
    render: (c) =>
      h("div", { class: "container-name" }, [
        h(
          NButton,
          {
            class: "container-title",
            text: true,
            type: "primary",
            title: c.name,
            onClick: () => (detailID.value = c.id),
          },
          () => c.name,
        ),
        c.component || c.project
          ? h("div", { class: "container-meta" }, [
              c.component
                ? h(
                    NTag,
                    { size: "small", bordered: false, type: "info" },
                    () => `系统 · ${components[c.component] ?? c.component}`,
                  )
                : null,
              c.project
                ? h(
                    "span",
                    {
                      class: "container-project",
                      title: `${c.project}${c.service ? " / " + c.service : ""}`,
                    },
                    `${c.project}${c.service ? " / " + c.service : ""}`,
                  )
                : null,
            ])
          : null,
      ]),
  },
  {
    title: "镜像",
    key: "image",
    minWidth: 210,
    render: (c) =>
      h(
        "div",
        { class: "container-image", title: c.image },
        c.image.startsWith("sha256:")
          ? [
              h("span", "本地镜像"),
              h("span", { class: "container-image-ref" }, c.image),
            ]
          : [h("span", { class: "container-image-name" }, c.image)],
      ),
  },
  {
    title: "状态",
    key: "state",
    width: 110,
    render: (c) =>
      h(
        NTag,
        {
          size: "small",
          bordered: false,
          type:
            c.state === "running"
              ? "success"
              : ["dead", "restarting"].includes(c.state)
                ? "warning"
                : "default",
        },
        () => stateLabel(c.state),
      ),
  },
  {
    title: "端口映射",
    key: "ports",
    minWidth: 220,
    render: (c) =>
      h(
        "span",
        { class: ["container-ports", { "container-muted": !c.ports.length }] },
        ports(c),
      ),
  },
  {
    title: "操作",
    key: "actions",
    width: 190,
    fixed: "right",
    render: (c) => {
      const options = ["created", "exited"].includes(c.state)
        ? [{ label: "启动容器", key: "start" }]
        : ["running", "restarting"].includes(c.state)
          ? [
              { label: "重启容器", key: "restart" },
              { label: "停止容器", key: "stop" },
            ]
          : [];
      return h("div", { class: "container-actions" }, [
        h(
          NButton,
          {
            size: "small",
            text: true,
            type: "primary",
            onClick: () => (detailID.value = c.id),
          },
          () => "详情",
        ),
        h(
          NButton,
          {
            size: "small",
            text: true,
            type: "primary",
            onClick: () => (logID.value = c.id),
          },
          () => "日志",
        ),
        !c.protected && options.length
          ? h(
              NDropdown,
              {
                trigger: "click",
                options,
                onSelect: (action: string) => selectControl(c, action),
              },
              {
                default: () =>
                  h(
                    NButton,
                    {
                      size: "small",
                      quaternary: true,
                      disabled:
                        !canWrite.value ||
                        busy.value ||
                        !!active.value ||
                        !!error.value,
                      "aria-label": `管理 ${c.name}`,
                    },
                    () => [
                      "更多",
                      h(
                        "span",
                        {
                          class: "container-action-arrow",
                          "aria-hidden": "true",
                        },
                        "⌄",
                      ),
                    ],
                  ),
              },
            )
          : null,
      ]);
    },
  },
];
watch(detailID, (id, _, cleanup) => {
  detail.value = null;
  detailError.value = "";
  if (!id) return;
  cleanup(
    api.watchDockerContainer(
      id,
      (value) => {
        if (detailID.value === id) {
          detail.value = value;
          detailError.value = "";
        }
      },
      (cause) => {
        if (detailID.value === id) detailError.value = cause.message;
      },
    ),
  );
});
watch([logID, tail, paused], ([id, count, freeze], _, cleanup) => {
  if (!id) {
    logs.value = null;
    logError.value = "";
    paused.value = false;
    return;
  }
  if (freeze) return;
  logs.value = null;
  logError.value = "";
  cleanup(
    api.watchDockerLogs(
      id,
      count,
      (value) => {
        if (logID.value === id && tail.value === count) {
          logs.value = value;
          logError.value = "";
        }
      },
      (cause) => {
        if (logID.value === id && tail.value === count)
          logError.value = cause.message;
      },
    ),
  );
});
useLiveRefresh(api, ["docker", "tasks"], load, () => busy.value);
onMounted(load);
onUnmounted(() => {
  closed = true;
});
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="!canRead" type="warning" :bordered="false">
      需要容器查看权限。
    </NAlert>
    <template v-else>
      <NAlert v-if="error" type="error" :bordered="false">
        {{ error }}
      </NAlert>
      <NAlert v-if="view && !view.available" type="warning" :bordered="false">
        {{ view.reason }}
      </NAlert>
      <div class="stat-grid">
        <div class="stat-card">
          <span class="stat-label">全部容器</span><strong>{{ view?.available ? list.length : "—" }}</strong>
        </div>
        <div class="stat-card">
          <span class="stat-label">运行中</span><strong>{{ view?.available ? running : "—" }}</strong>
        </div>
        <div class="stat-card">
          <span class="stat-label">已停止 / 未启动</span><strong>{{ view?.available ? stopped : "—" }}</strong>
        </div>
      </div>
      <section class="panel page-stack">
        <div class="container-list-toolbar">
          <h2>容器列表</h2>
          <div class="container-filters">
            <NInput
              v-model:value="search"
              class="container-search"
              clearable
              placeholder="搜索容器名称、镜像或项目"
            /><NSelect
              v-model:value="filter"
              :options="[
                { label: '全部状态', value: 'all' },
                { label: '运行中', value: 'running' },
                { label: '已停止 / 未启动', value: 'stopped' },
                { label: '其他状态', value: 'other' },
              ]"
            />
            <NButton :loading="loading" :disabled="busy" @click="load">
              刷新
            </NButton>
          </div>
        </div>
        <NAlert v-if="active" type="info" :bordered="false">
          <div class="toolbar">
            <span>有操作正在处理，完成后可继续启停容器。</span><NButton
              text
              type="primary"
              @click="inspectTask(active.id, '操作日志')"
            >
              查看操作日志
            </NButton>
          </div>
        </NAlert>
        <NDataTable
          class="container-table"
          table-layout="fixed"
          :loading="loading"
          :columns="columns"
          :data="filtered"
          :row-key="(c: DockerContainer) => c.id"
          :scroll-x="1040"
          :pagination="{ pageSize: 20 }"
          :bordered="false"
        />
      </section>
      <section v-if="containerTasks.length" class="panel page-stack">
        <h2>最近容器操作</h2>
        <div
          v-for="task in containerTasks.slice(0, 5)"
          :key="task.id"
          class="toolbar"
        >
          <span><NTag
                  size="small"
                  :bordered="false"
                  :type="
                    task.state === 'succeeded'
                      ? 'success'
                      : task.state === 'failed'
                        ? 'error'
                        : 'info'
                  "
                >{{ taskStates[task.state] || "状态待确认" }}</NTag>
            {{
              task.error ||
                task.result?.software?.message ||
                task.result?.runtime_reason ||
                "容器操作"
            }}<small class="section-note">
              · {{ time(task.created_at) }}</small></span><NButton size="small" @click="inspectTask(task.id, '容器操作日志')">
            查看日志
          </NButton>
        </div>
      </section>
    </template>
  </div>
  <NModal
    :show="!!detailID"
    preset="card"
    :title="detail?.name || '容器详情'"
    class="container-dialog"
    @update:show="
      (value) => {
        if (!value) detailID = '';
      }
    "
  >
    <NAlert v-if="detailError" type="error" :bordered="false">
      {{ detailError }}
    </NAlert>
    <NSpin v-else :show="!detail">
      <div v-if="detail" class="settings-stack">
        <NAlert v-if="detail.protected" type="info" :bordered="false">
          这是当前面板使用的系统容器，启停操作由系统管理。
        </NAlert>
        <SettingsSection title="基本信息">
          <dl class="detail-list">
            <dt>所属软件</dt>
            <dd>
              {{
                components[detail.component]
                  ? `${components[detail.component]}（系统容器）`
                  : "独立容器"
              }}
            </dd>
            <dt>状态</dt>
            <dd>{{ stateLabel(detail.state) }}</dd>
            <dt>镜像</dt>
            <dd>{{ detail.image }}</dd>
            <dt>容器 ID</dt>
            <dd class="break-all">
              {{ detail.id }}
            </dd>
            <dt>镜像 ID</dt>
            <dd class="break-all">
              {{ detail.image_id }}
            </dd>
            <dt>创建时间</dt>
            <dd>{{ time(detail.created) }}</dd>
            <dt>最近启动</dt>
            <dd>{{ time(detail.started) }}</dd>
            <dt>最近停止</dt>
            <dd>{{ time(detail.finished) }}</dd>
            <dt>自动重启策略</dt>
            <dd>
              {{
                policies[detail.restart_policy] || detail.restart_policy || "—"
              }}
            </dd>
            <dt>重启次数</dt>
            <dd>{{ detail.restarts }}</dd>
            <dt>健康检查</dt>
            <dd>{{ health[detail.health] || "未设置" }}</dd>
            <dt>退出码</dt>
            <dd>{{ detail.exit_code }}</dd>
            <dt v-if="detail.project">
              所属项目
            </dt>
            <dd v-if="detail.project">
              {{ detail.project }} / {{ detail.service || "—" }}
            </dd>
          </dl>
        </SettingsSection>
        <SettingsSection title="网络与端口">
          <p>网络模式：{{ detail.network_mode }}</p>
          <p class="container-ports">
            {{ ports(detail) }}
          </p>
          <div
            v-for="network in detail.networks"
            :key="network.name"
            class="container-network"
          >
            <strong>{{ network.name }}</strong><span>{{ network.address || "未分配地址" }}</span><span>网关：{{ network.gateway || "无" }}</span>
          </div>
        </SettingsSection>
        <SettingsSection title="数据挂载">
          <p v-if="!detail.mounts.length" class="section-note">
            未配置数据挂载。
          </p>
          <div
            v-for="(mount, index) in detail.mounts"
            :key="index"
            class="container-mount"
          >
            <span class="break-all">{{ mount.source }} → {{ mount.target }}</span><NTag size="small">
              {{ mount.read_only ? "只读" : "可读写" }}
            </NTag>
          </div>
        </SettingsSection>
      </div>
    </NSpin>
  </NModal>
  <NModal
    :show="!!logID"
    preset="card"
    :title="selectedLogName + ' · 日志'"
    class="container-dialog"
    @update:show="
      (value) => {
        if (!value) logID = '';
      }
    "
  >
    <div class="page-stack">
      <div class="toolbar">
        <NSelect
          v-model:value="tail"
          class="container-log-count"
          :disabled="paused"
          :options="
            [50, 100, 200, 500].map((value) => ({
              label: '最近 ' + value + ' 行',
              value,
            }))
          "
        /><NButton :disabled="!logs && !logError" @click="paused = !paused">
          {{ paused ? "继续更新" : "暂停更新" }}
        </NButton><NButton :disabled="!logs?.text" @click="copyLogs">
          复制日志
        </NButton>
      </div>
      <NAlert v-if="logError" type="error" :bordered="false">
        {{ logError }}
      </NAlert><NAlert v-if="logs?.truncated" type="warning" :bordered="false">
        日志较长，内容已截断。减少显示行数可查看最近的日志。
      </NAlert><NSpin :show="!logs && !logError && !paused">
        <pre class="container-log">{{
          logs?.text ||
          (logError ? "无法读取日志" : logs ? "暂无日志" : "正在读取日志…")
        }}</pre>
      </NSpin>
    </div>
  </NModal>
</template>
<style scoped>
.stat-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.container-list-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 16px;
  min-width: 0;
}
.container-list-toolbar h2 {
  flex-shrink: 0;
}
.container-filters {
  display: grid;
  grid-template-columns: minmax(180px, 320px) 160px auto;
  gap: 12px;
  max-width: 100%;
}
.container-table :deep(.n-data-table-td) {
  padding: 18px 16px;
  vertical-align: middle;
}
.container-table :deep(.container-name),
.container-table :deep(.container-image) {
  display: grid;
  gap: 8px;
  min-width: 0;
}
.container-table :deep(.container-title) {
  max-width: 100%;
  justify-content: flex-start;
  font-weight: 600;
}
.container-table :deep(.container-title .n-button__content),
.container-table :deep(.container-project),
.container-table :deep(.container-image-name),
.container-table :deep(.container-image-ref) {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.container-table :deep(.container-meta) {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 10px;
  min-width: 0;
}
.container-table :deep(.container-meta .n-tag) {
  flex-shrink: 0;
}
.container-table :deep(.container-project) {
  font-size: 12px;
  color: var(--text-muted);
}
.container-table :deep(.container-image-ref) {
  color: var(--text-muted);
  font:
    12px/1.5 ui-monospace,
    monospace;
}
.container-table :deep(.container-muted) {
  color: var(--text-muted);
}
.container-table :deep(.container-ports) {
  white-space: pre-line;
  overflow-wrap: anywhere;
}
.container-table :deep(.container-actions) {
  display: flex;
  align-items: center;
  flex-wrap: nowrap;
  gap: 16px;
  white-space: nowrap;
}
.container-table :deep(.container-action-arrow) {
  margin-left: 4px;
  font-size: 12px;
}
.container-dialog {
  width: 960px;
  max-width: calc(100vw - 32px);
}
.container-dialog :deep(.n-card__content) {
  max-height: calc(100dvh - 190px);
  overflow: auto;
}
.container-network {
  display: grid;
  grid-template-columns: 1fr 2fr 2fr;
  gap: 12px;
  padding: 10px 0;
  border-top: 1px solid var(--border-color);
  overflow-wrap: anywhere;
}
.container-mount {
  display: flex;
  gap: 16px;
  justify-content: space-between;
  align-items: center;
}
.container-log {
  height: min(55vh, 520px);
  min-height: 180px;
  overflow: auto;
  background: #15211d;
  color: #e8f0eb;
  padding: 18px;
  border-radius: 8px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font:
    13px/1.65 ui-monospace,
    monospace;
}
.container-log-count {
  width: 180px;
}
.break-all {
  overflow-wrap: anywhere;
}
@media (max-width: 640px) {
  .stat-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .container-network {
    grid-template-columns: minmax(0, 1fr);
  }
  .container-filters {
    flex: 1 1 100%;
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .container-search {
    grid-column: 1 / -1;
  }
  .container-mount {
    align-items: flex-start;
  }
}
</style>
