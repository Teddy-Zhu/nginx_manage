<route lang="json">
{
  "meta": {
    "title": "系统概览",
    "nav": true,
    "order": 0,
    "symbol": "◫",
    "group": "运行概况"
  }
}
</route>

<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { ref, computed, onMounted } from "vue";
import { NAlert, NButton, NDataTable, type DataTableColumns } from "naive-ui";
import { RouterLink } from "vue-router";
import {
  apiError,
  useNodeAPI,
  type Task,
  type NginxRuntime,
  type MonitoringLatest,
  type NotificationOverview,
} from "../api/client";
import { taskKinds, taskStates } from "../utils/tasks";

const api = useNodeAPI();
interface Capabilities {
  mode: string;
  reason: string;
  host: {
    os: string;
    version: string;
    architecture: string;
    kernel: string;
  } | null;
}
const capabilities = ref<Capabilities | null>(null),
  nginx = ref<NginxRuntime | null>(null);
const monitoring = ref<MonitoringLatest | null>(null),
  notifications = ref<NotificationOverview | null>(null);
const tasks = ref<Task[] | null>(null),
  errors = ref<string[]>([]),
  loading = ref(false);
const softwareState = computed(() =>
  !nginx.value ? "unavailable" : nginx.value.installed ? "installed" : "missing",
);
const nginxLabel = computed(() =>
  softwareState.value === "missing"
    ? "未安装"
    : softwareState.value === "unavailable"
      ? "状态不可用"
      : nginx.value?.running
        ? "运行中"
        : "未运行",
);
function metric(kind: string, field: string) {
  if (monitoring.value?.stale) return "—";
  const value = monitoring.value?.sample?.metrics.find(
    (item) => item.kind === kind && item.id === "total",
  )?.values[field];
  return value == null ? "—" : `${value.toFixed(1)}%`;
}
async function load() {
  if (loading.value) return;
  loading.value = true;
  const results = await Promise.allSettled([
    api.request<Capabilities>({ url: "/system/capabilities" }),
    api.nginxRuntime(),
    api.monitoringLatest(),
    api.tasks(),
    api.notifications(),
  ]);
  const labels = [
    "服务器状态",
    "Nginx 状态",
    "监控数据",
    "任务记录",
    "通知状态",
  ];
  errors.value = results.flatMap((result, index) =>
    result.status === "rejected"
      ? [`${labels[index]}：${apiError(result.reason).message}`]
      : [],
  );
  capabilities.value =
    results[0].status === "fulfilled" ? results[0].value : null;
  nginx.value = results[1].status === "fulfilled" ? results[1].value : null;
  monitoring.value =
    results[2].status === "fulfilled" ? results[2].value : null;
  tasks.value = results[3].status === "fulfilled" ? results[3].value : null;
  notifications.value =
    results[4].status === "fulfilled" ? results[4].value : null;
  loading.value = false;
}
function reload() {
  api.reloadLive();
  return load();
}
const columns: DataTableColumns<Task> = [
  {
    title: "任务",
    key: "kind",
    render: (row) => taskKinds[row.kind] ?? "系统任务",
  },
  {
    title: "状态",
    key: "state",
    render: (row) => taskStates[row.state] ?? "未知状态",
  },
  {
    title: "创建时间",
    key: "created_at",
    render: (row) => new Date(row.created_at * 1000).toLocaleString(),
  },
];
onMounted(load);
useLiveRefresh(
  api,
  ["tasks", "nginx", "monitoring", "notifications"],
  load,
  () => loading.value,
);
</script>

<template>
  <div class="page-stack">
    <div class="toolbar">
      <h2>服务器概况</h2>
      <NButton :loading="loading" @click="reload">
        刷新
      </NButton>
    </div>
    <NAlert v-if="errors.length" type="warning" title="部分状态暂时无法读取">
      其他功能仍可使用，请稍后刷新。
    </NAlert>
    <NAlert
      v-if="capabilities && capabilities.mode !== 'connected'"
      type="warning"
      title="服务器管理服务未连接"
    >
      请检查面板服务是否正常运行。
    </NAlert>
    <NAlert
      v-if="
        notifications &&
          (notifications.health.failed ||
            notifications.health.reason ||
            notifications.health.dropped_deliveries)
      "
      type="warning"
    >
      有通知未能正常发送，<RouterLink to="/notifications">
        查看通知记录
      </RouterLink>。
    </NAlert>
    <div class="stat-grid">
      <div class="stat-card">
        <span class="stat-label">CPU 使用率</span><strong>{{ metric("cpu", "usage_percent") }}</strong><span class="stat-hint">{{
          monitoring?.stale
            ? "数据已过期"
            : monitoring?.sample
              ? `更新于 ${new Date(monitoring.sample.at * 1000).toLocaleTimeString()}`
              : "暂无监控数据"
        }}</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">内存使用率</span><strong>{{ metric("memory", "used_percent") }}</strong><RouterLink to="/server">
          查看系统监控
        </RouterLink>
      </div>
      <div class="stat-card">
        <span class="stat-label">Nginx</span><strong>{{ nginxLabel }}</strong><RouterLink
          v-if="softwareState === 'missing'"
          :to="{ path: '/components', query: { software: 'nginx' } }"
        >
          前往安装
        </RouterLink><RouterLink v-else-if="softwareState === 'installed'" to="/nginx">
          管理网站
        </RouterLink><span v-else class="stat-hint">请刷新重试</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">待处理问题</span><strong>{{
          tasks
            ? tasks.filter((task) =>
              ["failed", "recovery_required"].includes(task.state),
            ).length
            : "—"
        }}</strong><RouterLink to="/tasks">
          查看操作记录
        </RouterLink>
      </div>
    </div>
    <section class="panel page-stack">
      <h2>常用操作</h2>
      <div class="shortcut-grid">
        <RouterLink to="/nginx">
          <strong>网站管理</strong><span class="muted">管理域名、网站和反向代理</span>
        </RouterLink>
        <RouterLink to="/certificates">
          <strong>证书管理</strong><span class="muted">申请和更新网站证书</span>
        </RouterLink>
        <RouterLink to="/firewall-rules">
          <strong>防火墙</strong><span class="muted">管理端口和访问规则</span>
        </RouterLink>
        <RouterLink to="/components">
          <strong>软件商店</strong><span class="muted">安装所需软件</span>
        </RouterLink>
      </div>
    </section>
    <div class="two-columns">
      <section class="surface">
        <div class="section-heading">
          <h2>系统信息</h2>
          <RouterLink to="/server">
            系统监控
          </RouterLink>
        </div>
        <dl v-if="capabilities?.host" class="detail-list">
          <dt>操作系统</dt>
          <dd>{{ capabilities.host.os }} {{ capabilities.host.version }}</dd>
          <dt>系统架构</dt>
          <dd>{{ capabilities.host.architecture }}</dd>
          <dt>内核版本</dt>
          <dd>{{ capabilities.host.kernel }}</dd>
        </dl>
        <p v-else class="muted">
          暂时无法读取系统信息
        </p>
      </section>
      <section class="surface">
        <div class="section-heading">
          <h2>最近任务</h2>
          <RouterLink to="/tasks">
            全部记录
          </RouterLink>
        </div>
        <NDataTable
          :columns="columns"
          :data="(tasks ?? []).slice(0, 5)"
          :bordered="false"
          :loading="loading"
          :single-line="false"
        />
      </section>
    </div>
  </div>
</template>
