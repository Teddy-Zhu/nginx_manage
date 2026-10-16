<route lang="json">
{
  "meta": {
    "title": "概览",
    "subtitle": "当前节点的配置与执行状态",
    "nav": true,
    "order": 0,
    "symbol": "◫"
  }
}
</route>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import {
  NAlert,
  NTag,
  NButton,
  NDataTable,
  NEmpty,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  type Task,
  type NginxRuntime,
  type MonitoringLatest,
  type NotificationOverview,
} from "../api/client";
import { RouterLink } from "vue-router";
import { useAction } from "../composables/action";
const api = useNodeAPI();
const { request } = api;

interface Tool {
  installed: boolean;
  path?: string;
  running: boolean | null;
}
interface Capabilities {
  nginx: NginxRuntime | null;
  mode: string;
  reason: string;
  host: null | {
    os: string;
    version: string;
    architecture: string;
    kernel: string;
    tools: Record<string, Tool>;
    dns: { candidate_owner: string; reason: string };
    selinux: string;
    apparmor: string;
  };
  version: number;
  desired_revision: string | null;
  applied_revision: string | null;
}
const { run, busy } = useAction(),
  capabilities = ref<Capabilities | null>(null),
  tasks = ref<Task[]>([]),
  monitoring = ref<MonitoringLatest | null>(null),
  notifications = ref<NotificationOverview | null>(null);
function metric(kind: string, field: string) {
  const value = monitoring.value?.sample?.metrics.find(
    (m) => m.kind === kind && m.id === "total",
  )?.values[field];
  return value == null ? "—" : `${value.toFixed(1)}%`;
}
async function load() {
  await run(async () => {
    const result = await Promise.all([
      request<Capabilities>({ url: "/system/capabilities" }),
      api.tasks(),
      api.monitoringLatest(),
      api.notifications(),
    ]);
    capabilities.value = result[0];
    tasks.value = result[1];
    monitoring.value = result[2];
    notifications.value = result[3];
  });
}
const columns: DataTableColumns<Task> = [
  { title: "任务", key: "kind" },
  { title: "状态", key: "state" },
  { title: "阶段", key: "stage" },
  {
    title: "创建时间",
    key: "created_at",
    render: (row) => new Date(row.created_at * 1000).toLocaleString(),
  },
];
onMounted(load);
</script>

<template>
  <div class="toolbar">
    <span class="muted">所有状态来自当前节点</span
    ><n-button :loading="busy" @click="load">刷新状态</n-button>
  </div>
  <n-alert
    v-if="capabilities?.mode === 'preview'"
    type="warning"
    :bordered="false"
    style="margin-bottom: 24px"
    title="预览模式"
    >未连接宿主机 Agent。配置可保存与预览，宿主机状态与实际应用不可用。</n-alert
  >
  <n-alert
    v-if="
      notifications &&
      (notifications.health.failed ||
        notifications.health.reason ||
        notifications.health.dropped_deliveries)
    "
    type="warning"
    :bordered="false"
    style="margin-bottom: 24px"
    >通知投递存在异常：{{
      notifications.health.reason ||
      `${notifications.health.failed} 条失败，${notifications.health.dropped_deliveries} 条因容量限制未完成`
    }}。<RouterLink to="/notifications">查看投递记录</RouterLink></n-alert
  >
  <div class="stat-grid">
    <div class="stat-card">
      <span class="stat-label">Agent 连接</span
      ><strong>{{
        capabilities
          ? capabilities.mode === "connected"
            ? "已连接"
            : "未连接"
          : "—"
      }}</strong
      ><span class="stat-hint">本机受限执行器</span>
    </div>
    <div class="stat-card">
      <span class="stat-label">期望配置修订</span
      ><strong>{{
        capabilities?.version ? `#${capabilities.version}` : "未保存"
      }}</strong
      ><span class="stat-hint">{{
        capabilities?.desired_revision?.slice(0, 8) ?? "暂无有效修订"
      }}</span>
    </div>
    <div class="stat-card">
      <span class="stat-label">实际生效修订</span
      ><strong>{{
        capabilities?.nginx?.running && capabilities.nginx.integrity
          ? capabilities.nginx.revision_id.slice(0, 8) || "初始配置"
          : "未确认"
      }}</strong
      ><span class="stat-hint"
        >最近确认：{{
          capabilities?.applied_revision?.slice(0, 8) ?? "尚无业务修订"
        }}</span
      >
    </div>
    <div class="stat-card">
      <span class="stat-label">最近失败任务</span
      ><strong>{{
        tasks.filter(
          (t) => t.state === "failed" || t.state === "recovery_required",
        ).length
      }}</strong
      ><span class="stat-hint">最近 {{ tasks.length }} 个任务</span>
    </div>
  </div>
  <section class="surface" style="margin-bottom: 24px">
    <div class="section-heading">
      <h2>资源概览</h2>
      <RouterLink to="/server">查看服务器</RouterLink>
    </div>
    <p class="muted">
      {{
        monitoring?.reason ||
        (monitoring?.stale ? "样本已过期" : "宿主机最新样本")
      }}
    </p>
    <div class="stat-grid">
      <div class="stat-card">
        <span class="stat-label">CPU</span
        ><strong>{{ metric("cpu", "usage_percent") }}</strong>
      </div>
      <div class="stat-card">
        <span class="stat-label">内存</span
        ><strong>{{ metric("memory", "used_percent") }}</strong>
      </div>
      <div class="stat-card">
        <span class="stat-label">采样时间</span
        ><strong style="font-size: 16px">{{
          monitoring?.sample
            ? new Date(monitoring.sample.at * 1000).toLocaleString()
            : "—"
        }}</strong>
      </div>
    </div>
  </section>
  <div class="two-columns">
    <section class="surface">
      <div class="section-heading">
        <h2>宿主机</h2>
        <n-tag
          size="small"
          :type="capabilities?.host ? 'success' : 'default'"
          :bordered="false"
          >{{ capabilities?.host ? "Agent 采集" : "未知" }}</n-tag
        >
      </div>
      <dl v-if="capabilities?.host" class="detail-list">
        <dt>操作系统</dt>
        <dd>{{ capabilities.host.os }} {{ capabilities.host.version }}</dd>
        <dt>架构</dt>
        <dd>{{ capabilities.host.architecture }}</dd>
        <dt>内核</dt>
        <dd>{{ capabilities.host.kernel }}</dd>
        <dt>SELinux</dt>
        <dd>{{ capabilities.host.selinux }}</dd>
        <dt>AppArmor</dt>
        <dd>{{ capabilities.host.apparmor }}</dd>
        <dt>DNS 候选所有者</dt>
        <dd>{{ capabilities.host.dns.candidate_owner }}</dd>
      </dl>
      <n-empty v-else description="连接宿主机 Agent 后可查看真实系统信息" />
    </section>
    <section class="surface">
      <div class="section-heading">
        <h2>组件探测</h2>
        <span class="muted">安装状态</span>
      </div>
      <template v-if="capabilities?.host"
        ><div
          v-for="(tool, name) in capabilities.host.tools"
          :key="name"
          class="component-row"
        >
          <span class="mono">{{ name }}</span
          ><n-tag
            size="small"
            :bordered="false"
            :type="tool.installed ? 'success' : 'default'"
            >{{ tool.installed ? "已安装" : "未发现" }}</n-tag
          >
        </div></template
      ><n-empty v-else description="暂无宿主机探测数据" />
    </section>
  </div>
  <section class="surface">
    <div class="section-heading">
      <h2>最近任务</h2>
      <router-link to="/tasks">查看全部 →</router-link>
    </div>
    <n-data-table
      :columns="columns"
      :data="tasks.slice(0, 6)"
      :bordered="false"
    />
  </section>
</template>
