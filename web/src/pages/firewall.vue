<route lang="json">
{
  "meta": {
    "title": "防火墙",
    "subtitle": "宿主机后端与转发路径诊断",
    "nav": true,
    "order": 0.7,
    "symbol": "◇"
  }
}
</route>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NCollapse,
  NCollapseItem,
  NDataTable,
  NEmpty,
  NTag,
  type DataTableColumns,
} from "naive-ui";
import { apiError, useNodeAPI, type FirewallObservation } from "../api/client";

const api = useNodeAPI();
const observation = ref<FirewallObservation | null>(null);
const reading = ref(false),
  error = ref("");
const controller = new AbortController();
let poll: ReturnType<typeof setInterval> | undefined;
const status = (value: boolean | null) =>
  value === null ? "未知" : value ? "是" : "否";
const managerNames: Record<string, string> = {
  unknown: "未确认",
  conflict: "管理器冲突",
  firewalld: "firewalld",
  ufw: "UFW",
  "direct-candidate": "未发现启用的管理器",
};
const registrationNames: Record<string, string> = {
  unavailable: "无法核对",
  unregistered: "未登记",
  registered: "已登记空表",
  released: "已释放登记",
  missing: "登记表缺失",
  drifted: "登记对象变化",
  recovery_required: "待本机恢复",
};
const backendNames: Record<string, string> = {
  unknown: "未确认",
  nftables: "nftables",
  legacy: "iptables-legacy",
  iptables: "iptables 链标记",
  mixed: "混合线索",
};
const scopeNames: Record<string, string> = {
  host: "宿主机",
  unconfirmed: "未确认",
  development: "开发环境",
};
const familyNames: Record<string, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  all: "全部地址族",
};
const displayTime = computed(() =>
  observation.value?.at
    ? new Date(observation.value.at * 1000).toLocaleString()
    : "未取得观测时间",
);
type ChainRow = {
  key: number;
  family: string;
  table: string;
  chain: string;
  type: string;
  hook: string;
  priority: number | null;
  policy: string;
  rules: number | null;
  jump: boolean | null;
};
const views = computed(() =>
  (observation.value?.rulesets ?? []).map((view) => {
    let key = 0;
    const rows: ChainRow[] = view.tables.flatMap<ChainRow>((table) =>
      table.chains.length
        ? table.chains.map((chain) => ({
            key: key++,
            family: table.family,
            table: table.name,
            chain: chain.name,
            type: chain.type,
            hook: chain.hook,
            priority: chain.priority,
            policy: chain.policy,
            rules: chain.rules,
            jump: chain.docker_user_jump,
          }))
        : [
            {
              key: key++,
              family: table.family,
              table: table.name,
              chain: "—",
              type: "",
              hook: "",
              priority: null,
              policy: "",
              rules: null,
              jump: null,
            },
          ],
    );
    return {
      ...view,
      rows,
      chainCount: view.tables.reduce(
        (sum, table) => sum + table.chains.length,
        0,
      ),
    };
  }),
);
const columns: DataTableColumns<ChainRow> = [
  {
    title: "地址族",
    key: "family",
    render: (r) => familyNames[r.family] ?? r.family,
    width: 100,
  },
  { title: "表", key: "table", minWidth: 130, ellipsis: { tooltip: true } },
  { title: "链", key: "chain", minWidth: 150, ellipsis: { tooltip: true } },
  { title: "类型", key: "type", render: (r) => r.type || "—", width: 90 },
  { title: "Hook", key: "hook", render: (r) => r.hook || "—", width: 120 },
  {
    title: "优先级",
    key: "priority",
    render: (r) => r.priority ?? "—",
    width: 90,
  },
  {
    title: "默认策略",
    key: "policy",
    render: (r) => (r.policy === "-" ? "—" : r.policy || "—"),
    width: 100,
  },
  { title: "规则数", key: "rules", render: (r) => r.rules ?? "—", width: 90 },
  {
    title: "跳转 DOCKER-USER",
    key: "jump",
    render: (r) => (r.jump === null ? "—" : r.jump ? "已观察到" : "未观察到"),
    width: 160,
  },
];

async function read() {
  if (reading.value || controller.signal.aborted) return;
  reading.value = true;
  try {
    const result = await api.firewall(controller.signal);
    if (!controller.signal.aborted) {
      observation.value = result;
      error.value = "";
    }
  } catch (cause) {
    if (!controller.signal.aborted) error.value = apiError(cause).message;
  } finally {
    reading.value = false;
  }
}
function visible() {
  if (!document.hidden) void read();
}
onMounted(() => {
  void read();
  poll = setInterval(visible, 30_000);
  document.addEventListener("visibilitychange", visible);
});
onUnmounted(() => {
  controller.abort();
  if (poll) clearInterval(poll);
  document.removeEventListener("visibilitychange", visible);
});
</script>

<template>
  <div class="page-toolbar">
    <h2>防火墙</h2>
    <div class="actions">
      <n-tag>只读</n-tag
      ><n-button :loading="reading" @click="read">刷新</n-button>
    </div>
  </div>
  <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>
  <n-alert type="info" :bordered="false" class="notice"
    >本机规则状态不代表外部可达性。云安全组、其他规则及实际转发路径须分别核对；各视图独立读取，观测结果最多缓存
    30 秒。</n-alert
  >
  <template v-if="observation">
    <section class="panel">
      <h3>观测概览</h3>
      <dl>
        <dt>观测时间</dt>
        <dd>{{ displayTime }}</dd>
        <dt>范围</dt>
        <dd>{{ scopeNames[observation.scope] ?? observation.scope }}</dd>
        <dt>管理器线索</dt>
        <dd>{{ managerNames[observation.manager] ?? observation.manager }}</dd>
        <dt>已观察到的内核策略</dt>
        <dd>{{ backendNames[observation.backend] ?? observation.backend }}</dd>
      </dl>
      <n-alert
        v-if="observation.reason"
        :type="observation.available ? 'info' : 'warning'"
        :bordered="false"
        >{{ observation.reason }}</n-alert
      >
      <n-alert
        v-for="warning in observation.warnings"
        :key="warning"
        type="warning"
        :bordered="false"
        class="notice"
        >{{ warning }}</n-alert
      >
    </section>
    <template v-if="observation.available">
      <section class="panel">
        <h3>目标表内核快照</h3>
        <n-alert
          v-if="!observation.kernel.available"
          type="warning"
          :bordered="false"
          >{{ observation.kernel.reason }}</n-alert
        >
        <dl v-else>
          <dt>规则代次</dt>
          <dd>{{ observation.kernel.generation }}</dd>
          <dt>目标表</dt>
          <dd>
            {{
              observation.kernel.table_exists
                ? "inet nginxpanel_host 已存在"
                : "inet nginxpanel_host 未存在"
            }}
          </dd>
          <dt>链 / 规则数</dt>
          <dd>
            {{ observation.kernel.chains }} / {{ observation.kernel.rules }}
          </dd>
          <dt>快照摘要</dt>
          <dd>
            <code>{{ observation.kernel.fingerprint }}</code>
          </dd>
        </dl>
        <dl>
          <dt>受管登记</dt>
          <dd>{{ registrationNames[observation.registration.state] }}</dd>
          <dt>登记核对</dt>
          <dd>{{ observation.registration.verified ? "通过" : "未通过" }}</dd>
        </dl>
        <n-alert
          v-if="observation.registration.reason"
          type="warning"
          :bordered="false"
          >{{ observation.registration.reason }}</n-alert
        >
        <p class="muted">空表登记不包含过滤策略；外部可达性须分别核对。</p>
      </section>
      <div class="managers">
        <section class="panel">
          <h3>firewalld</h3>
          <dl>
            <dt>当前运行</dt>
            <dd>{{ status(observation.firewalld.running) }}</dd>
            <dt>Panic 模式</dt>
            <dd>{{ status(observation.firewalld.panic) }}</dd>
            <dt>配置选择的后端</dt>
            <dd>{{ observation.firewalld.configured_backend || "未知" }}</dd>
            <dt>默认 zone</dt>
            <dd>{{ observation.firewalld.default_zone || "未知" }}</dd>
          </dl>
          <n-alert
            v-if="observation.firewalld.reason"
            type="warning"
            :bordered="false"
            >{{ observation.firewalld.reason }}</n-alert
          >
          <div
            v-for="zone in observation.firewalld.zones"
            :key="zone.name"
            class="zone"
          >
            <strong>{{ zone.name }}</strong>
            <p>接口：{{ zone.interfaces.join("、") || "无" }}</p>
            <p>来源：{{ zone.sources.join("、") || "无" }}</p>
          </div>
        </section>
        <section class="panel">
          <h3>UFW</h3>
          <dl>
            <dt>受信工具</dt>
            <dd>{{ observation.ufw.installed ? "已发现" : "不可用" }}</dd>
            <dt>配置启用</dt>
            <dd>{{ status(observation.ufw.enabled) }}</dd>
            <dt>当前活动</dt>
            <dd>{{ status(observation.ufw.active) }}</dd>
          </dl>
          <n-alert
            v-if="observation.ufw.reason"
            type="warning"
            :bordered="false"
            >{{ observation.ufw.reason }}</n-alert
          >
        </section>
      </div>
      <section class="panel">
        <h3>默认 iptables 命令</h3>
        <dl v-for="tool in observation.iptables" :key="tool.family">
          <dt>{{ familyNames[tool.family] ?? tool.family }}</dt>
          <dd>
            {{ backendNames[tool.backend] ?? tool.backend }}
            <p class="muted">{{ tool.version || tool.reason }}</p>
          </dd>
        </dl>
        <p class="muted">
          命令后端与已运行的规则分别展示；工具存在不代表已启用策略。
        </p>
      </section>
      <section class="panel">
        <h3>内核规则结构</h3>
        <p class="muted">
          nftables 与 iptables-nft
          可能展示同一内核对象，数量不可直接相加。此处仅显示表、链和规则数量。
        </p>
        <n-collapse>
          <n-collapse-item
            v-for="view in views"
            :key="view.id"
            :name="view.id"
            :title="view.id"
          >
            <template #header-extra
              ><n-tag :type="view.available ? 'default' : 'warning'">{{
                view.available
                  ? `${view.tables.length} 张表 / ${view.chainCount} 条链`
                  : "不可用"
              }}</n-tag></template
            >
            <n-alert v-if="view.reason" type="warning" :bordered="false">{{
              view.reason
            }}</n-alert>
            <n-data-table
              v-if="view.available"
              :columns="columns"
              :data="view.rows"
              :row-key="(row: ChainRow) => row.key"
              :pagination="{ pageSize: 20 }"
              :scroll-x="1130"
            />
          </n-collapse-item>
        </n-collapse>
      </section>
      <section class="panel">
        <h3>Docker 转发路径线索</h3>
        <dl>
          <dt>后端标记</dt>
          <dd>
            {{
              backendNames[observation.docker.backend_hint] ??
              observation.docker.backend_hint
            }}
          </dd>
        </dl>
        <n-alert type="warning" :bordered="false">{{
          observation.docker.reason
        }}</n-alert>
        <ul v-if="observation.docker.evidence.length">
          <li v-for="item in observation.docker.evidence" :key="item">
            <code>{{ item }}</code>
          </li>
        </ul>
      </section>
    </template>
  </template>
  <n-empty v-else-if="!reading && !error" description="尚未取得防火墙观测" />
</template>

<style scoped>
.panel {
  padding: 20px;
  margin-top: 16px;
  border: 1px solid var(--border, #e5eae7);
  border-radius: 12px;
  background: white;
  min-width: 0;
}
.panel h3 {
  margin-top: 0;
}
.notice {
  margin: 16px 0;
}
.managers {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
dl {
  display: grid;
  grid-template-columns: 160px minmax(0, 1fr);
  gap: 10px;
}
dt {
  color: #6d7772;
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
dd p,
.zone p {
  margin: 4px 0;
}
.zone {
  margin-top: 14px;
  overflow-wrap: anywhere;
}
li {
  margin: 8px 0;
  overflow-wrap: anywhere;
}
@media (max-width: 760px) {
  .managers {
    grid-template-columns: 1fr;
    gap: 0;
  }
  dl {
    grid-template-columns: 120px minmax(0, 1fr);
  }
}
</style>
