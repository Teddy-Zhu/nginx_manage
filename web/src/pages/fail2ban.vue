<route lang="json">
{
  "meta": {
    "title": "登录防护",
    "subtitle": "自动封禁多次认证失败的 IP",
    "nav": true,
    "order": 6,
    "symbol": "◈",
    "group": "网站与安全",
    "software": "fail2ban"
  }
}
</route>
<script setup lang="ts">
import { RouterLink } from "vue-router";

import Fail2banLifecyclePanel from "../components/Fail2banLifecyclePanel.vue";
import Fail2banUpgradePanel from "../components/Fail2banUpgradePanel.vue";
import Fail2banAddressPanel from "../components/Fail2banAddressPanel.vue";
import Fail2banExistingPanel from "../components/Fail2banExistingPanel.vue";
import Fail2banPolicyEditor from "../components/Fail2banPolicyEditor.vue";
import Fail2banLoginLogPanel from "../components/Fail2banLoginLogPanel.vue";

import { computed, h, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NTag,
  type DataTableColumns,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banObservation,
  type Fail2banInstance,
  type Fail2banJail,
} from "../api/client";

const api = useNodeAPI(),
  controller = new AbortController();
const view = ref<Fail2banObservation | null>(null),
  error = ref(""),
  reading = ref(false),
  moduleEnabled = ref<boolean | null>(null);
let closed = false;
let jailController: AbortController | null = null;
const instance = ref<Fail2banInstance | null>(null),
  instanceError = ref("");
const jail = ref<Fail2banJail | null>(null),
  jailError = ref(""),
  jailReading = ref(false),
  selectedJail = ref("");
const adoptedJails = ref(new Set<string>());
function setAdoptedJails(names: string[]) {
  adoptedJails.value = new Set(names);
}
const jailRows: DataTableColumns<Fail2banInstance["jails"][number]> = [
  { title: "防护规则", key: "name" },
  {
    title: "归属",
    key: "managed",
    render: (row) =>
      row.managed
        ? "面板管理"
        : adoptedJails.value.has(row.name)
          ? "已连接的规则"
          : "其他防护规则",
  },
  {
    title: "状态",
    key: "inspect",
    render: (row) =>
      h(
        NButton,
        {
          size: "small",
          loading: jailReading.value && selectedJail.value === row.name,
          disabled: reading.value,
          onClick: () => {
            void loadJail(row.name);
          },
        },
        { default: () => "查看状态" },
      ),
  },
];
const bannedRows = computed(
  () => jail.value?.banned.map((ip) => ({ ip })) ?? [],
);
const bannedColumns: DataTableColumns<{ ip: string }> = [
  { title: "已封禁的 IP", key: "ip" },
];
async function load() {
  if (reading.value || closed) return;
  reading.value = true;
  error.value = "";
  jailController?.abort();
  jailController = null;
  jail.value = null;
  jailError.value = "";
  selectedJail.value = "";
  jailReading.value = false;
  instanceError.value = "";
  const [diagnostic, flags, live] = await Promise.allSettled([
    api.fail2ban(controller.signal),
    api.modules(controller.signal),
    api.fail2banInstance(controller.signal),
  ]);
  if (closed) return;
  if (diagnostic.status === "fulfilled") view.value = diagnostic.value;
  else {
    view.value = null;
    error.value = apiError(diagnostic.reason).message;
  }
  if (flags.status === "fulfilled") {
    const flag = flags.value.find((item) => item.id === "fail2ban");
    moduleEnabled.value = flag?.enabled ?? null;
  } else moduleEnabled.value = null;
  if (live.status === "fulfilled") instance.value = live.value;
  else {
    instance.value = null;
    instanceError.value = apiError(live.reason).message;
  }
  reading.value = false;
}
async function loadJail(name: string) {
  jailController?.abort();
  const active = new AbortController();
  jailController = active;
  selectedJail.value = name;
  jailReading.value = true;
  jail.value = null;
  jailError.value = "";
  try {
    const value = await api.fail2banJail(name, active.signal);
    if (!closed && jailController === active) jail.value = value;
  } catch (cause) {
    if (!closed && jailController === active)
      jailError.value = apiError(cause).message;
  } finally {
    if (!closed && jailController === active) jailReading.value = false;
  }
}
onMounted(() => {
  void load();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
  jailController?.abort();
});
</script>
<template>
  <div class="page-stack">
    <div class="page-toolbar">
      <h2>登录防护</h2>
      <div class="inline-gap">
        <RouterLink
          :to="{ path: '/components', query: { software: 'fail2ban' } }"
          >软件设置</RouterLink
        ><NButton :loading="reading" @click="load">刷新</NButton>
      </div>
    </div>
    <div class="stat-grid">
      <div class="stat-card">
        <span class="stat-label">防护服务</span
        ><strong>{{
          instance?.available
            ? "运行中"
            : instanceError || instance
              ? "连接异常"
              : "正在读取"
        }}</strong>
      </div>
      <div class="stat-card">
        <span class="stat-label">运行规则</span
        ><strong>{{
          instance?.available ? instance.jails.length : "—"
        }}</strong>
      </div>
      <div class="stat-card">
        <span class="stat-label">软件版本</span
        ><strong>{{
          instance?.server_version || view?.managed.version || "—"
        }}</strong>
      </div>
    </div>
    <Fail2banPolicyEditor />
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="instanceError" type="error">{{ instanceError }}</NAlert>
    <section v-if="instance" class="panel page-stack">
      <div class="toolbar">
        <h3>防护规则</h3>
        <NTag :type="instance.available ? 'success' : 'warning'">{{
          instance.available ? "已连接" : "连接异常"
        }}</NTag>
      </div>
      <p v-if="instance.available && !instance.jails.length" class="muted">
        还没有防护规则，请先添加规则。
      </p>
      <NAlert v-if="instance.reason" type="warning"
        >暂时无法读取部分防护状态。</NAlert
      >
      <NDataTable
        v-if="instance.available"
        :columns="jailRows"
        :data="instance.jails"
        :row-key="(row: Fail2banInstance['jails'][number]) => row.name"
        :pagination="{ pageSize: 10 }"
      />
    </section>
    <section v-if="selectedJail" class="panel page-stack">
      <div class="toolbar">
        <h3>{{ selectedJail }}</h3>
        <NButton
          :loading="jailReading"
          :disabled="reading"
          @click="loadJail(selectedJail)"
          >刷新状态</NButton
        >
      </div>
      <NAlert v-if="jailError" type="error">{{ jailError }}</NAlert>
      <template v-if="jail">
        <NAlert :type="jail.available ? 'info' : 'warning'">{{
          jail.reason
        }}</NAlert>
        <template v-if="jail.available">
          <p>更新于 {{ new Date(jail.at * 1000).toLocaleString() }}</p>
          <p>
            当前失败 {{ jail.current_failed }} · 累计失败
            {{ jail.total_failed }} · 当前封禁 {{ jail.current_banned }} ·
            累计封禁 {{ jail.total_banned }}
          </p>
          <NDataTable
            :columns="bannedColumns"
            :data="bannedRows"
            :pagination="{ pageSize: 25 }"
          />
        </template>
        <Fail2banAddressPanel
          v-if="jail.managed"
          :key="jail.name"
          engine-owner="managed"
          adoption-id=""
          :jail="jail.name"
          :module-enabled="moduleEnabled === true"
        />
      </template>
    </section>
    <section class="page-stack">
      <Fail2banLifecyclePanel
        :module-enabled="moduleEnabled === true"
        :binding="view?.binding ?? null"
        :instance="instance"
        :managed="view?.managed ?? null"
        :service="
          view?.services.find(
            (item) => item.id === 'nginxpanel-fail2ban.service',
          ) ?? null
        "
        :observed-at="view?.at ?? 0"
        @changed="load"
      />
      <Fail2banUpgradePanel
        :module-enabled="moduleEnabled === true"
        @changed="load"
      />
      <Fail2banExistingPanel
        :module-enabled="moduleEnabled === true"
        @resources="setAdoptedJails"
        @changed="load"
      />
      <Fail2banLoginLogPanel />
    </section>
  </div>
</template>
