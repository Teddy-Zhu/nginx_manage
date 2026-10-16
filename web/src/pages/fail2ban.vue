<route lang="json">
{
  "meta": {
    "title": "Fail2ban",
    "subtitle": "jail 配置与宿主机状态",
    "nav": true,
    "order": 0.75,
    "symbol": "◈"
  }
}
</route>
<script setup lang="ts">
import Fail2banPolicyEditor from "../components/Fail2banPolicyEditor.vue";
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
const managedStates: Record<string, string> = {
  absent: "未登记",
  unavailable: "状态未知",
  reserved: "待安装",
  ready: "已准备",
  installed: "已登记",
  interrupted: "安装未完成",
  "rolling-back": "撤回中",
  "rolled-back": "已撤回",
};
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
const jailRows: DataTableColumns<Fail2banInstance["jails"][number]> = [
  { title: "Jail", key: "name" },
  {
    title: "归属",
    key: "managed",
    render: (row) => (row.managed ? "本应用管理 · 只读" : "原实例管理 · 只读"),
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
  { title: "引擎记录的封禁地址", key: "ip" },
];
const status = (value: boolean | null) =>
  value === null ? "未知" : value ? "是" : "否";
const python = computed(() => view.value?.python);
const tools: DataTableColumns<Fail2banObservation["tools"][number]> = [
  { title: "程序", key: "id" },
  { title: "发现文件", key: "present", render: (row) => status(row.present) },
  {
    title: "路径与权限已核对",
    key: "trusted",
    render: (row) => (row.trusted ? "是" : "未通过"),
  },
  {
    title: "实际路径",
    key: "resolved",
    render: (row) => row.resolved || row.path || "—",
    minWidth: 240,
    ellipsis: { tooltip: true },
  },
  {
    title: "状态说明",
    key: "reason",
    render: (row) => row.reason || "—",
    minWidth: 240,
  },
];
const services: DataTableColumns<Fail2banObservation["services"][number]> = [
  { title: "服务单元", key: "id" },
  {
    title: "加载",
    key: "load",
    render: (row) => (row.available ? row.load : "未知"),
  },
  {
    title: "活动状态",
    key: "active",
    render: (row) => (row.available ? `${row.active} / ${row.sub}` : "未知"),
  },
  {
    title: "开机状态",
    key: "unit_file",
    render: (row) => row.unit_file || "未知",
  },
  {
    title: "主进程 PID",
    key: "main_pid",
    render: (row) => row.main_pid ?? "未知",
  },
  {
    title: "状态说明",
    key: "reason",
    render: (row) => row.reason || "—",
    minWidth: 240,
  },
];
const modules: DataTableColumns<
  Fail2banObservation["python"]["modules"][number]
> = [
  { title: "标准库", key: "name" },
  { title: "可导入", key: "available", render: (row) => status(row.available) },
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
      <h2>Fail2ban</h2>
      <NButton :loading="reading" @click="load">刷新状态</NButton>
    </div>
    <Fail2banPolicyEditor />
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h3>管理状态</h3>
        <NTag :type="moduleEnabled ? 'info' : 'default'"
          >模块{{
            moduleEnabled === null
              ? "状态未知"
              : moduleEnabled
                ? "已启用"
                : "已停用"
          }}</NTag
        >
      </div>
      <p>
        服务运行独立于面板模块开关。已有实例接入后，未接管的 jail 保持只读。
      </p>
      <template v-if="view">
        <p>
          观测时间
          {{ view.at ? new Date(view.at * 1000).toLocaleString() : "未知" }} ·
          {{ view.available ? "宿主机诊断" : "宿主机范围未就绪" }}
        </p>
        <NAlert v-if="view.reason" type="warning">{{ view.reason }}</NAlert>
      </template>
    </section>
    <section v-if="view" class="panel page-stack">
      <div class="toolbar">
        <h3>受管引擎</h3>
        <NTag
          :type="
            view.managed.state === 'installed'
              ? 'info'
              : view.managed.state === 'interrupted'
                ? 'warning'
                : 'default'
          "
        >
          {{ managedStates[view.managed.state] || "状态未知" }}
        </NTag>
      </div>
      <template v-if="view.managed.operation_id">
        <p>
          Fail2ban {{ view.managed.version }} · Python
          {{ view.managed.python_version }}
        </p>
        <p>{{ view.managed.service }} · {{ view.managed.python_path }}</p>
        <p class="muted">
          批准时间
          {{ new Date(view.managed.approved_at * 1000).toLocaleString() }}
        </p>
      </template>
      <p v-if="view.managed.reason">{{ view.managed.reason }}</p>
      <p class="muted">安装登记、实际服务运行和 jail 保护状态分别核对。</p>
    </section>
    <NAlert v-if="instanceError" type="error">{{ instanceError }}</NAlert>
    <section v-if="instance" class="panel page-stack">
      <div class="toolbar">
        <h3>
          {{
            instance.binding.engine.owner === "managed"
              ? "受管实例"
              : instance.binding.engine.owner === "existing"
                ? "已接入实例"
                : "实例状态"
          }}
        </h3>
        <NTag :type="instance.available ? 'success' : 'default'">{{
          instance.available
            ? "已读取运行状态"
            : instance.binding.state === "bound"
              ? "接入状态待核对"
              : instance.binding.state === "unavailable"
                ? "接入状态未知"
                : "实例未接入"
        }}</NTag>
      </div>
      <p v-if="instance.binding.state === 'bound'">
        {{ instance.binding.service }} · {{ instance.binding.socket }}
      </p>
      <p v-if="instance.binding.engine.owner === 'managed'" class="muted">
        签名组件 {{ instance.binding.engine.asset_id }} · Python
        {{ instance.binding.engine.python_path }}
      </p>
      <p v-if="instance.available">
        服务端 {{ instance.server_version }} · 主进程
        {{ instance.service.main_pid }} · 采样
        {{ new Date(instance.at * 1000).toLocaleString() }}
      </p>
      <NAlert
        v-if="instance.reason"
        :type="instance.available ? 'info' : 'warning'"
        >{{ instance.reason }}</NAlert
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
          >刷新 jail</NButton
        >
      </div>
      <NAlert v-if="jailError" type="error">{{ jailError }}</NAlert>
      <template v-if="jail">
        <NAlert :type="jail.available ? 'info' : 'warning'">{{
          jail.reason
        }}</NAlert>
        <template v-if="jail.available">
          <p>
            采样 {{ new Date(jail.at * 1000).toLocaleString() }} · 服务端
            {{ jail.server_version }}
          </p>
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
      </template>
    </section>
    <template v-if="view?.available">
      <section class="panel page-stack">
        <h3>固定系统工具</h3>
        <p>官方客户端版本 {{ view.client_version || "未能读取" }}</p>
        <NDataTable :columns="tools" :data="view.tools" :scroll-x="900" />
        <NAlert v-if="view.missing.length" type="warning"
          >固定系统路径未发现：{{ view.missing.join("、") }}</NAlert
        >
      </section>
      <section v-if="python" class="panel page-stack">
        <h3>系统 Python</h3>
        <p>
          {{
            python.executable.resolved ||
            python.executable.path ||
            "未发现受信解释器"
          }}
          · 版本 {{ python.version || "未知" }}
        </p>
        <p>
          必要标准库可用：{{ status(python.standard_library) }} · SQLite
          {{ python.sqlite_version || "未知" }}
        </p>
        <p v-if="python.package.available">
          软件包归属 {{ python.package.manager }} / {{ python.package.name }} /
          {{ python.package.version }}
        </p>
        <p v-else>{{ python.package.reason }}</p>
        <NAlert
          v-if="python.reason"
          :type="python.standard_library ? 'info' : 'warning'"
          >{{ python.reason }}</NAlert
        >
        <NDataTable
          v-if="python.modules.length"
          :columns="modules"
          :data="python.modules"
          :pagination="{ pageSize: 8 }"
        />
      </section>
      <section class="panel page-stack">
        <h3>服务与默认 Socket</h3>
        <NDataTable
          :columns="services"
          :data="view.services"
          :scroll-x="1000"
        />
        <p>
          {{ view.socket.path }} · 文件存在：{{ status(view.socket.present) }} ·
          root 保护：{{ view.socket.root_protected ? "已核对" : "未核对" }}
        </p>
        <p class="muted">{{ view.socket.reason }}</p>
      </section>
      <NAlert v-for="warning in view.warnings" :key="warning" type="warning">{{
        warning
      }}</NAlert>
    </template>
  </div>
</template>
