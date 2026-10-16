<route lang="json">
{
  "meta": {
    "title": "防火墙应用",
    "subtitle": "入口保护与限时确认",
    "nav": true,
    "localOnly": true,
    "order": 0.72,
    "symbol": "↪"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NSpace,
  NTag,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type FirewallPlan,
  type FirewallRuntime,
  type FirewallPolicyView,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(),
  session = useSession(),
  dialog = useDialog(),
  { run, busy } = useAction(),
  keyFor = useIdempotency();
const view = ref<FirewallRuntime | null>(null),
  stored = ref<FirewallPolicyView | null>(null),
  plan = ref<FirewallPlan | null>(null),
  error = ref(""),
  uncertain = ref(false),
  remaining = ref(0);
const controller = new AbortController();
const canManage = computed(() =>
  ["read", "security.write"].every((scope) =>
    session.localMe?.scopes.includes(scope),
  ),
);
const operation = computed(() => view.value?.operation);
const active = computed(
  () =>
    !!operation.value &&
    [
      "running",
      "waiting_confirmation",
      "compensating",
      "recovery_required",
    ].includes(operation.value.state),
);
const states: Record<string, string> = {
  running: "正在应用",
  waiting_confirmation: "等待新连接确认",
  compensating: "正在恢复",
  recovery_required: "需要恢复",
  succeeded: "已确认",
  rolled_back: "已恢复",
  failed: "未完成",
};
const protections: DataTableColumns<FirewallPlan["protections"][number]> = [
  {
    title: "保护入口",
    key: "service",
    render: (r) => (r.service === "ssh" ? "SSH" : "管理 HTTPS"),
  },
  {
    title: "地址族",
    key: "family",
    render: (r) => (r.family === "ipv4" ? "IPv4" : "IPv6"),
  },
  { title: "TCP 端口", key: "port" },
  {
    title: "来源",
    key: "sources",
    render: (r) => r.sources.join(", "),
    minWidth: 240,
    ellipsis: { tooltip: true },
  },
];
let timer: ReturnType<typeof setInterval> | undefined,
  ticks = 0,
  closed = false,
  reading = false;
function updateDeadline() {
  remaining.value = Math.max(
    0,
    (operation.value?.deadline ?? 0) - Math.floor(Date.now() / 1000),
  );
}
async function readRuntime() {
  if (closed || reading || !canManage.value) return;
  reading = true;
  try {
    const result = await api.firewallRuntime(controller.signal);
    if (closed) return;
    view.value = result;
    error.value = "";
    updateDeadline();
    if (result.operation && result.operation.plan_id === plan.value?.id)
      uncertain.value = false;
  } catch (cause) {
    if (!closed) error.value = apiError(cause).message;
  } finally {
    reading = false;
  }
}
async function load() {
  await run(async () => {
    const result = await api.firewallPolicy(controller.signal);
    if (closed) return;
    stored.value = result;
    if (plan.value && plan.value.version !== result.version) plan.value = null;
    await readRuntime();
  });
}
async function generate() {
  if (!stored.value?.version) return;
  await run(async () => {
    plan.value = await api.planFirewall(
      stored.value!.version,
      controller.signal,
    );
    uncertain.value = false;
  });
}
async function submit() {
  const current = plan.value;
  if (!current) return;
  const input = { plan_id: current.id, version: current.version };
  await run(async () => {
    uncertain.value = true;
    const result = await api.applyFirewall(input, keyFor(input));
    if (closed) return;
    if (view.value)
      view.value = { ...view.value, available: false, operation: result };
    uncertain.value = false;
    updateDeadline();
    await readRuntime();
  });
}
function apply() {
  if (uncertain.value) {
    void submit();
    return;
  }
  dialog.warning({
    title: "应用防火墙策略",
    content:
      "将应用所列入口保护和已保存策略。120 秒内需通过新的管理 HTTPS 连接确认；连接中断或超时会恢复最后确认策略。",
    positiveText: "应用",
    negativeText: "取消",
    onPositiveClick: submit,
  });
}
async function decide(action: "confirm" | "rollback") {
  const current = operation.value;
  if (!current) return;
  await run(
    async () => {
      const result = await api.decideFirewall(current.id, action);
      if (view.value) view.value = { ...view.value, operation: result };
      await readRuntime();
    },
    action === "confirm" ? "防火墙策略已确认" : "恢复请求已记录",
  );
}
onMounted(() => {
  void load();
  timer = setInterval(() => {
    updateDeadline();
    if (++ticks % 3 === 0 && (active.value || uncertain.value))
      void readRuntime();
  }, 1000);
});
onUnmounted(() => {
  closed = true;
  controller.abort();
  if (timer) clearInterval(timer);
});
</script>
<template>
  <div class="page-toolbar">
    <h2>防火墙应用</h2>
    <n-space
      ><n-button :disabled="busy || !canManage" @click="load">刷新状态</n-button
      ><n-button
        :disabled="
          busy ||
          !canManage ||
          !view?.available ||
          !stored?.version ||
          active ||
          uncertain
        "
        @click="generate"
        >生成应用计划</n-button
      ></n-space
    >
  </div>
  <n-alert v-if="!canManage" type="warning" :bordered="false"
    >需要读取和安全写入权限。</n-alert
  >
  <n-alert v-if="error" type="error" :bordered="false" class="notice">{{
    error
  }}</n-alert>
  <n-alert
    v-if="view?.reason"
    type="warning"
    :bordered="false"
    class="notice"
    >{{ view.reason }}</n-alert
  >
  <n-alert type="info" :bordered="false" class="notice"
    >应用前须启用防火墙模块，并从目标节点已确认的管理 HTTPS
    入口访问。保护覆盖列出的管理来源及已观察到的 SSH
    来源；确认仅证明本次管理连接可达，业务端口和云安全组需另行核对。</n-alert
  >
  <section v-if="view" class="panel">
    <h3>已确认状态</h3>
    <p>
      已保存期望版本 {{ stored?.version ?? 0 }} · 已确认运行版本
      {{ view.confirmed_version }}
    </p>
    <n-data-table
      v-if="view.protections.length"
      :columns="protections"
      :data="view.protections"
      :pagination="{ pageSize: 10 }"
      :scroll-x="650"
    />
    <p v-else class="muted">尚无已确认的业务过滤策略。</p>
  </section>
  <section v-if="plan" class="panel">
    <div class="page-toolbar">
      <h3>版本 {{ plan.version }} 应用计划</h3>
      <n-tag type="info">{{ plan.generated_rules }} 条内核规则</n-tag>
    </div>
    <dl>
      <dt>管理监听</dt>
      <dd>{{ plan.listener }}</dd>
      <dt>当前来源</dt>
      <dd>{{ plan.control_source }}</dd>
      <dt>SSH 配置</dt>
      <dd>
        {{
          plan.ssh_profile === "openssh" ? "OpenSSH" : "本机已确认无 SSH 保护"
        }}
      </dd>
      <dt>SSH 监听</dt>
      <dd>{{ plan.ssh_listeners.join(", ") || "未观察到" }}</dd>
      <dt>计划有效期</dt>
      <dd>{{ new Date(plan.expires_at * 1000).toLocaleString() }}</dd>
    </dl>
    <n-data-table
      :columns="protections"
      :data="plan.protections"
      :pagination="{ pageSize: 10 }"
      :scroll-x="650"
    />
    <p class="muted">
      入口保护先于业务规则匹配。允许仅结束本应用链的判断，其余系统规则仍可阻止连接。
    </p>
    <n-button
      type="warning"
      :disabled="
        busy ||
        !canManage ||
        active ||
        operation?.plan_id === plan.id ||
        (!uncertain && Date.now() / 1000 >= plan.expires_at)
      "
      @click="apply"
      >{{ uncertain ? "查询或重送原应用请求" : "应用此计划" }}</n-button
    >
  </section>
  <n-alert v-if="uncertain" type="warning" :bordered="false" class="notice"
    >应用结果尚未取得。请保留本页，通过原请求查询或重送；未确认的策略会自动恢复。</n-alert
  >
  <section v-if="operation" class="panel">
    <div class="page-toolbar">
      <h3>运行操作</h3>
      <n-tag :type="operation.state === 'succeeded' ? 'success' : 'warning'">{{
        states[operation.state] ?? operation.state
      }}</n-tag>
    </div>
    <p>策略版本 {{ operation.version }} · 操作 {{ operation.id }}</p>
    <n-alert
      v-if="operation.error"
      type="warning"
      :bordered="false"
      class="notice"
      >{{ operation.error }}</n-alert
    >
    <template v-if="operation.state === 'waiting_confirmation'">
      <p>
        剩余
        {{ remaining }} 秒。应用已关闭原管理连接，确认请求必须使用生效后新建的
        TCP/TLS 连接。
      </p>
      <n-button
        type="primary"
        :disabled="busy || !canManage || remaining <= 0"
        @click="decide('confirm')"
        >确认当前管理连接</n-button
      >
    </template>
    <n-button
      v-if="active"
      :disabled="busy || !canManage"
      class="rollback"
      @click="decide('rollback')"
      >恢复最后确认策略</n-button
    >
    <p v-if="operation.state === 'succeeded'" class="muted">
      确认来源：{{ operation.confirmed_source }} · 确认范围：目标管理监听
    </p>
  </section>
</template>
<style scoped>
.notice {
  margin: 16px 0;
}
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
dl {
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr);
  gap: 10px;
}
dt {
  color: #6d7772;
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.rollback {
  margin-left: 12px;
}
</style>
