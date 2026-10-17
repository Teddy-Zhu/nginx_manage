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
  NSelect,
  NSpace,
  NTag,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type FirewallPlan,
  type FirewallPlanInput,
  type FirewallRuntime,
  type FirewallPolicyView,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useRoute } from "vue-router";
import { useSession } from "../stores/session";
import FirewalldPlanDetails from "../components/FirewalldPlanDetails.vue";
import UFWPlanDetails from "../components/UFWPlanDetails.vue";
import IPTablesPlanDetails from "../components/IPTablesPlanDetails.vue";
import DockerPlanDetails from "../components/DockerPlanDetails.vue";

const route = useRoute();
const action = ref<FirewallPlanInput["action"]>(
    route.query.action === "remove" ? "remove" : "apply",
  ),
  managementDisabled = ref<boolean | null>(null);
const actions = [
  { label: "应用期望策略", value: "apply" },
  { label: "移除本应用规则", value: "remove" },
];
const api = useNodeAPI(),
  session = useSession(),
  dialog = useDialog(),
  { run, busy, message } = useAction(),
  keyFor = useIdempotency();
const view = ref<FirewallRuntime | null>(null),
  stored = ref<FirewallPolicyView | null>(null),
  plan = ref<FirewallPlan | null>(null),
  error = ref(""),
  uncertain = ref(false),
  remaining = ref(0);
const controller = new AbortController();
const dockerTargets = ref<NonNullable<FirewallPlanInput["docker_targets"]> | null>(
  null,
);
const canManage = computed(() =>
  ["read", "security.write"].every((scope) =>
    session.localMe?.scopes.includes(scope),
  ),
);
const operation = computed(() => view.value?.operation);
const preparation = computed(() => {
  const latest = view.value?.preparation;
  return latest && ["running", "cancelling"].includes(latest.state)
    ? latest
    : plan.value?.preparation ?? latest;
});
const preparing = computed(
  () => !!preparation.value && ["running", "cancelling"].includes(preparation.value.state),
);
const preparationStates = {
  running: "正在准备",
  cancelling: "正在取消",
  ready: "准备完成",
  failed: "准备失败",
  cancelled: "已取消",
};
const observedProtections = computed(() => view.value?.protection_observation);
const protectionStates = {
  unavailable: "尚不可核对",
  not_applicable: "无适用策略",
  current: "采样时一致",
  changed: "保护依据已变化",
};
const emptyInitial = computed(
  () =>
    view.value?.available &&
    view.value.confirmed_action === "none" &&
    (view.value.backend === "firewalld" ||
      view.value.backend === "ufw" ||
      view.value.backend === "iptables-nft" ||
      view.value.backend === "iptables-legacy" ||
      (view.value.kernel.available &&
        view.value.kernel.table_exists &&
        view.value.kernel.chains === 0 &&
        view.value.kernel.rules === 0)),
);
const canDisable = computed(
  () =>
    canManage.value &&
    !!session.localMe?.scopes.includes("system.write") &&
    view.value?.available &&
    (view.value.confirmed_action === "remove" ||
      (action.value === "remove" && emptyInitial.value)) &&
    managementDisabled.value === false,
);
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
    const pending = result.preparation;
    if (pending && ["running", "cancelling"].includes(pending.state))
      action.value = pending.action;
    if (
      pending && pending.action === action.value &&
      (["running", "cancelling"].includes(pending.state) ||
        pending.action === "remove" || pending.version === stored.value?.version) &&
      (plan.value?.id !== pending.id || plan.value?.preparation?.state !== pending.state) &&
      ["running", "cancelling", "ready"].includes(pending.state)
    ) {
      plan.value = await api.planFirewall(
        { action: pending.action, version: pending.version, preparation_id: pending.id },
        controller.signal,
      );
    } else if (plan.value && pending && plan.value.id === pending.id) {
      plan.value = { ...plan.value, preparation: pending };
    }
  } catch (cause) {
    if (!closed) error.value = apiError(cause).message;
  } finally {
    reading = false;
  }
}
async function load() {
  await run(async () => {
    const [desired, modules] = await Promise.allSettled([
      api.firewallPolicy(controller.signal),
      api.modules(controller.signal),
    ]);
    if (closed) return;
    if (desired.status === "fulfilled") {
      if (stored.value?.version !== desired.value.version)
        dockerTargets.value = null;
      stored.value = desired.value;
      if (
        plan.value?.action === "apply" &&
        plan.value.version !== desired.value.version
      )
        plan.value = null;
    } else stored.value = null;
    if (modules.status === "fulfilled") {
      const module = modules.value.find((item) => item.id === "firewall");
      managementDisabled.value = module ? !module.enabled : null;
    } else managementDisabled.value = null;
    await readRuntime();
    if (desired.status === "rejected") throw desired.reason;
    if (modules.status === "rejected") throw modules.reason;
  });
}
function setAction(value: FirewallPlanInput["action"]) {
  action.value = value;
  plan.value = null;
  dockerTargets.value = null;
}
function bindDocker(
  targets: NonNullable<FirewallPlanInput["docker_targets"]> | null,
) {
  dockerTargets.value = targets;
  const current = plan.value;
  if (current?.docker) {
    plan.value = {
      ...current,
      can_apply: false,
      program_hash: "",
      generated_rules: current.docker.host_generated_rules,
      docker: {
        ...current.docker,
        compiled: false,
        bindings: [],
        bindings_hash: "",
        program_hash: "",
        program_bytes: 0,
        generated_rules: 0,
        entries: [],
        entries_truncated: false,
        reason: "目标绑定已修改，请重新生成计划",
      },
    };
  }
}
async function reloadDocker() {
  dockerTargets.value = null;
  plan.value = null;
  await generate();
}
async function generate() {
  const version =
    action.value === "remove"
      ? view.value?.confirmed_version
      : stored.value?.version;
  if (!version) return;
  await run(async () => {
    plan.value = await api.planFirewall(
      {
        action: action.value,
        version,
        ...(action.value === "apply" && dockerTargets.value
          ? { docker_targets: dockerTargets.value }
          : {}),
      },
      controller.signal,
    );
    uncertain.value = false;
  });
}
async function cancelPreparation() {
  const current = preparation.value;
  if (!current || !preparing.value) return;
  await run(async () => {
    plan.value = await api.planFirewall(
      {
        action: current.action,
        version: current.version,
        preparation_id: current.id,
        cancel_preparation: true,
      },
      controller.signal,
    );
  });
}
async function disableManagement() {
  if (!canDisable.value) return;
  const operationID = view.value?.confirmed_operation_id;
  await run(async () => {
    await api.setModule("firewall", false, {
      firewall_rules: "remove",
      ...(operationID ? { firewall_operation_id: operationID } : {}),
    });
    managementDisabled.value = true;
  }, "防火墙管理已停用，期望草稿保留");
}
async function submit() {
  const current = plan.value;
  if (!current?.can_apply) return;
  const input = {
    action: current.action,
    plan_id: current.id,
    version: current.version,
  };
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
  if (!plan.value?.can_apply) return;
  if (uncertain.value) {
    void submit();
    return;
  }
  dialog.warning({
    title:
      plan.value?.action === "remove"
        ? "移除本应用防火墙规则"
        : "应用防火墙策略",
    content:
      plan.value?.action === "remove"
        ? plan.value.backend === "firewalld"
          ? "将清空本应用 policy 的业务规则和入口保护，保留空 policy 登记；其余系统策略继续生效。120 秒内需通过新的管理 HTTPS 连接确认，确认后才清空永久规则，未确认将恢复原配置。"
          : plan.value.backend === "ufw"
            ? "将移除本应用 UFW 用户规则及入口保护，保留 UFW 授权和其他来源规则。120 秒内需通过新的管理 HTTPS 连接确认，确认后才保存配置，未确认将恢复原规则。"
            : plan.value.iptables
              ? "将移除本应用代际链、入口保护及 INPUT 跳转，保留本机授权和其他来源规则。120 秒内需通过新的管理 HTTPS 连接确认，未确认将恢复原规则。"
              : "将移除本应用的业务规则、入口保护和基础链，仅保留空表登记；其余系统策略继续生效。120 秒内需通过新的管理 HTTPS 连接确认，未确认将恢复原规则。"
        : "将应用所列入口保护和已保存策略。120 秒内需通过新的管理 HTTPS 连接确认；连接中断或超时会恢复最后确认策略。",
    positiveText: "执行",
    negativeText: "取消",
    onPositiveClick: submit,
  });
}
async function decide(action: "confirm" | "rollback") {
  const current = operation.value;
  if (!current) return;
  await run(async () => {
    const result = await api.decideFirewall(current.id, action);
    if (view.value) view.value = { ...view.value, operation: result };
    await readRuntime();
    if (action === "confirm" && result.state === "succeeded")
      message.success("防火墙变更已确认");
    else if (result.state === "rolled_back")
      message.warning(result.error || "变更已恢复，请重新生成计划");
    else message.info(`操作状态：${states[result.state] ?? result.state}`);
  });
}
onMounted(() => {
  void load();
  timer = setInterval(() => {
    updateDeadline();
    if (++ticks % (active.value || uncertain.value || preparing.value ? 3 : 30) === 0)
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
          !view?.can_plan ||
          (action === 'apply'
            ? !stored?.version || managementDisabled !== false
            : view?.confirmed_action !== 'apply') ||
          active ||
          uncertain ||
          preparing
        "
        @click="generate"
        >生成{{ action === "remove" ? "移除" : "应用" }}计划</n-button
      ></n-space
    >
  </div>
  <n-select
    :value="action"
    :options="actions"
    :disabled="busy || active || uncertain || preparing"
    aria-label="防火墙动作"
    @update:value="setAction"
  />
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
  <n-alert
    type="info"
    :bordered="false"
    class="notice"
    >应用期望策略前须启用防火墙模块，移除已确认规则可在模块停用后执行。两种操作均须直接访问目标已确认的管理
    HTTPS
    入口并通过新连接确认。确认仅证明本次管理连接可达，业务端口和云安全组需另行核对。</n-alert
  >
  <section v-if="view" class="panel">
    <h3>已确认状态</h3>
    <p>
      已保存期望版本 {{ stored?.version ?? 0 }} ·
      {{
        view.confirmed_action === "remove" ? "移除前规则版本" : "已确认运行版本"
      }}
      {{ view.confirmed_version }} ·
      {{
        view.confirmed_action === "apply"
          ? "规则已确认"
          : view.confirmed_action === "remove"
            ? "规则已移除"
            : "尚无确认策略"
      }}
    </p>
    <n-data-table
      v-if="view.protections.length"
      :columns="protections"
      :data="view.protections"
      :pagination="{ pageSize: 10 }"
      :scroll-x="650"
    />
    <n-alert
      v-if="action === 'remove' && emptyInitial"
      type="info"
      :bordered="false"
      class="notice"
      >当前授权范围内无已确认规则需要移除。</n-alert
    >
    <n-button v-if="canDisable" :disabled="busy" @click="disableManagement"
      >停用防火墙管理</n-button
    >
    <p v-if="managementDisabled" class="muted">防火墙管理已停用。</p>
    <p v-if="view.confirmed_action !== 'apply'" class="muted">
      {{
        view.confirmed_action === "remove"
          ? view.backend === "firewalld"
            ? "本应用运行和永久 policy 规则已清空，保留空 policy 登记；期望草稿保留，其余系统策略继续生效。"
            : view.backend === "ufw"
              ? "本应用 UFW 用户规则及入口保护已移除，授权和期望草稿保留，其他来源规则继续生效。"
              : view.backend === "iptables-nft" || view.backend === "iptables-legacy"
                ? "本应用代际链、入口保护及 INPUT 跳转已移除，本机授权和期望草稿保留，其他来源规则继续生效。"
                : "本应用链和规则已移除，仅保留空表登记；期望草稿保留，其余系统策略继续生效。"
          : "尚无已确认的业务过滤策略。"
      }}
    </p>
  </section>
  <section v-if="observedProtections" class="panel">
    <div class="page-toolbar">
      <h3>保护依据核对</h3>
      <n-tag
        :type="
          observedProtections.state === 'current'
            ? 'success'
            : observedProtections.state === 'not_applicable'
              ? 'default'
              : 'warning'
        "
      >
        {{ protectionStates[observedProtections.state] }}
      </n-tag>
    </div>
    <p v-if="observedProtections.observed_at">
      采样时间
      {{ new Date(observedProtections.observed_at * 1000).toLocaleString() }} ·
      计划 {{ observedProtections.plan_id }}
    </p>
    <n-alert
      v-if="observedProtections.reason"
      :type="
        observedProtections.state === 'not_applicable' ? 'info' : 'warning'
      "
      :bordered="false"
      class="notice"
    >
      {{ observedProtections.reason }}
    </n-alert>
    <template
      v-if="
        observedProtections.state === 'current' ||
        observedProtections.state === 'changed'
      "
    >
      <p>
        当前 SSH 保护：{{
          observedProtections.ssh_profile === "openssh"
            ? "OpenSSH"
            : "本机已确认无 SSH 保护"
        }}
        · 实际监听
        {{ observedProtections.ssh_listeners.join(", ") || "未观察到" }}
      </p>
      <n-data-table
        v-if="observedProtections.protections.length"
        :columns="protections"
        :data="observedProtections.protections"
        :pagination="{ pageSize: 10 }"
        :scroll-x="650"
      />
      <p class="muted">
        此处为采样时重新核对的保护项，上方仍为已确认规则中的保护项。差异需要重新应用并确认；采样不自动修改规则，也不证明外部可达性。
      </p>
    </template>
  </section>
  <section v-if="preparation" class="panel">
    <div class="page-toolbar">
      <h3>UFW 计划准备</h3>
      <n-tag
        :type="preparation.state === 'ready' ? 'success' : preparation.state === 'failed' ? 'error' : 'info'"
      >
        {{ preparationStates[preparation.state] }}
      </n-tag>
    </div>
    <p>
      已核对 {{ preparation.completed_commands }} / {{ preparation.total_commands }} 步 ·
      版本 {{ preparation.version }}
    </p>
    <p v-if="preparing" class="muted">
      准备期间尚未应用规则。截止时间 {{ new Date(preparation.deadline * 1000).toLocaleString() }}
    </p>
    <n-alert v-if="preparation.error" type="warning" :bordered="false" class="notice">
      {{ preparation.error }}
    </n-alert>
    <n-button
      v-if="preparing"
      :disabled="busy || preparation.state === 'cancelling'"
      @click="cancelPreparation"
      >取消准备</n-button
    >
  </section>
  <section v-if="plan && !preparing && (!plan.preparation || plan.preparation.state === 'ready')" class="panel">
    <div class="page-toolbar">
      <h3>
        版本 {{ plan.version }}
        {{ plan.action === "remove" ? "移除" : "应用" }}计划
      </h3>
      <n-tag type="info">{{
        plan.action === "remove"
          ? plan.backend === "firewalld"
            ? "清空本应用 policy 规则"
            : plan.backend === "ufw"
              ? "移除本应用 UFW 用户规则"
              : plan.iptables
                ? "移除本应用 iptables 链及跳转"
                : `移除 ${plan.baseline.rules} 条规则`
          : plan.docker
            ? "Docker 目标绑定预览"
            : `${plan.generated_rules} 条${plan.backend === "firewalld" ? " rich rules" : plan.backend === "ufw" ? " UFW 命令" : plan.iptables ? "生成规则" : "内核规则"}`
      }}</n-tag>
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
    <DockerPlanDetails
      v-if="plan.docker && stored"
      :plan="plan.docker"
      :targets="dockerTargets"
      :policy="stored.policy"
      :disabled="busy || !canManage || active"
      @change="bindDocker"
      @reload="reloadDocker"
    />
    <FirewalldPlanDetails
      v-if="plan.firewalld"
      :plan="plan.firewalld"
      :program-hash="plan.program_hash"
    />
    <UFWPlanDetails
      v-if="plan.ufw"
      :plan="plan.ufw"
      :program-hash="plan.program_hash"
    />
    <IPTablesPlanDetails
      v-if="plan.iptables"
      :plan="plan.iptables"
      :program-hash="plan.program_hash"
    />
    <n-data-table
      :columns="protections"
      :data="plan.protections"
      :pagination="{ pageSize: 10 }"
      :scroll-x="650"
    />
    <p class="muted">
      {{
        plan.action === "remove"
          ? "所列入口仅用于本次连接核对，移除后不再保留本应用保护条目；删除不等同于允许端口，其余系统策略仍可能阻止连接。"
          : plan.docker
            ? "主机入站与 Docker 转发分别核对。此目标计划尚不能执行，也不表示端口已经受保护。"
            : plan.backend === "firewalld"
            ? "入口保护先于业务规则匹配。accept 可能结束后续 firewalld 过滤，其他内核规则或云安全组仍可阻止连接。"
            : plan.backend === "ufw"
              ? "计划优先保留入口保护；与保护条件完全相同的业务项已由保护项覆盖。逐条预演通过不代表规则已经应用或端口可达。"
              : plan.iptables
                ? "入口保护先于业务规则匹配。ACCEPT 可能结束后续 INPUT 判断，其他过滤路径及云安全组仍可阻止连接。"
                : "入口保护先于业务规则匹配。允许仅结束本应用链的判断，其余系统规则仍可阻止连接。"
      }}
    </p>
    <n-button
      type="warning"
      :disabled="
        busy ||
        !plan.can_apply ||
        !canManage ||
        active ||
        operation?.plan_id === plan.id ||
        (!uncertain && Date.now() / 1000 >= plan.expires_at)
      "
      @click="apply"
      >{{ uncertain ? "查询或重送原请求" : "执行此计划" }}</n-button
    >
  </section>
  <n-alert v-if="uncertain" type="warning" :bordered="false" class="notice"
    >执行结果尚未取得。请保留本页，通过原请求查询或重送；未确认的变更会自动恢复。</n-alert
  >
  <section v-if="operation" class="panel">
    <div class="page-toolbar">
      <h3>运行操作</h3>
      <n-tag :type="operation.state === 'succeeded' ? 'success' : 'warning'">{{
        states[operation.state] ?? operation.state
      }}</n-tag>
    </div>
    <p>
      {{ operation.action === "remove" ? "移除" : "应用" }} · 策略版本
      {{ operation.version }} · 操作 {{ operation.id }}
    </p>
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
        {{ remaining }} 秒。变更已关闭原管理连接，确认请求必须使用生效后新建的
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
    <n-alert
      v-if="operation.action === 'remove' && operation.state === 'succeeded'"
      type="info"
      :bordered="false"
      class="notice"
      >本应用规则已确认移除。期望草稿保留，重新应用需生成新计划。</n-alert
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
