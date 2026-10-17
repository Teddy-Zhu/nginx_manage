<script setup lang="ts">
import { computed, h, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NFormItem,
  NSelect,
  NSpace,
  type DataTableColumns,
} from "naive-ui";
import type {
  FirewallPlan,
  FirewallPlanInput,
  FirewallPolicy,
} from "../api/client";

type Plan = NonNullable<FirewallPlan["docker"]>;
type Targets = NonNullable<FirewallPlanInput["docker_targets"]>;
type Binding = Targets["bindings"][number];
const props = defineProps<{
  plan: Plan;
  targets: Targets | null;
  policy: FirewallPolicy;
  disabled: boolean;
}>();
const emit = defineEmits<{ change: [Targets | null]; reload: [] }>();
const ruleID = ref(""),
  mapping = ref<number | null>(null),
  address = ref<number | null>(null);
const rules = computed(() =>
  props.policy.rules.filter(
    (rule) => rule.enabled && rule.scope === "docker_published",
  ),
);
const selectedRule = computed(() =>
  rules.value.find((rule) => rule.id === ruleID.value),
);
const selectedPort = computed(() =>
  mapping.value === null ? null : props.plan.ports[mapping.value],
);
const ruleOptions = computed(() =>
  rules.value.map((rule) => ({ label: rule.name, value: rule.id })),
);
const mappingOptions = computed(() =>
  props.plan.ports.flatMap((port, index) => {
    const rule = selectedRule.value;
    if (
      !rule ||
      port.path !== "bridge_nat_candidate" ||
      port.network_ids.length !== 1 ||
      port.protocol !== rule.protocol ||
      (rule.family !== "both" && port.family !== rule.family) ||
      !rule.ports.some(
        (range) => port.host_port >= range.from && port.host_port <= range.to,
      )
    )
      return [];
    return [{
      label: `${port.family === "ipv4" ? "IPv4" : "IPv6"} ${port.protocol.toUpperCase()} [${port.host_ip}]:${port.host_port} → ${port.container_id.slice(0, 12)}:${port.container_port}`,
      value: index,
    }];
  }),
);
const addressOptions = computed(() =>
  props.plan.addresses.flatMap((entry, index) => {
    const port = selectedPort.value,
      rule = selectedRule.value;
    if (
      !port ||
      entry.family !== port.family ||
      (rule?.interface && rule.interface !== entry.interface) ||
      (!["0.0.0.0", "::"].includes(port.host_ip) && port.host_ip !== entry.address)
    )
      return [];
    return [{ label: `${entry.interface} / ${entry.address}`, value: index }];
  }),
);
const bindings = computed(() => props.targets?.bindings ?? []);
watch([ruleID, () => props.plan.snapshot_hash], () => {
  mapping.value = null;
  address.value = null;
});
watch(mapping, () => { address.value = null; });
function change(next: Binding[]) {
  emit("change", next.length ? {
    engine_hash: props.plan.engine_hash,
    snapshot_hash: props.plan.snapshot_hash,
    bindings: next,
  } : null);
}
function sameBinding(a: Binding, b: Binding) {
  return Object.keys(a).every(
    (key) => a[key as keyof Binding] === b[key as keyof Binding],
  );
}
function add() {
  const port = selectedPort.value;
  const local = address.value === null ? null : props.plan.addresses[address.value];
  if (
    !port || !local || !selectedRule.value ||
    (port.family !== "ipv4" && port.family !== "ipv6") ||
    (port.protocol !== "tcp" && port.protocol !== "udp") ||
    props.disabled || bindings.value.length >= 128 ||
    !mappingOptions.value.some((option) => option.value === mapping.value) ||
    !addressOptions.value.some((option) => option.value === address.value)
  )
    return;
  const binding: Binding = {
    rule_id: ruleID.value,
    container_id: port.container_id,
    network_id: port.network_ids[0]!,
    family: port.family,
    protocol: port.protocol,
    host_ip: port.host_ip,
    host_port: port.host_port,
    container_port: port.container_port,
    destination: local.address,
    input_interface: local.interface,
  };
  if (bindings.value.some((entry) => sameBinding(entry, binding))) return;
  change([...bindings.value, binding]);
}
const columns: DataTableColumns<Binding> = [
  { title: "规则", key: "rule_id", width: 170, render: (row) => rules.value.find((rule) => rule.id === row.rule_id)?.name ?? row.rule_id },
  { title: "容器", key: "container_id", width: 140, ellipsis: { tooltip: true } },
  { title: "原始目的", key: "destination", width: 210, render: (row) => `[${row.destination}]:${row.host_port} / ${row.protocol.toUpperCase()}` },
  { title: "容器端口", key: "container_port", width: 100 },
  { title: "入口接口", key: "input_interface", width: 140 },
  {
    title: "操作",
    key: "actions",
    width: 90,
    render: (row) => h(
      NButton,
      {
        size: "small",
        disabled: props.disabled,
        onClick: () => change(bindings.value.filter((entry) => !sameBinding(entry, row))),
      },
      () => "移除",
    ),
  },
];
const entries: DataTableColumns<Plan["entries"][number]> = [
  { title: "地址族", key: "family", width: 90 },
  { title: "规则参数", key: "expression", minWidth: 950, ellipsis: { tooltip: true } },
];
const resolved: DataTableColumns<Plan["bindings"][number]> = [
  { title: "容器地址", key: "container_address", minWidth: 190 },
  { title: "bridge 出口", key: "output_interface", minWidth: 170 },
  { title: "原始目的", key: "binding.destination", minWidth: 210, render: (row) => `[${row.binding.destination}]:${row.binding.host_port}` },
];
</script>

<template>
  <h4>Docker 发布端口目标</h4>
  <n-alert type="warning" :bordered="false">{{ plan.reason }}</n-alert>
  <p class="muted">选择规则对应的实际映射和入口地址。每个地址族、主机端口均需绑定；通配绑定不会自动覆盖所有本机地址。目标绑定仅用于本次计划，刷新页面后需重新选择。</p>
  <n-space class="notice">
    <n-button :disabled="disabled" @click="emit('reload')">重新读取目标</n-button>
    <n-button :disabled="disabled || !bindings.length" @click="change([])">清空绑定</n-button>
    <span>{{ bindings.length }} / 128 个绑定</span>
  </n-space>
  <p v-if="plan.truncated" class="muted">映射清单仅展示前 128 项；未展示的映射可通过 API 提交经核对的目标绑定。</p>
  <div class="grid">
    <n-form-item label="期望规则"><n-select v-model:value="ruleID" :options="ruleOptions" :disabled="disabled" /></n-form-item>
    <n-form-item label="主机发布映射"><n-select v-model:value="mapping" :options="mappingOptions" :disabled="disabled || !ruleID" filterable /></n-form-item>
    <n-form-item label="入口接口 / 原始目的地址"><n-select v-model:value="address" :options="addressOptions" :disabled="disabled || mapping === null" filterable /></n-form-item>
  </div>
  <n-button :disabled="disabled || address === null || bindings.length >= 128" @click="add">添加目标绑定</n-button>
  <p v-if="ruleID && !mappingOptions.length" class="muted">没有符合该规则的同族 bridge/NAT 映射候选，请检查容器运行状态、发布端口和网络模式。</p>
  <p v-if="mapping !== null && !addressOptions.length" class="muted">没有与该映射对应的本机入口地址，请核对接口及固定或通配绑定。</p>
  <n-data-table :columns="columns" :data="bindings" :pagination="{ pageSize: 10 }" :scroll-x="1000" class="notice" />
  <n-alert v-for="warning in plan.warnings" :key="warning" type="info" :bordered="false" class="notice">{{ warning }}</n-alert>
  <template v-if="plan.compiled">
    <dl>
      <dt>Docker 生成规则</dt><dd>{{ plan.generated_rules }} 条 / {{ plan.program_bytes }} 字节</dd>
      <dt>主机入站生成规则</dt><dd>{{ plan.host_generated_rules }} 条（含入口保护）</dd>
      <dt>目标绑定摘要</dt><dd class="digest">{{ plan.bindings_hash }}</dd>
      <dt>Docker 程序摘要</dt><dd class="digest">{{ plan.program_hash }}</dd>
    </dl>
    <n-data-table :columns="resolved" :data="plan.bindings" :pagination="{ pageSize: 10 }" :scroll-x="650" />
    <h4>Docker 规则预览</h4>
    <p v-if="plan.entries_truncated" class="muted">仅展示前 128 条；摘要包含完整编译规则。</p>
    <n-data-table :columns="entries" :data="plan.entries" :pagination="{ pageSize: 10 }" :scroll-x="1100" />
  </template>
</template>

<style scoped>
.digest { overflow-wrap: anywhere; }
</style>
