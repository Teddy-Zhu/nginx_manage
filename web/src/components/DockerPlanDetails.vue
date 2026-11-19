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
    return [
      {
        label: `${port.family === "ipv4" ? "IPv4" : "IPv6"} ${port.protocol.toUpperCase()} [${port.host_ip}]:${port.host_port} → 容器端口 ${port.container_port}`,
        value: index,
      },
    ];
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
      (!["0.0.0.0", "::"].includes(port.host_ip) &&
        port.host_ip !== entry.address)
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
watch(mapping, () => {
  address.value = null;
});
function change(next: Binding[]) {
  emit(
    "change",
    next.length
      ? {
          engine_hash: props.plan.engine_hash,
          snapshot_hash: props.plan.snapshot_hash,
          bindings: next,
        }
      : null,
  );
}
function sameBinding(a: Binding, b: Binding) {
  return Object.keys(a).every(
    (key) => a[key as keyof Binding] === b[key as keyof Binding],
  );
}
function add() {
  const port = selectedPort.value;
  const local =
    address.value === null ? null : props.plan.addresses[address.value];
  if (
    !port ||
    !local ||
    !selectedRule.value ||
    (port.family !== "ipv4" && port.family !== "ipv6") ||
    (port.protocol !== "tcp" && port.protocol !== "udp") ||
    props.disabled ||
    bindings.value.length >= 128 ||
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
  {
    title: "规则",
    key: "rule_id",
    width: 170,
    render: (row) =>
      rules.value.find((rule) => rule.id === row.rule_id)?.name ?? row.rule_id,
  },
  {
    title: "容器",
    key: "container_id",
    width: 140,
    ellipsis: { tooltip: true },
  },
  {
    title: "访问地址",
    key: "destination",
    width: 210,
    render: (row) =>
      `[${row.destination}]:${row.host_port} / ${row.protocol.toUpperCase()}`,
  },
  { title: "容器端口", key: "container_port", width: 100 },
  { title: "网卡", key: "input_interface", width: 140 },
  {
    title: "操作",
    key: "actions",
    width: 90,
    render: (row) =>
      h(
        NButton,
        {
          size: "small",
          disabled: props.disabled,
          onClick: () =>
            change(bindings.value.filter((entry) => !sameBinding(entry, row))),
        },
        () => "移除",
      ),
  },
];
</script>

<template>
  <h4>容器端口规则</h4>
  <n-alert type="warning" :bordered="false">
    {{ plan.reason }}
  </n-alert>
  <p class="muted">
    选择要保护的容器端口和访问地址。
  </p>
  <n-space class="notice">
    <n-button :disabled="disabled" @click="emit('reload')">
      重新读取目标
    </n-button>
    <n-button :disabled="disabled || !bindings.length" @click="change([])">
      清空关联
    </n-button>
    <span>{{ bindings.length }} / 128 项关联</span>
  </n-space>
  <p v-if="plan.truncated" class="muted">
    仅显示前 128 项，请减少选择范围后重试。
  </p>
  <div class="grid">
    <n-form-item label="防火墙规则">
      <n-select
        v-model:value="ruleID"
        :options="ruleOptions"
        :disabled="disabled"
      />
    </n-form-item>
    <n-form-item label="容器端口">
      <n-select
        v-model:value="mapping"
        :options="mappingOptions"
        :disabled="disabled || !ruleID"
        filterable
      />
    </n-form-item>
    <n-form-item label="访问地址">
      <n-select
        v-model:value="address"
        :options="addressOptions"
        :disabled="disabled || mapping === null"
        filterable
      />
    </n-form-item>
  </div>
  <n-button
    :disabled="disabled || address === null || bindings.length >= 128"
    @click="add"
  >
    添加关联
  </n-button>
  <p v-if="ruleID && !mappingOptions.length" class="muted">
    没有匹配的容器端口，请检查容器是否运行并开放了对应端口。
  </p>
  <p v-if="mapping !== null && !addressOptions.length" class="muted">
    找不到此端口映射的本机访问地址，请检查端口绑定。
  </p>
  <n-data-table
    :columns="columns"
    :data="bindings"
    :pagination="{ pageSize: 10 }"
    :scroll-x="1000"
    class="notice"
  />
  <n-alert
    v-for="warning in plan.warnings"
    :key="warning"
    type="info"
    :bordered="false"
    class="notice"
  >
    {{ warning }}
  </n-alert>
  <p v-if="plan.compiled" class="muted">
    规则检查通过，可应用变更。
  </p>
</template>

<style scoped>
.digest {
  overflow-wrap: anywhere;
}
</style>
