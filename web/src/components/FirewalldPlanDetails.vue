<script setup lang="ts">
import { computed } from "vue";
import { NAlert, NDataTable, type DataTableColumns } from "naive-ui";
import type { FirewallPlan } from "../api/client";

const props = defineProps<{
  plan: NonNullable<FirewallPlan["firewalld"]>;
  programHash: string;
}>();
const entries = computed(() =>
  props.plan.entries.map((entry, index) => ({
    ...entry,
    protection: index < props.plan.protection_rules,
  })),
);
type Entry = (typeof entries.value)[number];
const columns: DataTableColumns<Entry> = [
  {
    title: "类型",
    key: "protection",
    render: (r) => (r.protection ? "入口保护" : "业务规则"),
  },
  { title: "优先级", key: "backend_priority" },
  { title: "地址族", key: "family" },
  {
    title: "来源",
    key: "source",
    render: (r) => r.source || "任意",
    ellipsis: { tooltip: true },
  },
  {
    title: "规则表达式",
    key: "expression",
    minWidth: 360,
    ellipsis: { tooltip: true },
  },
];
</script>

<template>
  <n-alert type="info" :bordered="false">{{ plan.reason }}</n-alert>
  <n-alert
    v-for="warning in plan.warnings"
    :key="warning"
    type="warning"
    :bordered="false"
  >
    {{ warning }}
  </n-alert>
  <dl>
    <dt>主机策略</dt>
    <dd>
      {{ plan.settings.policy }} ·
      {{ plan.settings.ingress_zones.join("、") }} →
      {{ plan.settings.egress_zones.join("、") }}
    </dd>
    <dt>策略优先级 / 默认目标</dt>
    <dd>{{ plan.settings.priority }} / {{ plan.settings.target }}</dd>
    <dt>入口保护 / 完整配置大小</dt>
    <dd>
      {{ plan.protection_rules }} 条 / {{ plan.settings.settings_bytes }} 字节
    </dd>
    <dt>独立登记操作</dt>
    <dd>{{ plan.registration_operation_id }}</dd>
    <dt>运行配置基线</dt>
    <dd class="digest">{{ plan.runtime_hash }}</dd>
    <dt>永久配置基线</dt>
    <dd class="digest">{{ plan.permanent_hash }}</dd>
    <dt>完整程序摘要</dt>
    <dd class="digest">{{ programHash }}</dd>
  </dl>
  <n-data-table
    :columns="columns"
    :data="entries"
    :pagination="{ pageSize: 10 }"
    :scroll-x="850"
  />
  <p v-if="plan.truncated" class="muted">
    仅展示前 128 条；规则计数和程序摘要覆盖完整配置。
  </p>
</template>

<style scoped>
.digest {
  overflow-wrap: anywhere;
}
</style>
