<script setup lang="ts">
import { computed } from "vue";
import { NAlert, NDataTable, type DataTableColumns } from "naive-ui";
import type { FirewallPlan } from "../api/client";

const props = defineProps<{
  plan: NonNullable<FirewallPlan["ufw"]>;
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
    render: (entry) => (entry.protection ? "入口保护" : "业务规则"),
  },
  { title: "地址族", key: "family" },
  {
    title: "来源",
    key: "source",
    ellipsis: { tooltip: true },
  },
  {
    title: "预演命令（目标顺序）",
    key: "expression",
    minWidth: 420,
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
    <dt>本机授权登记操作</dt>
    <dd>{{ plan.registration_operation_id }}</dd>
    <dt>累积批次 dry-run</dt>
    <dd>{{ plan.dry_run_commands }} 条</dd>
    <dt>核对保留的既有用户规则</dt>
    <dd>{{ plan.preserved_rules }} 条（按原生 tuple 计）</dd>
    <dt>入口保护 / 覆盖相同条件的业务项</dt>
    <dd>{{ plan.protection_rules }} 条 / {{ plan.protection_overrides }} 条</dd>
    <dt>固定配置基线</dt>
    <dd class="digest">{{ plan.configuration_hash }}</dd>
    <dt>UFW 可执行文件摘要</dt>
    <dd class="digest">{{ plan.tool_hash }}</dd>
    <dt>完整预演输出摘要</dt>
    <dd class="digest">{{ plan.dry_run_hash }}</dd>
    <dt>生成原生规则摘要</dt>
    <dd class="digest">{{ plan.native_program_hash }}</dd>
    <dt>完整候选批次摘要</dt>
    <dd class="digest">{{ plan.batch_hash }}</dd>
    <dt>原运行后端</dt>
    <dd>{{ plan.reload_backend }}</dd>
    <dt>重载范围</dt>
    <dd>{{ plan.reload_chains }} 个用户链 / {{ plan.reload_rules }} 条报文规则</dd>
    <dt>原运行规则摘要</dt>
    <dd class="digest">{{ plan.reload_hash }}</dd>
    <dt>完整程序摘要</dt>
    <dd class="digest">{{ programHash }}</dd>
  </dl>
  <n-data-table
    :columns="columns"
    :data="entries"
    :pagination="{ pageSize: 10 }"
    :scroll-x="900"
  />
  <p v-if="plan.truncated" class="muted">
    仅展示前 128 条；命令计数和程序摘要覆盖完整配置。
  </p>
</template>

<style scoped>
.digest {
  overflow-wrap: anywhere;
}
</style>
