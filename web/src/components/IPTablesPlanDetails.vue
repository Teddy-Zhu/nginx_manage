<script setup lang="ts">
import { NAlert, NDataTable, type DataTableColumns } from "naive-ui";
import type { FirewallPlan } from "../api/client";

defineProps<{
  plan: NonNullable<FirewallPlan["iptables"]>;
  programHash: string;
}>();
type Family = NonNullable<FirewallPlan["iptables"]>["families"][number];
const columns: DataTableColumns<Family> = [
  {
    title: "地址族",
    key: "family",
    render: (entry) => (entry.family === "ipv4" ? "IPv4" : "IPv6"),
  },
  { title: "后端工具", key: "binary" },
  { title: "代际链", key: "chain", minWidth: 250 },
  { title: "INPUT 位置", key: "hook_position" },
  { title: "生成规则", key: "generated_rules" },
  { title: "保留既有规则", key: "preserved_rules" },
  {
    title: "候选 / 恢复批次",
    key: "candidate_bytes",
    render: (entry) => `${entry.candidate_bytes} / ${entry.previous_bytes} 字节`,
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
    <dt>入口保护规则</dt>
    <dd>{{ plan.protection_rules }} 条</dd>
    <dt>完整规则基线</dt>
    <dd class="digest">{{ plan.configuration_hash }}</dd>
    <dt>诊断工具摘要</dt>
    <dd class="digest">{{ plan.tool_hash }}</dd>
    <dt>固定 command/save/restore 工具摘要</dt>
    <dd class="digest">{{ plan.toolchain_hash }}</dd>
    <dt>官方预演</dt>
    <dd>{{ plan.dry_run_commands }} 次（候选及正反向批次）</dd>
    <dt>完整预演摘要</dt>
    <dd class="digest">{{ plan.dry_run_hash }}</dd>
    <dt>逻辑规则摘要</dt>
    <dd class="digest">{{ plan.logical_hash }}</dd>
    <dt>完整代际程序摘要</dt>
    <dd class="digest">{{ programHash }}</dd>
  </dl>
  <n-data-table
    :columns="columns"
    :data="plan.families"
    :pagination="false"
    :scroll-x="1100"
  />
</template>

<style scoped>
.digest {
  overflow-wrap: anywhere;
}
</style>
