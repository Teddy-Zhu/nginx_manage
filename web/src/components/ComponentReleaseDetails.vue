<script setup lang="ts">
import type { ComponentRelease } from "../api/client";

defineProps<{
  details: Pick<ComponentRelease, "notes" | "requirements" | "receiver">;
}>();
</script>

<template>
  <div class="release-details">
    <table>
      <thead><tr><th>接收端要求</th><th>发行要求</th><th>当前节点</th></tr></thead>
      <tbody>
        <tr><td>API 主版本</td><td>{{ details.requirements.api_major }}</td><td>{{ details.receiver.api_major }}</td></tr>
        <tr><td>Agent 协议下限</td><td>{{ details.requirements.minimum_agent_protocol }}</td><td>{{ details.receiver.agent_protocol }}</td></tr>
        <tr><td>launcher 下限</td><td>{{ details.requirements.minimum_launcher }}</td><td>{{ details.receiver.launcher }}</td></tr>
      </tbody>
    </table>
    <p>目标数据库结构 {{ details.requirements.database_schema }} · 配套前端 {{ details.requirements.frontend_version }} · 自动回滚{{ details.requirements.automatic_rollback ? "允许" : "禁用" }}</p>
    <details>
      <summary>已验签发行说明</summary>
      <pre v-if="details.notes">{{ details.notes }}</pre>
      <p v-else class="muted">此发行未提供说明</p>
    </details>
  </div>
</template>

<style scoped>
.release-details { overflow-wrap: anywhere; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th, td { padding: 8px; border-bottom: 1px solid var(--border-color, #e5e7eb); }
pre { white-space: pre-wrap; font: inherit; }
summary { cursor: pointer; }
</style>
