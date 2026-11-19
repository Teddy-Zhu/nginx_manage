<script setup lang="ts">
import { NAlert } from "naive-ui";
import type { MigrationFail2banPlan } from "../api/client";
defineProps<{ info: MigrationFail2banPlan }>();
const states: Record<string, string> = {
  preserved: "保留目标",
  pending_import: "待保存",
  saved_unapplied: "已保存，未应用",
  restored: "已恢复",
  recovery_required: "需要恢复",
};
</script>
<template>
  <div class="surface">
    <h3>Fail2ban jail</h3>
    <p>
      {{ states[info.state] || info.state }} · 源配置 {{ info.source_jails }} 个
    </p>
    <p v-if="info.mode !== 'preserve'">
      保留 {{ info.preserved_jails }} 个，替换
      {{ info.replaced_jails }} 个，目标共 {{ info.total_jails }} 个。
    </p>
    <NAlert v-for="warning in info.warnings" :key="warning" type="warning">
      {{
        warning
      }}
    </NAlert>
  </div>
</template>
