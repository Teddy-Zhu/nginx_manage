<script setup lang="ts">
import { computed } from "vue";
import type { MigrationMonitoringPlan } from "../api/client";
const props = defineProps<{ info: MigrationMonitoringPlan }>();
const states: Record<MigrationMonitoringPlan["state"], string> = {
  preserved: "保留目标配置",
  pending_import: "待导入",
  not_imported: "已保存草稿，未导入监控配置",
  saved: "已导入监控配置",
  restored: "已恢复目标原配置",
  recovery_required: "需要恢复",
};
const thresholds = computed(() => [
  { name: "CPU", value: props.info.settings.cpu },
  { name: "内存", value: props.info.settings.memory },
  { name: "磁盘", value: props.info.settings.disk },
]);
</script>
<template>
  <div class="surface">
    <h3>监控配置</h3>
    <p>{{ states[info.state] }}</p>
    <p>
      源采样间隔 {{ info.settings.interval_seconds }} 秒，数据保留
      {{ info.settings.retention_hours }} 小时。
    </p>
    <p v-for="threshold in thresholds" :key="threshold.name">
      {{ threshold.name }}：{{ threshold.value.enabled ? "启用" : "停用" }}；
      超限 {{ threshold.value.high }}% 持续
      {{ threshold.value.for_seconds }} 秒，恢复至
      {{ threshold.value.recover }}% 持续
      {{ threshold.value.recover_seconds }} 秒。
    </p>
    <p v-if="info.mode === 'replace'">
      目标基础版本 {{ info.base_version
      }}<span v-if="info.saved_version"
        >，导入版本 {{ info.saved_version }}</span
      >。
    </p>
  </div>
</template>
