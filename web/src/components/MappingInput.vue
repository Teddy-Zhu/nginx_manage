<script setup lang="ts">
import { NButton, NInput } from "naive-ui";
import type { MappingRow } from "../utils/form";
withDefaults(defineProps<{
  value: MappingRow[]; disabled?: boolean; max?: number;
  sourceLabel?: string; targetLabel?: string;
}>(), { max: 64, sourceLabel: "原参数", targetLabel: "目标参数" });
const emit = defineEmits<{ "update:value": [value: MappingRow[]] }>();
</script>
<template>
  <div class="field-list">
    <div v-for="(row, index) in value" :key="index" class="mapping-row field-row">
      <label class="field-label">{{ sourceLabel }}<NInput :value="row.source" :placeholder="sourceLabel" :disabled="disabled" :maxlength="2048" @update:value="emit('update:value', value.map((item, i) => i === index ? { ...item, source: $event } : item))" /></label>
      <span class="arrow" aria-hidden="true">→</span>
      <label class="field-label">{{ targetLabel }}<NInput :value="row.target" :placeholder="targetLabel" :disabled="disabled" :maxlength="2048" @update:value="emit('update:value', value.map((item, i) => i === index ? { ...item, target: $event } : item))" /></label>
      <NButton attr-type="button" :disabled="disabled" :aria-label="`移除映射 ${index + 1}`" @click="emit('update:value', value.filter((_, i) => i !== index))">移除</NButton>
    </div>
    <NButton class="field-add" attr-type="button" dashed :disabled="disabled || value.length >= max" @click="emit('update:value', [...value, { source: '', target: '' }])">＋ 添加映射</NButton>
  </div>
</template>
<style scoped>
.mapping-row { grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto; }
.arrow { display: flex; align-items: center; height: var(--control-height); color: var(--text-muted); }
@container (max-width: 500px) {
  .mapping-row { grid-template-columns: minmax(0, 1fr) auto; }
  .mapping-row label { grid-column: 1 / -1; }
  .mapping-row > button { grid-column: 2; }
  .arrow { display: none; }
}
</style>
