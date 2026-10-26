<script setup lang="ts">
import { NButton, NInputNumber, NSelect } from "naive-ui";
import type { PortRange } from "../utils/form";
const props = defineProps<{ value: PortRange[]; disabled?: boolean }>();
const emit = defineEmits<{ "update:value": [value: PortRange[]] }>();
function update(index: number, changes: Partial<PortRange>) {
  emit("update:value", props.value.map((row, i) => i === index ? { ...row, ...changes } : row));
}
</script>
<template>
  <div class="field-list">
    <div v-for="(row, index) in value" :key="index" class="port-row field-row" :class="{ single: row.to === null }">
      <NSelect :value="row.to === null ? 'single' : 'range'" :options="[{ label: '单个端口', value: 'single' }, { label: '端口范围', value: 'range' }]" :disabled="disabled" @update:value="update(index, { to: $event === 'single' ? null : row.from ?? 1 })" />
      <NInputNumber class="range-start" :value="row.from" :min="1" :max="65535" :precision="0" :aria-label="`起始端口 ${index + 1}`" placeholder="端口" :disabled="disabled" @update:value="update(index, { from: $event })" />
      <NInputNumber v-if="row.to !== null" :value="row.to" :min="row.from ?? 1" :max="65535" :precision="0" :clearable="false" :aria-label="`结束端口 ${index + 1}`" placeholder="结束端口" :disabled="disabled" @update:value="update(index, { to: $event })" />
      <NButton attr-type="button" :disabled="disabled" @click="emit('update:value', value.filter((_, i) => i !== index))">移除</NButton>
    </div>
    <NButton class="field-add" attr-type="button" dashed :disabled="disabled || value.length >= 16" @click="emit('update:value', [...value, { from: null, to: null }])">＋ 添加端口</NButton>
  </div>
</template>
<style scoped>
.port-row { grid-template-columns: 132px repeat(2, minmax(0, 1fr)) auto; }
.port-row.single .range-start { grid-column: 2 / 4; }
@container (max-width: 480px) {
  .port-row { grid-template-columns: repeat(2, minmax(0, 1fr)) auto; }
  .port-row > :first-child { grid-column: 1 / -1; }
  .port-row.single .range-start { grid-column: 1 / 3; }
}
</style>
