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
  <div class="port-ranges">
    <div v-for="(row, index) in value" :key="index" class="port-row">
      <NSelect :value="row.to === null ? 'single' : 'range'" :options="[{ label: '单个端口', value: 'single' }, { label: '端口范围', value: 'range' }]" :disabled="disabled" @update:value="update(index, { to: $event === 'single' ? null : row.from ?? 1 })" />
      <NInputNumber :value="row.from" :min="1" :max="65535" :precision="0" :aria-label="`起始端口 ${index + 1}`" placeholder="端口" :disabled="disabled" @update:value="update(index, { from: $event })" />
      <NInputNumber v-if="row.to !== null" :value="row.to" :min="row.from ?? 1" :max="65535" :precision="0" :clearable="false" :aria-label="`结束端口 ${index + 1}`" placeholder="结束端口" :disabled="disabled" @update:value="update(index, { to: $event })" />
      <NButton attr-type="button" :disabled="disabled" @click="emit('update:value', value.filter((_, i) => i !== index))">移除</NButton>
    </div>
    <NButton attr-type="button" dashed :disabled="disabled || value.length >= 16" @click="emit('update:value', [...value, { from: null, to: null }])">＋ 添加端口</NButton>
  </div>
</template>
<style scoped>
.port-ranges { width: 100%; display: grid; gap: 10px; }
.port-row { display: flex; flex-wrap: wrap; gap: 8px; }
.port-row > :first-child { width: 125px; }
.port-row > :not(:first-child):not(:last-child) { flex: 1; min-width: 100px; }
.port-ranges > :last-child { justify-self: start; }
</style>
