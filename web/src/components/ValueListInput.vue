<script setup lang="ts">
import { computed } from "vue";
import { NButton, NInput } from "naive-ui";
const props = withDefaults(defineProps<{
  value: string[]; disabled?: boolean; itemLabel?: string;
  placeholder?: string; max?: number; maxlength?: number;
}>(), { itemLabel: "项目", placeholder: "请输入", max: 128, maxlength: 2048 });
const emit = defineEmits<{ "update:value": [value: string[]] }>();
const rows = computed(() => props.value.length ? props.value : [""]);
function update(index: number, value: string) {
  const next = [...rows.value]; next[index] = value; emit("update:value", next);
}
function remove(index: number) { emit("update:value", rows.value.filter((_, i) => i !== index)); }
</script>
<template>
  <div class="field-list">
    <div v-for="(value, index) in rows" :key="index" class="value-row field-row">
      <NInput :value="value" :aria-label="`${itemLabel} ${index + 1}`" :placeholder="placeholder" :maxlength="maxlength" :disabled="disabled" @update:value="update(index, $event)" />
      <NButton attr-type="button" :disabled="disabled" :aria-label="`移除${itemLabel} ${index + 1}`" @click="remove(index)">移除</NButton>
    </div>
    <NButton class="field-add" attr-type="button" dashed :disabled="disabled || rows.length >= max" @click="emit('update:value', [...rows, ''])">＋ 添加{{ itemLabel }}</NButton>
  </div>
</template>
<style scoped>
.value-row { grid-template-columns: minmax(0, 1fr) auto; }
</style>
