<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NInputNumber, NSelect } from "naive-ui";
const props = withDefaults(defineProps<{ value: string; kind: "time" | "size"; disabled?: boolean }>(), {});
const emit = defineEmits<{ "update:value": [value: string] }>();
const amount = ref<number | null>(null), unit = ref("");
const options = computed(() => props.kind === "size"
  ? [{ label: "字节", value: "" }, { label: "KB", value: "k" }, { label: "MB", value: "m" }, { label: "GB", value: "g" }]
  : [{ label: "秒", value: "" }, { label: "毫秒", value: "ms" }, { label: "分钟", value: "m" }, { label: "小时", value: "h" }]);
watch(() => props.value, (value) => {
  const match = /^(\d+)(ms|s|[kKmMgGhH])?$/.exec(value);
  amount.value = match ? Number(match[1]) : null;
  unit.value = match?.[2] === "s" ? "" : (match?.[2] ?? "").toLowerCase();
}, { immediate: true });
function update() { emit("update:value", amount.value === null ? "" : props.kind === "size" && amount.value === 0 ? "0" : `${amount.value}${unit.value}`); }
</script>
<template>
  <div class="unit-input">
    <NInputNumber v-model:value="amount" :min="0" :max="kind === 'size' ? 999999999 : 9999999" :precision="0" :disabled="disabled" placeholder="未设置" @update:value="update" />
    <NSelect v-model:value="unit" :options="options" :disabled="disabled" @update:value="update" />
  </div>
</template>
<style scoped>
.unit-input { width: 100%; display: grid; grid-template-columns: minmax(0, 1fr) 90px; gap: 8px; }
</style>
