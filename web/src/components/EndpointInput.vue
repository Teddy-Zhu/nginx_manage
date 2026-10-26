<script setup lang="ts">
import { ref, watch } from "vue";
import { NInput, NInputNumber } from "naive-ui";
const props = defineProps<{ value: string; disabled?: boolean }>();
const emit = defineEmits<{ "update:value": [value: string] }>();
const host = ref(""), port = ref<number | null>(null);
let emitted: string | undefined;
watch(() => props.value, (value) => {
  if (value === emitted) return;
  const match = /^(?:\[([^\]]+)\]|([^:]+)):(\d*)$/.exec(value);
  host.value = match ? match[1] ?? match[2] ?? "" : value;
  port.value = match?.[3] ? Number(match[3]) : null;
}, { immediate: true });
function update() {
  const address = host.value.trim();
  emitted = !address && port.value === null ? "" : `${address.includes(":") ? `[${address}]` : address}:${port.value ?? ""}`;
  emit("update:value", emitted);
}
</script>
<template>
  <div class="endpoint-input">
    <label>后端地址<NInput v-model:value="host" placeholder="IP 地址或域名" :maxlength="253" :disabled="disabled" @update:value="update" /></label>
    <label>端口<NInputNumber v-model:value="port" :min="1" :max="65535" :precision="0" placeholder="端口" :disabled="disabled" @update:value="update" /></label>
  </div>
</template>
<style scoped>
.endpoint-input { width: 100%; display: grid; grid-template-columns: minmax(0, 1fr) 110px; gap: 8px; }
label { min-width: 0; display: grid; gap: 6px; font-size: 13px; }
</style>
