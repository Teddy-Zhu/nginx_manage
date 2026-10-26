<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NButton, NInput, NInputNumber, NSelect } from "naive-ui";
const props = defineProps<{ value: string; kind: string; disabled?: boolean }>();
const emit = defineEmits<{ "update:value": [value: string] }>();
type Listener = { address: string; port: number | null; options: string[] };
const rows = ref<Listener[]>([]), error = ref("");
const options = computed(() => [
  ...(props.kind === "http" ? [{ label: "HTTPS", value: "ssl" }, { label: "HTTP/2", value: "http2" }] : [{ label: "UDP", value: "udp" }, { label: "端口复用", value: "reuseport" }]),
  { label: "默认站点", value: "default_server" },
  { label: "仅 IPv6", value: "ipv6only=on" },
  { label: "IPv4 / IPv6 双栈", value: "ipv6only=off" },
]);
let emitted: string | undefined;
watch(() => props.value, (value) => {
  if (value === emitted) return;
  error.value = "";
  const parsed: Listener[] = [];
  for (const line of value.split("\n").filter((item) => item.trim())) {
    const [endpoint = "", ...flags] = line.trim().split(/\s+/);
    const match = /^(?:(\[[^\]]+\]|[^:]*):)?(\d+)$/.exec(endpoint);
    if (!match) { error.value = "此监听包含复杂参数，请通过高级源文件编辑调整。"; return; }
    parsed.push({ address: (match[1] ?? "").replace(/^\[|\]$/g, ""), port: Number(match[2]), options: flags });
  }
  rows.value = parsed;
}, { immediate: true });
function update() {
  emitted = rows.value.map((row) => {
    const address = row.address.trim();
    const endpoint = `${address ? (address.includes(":") ? `[${address}]` : address) + ":" : ""}${row.port ?? ""}`;
    return [endpoint, ...row.options].join(" ");
  }).filter((line) => line.trim()).join("\n");
  emit("update:value", emitted);
}
function remove(index: number) { rows.value.splice(index, 1); update(); }
function setOptions(row: Listener, value: string[]) {
  const added = value.find((option) => option.startsWith("ipv6only=") && !row.options.includes(option));
  row.options = added ? value.filter((option) => !option.startsWith("ipv6only=") || option === added) : value;
  update();
}
</script>
<template>
  <NAlert v-if="error" type="warning">{{ error }}</NAlert>
  <div v-else class="listeners-input">
    <div v-for="(row, index) in rows" :key="index" class="listener-row">
      <label>监听地址<NInput v-model:value="row.address" placeholder="全部网卡，可填 IPv4 / IPv6" :disabled="disabled" @update:value="update" /></label>
      <label>端口<NInputNumber v-model:value="row.port" :min="1" :max="65535" :precision="0" placeholder="端口" :disabled="disabled" @update:value="update" /></label>
      <label class="listener-options">监听选项<NSelect :value="row.options" multiple :options="options" :disabled="disabled" placeholder="普通监听" @update:value="setOptions(row, $event)" /></label>
      <NButton attr-type="button" :disabled="disabled" :aria-label="`移除监听 ${index + 1}`" @click="remove(index)">移除</NButton>
    </div>
    <NButton attr-type="button" dashed :disabled="disabled || rows.length >= 128" @click="rows.push({ address: '', port: null, options: [] })">＋ 添加监听</NButton>
  </div>
</template>
<style scoped>
.listeners-input { width: 100%; display: grid; gap: 12px; }
.listener-row { display: grid; grid-template-columns: minmax(140px, 1fr) 120px minmax(170px, 1fr) auto; gap: 10px; align-items: end; }
label { min-width: 0; display: grid; gap: 6px; font-size: 13px; }
.listeners-input > :last-child { justify-self: start; }
@media (max-width: 900px) { .listener-row { grid-template-columns: minmax(0, 1fr) 110px; } .listener-options { grid-column: 1; } }
</style>
