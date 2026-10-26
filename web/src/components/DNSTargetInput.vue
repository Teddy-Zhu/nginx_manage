<script setup lang="ts">
import { ref, watch } from "vue";
import { NInput, NSelect } from "naive-ui";
const props = defineProps<{ value: string; disabled?: boolean }>();
const emit = defineEmits<{ "update:value": [value: string] }>();
const kind = ref("system"), connection = ref(""), networkInterface = ref("");
const options = [{ label: "系统 DNS", value: "system" }, { label: "网卡 DNS", value: "networkd" }, { label: "网络连接 DNS", value: "connection" }];
let emitted: string | undefined;
watch(() => props.value, (value) => {
  if (value === emitted) return;
  kind.value = !value ? "system" : value.startsWith("networkd:") ? "networkd" : "connection";
  connection.value = kind.value === "connection" ? value.split("@")[0] ?? "" : "";
  networkInterface.value = kind.value === "networkd" ? value.slice(9) : value.split("@")[1] ?? "";
}, { immediate: true });
function update() {
  emitted = kind.value === "system" ? "" : kind.value === "networkd" ? `networkd:${networkInterface.value.trim()}` : `${connection.value.trim()}@${networkInterface.value.trim()}`;
  emit("update:value", emitted);
}
</script>
<template>
  <div class="field-list">
    <NSelect v-model:value="kind" :options="options" :disabled="disabled" @update:value="update" />
    <NInput v-if="kind === 'connection'" v-model:value="connection" aria-label="连接 UUID" placeholder="连接 UUID" :maxlength="36" :disabled="disabled" @update:value="update" />
    <NInput v-if="kind !== 'system'" v-model:value="networkInterface" aria-label="网卡名称" placeholder="网卡名称，例如 eth0" :maxlength="15" :disabled="disabled" @update:value="update" />
  </div>
</template>
