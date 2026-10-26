<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NFormItem, NSelect } from "naive-ui";
import type { MigrationFirewallInput } from "../api/client";
import MappingInput from "./MappingInput.vue";
import { mappingRecord, type MappingRow } from "../utils/form";
const props = defineProps<{ modelValue: MigrationFirewallInput; disabled?: boolean }>();
const emit = defineEmits<{ "update:modelValue": [value: MigrationFirewallInput]; "update:valid": [value: boolean] }>();
const rows = ref<MappingRow[]>([]), mappingError = ref("");
const importing = computed(() => props.modelValue.mode !== "preserve");
let canonical = "";
watch(() => props.modelValue.interfaces, (value) => {
  const next = JSON.stringify(value);
  if (next === canonical) return;
  canonical = next;
  rows.value = Object.entries(value).map(([source, target]) => ({ source, target }));
  mappingError.value = "";
  emit("update:valid", true);
}, { immediate: true });
function setMode(mode: MigrationFirewallInput["mode"]) {
  rows.value = []; canonical = "{}"; mappingError.value = "";
  emit("update:modelValue", { mode, backend: mode === "preserve" ? "" : props.modelValue.backend || "direct-nftables", interfaces: {} });
  emit("update:valid", true);
}
function setMapping(value: MappingRow[]) {
  rows.value = value;
  try {
    const interfaces = mappingRecord(value);
    canonical = JSON.stringify(interfaces); mappingError.value = "";
    emit("update:modelValue", { ...props.modelValue, interfaces });
    emit("update:valid", true);
  } catch (cause) {
    mappingError.value = (cause as Error).message;
    emit("update:valid", false);
  }
}
</script>
<template>
  <div>
    <NFormItem label="目标防火墙策略">
      <NSelect :value="modelValue.mode" :options="[{ label: '保留目标防火墙', value: 'preserve' }, { label: '合并防火墙规则', value: 'merge' }, { label: '替换防火墙规则', value: 'replace' }]" :disabled="disabled" @update:value="setMode" />
    </NFormItem>
    <template v-if="importing">
      <NFormItem label="目标防火墙类型">
        <NSelect :value="modelValue.backend" :options="[{ label: 'nftables', value: 'direct-nftables' }, { label: 'iptables-nft', value: 'iptables-nft' }, { label: 'iptables-legacy', value: 'iptables-legacy' }, { label: 'firewalld', value: 'firewalld' }, { label: 'ufw', value: 'ufw' }]" :disabled="disabled" @update:value="emit('update:modelValue', { ...modelValue, backend: $event })" />
      </NFormItem>
      <NFormItem label="网卡映射" :validation-status="mappingError ? 'error' : undefined" :feedback="mappingError || '目标网卡留空时解除网卡绑定。'">
        <MappingInput :max="256" :value="rows" source-label="来源网卡" target-label="目标网卡（可留空）" :disabled="disabled" @update:value="setMapping" />
      </NFormItem>
      <NAlert type="warning">请为规则绑定的每张网卡设置映射。迁移后需在目标防火墙页面确认应用。</NAlert>
    </template>
  </div>
</template>
