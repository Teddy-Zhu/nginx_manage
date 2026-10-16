<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NFormItem, NInput, NSelect } from "naive-ui";
import type { MigrationFirewallInput } from "../api/client";

const props = defineProps<{
  modelValue: MigrationFirewallInput;
  disabled?: boolean;
}>();
const emit = defineEmits<{
  "update:modelValue": [value: MigrationFirewallInput];
  "update:valid": [value: boolean];
}>();
const modes = [
  { label: "保留目标防火墙", value: "preserve" },
  { label: "合并期望规则", value: "merge" },
  { label: "替换期望规则", value: "replace" },
];
const backends = [
  { label: "直接 nftables", value: "direct-nftables" },
  { label: "iptables-nft", value: "iptables-nft" },
  { label: "iptables-legacy", value: "iptables-legacy" },
  { label: "firewalld", value: "firewalld" },
  { label: "ufw", value: "ufw" },
];
const mappingText = ref(JSON.stringify(props.modelValue.interfaces, null, 2));
let canonical = JSON.stringify(props.modelValue.interfaces);
const mappingError = ref("");
const importing = computed(() => props.modelValue.mode !== "preserve");
watch(
  () => props.modelValue.interfaces,
  (value) => {
    const next = JSON.stringify(value);
    if (next !== canonical) {
      canonical = next;
      mappingText.value = JSON.stringify(value, null, 2);
    }
  },
);
function setMode(mode: MigrationFirewallInput["mode"]) {
  mappingError.value = "";
  mappingText.value = "{}";
  canonical = "{}";
  emit("update:modelValue", {
    mode,
    backend:
      mode === "preserve" ? "" : props.modelValue.backend || "direct-nftables",
    interfaces: {},
  });
  emit("update:valid", true);
}
function setBackend(backend: string) {
  emit("update:modelValue", { ...props.modelValue, backend });
}
function setMapping(text: string) {
  mappingText.value = text;
  try {
    const value: unknown = JSON.parse(text);
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.values(value).some((item) => typeof item !== "string")
    )
      throw new Error("网卡映射须为源接口到目标接口的 JSON 对象");
    const interfaces = value as Record<string, string>;
    canonical = JSON.stringify(interfaces);
    mappingError.value = "";
    emit("update:modelValue", { ...props.modelValue, interfaces });
    emit("update:valid", true);
  } catch {
    mappingError.value = "网卡映射须为源接口到目标接口的 JSON 对象";
    emit("update:valid", false);
  }
}
</script>

<template>
  <div>
    <NFormItem label="目标防火墙策略">
      <NSelect
        :value="modelValue.mode"
        :options="modes"
        :disabled="disabled"
        @update:value="setMode"
      />
    </NFormItem>
    <template v-if="importing">
      <NFormItem label="目标防火墙后端">
        <NSelect
          :value="modelValue.backend"
          :options="backends"
          :disabled="disabled"
          @update:value="setBackend"
        />
      </NFormItem>
      <NFormItem
        label="网卡映射（源接口 → 目标接口）"
        :validation-status="mappingError ? 'error' : undefined"
        :feedback="mappingError"
      >
        <NInput
          :value="mappingText"
          type="textarea"
          :autosize="{ minRows: 3, maxRows: 8 }"
          :disabled="disabled"
          placeholder='{"eth0":"ens3","eth1":""}'
          @update:value="setMapping"
        />
      </NFormItem>
      <NAlert type="warning"
        >须包含源防火墙规则，并为每个绑定接口明确映射；空字符串解除绑定。合并保留目标既有规则及其后端，源、目标优先级须无重叠。迁移只保存期望策略，生效须在目标防火墙页面单独确认。</NAlert
      >
    </template>
  </div>
</template>
