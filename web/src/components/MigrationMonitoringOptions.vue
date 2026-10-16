<script setup lang="ts">
import { computed } from "vue";
import { NFormItem, NSelect } from "naive-ui";
import type { MigrationMonitoringInput } from "../api/client";
const props = withDefaults(
  defineProps<{
    modelValue: MigrationMonitoringInput;
    disabled?: boolean;
    allowReplace?: boolean;
  }>(),
  { allowReplace: true },
);
const emit = defineEmits<{
  "update:modelValue": [value: MigrationMonitoringInput];
}>();
const options = computed(() => [
  { label: "保留目标监控配置", value: "preserve" },
  {
    label: "替换目标监控配置",
    value: "replace",
    disabled: !props.allowReplace,
  },
]);
function setMode(mode: MigrationMonitoringInput["mode"]) {
  emit("update:modelValue", { mode });
}
</script>
<template>
  <NFormItem label="监控配置迁入方式">
    <NSelect
      :value="modelValue.mode"
      :options="options"
      :disabled="disabled"
      @update:value="setMode"
    />
  </NFormItem>
</template>
