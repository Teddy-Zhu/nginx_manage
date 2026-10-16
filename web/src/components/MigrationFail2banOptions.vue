<script setup lang="ts">
import { NFormItem, NSelect } from "naive-ui";
import type { MigrationFail2banInput } from "../api/client";
defineProps<{ modelValue: MigrationFail2banInput; disabled?: boolean }>();
const emit = defineEmits<{
  "update:modelValue": [value: MigrationFail2banInput];
}>();
function setMode(mode: MigrationFail2banInput["mode"]) {
  emit("update:modelValue", { mode });
}
const options = [
  { label: "保留目标 jail 配置", value: "preserve" },
  { label: "合并 jail 期望配置", value: "merge" },
  { label: "替换 jail 期望配置", value: "replace" },
];
</script>
<template>
  <NFormItem label="Fail2ban jail 迁入方式">
    <NSelect
      :value="modelValue.mode"
      :options="options"
      :disabled="disabled"
      @update:value="setMode"
    />
  </NFormItem>
</template>
