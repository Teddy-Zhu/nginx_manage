<script setup lang="ts">
import { NSelect } from "naive-ui";
import { dnsLocationLabel } from "../utils/form";
defineProps<{
  value: string | null;
  options: { label: string; value: string }[];
  disabled?: boolean;
  loading?: boolean;
}>();
const emit = defineEmits<{ "update:value": [value: string] }>();
</script>
<template>
  <NSelect
    :value="value"
    :options="options"
    :fallback-option="
      (value) => ({ label: dnsLocationLabel(String(value)), value })
    "
    :disabled="disabled"
    :loading="loading"
    filterable
    placeholder="选择目标网络"
    @update:value="emit('update:value', $event)"
  />
</template>
