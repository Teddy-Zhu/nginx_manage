<script setup lang="ts">
import { computed } from "vue";
import { NButton } from "naive-ui";
import {
  softwareControls,
  type RuntimeState,
  type SoftwareOperation,
} from "../utils/software";
const props = defineProps<{
  installed: boolean;
  runtime: RuntimeState;
  permitted: boolean;
  logsPermitted: boolean;
  busy: boolean;
  actions: SoftwareOperation[];
  versioned?: boolean;
}>();
defineEmits<{ operate: [action: SoftwareOperation] }>();
const controls = computed(() =>
  softwareControls(props.installed, props.runtime, props.actions).map(
    (action) =>
      props.versioned && action.id === "update"
        ? { ...action, label: "切换版本" }
        : action,
  ),
);
</script>
<template>
  <div class="button-row">
    <NButton
      v-for="action in controls"
      :key="action.id"
      :type="
        action.danger
          ? 'error'
          : action.id === 'install' || action.id === 'update'
            ? 'primary'
            : 'default'
      "
      :secondary="action.danger"
      :disabled="action.id === 'logs' ? !logsPermitted : !permitted || busy"
      @click="$emit('operate', action.id)"
    >
      {{ action.label }}
    </NButton>
  </div>
</template>
