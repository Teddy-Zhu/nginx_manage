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
  busy: boolean;
  actions: SoftwareOperation[];
}>();
defineEmits<{ operate: [action: SoftwareOperation] }>();
const controls = computed(() =>
  softwareControls(props.installed, props.runtime, props.actions),
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
          : action.id === 'install'
            ? 'primary'
            : 'default'
      "
      :secondary="action.danger"
      :disabled="!permitted || busy"
      @click="$emit('operate', action.id)"
      >{{ action.label }}</NButton
    >
  </div>
</template>
