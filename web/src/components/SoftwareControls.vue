<script setup lang="ts">
import { computed } from "vue";
import { NButton, NDropdown } from "naive-ui";
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
  compact?: boolean;
}>();
defineEmits<{ operate: [action: SoftwareOperation] }>();
const controls = computed(() =>
  softwareControls(props.installed, props.runtime, props.actions),
);
const visible = computed(() =>
  controls.value.filter(
    (action) =>
      !props.compact ||
      ["install", "start", "stop", "logs"].includes(action.id),
  ),
);
const more = computed(() =>
  controls.value
    .filter((action) => !visible.value.includes(action))
    .map((action) => ({
      key: action.id,
      label: action.label,
      disabled: !props.permitted || props.busy,
    })),
);
</script>
<template>
  <div class="button-row">
    <NButton
      v-for="action in visible"
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
    <NDropdown
      v-if="more.length"
      trigger="click"
      :options="more"
      @select="$emit('operate', $event as SoftwareOperation)"
    >
      <NButton :disabled="!permitted || busy">更多操作</NButton>
    </NDropdown>
  </div>
</template>
