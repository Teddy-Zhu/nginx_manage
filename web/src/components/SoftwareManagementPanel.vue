<script setup lang="ts">
import { NAlert, NTag } from "naive-ui";
import type { ComponentTask } from "../api/client";
import type {
  RuntimeState,
  SoftwareOperation,
  SoftwareView,
} from "../utils/software";
import SoftwareControls from "./SoftwareControls.vue";
import TaskLogButton from "./TaskLogButton.vue";
defineProps<{
  app: SoftwareView;
  runtime: RuntimeState;
  actions: SoftwareOperation[];
  permitted: boolean;
  logsPermitted: boolean;
  busy: boolean;
  task?: ComponentTask;
  error?: string;
}>();
defineEmits<{ operate: [action: SoftwareOperation] }>();
</script>
<template>
  <div class="page-stack">
    <div class="button-row">
      <NTag :type="app.status.tone" :bordered="false">
        {{ app.status.label }}
      </NTag>
      <span class="muted">{{ app.note }}</span>
    </div>
    <NAlert v-if="error" type="warning">
      {{ error }}
    </NAlert>
    <NAlert v-if="task?.error" type="error">
      上次操作未完成：{{ task.error }}
    </NAlert>
    <SoftwareControls
      :versioned="app.versioned"
      :installed="app.installed"
      :runtime="runtime"
      :permitted="permitted && (app.installed || app.status.state !== 'unknown')"
      :logs-permitted="logsPermitted"
      :busy="busy"
      :actions="actions"
      @operate="$emit('operate', $event)"
    />
    <div v-if="task" class="management-task">
      <span class="muted">{{
        task.state === "succeeded"
          ? "操作已完成"
          : task.state === "failed"
            ? "操作未完成"
            : "正在处理，请稍候"
      }}</span>
      <TaskLogButton :task-id="task.id" />
    </div>
  </div>
</template>
<style scoped>
.management-task {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  padding-top: 16px;
  border-top: 1px solid var(--border-color);
}
</style>
