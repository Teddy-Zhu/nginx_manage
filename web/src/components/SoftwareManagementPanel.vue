<script setup lang="ts">
import { NAlert, NButton, NTag } from "naive-ui";
import { RouterLink } from "vue-router";
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
  busy: boolean;
  task?: ComponentTask;
  error?: string;
  settingsAvailable?: boolean;
}>();
defineEmits<{ operate: [action: SoftwareOperation]; settings: [] }>();
</script>
<template>
  <div class="page-stack software-management">
    <div class="software-summary">
      <div class="button-row">
        <NTag :type="app.status.tone" :bordered="false">
          {{
            app.status.label
          }}
        </NTag>
        <span class="muted">{{ app.note }}</span>
      </div>
      <p class="muted">
        {{ app.description }}
      </p>
    </div>
    <NAlert v-if="error" type="warning">
      {{ error }}
    </NAlert>
    <NAlert v-if="task?.error" type="error">
      上次操作未完成：{{ task.error }}
    </NAlert>
    <section class="software-section">
      <div class="management-heading">
        <h3>运行管理</h3>
        <NButton
          v-if="settingsAvailable"
          :disabled="!permitted || busy"
          @click="$emit('settings')"
        >
          运行设置
        </NButton>
      </div>
      <SoftwareControls
        :versioned="app.versioned"
        compact
        :installed="app.installed"
        :runtime="runtime"
        :permitted="
          permitted && (app.installed || app.status.state !== 'unknown')
        "
        :busy="busy"
        :actions="actions"
        @operate="$emit('operate', $event)"
      />
      <slot />
    </section>
    <section v-if="app.installed && app.entry" class="software-entry">
      <div>
        <h3>功能入口</h3>
        <p class="muted">
          {{ app.name }}
        </p>
      </div>
      <RouterLink v-if="app.entry.to" :to="app.entry.to">
        <NButton type="primary">
          打开功能页面
        </NButton>
      </RouterLink>
      <NButton
        v-else-if="app.entry.href"
        tag="a"
        :href="app.entry.href"
        target="_blank"
        rel="noopener noreferrer"
        type="primary"
      >
        打开应用
      </NButton>
    </section>
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
.software-summary p {
  margin: 12px 0 0;
  line-height: 1.7;
}
.software-management h3 {
  margin: 0;
  font-size: 15px;
}
.software-section {
  display: grid;
  gap: 16px;
}
.management-heading,
.software-entry,
.management-task {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}
.software-entry {
  border-top: 1px solid var(--border-color);
  padding-top: 20px;
}
.software-entry p {
  margin: 6px 0 0;
}
.management-task {
  padding-top: 16px;
  border-top: 1px solid var(--border-color);
}
</style>
