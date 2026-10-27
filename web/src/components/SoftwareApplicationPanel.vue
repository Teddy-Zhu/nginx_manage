<script setup lang="ts">
import { computed } from "vue";
import { NAlert, NButton, NTag } from "naive-ui";
import type { ComponentTask } from "../api/client";
import {
  applicationView,
  applicationActions,
  softwareApplicationTask,
  type CatalogEntry,
  type SoftwareOperation,
} from "../utils/software";
import SoftwareControls from "./SoftwareControls.vue";
import TaskLogButton from "./TaskLogButton.vue";
const props = defineProps<{
  entry: CatalogEntry;
  tasks: ComponentTask[];
  origin: string;
  permitted: boolean;
  busy: boolean;
}>();
defineEmits<{ operate: [action: SoftwareOperation] }>();
const app = computed(() =>
  applicationView(props.entry, props.tasks, props.origin),
);
const last = computed(() =>
  softwareApplicationTask(
    props.tasks,
    props.entry.source.id,
    props.entry.application.id,
  ),
);
</script>
<template>
  <div class="page-stack">
    <div class="button-row">
      <NTag :type="app.status.tone" :bordered="false">{{
        app.status.label
      }}</NTag
      ><span class="muted">{{ app.note }}</span>
    </div>
    <p>{{ app.description }}</p>
    <NAlert v-if="entry.installation?.error" type="warning">{{
      entry.installation.error
    }}</NAlert>
    <NAlert v-if="!entry.listed" type="warning"
      >软件源已不再提供此软件，仍可启停、查看日志或卸载。</NAlert
    >
    <NAlert v-if="last?.error" type="error"
      >上次操作未完成：{{ last.error }}</NAlert
    >
    <div v-if="app.entry?.href" class="button-row">
      <NButton
        tag="a"
        :href="app.entry.href"
        target="_blank"
        rel="noopener noreferrer"
        type="primary"
        >打开</NButton
      >
    </div>
    <SoftwareControls
      :installed="app.installed"
      :runtime="entry.installation?.state ?? 'unknown'"
      :permitted="permitted"
      :busy="busy"
      :actions="applicationActions(entry)"
      @operate="$emit('operate', $event)"
    />
    <div v-if="last" class="button-row">
      <TaskLogButton :task-id="last.id" /><span class="muted">{{
        last.state === "succeeded"
          ? "操作已完成"
          : last.state === "failed"
            ? "操作未完成"
            : "正在处理"
      }}</span>
    </div>
  </div>
</template>
