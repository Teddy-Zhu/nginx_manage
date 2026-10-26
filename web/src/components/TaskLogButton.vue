<script setup lang="ts">
import { NButton } from "naive-ui";
import { useRoute } from "vue-router";
import { inspectTask } from "../stores/operation";

defineProps<{ taskId: string; title?: string }>();
const route = useRoute();
</script>

<template>
  <NButton
    size="small"
    @click="inspectTask(taskId, title, !!route.meta.localOnly)"
    >查看日志</NButton
  >
</template>
