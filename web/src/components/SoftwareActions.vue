<script setup lang="ts">
import { NButton } from "naive-ui";
import { RouterLink } from "vue-router";
import type { SoftwareView } from "../utils/software";
defineProps<{ app: SoftwareView; permitted: boolean; active: boolean }>();
defineEmits<{ manage: []; install: [] }>();
</script>
<template>
  <RouterLink v-if="app.installed && app.entry?.to" :to="app.entry.to">
    <NButton type="primary">
      打开
    </NButton>
  </RouterLink>
  <NButton
    v-else
    type="primary"
    :disabled="
      !app.installed && (!permitted || active || app.status.state === 'unknown')
    "
    @click="app.installed ? $emit('manage') : $emit('install')"
  >
    {{ app.installed ? "软件管理" : "安装" }}
  </NButton>
  <NButton
    v-if="app.entry || !app.installed"
    quaternary
    @click="$emit('manage')"
  >
    {{ app.installed ? "软件管理" : "详情" }}
  </NButton>
</template>
