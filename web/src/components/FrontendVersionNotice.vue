<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { onMounted, onUnmounted, ref } from "vue";
import { NAlert, NButton, NPopconfirm } from "naive-ui";
import { api, apiError } from "../api/client";
import { loadedFrontendEntries } from "../frontend-version";

const changed = ref(false), error = ref("");
const controller = new AbortController();
const reading = ref(false);
let closed = false;
async function check() {
  if (closed || reading.value || document.hidden) return;
  reading.value = true;
  try {
    const version = await api.systemVersion(controller.signal);
    if (closed) return;
    error.value = "";
    if (version.frontend_id && loadedFrontendEntries.length) changed.value = JSON.stringify([...version.frontend_entries].sort()) !== JSON.stringify(loadedFrontendEntries);
  } catch (e) { if (!closed) error.value = apiError(e).message; }
  finally { reading.value = false; }
}
function reload() { window.location.reload(); }
onMounted(() => void check());
onUnmounted(() => { closed = true; controller.abort(); });
useLiveRefresh(api, ["version"], check, () => reading.value);
</script>

<template>
  <NAlert v-if="changed" class="version-notice" type="info">
    页面有新版本。保存当前修改后可重新载入。
    <NPopconfirm @positive-click="reload">
      <template #trigger>
        <NButton size="small">
          重新载入
        </NButton>
      </template>重新载入会丢弃未保存的修改，是否继续？
    </NPopconfirm>
  </NAlert>
  <NAlert v-else-if="error" class="version-notice" type="warning">
    无法检查页面版本：{{ error }}<NButton size="small" @click="check">
      重试
    </NButton>
  </NAlert>
</template>

<style scoped>
.version-notice { margin: 12px; }
</style>
