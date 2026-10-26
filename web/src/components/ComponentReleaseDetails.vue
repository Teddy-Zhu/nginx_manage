<script setup lang="ts">
import type { ComponentRelease } from "../api/client";
defineProps<{
  details: Pick<ComponentRelease, "notes" | "requirements" | "receiver">;
}>();
</script>
<template>
  <section class="release-details">
    <h4>更新说明</h4>
    <p class="release-notes">{{ details.notes || "此版本暂无更新说明。" }}</p>
  </section>
</template>
<style scoped>
.release-details {
  overflow-wrap: anywhere;
}
.release-notes {
  white-space: pre-wrap;
}
</style>
