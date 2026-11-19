<script setup lang="ts">
import { NButton, NModal } from "naive-ui";

withDefaults(
  defineProps<{ title: string; width?: string; busy?: boolean; bodyHeight?: string }>(),
  { width: "760px", busy: false, bodyHeight: undefined },
);
const show = defineModel<boolean>("show", { required: true });
</script>

<template>
  <NModal
    v-model:show="show"
    preset="card"
    :title="title"
    :style="{ width, maxWidth: 'calc(100vw - 24px)' }"
    :mask-closable="false"
    :closable="!busy"
    :close-on-esc="!busy"
  >
    <div class="detail-dialog-body" :style="{ height: bodyHeight }">
      <slot />
    </div>
    <template #footer>
      <div class="detail-dialog-actions">
        <slot name="actions" />
        <NButton :disabled="busy" @click="show = false">
          关闭
        </NButton>
      </div>
    </template>
  </NModal>
</template>

<style scoped>
.detail-dialog-body {
  max-height: max(100px, calc(100dvh - 176px));
  overflow: auto;
  overscroll-behavior: contain;
  overflow-wrap: anywhere;
  padding-right: 4px;
  scrollbar-gutter: stable;
}
.detail-dialog-actions {
  display: flex;
  justify-content: flex-end;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
</style>
