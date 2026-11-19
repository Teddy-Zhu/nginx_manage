<script setup lang="ts">
import { NButton, NForm, NModal, NSpace } from "naive-ui";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { onBeforeRouteLeave } from "vue-router";
const props = withDefaults(
  defineProps<{
    show: boolean;
    title: string;
    busy?: boolean;
    formDisabled?: boolean;
    dirty?: boolean;
    draft?: unknown;
    submitDisabled?: boolean;
    submitText?: string;
    width?: string;
  }>(),
  {
    busy: false,
    draft: undefined,
    submitDisabled: false,
    submitText: "保存",
    width: "720px",
  },
);
const emit = defineEmits<{ submit: []; cancel: [] }>();
const baseline = ref("");
watch(
  () => props.show,
  (show) => {
    if (show) baseline.value = JSON.stringify(props.draft) ?? "";
  },
  { immediate: true },
);
const dirty = computed(
  () =>
    props.dirty ??
    (props.draft !== undefined &&
      JSON.stringify(props.draft) !== baseline.value),
);
function submit() {
  if (!props.busy && !props.submitDisabled) emit("submit");
}
function cancel() {
  if (!props.busy && canDiscard()) emit("cancel");
}
function canDiscard() {
  return (
    !props.show || !dirty.value || window.confirm("修改尚未保存，确认放弃？")
  );
}
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (props.show && dirty.value) event.preventDefault();
};
onBeforeRouteLeave(canDiscard);
onMounted(() => window.addEventListener("beforeunload", beforeUnload));
onUnmounted(() => window.removeEventListener("beforeunload", beforeUnload));
</script>
<template>
  <NModal
    :show="show"
    preset="card"
    :title="title"
    :style="{ width, maxWidth: 'calc(100vw - 32px)' }"
    :mask-closable="false"
    :close-on-esc="!busy"
    :closable="!busy"
    @update:show="
      (value: boolean) => {
        if (!value) cancel();
      }
    "
  >
    <NForm
      label-placement="top"
      :disabled="busy || formDisabled"
      @submit.prevent="submit"
    >
      <div class="form-dialog-body">
        <fieldset :disabled="busy || formDisabled">
          <slot />
        </fieldset>
      </div>
      <slot name="footer">
        <div class="form-dialog-footer">
          <div><slot name="actions" /></div>
          <NSpace justify="end">
            <NButton :disabled="busy" @click="cancel">
              取消
            </NButton>
            <NButton
              type="primary"
              attr-type="submit"
              :loading="busy"
              :disabled="busy || submitDisabled"
            >
              {{ submitText }}
            </NButton>
          </NSpace>
        </div>
      </slot>
    </NForm>
  </NModal>
</template>
<style scoped>
.form-dialog-body {
  container-type: inline-size;
  max-height: calc(100dvh - 220px);
  overflow-y: auto;
  padding-right: 4px;
}
.form-dialog-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 24px;
}
.form-dialog-body > fieldset {
  min-width: 0;
  margin: 0;
  padding: 0;
  border: 0;
}
</style>
