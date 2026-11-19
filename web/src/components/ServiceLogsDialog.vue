<script setup lang="ts">
import { nextTick, ref, useTemplateRef, watch } from "vue";
import { NAlert, NButton, NEmpty, NModal, NSpin, useMessage } from "naive-ui";
import { apiError, useNodeAPI } from "../api/client";
import { liveDisconnected } from "../api/live";
import { copyText } from "../utils/copy";

const show = defineModel<boolean>("show", { required: true });
const props = defineProps<{ app: "frps" | "fail2ban"; name: string }>();
const api = useNodeAPI();
const message = useMessage();
const log = ref("");
const error = ref("");
const loading = ref(false);
const paused = ref(false);
const output = useTemplateRef("output");

watch([show, () => props.app], () => {
  log.value = "";
  error.value = "";
  paused.value = false;
});
watch([show, () => props.app, paused], ([visible, app, freeze], _, cleanup) => {
  loading.value = visible && !freeze && !log.value;
  if (!visible || freeze) return;
  let subscribed = true;
  try {
    const stop = api.watchServiceLogs(
      app,
      (text) => {
        const box = output.value;
        const follow =
          !box || box.scrollHeight - box.scrollTop - box.clientHeight < 24;
        log.value = text;
        error.value = "";
        loading.value = false;
        if (follow) {
          void nextTick(() => {
            if (subscribed && output.value)
              output.value.scrollTop = output.value.scrollHeight;
          });
        }
      },
      (failure) => {
        if (failure.code !== "CANCELLED") error.value = failure.message;
        loading.value = false;
      },
    );
    cleanup(() => {
      subscribed = false;
      stop();
    });
  } catch (failure) {
    error.value = apiError(failure).message;
    loading.value = false;
  }
});
async function copy() {
  try {
    await copyText(log.value);
    message.success("日志已复制");
  } catch {
    message.error("无法复制日志");
  }
}
</script>

<template>
  <NModal
    v-model:show="show"
    preset="card"
    :title="name + ' · 服务日志'"
    style="width: 900px; max-width: calc(100vw - 32px)"
  >
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <NAlert v-else-if="liveDisconnected && !paused" type="warning">
      正在重新连接
    </NAlert>
    <NSpin v-if="!error || log" :show="loading && !liveDisconnected">
      <pre v-if="log" ref="output" class="service-log">{{ log }}</pre>
      <NEmpty v-else :description="loading ? '正在读取日志' : '暂无日志'" />
    </NSpin>
    <template #footer>
      <div class="button-row">
        <NButton @click="paused = !paused">
          {{ paused ? "继续更新" : "暂停更新" }}
        </NButton>
        <NButton :disabled="!log" @click="copy">
          复制日志
        </NButton>
      </div>
    </template>
  </NModal>
</template>

<style scoped>
.service-log {
  max-height: 60vh;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  margin: 0;
}
</style>
