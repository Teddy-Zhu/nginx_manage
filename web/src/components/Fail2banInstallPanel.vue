<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton, NCheckbox, NFormItem, NInput, NTag } from "naive-ui";
import {
  type Fail2banContainerStatus,
  type Fail2banContainerRequest,
} from "../api/client";
import { useSoftwareOperations } from "../composables/software";
import { useLiveRefresh } from "../composables/live";
import TaskLogButton from "./TaskLogButton.vue";
import {
  fail2banRuntime,
  standardServiceActions,
  softwareStatus,
  softwareConfirmation,
  type SoftwareOperation,
} from "../utils/software";
import SoftwareControls from "./SoftwareControls.vue";
defineProps<{ embedded?: boolean }>();
const emit = defineEmits<{ changed: []; busy: [value: boolean] }>();
const reading = ref(false),
  readError = ref("");
const status = ref<Fail2banContainerStatus | null>(null),
  image = ref("crazymax/fail2ban:debian"),
  autoStart = ref(true);
const { api, run, busy, permitted, active, last, submit } =
  useSoftwareOperations(load);
const processing = computed(() => busy.value || active.value);
const displayStatus = computed(() =>
  softwareStatus(
    status.value ? status.value.installed : null,
    fail2banRuntime(status.value),
    last.value,
  ),
);
watch(processing, (value) => emit("busy", value));
async function load() {
  if (reading.value) return;
  reading.value = true;
  try {
    const next = await api.fail2banContainer();
    if (!status.value || image.value === status.value.config.image)
      image.value = next.config.image;
    if (!status.value || autoStart.value === status.value.config.auto_start)
      autoStart.value = next.config.auto_start;
    status.value = next;
    emit("changed");
    readError.value = "";
  } catch (error) {
    readError.value =
      error instanceof Error ? error.message : "无法读取防护状态";
  } finally {
    reading.value = false;
  }
}
async function operate(action: Fail2banContainerRequest["action"]) {
  const confirmation =
    action === "stop"
      ? "停止登录防护？已封禁的地址将解除限制。"
      : action === "configure"
        ? ""
        : softwareConfirmation(action as SoftwareOperation, "Fail2ban");
  if (confirmation && !window.confirm(confirmation)) return;
  if (action === "install") {
    const ready = await run(async () => {
      const modules = await api.modules();
      if (!modules.some((m) => m.id === "fail2ban" && m.enabled))
        await api.setModule("fail2ban", true);
      return true;
    });
    if (!ready) return;
  }
  const config = status.value?.config;
  if ((action === "install" || action === "configure") && !config) return;
  await submit(
    {
      action: "fail2ban",
      fail2ban: {
        action,
        ...(action === "install" || action === "configure"
          ? {
              config: {
                ...config!,
                image: image.value.trim(),
                auto_start: autoStart.value,
              },
            }
          : {}),
      },
    },
    action === "install" ? "Fail2ban 安装日志" : "登录防护操作日志",
  );
}
useLiveRefresh(api, ["fail2ban"], load, () => reading.value);
onMounted(load);
</script>
<template>
  <section class="page-stack" :class="{ panel: !embedded }">
    <div v-if="!embedded" class="section-heading">
      <div>
        <h3>{{ status?.installed ? "登录防护软件" : "安装 Fail2ban" }}</h3>
        <p class="muted">自动封禁反复认证失败的 IP，保护服务器、面板和网站。</p>
      </div>
      <NTag :type="displayStatus.tone">{{ displayStatus.label }}</NTag>
    </div>
    <NAlert v-if="status?.error" type="warning">{{ status.error }}</NAlert>
    <template v-if="!status?.installed">
      <NFormItem label="下载来源"
        ><NInput
          v-model:value="image"
          placeholder="crazymax/fail2ban:debian"
          :disabled="processing"
      /></NFormItem>
      <p class="muted">默认使用预置镜像，也可以填写兼容镜像的下载地址。</p>
      <NCheckbox v-model:checked="autoStart" :disabled="processing"
        >开机自动启动</NCheckbox
      >
      <div class="button-row">
        <NButton
          type="primary"
          :loading="processing"
          :disabled="!permitted || processing || !status || !image.trim()"
          @click="operate('install')"
          >{{ processing ? "正在处理" : "立即安装" }}</NButton
        >
      </div>
    </template>
    <template v-else>
      <div class="button-row">
        <RouterLink to="/fail2ban"
          ><NButton type="primary">防护规则</NButton></RouterLink
        ><NButton :disabled="processing" @click="load">刷新</NButton>
      </div>
      <SoftwareControls
        :installed="status.installed"
        :runtime="fail2banRuntime(status)"
        :permitted="permitted"
        :busy="processing"
        :actions="standardServiceActions"
        @operate="operate($event as Fail2banContainerRequest['action'])"
      />
      <div class="button-row">
        <NCheckbox
          v-model:checked="autoStart"
          :disabled="!permitted || processing"
          >开机自动启动</NCheckbox
        ><NButton
          size="small"
          :disabled="
            !permitted || processing || autoStart === status.config.auto_start
          "
          @click="operate('configure')"
          >保存</NButton
        >
      </div>
    </template>
    <NAlert v-if="readError" type="error">{{ readError }}</NAlert
    ><NAlert v-if="last?.error" type="error">{{ last.error }}</NAlert>
    <div v-if="last" class="button-row">
      <span>{{
        last.state === "succeeded"
          ? "操作已完成"
          : last.state === "failed"
            ? "操作未完成"
            : "正在处理，请稍候"
      }}</span
      ><TaskLogButton :task-id="last.id" />
    </div>
  </section>
</template>
<style scoped>
.section-heading p {
  margin: 8px 0 0;
}
</style>
