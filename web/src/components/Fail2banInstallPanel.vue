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
  if (
    action === "uninstall" &&
    !window.confirm("卸载登录防护？防护会停止，配置和数据保留。")
  )
    return;
  if (
    action === "stop" &&
    !window.confirm("停止登录防护？已封禁的地址将解除限制。")
  )
    return;
  if (
    action === "update" &&
    !window.confirm("更新登录防护？防护将短暂重启，规则和数据保留。")
  )
    return;
  if (action === "install") {
    if (
      status.value?.installed &&
      !window.confirm("重新安装登录防护？规则和数据会保留。")
    )
      return;
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
      <NTag
        :type="
          status?.ready ? 'success' : status?.installed ? 'warning' : 'default'
        "
        >{{
          status?.ready
            ? "运行中"
            : status?.running
              ? "正在启动"
              : status?.installed
                ? "已停止"
                : "未安装"
        }}</NTag
      >
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
        ><NButton
          :disabled="!permitted || processing"
          :loading="busy"
          @click="operate(status.running ? 'stop' : 'start')"
          >{{ status.running ? "停止" : "启动" }}</NButton
        ><NButton
          :disabled="!permitted || processing || !status.running"
          @click="operate('restart')"
          >重启</NButton
        ><NButton
          :disabled="!permitted || processing"
          @click="operate('update')"
          >更新</NButton
        ><NButton
          :disabled="!permitted || processing"
          @click="operate('install')"
          >重新安装</NButton
        ><NButton
          :disabled="!permitted || processing"
          @click="operate('uninstall')"
          >卸载</NButton
        ><NButton :disabled="processing" @click="load">刷新</NButton>
      </div>
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
    <details v-if="status?.logs">
      <summary>服务日志</summary>
      <pre class="service-log">{{ status.logs }}</pre>
    </details>
  </section>
</template>
<style scoped>
.service-log {
  max-height: 320px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: var(--surface-soft);
  padding: 16px;
  border-radius: 10px;
}
.section-heading p {
  margin: 8px 0 0;
}
</style>
