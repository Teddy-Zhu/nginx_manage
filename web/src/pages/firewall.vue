<route lang="json">
{
  "meta": {
    "title": "防火墙状态",
    "subtitle": "查看规则状态与连接保护",
    "nav": false,
    "parent": "/firewall-rules"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton, NTag } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type FirewallObservation,
  type FirewallRuntime,
} from "../api/client";
import { useLiveRefresh } from "../composables/live";
const api = useNodeAPI(),
  controller = new AbortController();
const observation = ref<FirewallObservation | null>(null),
  runtime = ref<FirewallRuntime | null>(null),
  busy = ref(false),
  error = ref("");
const changed = computed(
  () =>
    runtime.value?.operation &&
    ["waiting_confirmation", "running"].includes(runtime.value.operation.state),
);
const applied = computed(() => runtime.value?.confirmed_action === "apply");
const systemStatus = computed(() =>
  observation.value?.manager === "conflict"
    ? "需要检查规则冲突"
    : ["firewalld", "ufw"].includes(observation.value?.manager ?? "")
      ? "已有其他防火墙规则"
      : "未发现其他防火墙管理服务",
);
async function load() {
  if (busy.value || controller.signal.aborted) return;
  busy.value = true;
  try {
    const [view, state] = await Promise.all([
      api.firewall(controller.signal),
      api.firewallRuntime(controller.signal),
    ]);
    if (!controller.signal.aborted) {
      observation.value = view;
      runtime.value = state;
      error.value = "";
    }
  } catch (failure) {
    if (!controller.signal.aborted) error.value = apiError(failure).message;
  } finally {
    if (!controller.signal.aborted) busy.value = false;
  }
}
onMounted(load);
onUnmounted(() => controller.abort());
useLiveRefresh(api, ["tasks", "firewall", "listener"], load, () => busy.value);
</script>
<template>
  <div class="page-stack">
    <div class="section-heading">
      <h2>防火墙状态</h2>
      <NButton :loading="busy" @click="load">
        刷新状态
      </NButton>
    </div>
    <NAlert v-if="error" type="error">
      暂时无法读取防火墙状态，请稍后重试。
    </NAlert>
    <section class="panel page-stack">
      <div class="section-heading">
        <h3>本工具的规则</h3>
        <NTag :type="applied ? 'success' : 'default'">
          {{
            !runtime
              ? "正在读取"
              : changed
                ? "变更待确认"
                : applied
                  ? "已应用"
                  : "未应用"
          }}
        </NTag>
      </div>
      <p class="muted">
        管理端口放通、端口屏蔽以及 IP 和国家黑白名单。
      </p>
      <div class="button-row">
        <RouterLink to="/firewall-rules">
          <NButton type="primary">
            管理规则
          </NButton>
        </RouterLink><RouterLink to="/firewall-apply">
          <NButton>应用与确认变更</NButton>
        </RouterLink>
      </div>
    </section>
    <section v-if="observation" class="panel page-stack">
      <h3>已有防火墙</h3>
      <p>{{ systemStatus }}</p>
      <NAlert type="info">
        系统已有规则会继续生效。存在规则冲突时，修改前会要求确认。
      </NAlert>
      <p v-if="observation.at" class="muted">
        更新于 {{ new Date(observation.at * 1000).toLocaleString() }}
      </p>
    </section>
    <section class="panel page-stack">
      <h3>操作记录</h3>
      <div class="button-row">
        <RouterLink to="/tasks">
          查看防火墙操作
        </RouterLink><RouterLink to="/logs">
          查看服务日志
        </RouterLink>
      </div>
    </section>
  </div>
</template>
