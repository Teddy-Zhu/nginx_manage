<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NButton, NSpin } from "naive-ui";
import { apiError, useNodeAPI } from "../api/client";
import SoftwareRequired from "./SoftwareRequired.vue";
import {
  nginxState,
  fail2banState,
  type SoftwareState,
} from "../utils/software";
import { useSession } from "../stores/session";

const props = defineProps<{ software?: "nginx" | "fail2ban" }>();
const api = useNodeAPI();
const session = useSession();
// The software inventory requires a separate scope. Read-only website users
// retain the feature's existing access checks without requiring that scope.
const canInspect = computed(
  () =>
    props.software !== "nginx" ||
    session.me?.scopes.includes("components.manage"),
);
const loading = ref(!!props.software),
  state = ref<SoftwareState>("unavailable"),
  error = ref("");
async function load() {
  if (!props.software || !canInspect.value) return;
  loading.value = true;
  error.value = "";
  try {
    if (props.software === "nginx") {
      const status = await api.components();
      state.value = nginxState(status);
      if (state.value === "unavailable")
        throw new Error(status.reason || "服务器管理服务不可用。");
    } else {
      const status = await api.fail2ban();
      state.value = fail2banState(status);
      if (state.value === "unavailable")
        throw new Error(
          status.reason ||
            status.binding.reason ||
            status.managed.reason ||
            "服务器管理服务不可用。",
        );
    }
  } catch (cause) {
    error.value = apiError(cause).message;
  } finally {
    loading.value = false;
  }
}
watch([() => props.software, canInspect], load, { immediate: true });
</script>

<template>
  <slot v-if="!software || !canInspect" />
  <section v-else-if="loading" class="surface software-required">
    <NSpin size="small" />
    <p class="muted">正在读取软件状态…</p>
  </section>
  <section v-else-if="error" class="surface">
    <NAlert type="error" title="暂时无法读取软件状态"
      >请稍后重试，或检查服务器上的面板服务是否正常运行。</NAlert
    >
    <NButton style="margin-top: 16px" @click="load">重新读取</NButton>
  </section>
  <SoftwareRequired
    v-else-if="
      state === 'missing' || state === 'unbound' || state === 'recovery'
    "
    :software="software"
    :state="state"
  />
  <slot v-else />
</template>
