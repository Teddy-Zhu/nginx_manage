<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NButton, NSpin } from "naive-ui";
import { apiError, useNodeAPI } from "../api/client";
import SoftwareRequired from "./SoftwareRequired.vue";
import {
  fail2banState,
  type SoftwareState,
} from "../utils/software";
import { useSession } from "../stores/session";
import { useLiveRefresh } from "../composables/live";

const props = defineProps<{ software?: "nginx" | "fail2ban" }>();
const api = useNodeAPI();
const session = useSession();
// Only users who can open the software store see the Nginx installation prompt.
const canInspect = computed(
  () =>
    props.software !== "nginx" ||
    session.me?.scopes.includes("components.manage"),
);
const loading = ref(!!props.software),
  reading = ref(false),
  state = ref<SoftwareState>("unavailable"),
  error = ref("");
async function load() {
  if (!props.software || !canInspect.value || reading.value) return;
  reading.value = true;
  error.value = "";
  try {
    if (props.software === "nginx") {
      const status = await api.nginxRuntime();
      state.value = status.installed ? "installed" : "missing";
    } else {
      const status = await api.fail2banContainer();
      state.value = fail2banState(status);
    }
  } catch (cause) {
    error.value = apiError(cause).message;
  } finally {
    reading.value = false;
    loading.value = false;
  }
}
watch([() => props.software, canInspect], load, { immediate: true });
function reload() {
  if (props.software === "nginx") api.reloadLive();
  return load();
}
useLiveRefresh(
  api,
  props.software === "nginx" ? ["nginx"] : [],
  load,
  () => reading.value,
);
</script>

<template>
  <slot v-if="!software || !canInspect" />
  <section v-else-if="loading" class="surface software-required">
    <NSpin size="small" />
    <p class="muted">
      正在读取软件状态…
    </p>
  </section>
  <section v-else-if="error" class="surface">
    <NAlert type="error" title="暂时无法读取软件状态">
      请稍后重试，或检查服务器上的面板服务是否正常运行。
    </NAlert>
    <NButton style="margin-top: 16px" @click="reload">
      重新读取
    </NButton>
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
