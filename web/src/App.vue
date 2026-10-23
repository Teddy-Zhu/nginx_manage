<script setup lang="ts">
import {
  NConfigProvider,
  NMessageProvider,
  NDialogProvider,
  zhCN,
  dateZhCN,
} from "naive-ui";
import { useRoute } from "vue-router";
import ShellLayout from "./components/ShellLayout.vue";
import SoftwareGate from "./components/SoftwareGate.vue";
import FrontendVersionNotice from "./components/FrontendVersionNotice.vue";
import { useNodes } from "./stores/node";

const route = useRoute();
const nodes = useNodes();
const themeOverrides = {
  common: {
    primaryColor: "#087f68",
    primaryColorHover: "#0c987d",
    primaryColorPressed: "#066751",
    borderRadius: "8px",
    fontFamily: 'Inter, "Noto Sans SC", system-ui, sans-serif',
  },
};
</script>

<template>
  <n-config-provider
    :locale="zhCN"
    :date-locale="dateZhCN"
    :theme-overrides="themeOverrides"
  >
    <n-dialog-provider>
      <n-message-provider>
        <FrontendVersionNotice />
        <router-view v-if="route.meta.public" />
        <shell-layout v-else>
          <SoftwareGate v-if="!nodes.switching" :key="`${nodes.generation}:${route.fullPath}`" :software="route.meta.software">
            <router-view />
          </SoftwareGate>
          <p v-else class="muted">正在连接服务器…</p>
        </shell-layout>
      </n-message-provider>
    </n-dialog-provider>
  </n-config-provider>
</template>
