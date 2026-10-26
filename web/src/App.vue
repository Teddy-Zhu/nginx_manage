<script setup lang="ts">
import {
  NConfigProvider,
  NMessageProvider,
  NDialogProvider,
  zhCN,
  dateZhCN,
  type GlobalThemeOverrides,
} from "naive-ui";
import { useRoute } from "vue-router";
import ShellLayout from "./components/ShellLayout.vue";
import SoftwareGate from "./components/SoftwareGate.vue";
import FrontendVersionNotice from "./components/FrontendVersionNotice.vue";
import OperationDrawer from "./components/OperationDrawer.vue";
import { useNodes } from "./stores/node";

const route = useRoute();
const nodes = useNodes();
const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: "#087f68",
    primaryColorHover: "#0c987d",
    primaryColorPressed: "#066751",
    borderRadius: "8px",
    fontFamily: 'Inter, "Noto Sans SC", system-ui, sans-serif',
    fontSize: "14px",
    lineHeight: "1.6",
    heightMedium: "36px",
    borderColor: "#e2e9e5",
  },
  DataTable: {
    thColor: "#f7faf8",
    thTextColor: "#58695f",
    thFontWeight: "600",
    thPaddingMedium: "12px 16px",
    tdPaddingMedium: "14px 16px",
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
        <OperationDrawer v-if="!route.meta.public" />
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
