<script setup lang="ts">
import { computed } from "vue";
import { useSession } from "../stores/session";
import { NButton } from "naive-ui";
import { RouterLink } from "vue-router";

withDefaults(defineProps<{ software: "nginx" | "fail2ban"; state?: "missing" | "unbound" | "recovery" }>(), { state: "missing" });
const session = useSession();
const canInstall = computed(() => session.me?.scopes.includes("components.manage"));
const names = { nginx: "Nginx", fail2ban: "Fail2ban" };
const descriptions = {
  nginx: "安装后即可创建网站、配置反向代理和管理站点防护。",
  fail2ban: "安装后即可设置登录保护，自动封禁多次认证失败的 IP。",
};
</script>

<template>
  <section class="surface software-required">
    <span class="software-icon">{{ software === "nginx" ? "N" : "F" }}</span>
    <h2>{{ state === "unbound" ? "连接已有软件" : state === "recovery" ? "安装尚未完成" : `尚未安装 ${names[software]}` }}</h2>
    <p class="muted">
      {{ state === "unbound" ? `服务器上已有 ${names[software]}，连接后即可管理。` : state === "recovery" ? "请继续完成安装，或恢复上一次安装操作。" : descriptions[software] }}
    </p>
    <RouterLink v-if="canInstall" :to="{ path: '/components', query: { software, ...(state === 'unbound' ? { existing: '1' } : {}) } }">
      <NButton type="primary">
        {{ state === "unbound" ? "连接" : state === "recovery" ? "继续安装" : "安装" }} {{ names[software] }}
      </NButton>
    </RouterLink>
    <p v-else class="muted">
      请联系管理员安装或连接此软件。
    </p>
  </section>
</template>
