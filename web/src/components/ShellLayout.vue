<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import { NButton, NTag, NModal, NInput, NForm, NFormItem } from "naive-ui";
import { useSession } from "../stores/session";
import { api } from "../api/client";
import { useAction } from "../composables/action";

const route = useRoute(),
  router = useRouter(),
  session = useSession();
const { run, busy } = useAction();
const reauth = ref(false),
  password = ref("");
const title = computed(() => route.meta.title ?? "NginxPanel");
const links = computed(() =>
  router
    .getRoutes()
    .filter((item) => item.meta.nav)
    .sort((a, b) => (a.meta.order ?? 0) - (b.meta.order ?? 0))
    .map(({ path, meta }) => ({ path, meta, active: route.path === path })),
);
function requestReauth() {
  reauth.value = true;
}
async function verify() {
  await run(async () => {
    await api.reauthenticate(password.value);
    password.value = "";
    reauth.value = false;
  }, "身份已确认，请重试刚才的操作");
}
async function logout() {
  await run(async () => {
    await session.logout();
    await router.push("/login");
  });
}
onMounted(() =>
  window.addEventListener("reauthentication-required", requestReauth),
);
onUnmounted(() =>
  window.removeEventListener("reauthentication-required", requestReauth),
);
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <router-link class="brand" to="/"
        ><span class="brand-mark">N</span
        ><span>Nginx<span class="brand-light">Panel</span></span></router-link
      >
      <div class="sidebar-label">工作空间</div>
      <nav class="nav-list" aria-label="主导航">
        <router-link
          v-for="link in links"
          :key="link.path"
          :to="link.path"
          class="nav-link"
          :class="{ active: link.active }"
          ><span class="nav-symbol">{{ link.meta.symbol }}</span
          >{{ link.meta.title }}</router-link
        >
      </nav>
      <div class="sidebar-bottom">
        <span class="status-dot" />本机节点<span class="local-badge"
          >LOCAL</span
        >
      </div>
    </aside>
    <div class="main-column">
      <header class="topbar">
        <span class="breadcrumb">工作空间 <span>/</span> {{ title }}</span>
        <div class="topbar-right">
          <n-tag size="small" :bordered="false">本机</n-tag
          ><span class="username">{{ session.me?.username }}</span
          ><n-button text @click="logout">退出</n-button>
        </div>
      </header>
      <main class="content">
        <div class="page-heading">
          <div>
            <h1>{{ title }}</h1>
            <p>{{ route.meta.subtitle }}</p>
          </div>
        </div>
        <slot />
      </main>
      <footer class="footer">
        NginxPanel <span>节点自治 · 配置可追溯</span>
      </footer>
    </div>
    <n-modal
      v-model:show="reauth"
      preset="card"
      title="验证身份"
      style="width: 400px; max-width: 92vw"
      @after-leave="password = ''"
    >
      <p class="muted">此操作涉及敏感配置，请确认当前管理员密码。</p>
      <n-form @submit.prevent="verify"
        ><n-form-item label="密码"
          ><n-input
            v-model:value="password"
            type="password"
            autofocus
            show-password-on="click"
            autocomplete="current-password" /></n-form-item
        ><n-button type="primary" attr-type="submit" block :loading="busy"
          >确认身份</n-button
        ></n-form
      >
    </n-modal>
  </div>
</template>
