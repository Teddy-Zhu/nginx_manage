<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import { NAlert, NButton, NTag, NModal, NInput, NForm, NFormItem, NSelect, useDialog } from "naive-ui";
import { useSession } from "../stores/session";
import { api } from "../api/client";
import { useAction } from "../composables/action";
import { useNodes } from "../stores/node";
import { sourceNodeId } from "../api/context";

const route = useRoute(),
  router = useRouter(),
  session = useSession();
const { run, busy } = useAction();
const nodes = useNodes(), dialog = useDialog();
const canManageNodes = computed(() => ["read", "nodes.manage"].every((scope) => session.localMe?.scopes.includes(scope)));
const currentNode = computed(() => route.meta.localOnly || !nodes.selected ? "本机" : nodes.selected.name);
const nodeOptions = computed(() => [
  { label: "本机", value: "" },
  ...nodes.connections.filter((node) => !node.removed_at || node.id === nodes.selected?.connection).map((node) => ({ label: node.name, value: node.id, disabled: !!node.removed_at || node.state === "removing" })),
]);
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
async function loadNodes() {
  if (canManageNodes.value) await run(() => nodes.load());
}
function selectNode(id: string) {
  if (nodes.switching || busy.value || route.meta.localOnly) return;
  dialog.warning({
    title: "切换操作节点",
    content: "未保存的表单将被丢弃，当前查询和日志流将关闭。确认切换？",
    positiveText: "确认切换",
    negativeText: "取消",
    onPositiveClick: async () => {
      dialog.destroyAll();
      reauth.value = false;
      password.value = "";
      await run(() => nodes.select(id));
    },
  });
}
onMounted(() => {
  window.addEventListener("reauthentication-required", requestReauth);
  window.addEventListener("node-connections-changed", loadNodes);
  void loadNodes();
});
onUnmounted(() => {
  window.removeEventListener("reauthentication-required", requestReauth);
  window.removeEventListener("node-connections-changed", loadNodes);
});
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
        <span class="status-dot" />{{ currentNode }}<span class="local-badge">{{ route.meta.localOnly || !nodes.selected ? "LOCAL" : "REMOTE" }}</span>
      </div>
    </aside>
    <div class="main-column">
      <header class="topbar">
        <span class="breadcrumb">工作空间 <span>/</span> {{ title }}</span>
        <div class="topbar-right">
          <template v-if="canManageNodes">
            <n-select aria-label="当前操作节点" style="width: 190px" :value="route.meta.localOnly ? '' : nodes.selected?.connection ?? ''" :options="nodeOptions" :disabled="!!route.meta.localOnly || nodes.switching || busy" @update:value="selectNode" />
            <n-button text :disabled="busy || nodes.switching" @click="loadNodes">刷新节点</n-button>
          </template>
          <n-tag size="small" :bordered="false">{{ route.meta.localOnly ? "本机管理" : currentNode }}</n-tag
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
        <p class="muted">节点：{{ currentNode }} · {{ route.meta.localOnly ? sourceNodeId : nodes.selected?.nodeId ?? sourceNodeId }}</p>
        <n-alert v-if="nodes.error && !route.meta.localOnly" type="error" style="margin-bottom: 16px">
          {{ nodes.error }}
          <n-button v-if="nodes.selected" size="small" :disabled="busy || nodes.switching" @click="selectNode(nodes.selected.connection)">重新检查连接</n-button>
        </n-alert>
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
