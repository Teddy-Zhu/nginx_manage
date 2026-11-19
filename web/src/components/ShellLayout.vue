<script setup lang="ts">
import { computed, onMounted, onUnmounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import { NAlert, NButton, NTag, NSelect, useDialog } from "naive-ui";
import { useSession } from "../stores/session";
import { useAction } from "../composables/action";
import { useNodes } from "../stores/node";
import { liveDisconnected } from "../api/live";
import { currentOperation, operationVisible } from "../stores/operation";

const route = useRoute(),
  router = useRouter(),
  session = useSession();
const { run, busy } = useAction();
const nodes = useNodes(),
  dialog = useDialog();
const canManageNodes = computed(() =>
  ["read", "nodes.manage"].every((scope) =>
    session.localMe?.scopes.includes(scope),
  ),
);
const currentNode = computed(() =>
  route.meta.localOnly || !nodes.selected ? "本机" : nodes.selected.name,
);
const nodeOptions = computed(() => [
  { label: "本机", value: "" },
  ...nodes.connections
    .filter(
      (node) => !node.removed_at || node.id === nodes.selected?.connection,
    )
    .map((node) => ({
      label: node.name,
      value: node.id,
      disabled: !!node.removed_at || node.state === "removing",
    })),
]);
const title = computed(() => route.meta.title ?? "NginxPanel");
const links = computed(() =>
  router
    .getRoutes()
    .filter((item) => item.meta.nav)
    .sort((a, b) => (a.meta.order ?? 0) - (b.meta.order ?? 0))
    .map(({ path, meta }) => ({
      path,
      meta,
      active: route.path === path || route.meta.parent === path,
    })),
);
const groups = computed(() => {
  const result = new Map<string, typeof links.value>();
  for (const link of links.value) {
    const group = link.meta.group ?? "常用功能";
    if (!result.has(group)) result.set(group, []);
    result.get(group)!.push(link);
  }
  return [...result].map(([name, items]) => ({ name, items }));
});
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
    title: "切换服务器",
    content: "未保存的表单将被丢弃，当前查询和日志流将关闭。确认切换？",
    positiveText: "确认切换",
    negativeText: "取消",
    onPositiveClick: async () => {
      dialog.destroyAll();
      await run(() => nodes.select(id));
    },
  });
}
onMounted(() => {
  window.addEventListener("node-connections-changed", loadNodes);
  void loadNodes();
});
onUnmounted(() => {
  window.removeEventListener("node-connections-changed", loadNodes);
});
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <router-link class="brand" to="/">
        <span class="brand-mark">N</span><span>Nginx<span class="brand-light">Panel</span></span>
      </router-link>
      <nav class="nav-list" aria-label="主导航">
        <div v-for="group in groups" :key="group.name" class="nav-group">
          <div class="sidebar-label">
            {{ group.name }}
          </div>
          <router-link
            v-for="link in group.items"
            :key="link.path"
            :to="link.path"
            class="nav-link"
            :class="{ active: link.active }"
          >
            <span class="nav-symbol">{{ link.meta.symbol }}</span>{{ link.meta.title }}
          </router-link>
        </div>
      </nav>
      <div class="sidebar-bottom">
        {{ currentNode }}
      </div>
    </aside>
    <div class="main-column">
      <header class="topbar">
        <span class="breadcrumb">控制台 <span>/</span> {{ title }}</span>
        <div class="topbar-right">
          <NButton
            v-if="currentOperation"
            size="small"
            @click="operationVisible = true"
          >
            操作进度
          </NButton>
          <template
            v-if="
              canManageNodes && (nodes.connections.length || nodes.selected)
            "
          >
            <n-select
              aria-label="当前服务器"
              class="node-select"
              :value="
                route.meta.localOnly ? '' : (nodes.selected?.connection ?? '')
              "
              :options="nodeOptions"
              :disabled="!!route.meta.localOnly || nodes.switching || busy"
              @update:value="selectNode"
            />
          </template>
          <n-tag size="small" :bordered="false">
            {{
              route.meta.localOnly ? "本机" : currentNode
            }}
          </n-tag><span class="username">{{ session.me?.username }}</span><n-button text @click="logout">
            退出
          </n-button>
        </div>
      </header>
      <main class="content">
        <div class="page-heading">
          <div>
            <h1>{{ title }}</h1>
            <p v-if="route.meta.subtitle">
              {{ route.meta.subtitle }}
            </p>
          </div>
          <div id="page-heading-actions" />
        </div>
        <n-alert
          v-if="nodes.error && !route.meta.localOnly"
          type="error"
          style="margin-bottom: 16px"
        >
          {{ nodes.error }}
          <n-button
            v-if="nodes.selected"
            size="small"
            :disabled="busy || nodes.switching"
            @click="selectNode(nodes.selected.connection)"
          >
            重新检查连接
          </n-button>
        </n-alert>
        <NAlert v-if="liveDisconnected" type="warning" class="live-warning">
          实时状态更新暂时中断，正在重新连接。您可以手动刷新查看最新状态。
        </NAlert>
        <slot />
      </main>
      <footer class="footer">
        NginxPanel
      </footer>
    </div>
  </div>
</template>

<style scoped>
.live-warning {
  margin-bottom: 20px;
}
</style>
