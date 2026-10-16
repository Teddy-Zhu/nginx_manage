<route lang="json">
{
  "meta": {
    "title": "功能模块",
    "subtitle": "当前节点的面板管理能力",
    "nav": true,
    "order": 6.1,
    "symbol": "◈"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { NButton, NSwitch } from "naive-ui";
import { useNodeAPI, type Module } from "../api/client";
import { useSession } from "../stores/session";
import { useAction } from "../composables/action";

const api = useNodeAPI(), session = useSession(), { run, busy } = useAction();
const modules = ref<Module[]>([]);
const canManage = computed(() => !!session.me?.scopes.includes("system.write"));
async function load() {
  await run(async () => { modules.value = await api.modules(); });
}
async function toggle(module: Module, enabled: boolean) {
  if (!window.confirm(`${enabled ? "启用" : "停用"}${module.name}的面板管理？`)) return;
  await run(async () => {
    await api.setModule(module.id, enabled);
    modules.value = await api.modules();
  }, "模块设置已更新");
}
onMounted(load);
</script>
<template>
  <section class="surface">
    <div class="section-heading"><h2>功能模块</h2><NButton text :loading="busy" @click="load">刷新</NButton></div>
    <div v-for="module in modules" :key="module.id" class="module-row">
      <div><strong>{{ module.name }}</strong><p v-if="module.reason" class="muted">{{ module.reason }}</p></div>
      <NSwitch :value="module.enabled" :disabled="!canManage || !module.available || busy" :on-update:value="(value: boolean) => toggle(module, value)" />
    </div>
  </section>
</template>
