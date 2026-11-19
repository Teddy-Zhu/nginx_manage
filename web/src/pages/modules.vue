<route lang="json">
{
  "meta": {
    "title": "功能开关",
    "nav": false,
    "order": 6.1,
    "symbol": "◈",
    "parent": "/settings"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { NButton, NSwitch, useDialog } from "naive-ui";
import { useNodeAPI, type Module } from "../api/client";
import { useRouter } from "vue-router";
import { selectedTarget } from "../api/context";
import { useSession } from "../stores/session";
import { useAction } from "../composables/action";

const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction();
const dialog = useDialog(),
  router = useRouter();
const modules = ref<Module[]>([]);
const canManage = computed(() => !!session.me?.scopes.includes("system.write"));
async function load() {
  await run(async () => {
    modules.value = await api.modules();
  });
}
async function setModule(module: Module, enabled: boolean) {
  await run(async () => {
    await api.setModule(
      module.id,
      enabled,
      module.id === "firewall" && !enabled ? { firewall_rules: "keep" } : {},
    );
    modules.value = await api.modules();
  }, "模块设置已更新");
}
async function toggle(module: Module, enabled: boolean) {
  if (module.id === "firewall" && !enabled) {
    const canRemove =
      !selectedTarget.value &&
      ["read", "security.write"].every((scope) =>
        session.me?.scopes.includes(scope),
      );
    dialog.warning({
      title: "停用防火墙管理",
      content: canRemove
        ? "可保留已确认规则并停用，或先移除本应用规则。移除需在目标管理连接上独立确认，完成后再停用；其余系统策略保持生效。"
        : "停用将保留已确认规则，既有确认与恢复继续可用。移除规则需要读取和安全写入权限，并直接访问目标节点的防火墙应用页。",
      positiveText: "保留规则并停用",
      negativeText: canRemove ? "先移除规则" : "取消",
      onPositiveClick: () => setModule(module, false),
      onNegativeClick: () => {
        if (canRemove)
          void router.push({
            path: "/firewall-apply",
            query: { action: "remove" },
          });
      },
    });
    return;
  }
  if (!window.confirm(`${enabled ? "启用" : "停用"}${module.name}的面板管理？`))
    return;
  await setModule(module, enabled);
}
onMounted(load);
</script>
<template>
  <section class="surface">
    <div class="section-heading">
      <h2>功能模块</h2>
      <NButton text :loading="busy" @click="load">
        刷新
      </NButton>
    </div>
    <div v-for="module in modules" :key="module.id" class="module-row">
      <div>
        <strong>{{ module.name }}</strong>
        <p v-if="module.reason" class="muted">
          {{ module.reason }}
        </p>
      </div>
      <NSwitch
        :value="module.enabled"
        :disabled="!canManage || !module.available || busy"
        :on-update:value="(value: boolean) => toggle(module, value)"
      />
    </div>
  </section>
</template>
