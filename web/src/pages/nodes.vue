<route lang="json">
{
  "meta": {
    "title": "服务器连接",
    "subtitle": "连接和管理其他服务器",
    "nav": true,
    "localOnly": true,
    "order": 24,
    "symbol": "◎",
    "group": "数据与设置"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { NAlert, NButton, NCheckbox, NFormItem, NInput, NPopconfirm, NTag } from "naive-ui";
import { useNodeAPI, apiError, type NodeConnection } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import NodePairing from "../components/NodePairing.vue";
const api = useNodeAPI();

const session = useSession(), { run, busy, message } = useAction();
const nodes = ref<NodeConnection[]>([]), error = ref(""), selected = ref<string[]>([]), checking = ref<string[]>([]);
const form = reactive({ name: "", url: "", api_key: "", fingerprint: "" });
const canManage = computed(() => !!session.localMe?.scopes.includes("nodes.manage") && !!session.localMe?.scopes.includes("read"));
const active = computed(() => nodes.value.filter((n) => !n.removed_at));
const removed = computed(() => nodes.value.filter((n) => n.removed_at));
const states: Record<string, string> = { connected: "连接正常", stale: "需要重新检查", unreachable: "无法连接", identity_changed: "身份已变化", authorization_failed: "授权不可用", incompatible: "版本不兼容", removing: "删除待完成", removed: "连接已删除" };
let keyFor = useIdempotency(), closed = false;
const controller = new AbortController();
function date(value: number) { return value ? new Date(value * 1000).toLocaleString() : "—"; }
function replace(value: NodeConnection) {
  nodes.value = [value, ...nodes.value.filter((n) => n.id !== value.id)];
  window.dispatchEvent(new Event("node-connections-changed"));
}
async function load() {
  if (!canManage.value) return;
  try { const result = await api.nodes(controller.signal); if (!closed) { nodes.value = result; selected.value = selected.value.filter((id) => result.some((n) => n.id === id && !n.removed_at)); error.value = ""; } }
  catch (cause) { if (!closed) error.value = apiError(cause).message; }
}
async function create() {
  const input = { ...form };
  await run(async () => {
    const value = await api.createNode(input, keyFor(input));
    if (closed) return;
    replace(value); form.name = form.url = form.api_key = form.fingerprint = ""; keyFor = useIdempotency();
  }, "节点连接已登记");
}
function select(id: string, value: boolean) {
  if (value && selected.value.length < 8) selected.value = [...selected.value, id];
  if (!value) selected.value = selected.value.filter((v) => v !== id);
}
async function check(ids: string[]) {
  if (!canManage.value || checking.value.length || !ids.length) return;
  checking.value = [...ids];
  const queue = [...ids], failures: string[] = [];
  async function worker() {
    while (queue.length && !closed) {
      const id = queue.shift()!;
      try { const value = await api.refreshNode(id, crypto.randomUUID()); if (!closed) replace(value); }
      catch (cause) { failures.push(`${nodes.value.find((n) => n.id === id)?.name ?? id}：${apiError(cause).message}`); }
    }
  }
  await Promise.all([worker(), worker()]);
  if (!closed) { checking.value = []; if (failures.length) message.error(failures.join("；")); }
}
async function remove(node: NodeConnection) {
  await run(async () => {
    const value = await api.deleteNode(node.id, keyFor({ action: "delete", id: node.id }));
    if (closed) return;
    replace(value); selected.value = selected.value.filter((id) => id !== node.id); keyFor = useIdempotency();
  });
}
onMounted(load);
onUnmounted(() => { closed = true; controller.abort(); form.api_key = ""; });
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="!canManage" type="warning">需要节点管理与读取权限。</NAlert>
    <template v-else>
      <NodePairing @connected="load" />
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <section class="panel page-stack">
        <div class="toolbar"><h2>添加节点连接</h2><NButton @click="load">刷新列表</NButton></div>
        <p>填写目标节点的 HTTPS API 地址和专用 Token，并通过独立渠道核对目标证书的 SHA-256 指纹。</p>
        <NFormItem label="连接名称"><NInput v-model:value="form.name" :disabled="busy" :maxlength="100" /></NFormItem>
        <NFormItem label="目标 API"><NInput v-model:value="form.url" :disabled="busy" placeholder="https://node.example.com/api/v1" :maxlength="2048" /></NFormItem>
        <NFormItem label="目标 Token"><NInput v-model:value="form.api_key" :disabled="busy" type="password" show-password-on="click" autocomplete="off" :maxlength="193" /></NFormItem>
        <NFormItem label="证书 SHA-256 指纹"><NInput v-model:value="form.fingerprint" :disabled="busy" placeholder="64 位十六进制 SHA-256" :maxlength="64" /></NFormItem>
        <p class="muted">Token 至少需要 read 权限。每个控制节点使用独立 Token，并在目标节点限制允许来源。</p>
        <div><NButton type="primary" :loading="busy" :disabled="!form.name || !form.url || !form.api_key || form.fingerprint.length !== 64 || !!checking.length" @click="create">核对并添加</NButton></div>
      </section>
      <section class="panel page-stack">
        <div class="toolbar"><h2>已登记节点</h2><NButton :loading="!!checking.length" :disabled="!selected.length || busy" @click="check(selected)">检查所选 {{ selected.length }} 个节点</NButton></div>
        <p class="muted">最多选择 8 个节点；每个节点分别显示检查结果。</p>
        <p v-if="!active.length" class="muted">暂无节点连接</p>
        <article v-for="node in active" :key="node.id" class="panel page-stack">
          <div class="toolbar">
            <NCheckbox :checked="selected.includes(node.id)" :disabled="busy || !!checking.length || node.state === 'removing' || (!selected.includes(node.id) && selected.length >= 8)" @update:checked="(value: boolean) => select(node.id, value)">{{ node.name }}</NCheckbox>
            <NTag :type="node.state === 'connected' ? 'success' : 'warning'">{{ states[node.state] ?? node.state }}</NTag>
          </div>
          <p>{{ node.url }}</p>
          <p class="muted">永久节点编号 {{ node.node_id }} · API v{{ node.api_version }}</p>
          <p class="muted">最近检查 {{ date(node.checked_at) }} · 授权到期 {{ date(node.expires_at) }}</p>
          <p v-if="node.capabilities && node.state === 'connected'">目标执行器：{{ node.capabilities.mode === "connected" ? "已连接" : "预览模式" }}</p>
          <details><summary>连接与授权详情</summary><p>凭据编号 {{ node.credential_id }}</p><p>指纹 {{ node.fingerprint }}</p><p>权限 {{ node.scopes.join("、") }}</p></details>
          <NAlert v-if="node.error" type="warning">{{ node.error }}</NAlert>
          <div class="toolbar">
            <NButton :disabled="busy || !!checking.length || node.state === 'removing'" @click="check([node.id])">检查连接</NButton>
            <NPopconfirm :disabled="busy || !!checking.length" positive-text="删除连接" @positive-click="remove(node)"><template #trigger><NButton type="error" :disabled="busy || !!checking.length">{{ node.state === "removing" ? "继续删除" : "删除连接" }}</NButton></template>删除 {{ node.name }} 并尝试撤销目标 Token。若无法确认撤销，需要在目标节点补做撤销。</NPopconfirm>
          </div>
        </article>
      </section>
      <section v-if="removed.length" class="panel page-stack">
        <h2>已删除连接</h2>
        <article v-for="node in removed" :key="node.id" class="panel page-stack">
          <div class="toolbar"><strong>{{ node.name }}</strong><NTag :type="node.revocation === 'revoked' ? 'success' : 'warning'">{{ node.revocation === "revoked" ? "目标授权已撤销" : "目标授权待核对" }}</NTag></div>
          <p class="muted">{{ node.url }} · {{ date(node.removed_at) }}</p>
          <p>永久节点编号 {{ node.node_id }} · 目标凭据编号 {{ node.credential_id }}</p>
          <NAlert v-if="node.revocation === 'pending'" type="warning">未确认目标授权撤销，请在目标节点的机器凭据中撤销此凭据。</NAlert>
        </article>
      </section>
    </template>
  </div>
</template>
