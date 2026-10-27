<route lang="json">
{
  "meta": {
    "title": "服务器连接",
    "subtitle": "连接和管理其他服务器",
    "nav": true,
    "localOnly": true,
    "order": 43,
    "symbol": "◎",
    "group": "系统管理"
  }
}
</route>
<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import FormDialog from "../components/FormDialog.vue";
import { randomUUID } from "../utils/crypto";

import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NInput,
  NPopconfirm,
  NTag,
} from "naive-ui";
import { useNodeAPI, apiError, type NodeConnection } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import NodePairing from "../components/NodePairing.vue";
const api = useNodeAPI();

const session = useSession(),
  { run, busy, message } = useAction();
const nodes = ref<NodeConnection[]>([]),
  error = ref(""),
  selected = ref<string[]>([]),
  checking = ref<string[]>([]);
const adding = ref(false);
const form = reactive({ name: "", url: "", api_key: "" });
const canManage = computed(
  () =>
    !!session.localMe?.scopes.includes("nodes.manage") &&
    !!session.localMe?.scopes.includes("read"),
);
const active = computed(() => nodes.value.filter((n) => !n.removed_at));
const removed = computed(() => nodes.value.filter((n) => n.removed_at));
const states: Record<string, string> = {
  connected: "连接正常",
  stale: "需要重新检查",
  unreachable: "无法连接",
  identity_changed: "身份已变化",
  authorization_failed: "授权不可用",
  incompatible: "版本不兼容",
  removing: "删除待完成",
  removed: "连接已删除",
};
let keyFor = useIdempotency(),
  closed = false;
const controller = new AbortController();
function date(value: number) {
  return value ? new Date(value * 1000).toLocaleString() : "—";
}
function replace(value: NodeConnection) {
  nodes.value = [value, ...nodes.value.filter((n) => n.id !== value.id)];
  window.dispatchEvent(new Event("node-connections-changed"));
}
async function load() {
  if (!canManage.value) return;
  try {
    const result = await api.nodes(controller.signal);
    if (!closed) {
      nodes.value = result;
      selected.value = selected.value.filter((id) =>
        result.some((n) => n.id === id && !n.removed_at),
      );
      error.value = "";
    }
  } catch (cause) {
    if (!closed) error.value = apiError(cause).message;
  }
}
async function create() {
  const input = { ...form };
  await run(async () => {
    const value = await api.createNode(input, keyFor(input));
    if (closed) return;
    replace(value);
    form.name = form.url = form.api_key = "";
    keyFor = useIdempotency();
    adding.value = false;
  }, "服务器连接已添加");
}
function select(id: string, value: boolean) {
  if (value && selected.value.length < 8)
    selected.value = [...selected.value, id];
  if (!value) selected.value = selected.value.filter((v) => v !== id);
}
async function check(ids: string[]) {
  if (!canManage.value || checking.value.length || !ids.length) return;
  checking.value = [...ids];
  const queue = [...ids],
    failures: string[] = [];
  async function worker() {
    while (queue.length && !closed) {
      const id = queue.shift()!;
      try {
        const value = await api.refreshNode(id, randomUUID());
        if (!closed) replace(value);
      } catch (cause) {
        failures.push(
          `${nodes.value.find((n) => n.id === id)?.name ?? id}：${apiError(cause).message}`,
        );
      }
    }
  }
  await Promise.all([worker(), worker()]);
  if (!closed) {
    checking.value = [];
    if (failures.length) message.error(failures.join("；"));
  }
}
async function remove(node: NodeConnection) {
  await run(async () => {
    const value = await api.deleteNode(
      node.id,
      keyFor({ action: "delete", id: node.id }),
    );
    if (closed) return;
    replace(value);
    selected.value = selected.value.filter((id) => id !== node.id);
    keyFor = useIdempotency();
  });
}
useLiveRefresh(api, ["nodes"], load, () => busy.value);
onMounted(load);
onUnmounted(() => {
  closed = true;
  controller.abort();
  form.api_key = "";
});
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="!canManage" type="warning">需要服务器连接管理权限。</NAlert>
    <template v-else>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <section class="panel page-stack">
        <div class="toolbar">
          <h2>已连接的服务器</h2>
          <div class="inline-gap">
            <NButton
              :loading="!!checking.length"
              :disabled="!selected.length || busy"
              @click="check(selected)"
              >检查所选连接<span v-if="selected.length"
                >（{{ selected.length }}）</span
              ></NButton
            ><NButton :disabled="busy" @click="load">刷新</NButton
            ><NButton
              type="primary"
              :disabled="busy || !!checking.length"
              @click="adding = true"
              >添加服务器</NButton
            >
          </div>
        </div>
        <p v-if="!active.length" class="empty-state">暂无服务器连接。</p>
        <div v-else class="record-list">
          <article v-for="node in active" :key="node.id" class="record-card">
            <div class="toolbar">
              <NCheckbox
                :checked="selected.includes(node.id)"
                :disabled="
                  busy ||
                  !!checking.length ||
                  node.state === 'removing' ||
                  (!selected.includes(node.id) && selected.length >= 8)
                "
                @update:checked="(value: boolean) => select(node.id, value)"
                ><strong>{{ node.name }}</strong></NCheckbox
              >
              <NTag
                :type="node.state === 'connected' ? 'success' : 'warning'"
                >{{ states[node.state] ?? node.state }}</NTag
              >
            </div>
            <p class="record-address">{{ node.url }}</p>
            <div class="record-meta">
              <span>最近检查 {{ date(node.checked_at) }}</span
              ><span>授权到期 {{ date(node.expires_at) }}</span>
            </div>
            <NAlert v-if="node.error" type="warning">{{ node.error }}</NAlert>

            <div class="button-row">
              <NButton
                :loading="checking.includes(node.id)"
                :disabled="
                  busy || !!checking.length || node.state === 'removing'
                "
                @click="check([node.id])"
                >检查连接</NButton
              >
              <NPopconfirm
                :disabled="busy || !!checking.length"
                positive-text="删除连接"
                @positive-click="remove(node)"
                ><template #trigger
                  ><NButton
                    type="error"
                    secondary
                    :disabled="busy || !!checking.length"
                    >{{
                      node.state === "removing" ? "继续删除" : "删除连接"
                    }}</NButton
                  ></template
                >删除
                {{ node.name }}
                并撤销连接授权。无法连接时，请到目标服务器撤销对应授权。</NPopconfirm
              >
            </div>
          </article>
        </div>
      </section>
      <section class="panel page-stack">
        <NodePairing @connected="load" />
      </section>
      <FormDialog
        :show="adding"
        title="添加服务器"
        :busy="busy"
        :dirty="!!(form.name || form.url || form.api_key)"
        :submit-disabled="
          !form.name.trim() ||
          !form.url.trim() ||
          !form.api_key ||
          !!checking.length
        "
        submit-text="添加"
        @submit="create"
        @cancel="
          adding = false;
          form.name = form.url = form.api_key = '';
        "
      >
        <div class="form-grid">
          <NFormItem label="连接名称"
            ><NInput
              v-model:value="form.name"
              placeholder="例如：生产服务器"
              :maxlength="100"
          /></NFormItem>
          <NFormItem label="服务器 API 地址"
            ><NInput
              v-model:value="form.url"
              placeholder="https://server.example.com/api/v1"
              :maxlength="2048"
          /></NFormItem>
          <NFormItem class="full-width" label="API 密钥"
            ><NInput
              v-model:value="form.api_key"
              type="password"
              show-password-on="click"
              autocomplete="off"
              :maxlength="193"
          /></NFormItem>
        </div>
        <p class="section-note">
          填写目标服务器地址和专用 API 密钥，密钥至少需要读取权限。
        </p>
      </FormDialog>
      <section v-if="removed.length">
        <h3>已删除的连接</h3>
        <div class="record-list">
          <article v-for="node in removed" :key="node.id" class="record-card">
            <div class="toolbar">
              <strong>{{ node.name }}</strong
              ><NTag
                :type="node.revocation === 'revoked' ? 'success' : 'warning'"
                >{{
                  node.revocation === "revoked" ? "授权已撤销" : "授权待核对"
                }}</NTag
              >
            </div>
            <p class="record-address">{{ node.url }}</p>
            <p class="muted">删除时间 {{ date(node.removed_at) }}</p>
            <NAlert v-if="node.revocation === 'pending'" type="warning"
              >请在目标服务器中撤销此连接授权。</NAlert
            >
          </article>
        </div>
      </section>
    </template>
  </div>
</template>
