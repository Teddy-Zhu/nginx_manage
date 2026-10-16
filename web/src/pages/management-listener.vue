<route lang="json">
{
  "meta": {
    "title": "管理入口",
    "subtitle": "HTTPS 监听与来源限制",
    "nav": true,
    "localOnly": true,
    "order": 8.5,
    "symbol": "⇄"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { NAlert, NButton, NCheckbox, NFormItem, NInput, NPopconfirm, NTag } from "naive-ui";
import { apiError, useNodeAPI, type ManagementListenerInput, type ManagementListenerView } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(), session = useSession(), { run, busy } = useAction();
const view = ref<ManagementListenerView | null>(null), error = ref(""), uncertain = ref(false), publicURL = ref(""), version = ref(-1);
const canManage = computed(() => ["read", "system.write"].every((scope) => session.localMe?.scopes.includes(scope)));
const form = reactive({ listen: "0.0.0.0:9444", sources: "", certificate: "", key: "", rotate: false });
let keyFor = useIdempotency(), timer: ReturnType<typeof setInterval> | undefined, closed = false;
const operation = computed(() => view.value?.operation);
const pending = computed(() => operation.value?.state === "waiting_confirmation");
const remaining = ref(0);
const states = { waiting_confirmation: "等待新连接确认", succeeded: "已完成", rolled_back: "已恢复", recovery_required: "需要本机恢复" };
const confirmURL = computed(() => {
  try { const url = new URL(publicURL.value); if (url.protocol !== "https:" || url.username || url.password) return ""; url.pathname = "/management-listener"; url.search = ""; url.hash = ""; return url.toString(); } catch { return ""; }
});
function date(value: number) { return value ? new Date(value * 1000).toLocaleString() : "—"; }
function resetForm() {
  if (!view.value) return;
  version.value = view.value.version;
  form.listen = view.value.confirmed.listen || "0.0.0.0:9444";
  form.sources = view.value.confirmed.allowed_sources.join("\n");
  form.certificate = form.key = ""; form.rotate = false;
  keyFor = useIdempotency(); uncertain.value = false;
}
async function load() {
  if (!canManage.value || closed) return;
  try { const result = await api.managementListener(); if (closed) return; view.value = result; error.value = ""; remaining.value = Math.max(0, (result.operation?.deadline ?? 0) - Math.floor(Date.now() / 1000)); if (version.value < 0) resetForm(); }
  catch (cause) { if (!closed) error.value = apiError(cause).message; }
}
async function apply(enabled: boolean) {
  if (!view.value) return;
  const input: ManagementListenerInput = { version: version.value, enabled, listen: enabled ? form.listen.trim() : "", allowed_sources: enabled ? form.sources.trim().split(/\s+/).filter(Boolean) : [], certificate_pem: enabled ? form.certificate : "", key_pem: enabled ? form.key : "", rotate_certificate: enabled && form.rotate };
  await run(async () => {
    uncertain.value = true;
    try { const result = await api.applyManagementListener(input, keyFor(input)); if (view.value) view.value = { ...view.value, operation: result, version: result.version }; }
    catch (cause) { const failure = apiError(cause); if (failure.status >= 400 && failure.status < 500) uncertain.value = false; throw cause; }
    uncertain.value = false; form.certificate = form.key = ""; form.rotate = false;
    keyFor = useIdempotency();
  });
  await load();
}
async function decide(action: "confirm" | "rollback") {
  const id = operation.value?.id; if (!id) return;
  await run(async () => { const result = await api.decideManagementListener(id, action); if (view.value) view.value = { ...view.value, operation: result }; uncertain.value = false; });
  await load();
}
onMounted(async () => {
  await load();
  if (closed) return;
  let ticks = 0;
  timer = setInterval(() => { remaining.value = Math.max(0, (operation.value?.deadline ?? 0) - Math.floor(Date.now() / 1000)); if (pending.value && ++ticks % 3 === 0 && !busy.value) void load(); }, 1000);
});
onUnmounted(() => { closed = true; if (timer) clearInterval(timer); form.key = form.certificate = ""; });
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="!canManage" type="warning">需要系统写入与读取权限。</NAlert>
    <template v-else>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <NAlert v-if="uncertain" type="warning">请求回执尚未确认。请刷新原操作状态，避免重复变更。</NAlert>
      <section class="panel page-stack">
        <div class="toolbar"><h2>当前入口</h2><NButton :disabled="busy" @click="load">刷新状态</NButton></div>
        <p>本机回环恢复入口持续保留。可选远程入口仅接受允许来源的 HTTPS 连接。</p>
        <template v-if="view">
          <NAlert v-if="view.reason" type="warning">{{ view.reason }}</NAlert>
          <p><NTag :type="view.confirmed.enabled ? 'success' : 'default'">{{ view.confirmed.enabled ? '已启用' : '未启用' }}</NTag> · {{ view.serving ? '远程端口已监听' : '远程端口未监听' }} · {{ view.attached ? '应用通道已连接' : '应用通道未连接' }}</p>
          <p v-if="view.confirmed.enabled">已确认地址 {{ view.confirmed.listen }} · 来源 {{ view.confirmed.allowed_sources.join('、') }}</p>
          <p v-if="view.confirmed.enabled" class="fingerprint">SHA-256 {{ view.confirmed.tls_fingerprint }}<br />证书到期 {{ date(view.confirmed.certificate_expires_at) }}</p>
        </template>
      </section>
      <section v-if="operation" class="panel page-stack">
        <div class="toolbar"><h2>最近操作</h2><NTag :type="operation.state === 'succeeded' ? 'success' : 'warning'">{{ states[operation.state] }}</NTag></div>
        <p>操作编号 {{ operation.id }}</p>
        <p v-if="operation.config.enabled">候选地址 {{ operation.config.listen }} · 来源 {{ operation.config.allowed_sources.join('、') }}</p>
        <p v-if="operation.config.enabled" class="fingerprint">SHA-256 {{ operation.config.tls_fingerprint }}</p>
        <NAlert v-if="operation.error" type="warning">{{ operation.error }}</NAlert>
        <p v-if="operation.confirmed_source">已确认来源 {{ operation.confirmed_source }}。此结果仅证明该来源到当前入口的连接可达。</p>
        <template v-if="pending">
          <NAlert type="warning">请在 {{ date(operation.deadline) }} 前通过新入口确认（约 {{ remaining }} 秒）。超时或应用通道断开后自动恢复。请先核对上方证书指纹。</NAlert>
          <NFormItem label="新入口 HTTPS 地址"><NInput v-model:value="publicURL" placeholder="https://node.example.com:9444" /></NFormItem>
          <p v-if="confirmURL"><a :href="confirmURL" target="_blank" rel="noopener noreferrer">打开新入口确认页面</a></p>
          <div class="toolbar">
            <NButton type="primary" :disabled="busy" @click="decide('confirm')">确认当前新连接</NButton>
            <NPopconfirm positive-text="恢复" @positive-click="decide('rollback')"><template #trigger><NButton :disabled="busy">恢复原入口</NButton></template>恢复后候选入口的连接将关闭。</NPopconfirm>
          </div>
        </template>
      </section>
      <section v-if="view?.available" class="panel page-stack">
        <div class="toolbar"><h2>配置远程监听</h2><NButton :disabled="busy || pending" @click="resetForm">载入已确认配置</NButton></div>
        <NAlert v-if="version !== view.version && !pending" type="warning">监听版本已变化，请重新载入已确认配置。</NAlert>
        <p>地址、来源或证书变更均需在 120 秒内确认。变更时已有远程连接会断开。</p>
        <NAlert type="info">端口和允许来源须与已确认的防火墙策略一致。冲突时请先调整并确认防火墙策略；云安全组和其他系统规则需另行核对。</NAlert>
        <NFormItem label="监听 IP 与端口"><NInput v-model:value="form.listen" :disabled="busy || pending" placeholder="0.0.0.0:9444 或 [::]:9444" :maxlength="64" /></NFormItem>
        <NFormItem label="允许来源 CIDR"><NInput v-model:value="form.sources" type="textarea" :disabled="busy || pending" placeholder="203.0.113.10/32，每行一个来源" /></NFormItem>
        <NFormItem label="证书 PEM"><NInput v-model:value="form.certificate" type="textarea" :disabled="busy || pending" :maxlength="16384" placeholder="留空沿用已确认的证书；首次启用生成自签证书" /></NFormItem>
        <NFormItem label="私钥 PEM"><NInput v-model:value="form.key" type="textarea" :disabled="busy || pending" :maxlength="8192" autocomplete="off" /></NFormItem>
        <NCheckbox v-model:checked="form.rotate" :disabled="busy || pending || !!form.certificate || !!form.key">生成新的自签证书</NCheckbox>
        <p class="muted">自签证书须独立核对指纹；更换证书后，现有控制节点需要显式更新信任。</p>
        <div class="toolbar">
          <NButton type="primary" :loading="busy" :disabled="pending || version !== view.version || !view.attached || !form.sources.trim()" @click="apply(true)">暂用并等待确认</NButton>
          <NPopconfirm positive-text="停用" @positive-click="apply(false)"><template #trigger><NButton :disabled="busy || pending || !view.confirmed.enabled || version !== view.version">停用远程入口</NButton></template>停用须从本机回环恢复入口执行。</NPopconfirm>
        </div>
      </section>
    </template>
  </div>
</template>
<style scoped>
.fingerprint { overflow-wrap: anywhere; font-family: monospace; }
</style>
