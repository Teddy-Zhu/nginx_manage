<route lang="json">
{
  "meta": {
    "title": "完整备份",
    "subtitle": "加密归档与离线保管",
    "nav": true,
    "localOnly": true,
    "order": 9.5,
    "symbol": "▣"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { NAlert, NButton, NCheckbox, NFormItem, NInput, NInputNumber, NPopconfirm, NRadioButton, NRadioGroup, NTag } from "naive-ui";
import { apiError, useNodeAPI, type BackupInput, type BackupOverview, type BackupPolicy } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(), session = useSession(), { run, busy } = useAction();
const view = ref<BackupOverview | null>(null), error = ref(""), uncertain = ref(false), policyVersion = ref(0);
const canRead = computed(() => session.localMe?.scopes.includes("backup.export"));
const canWrite = computed(() => ["backup.export", "backup.secrets", "system.write"].every(scope => session.localMe?.scopes.includes(scope)));
const canDownload = computed(() => ["backup.export", "backup.secrets"].every(scope => session.localMe?.scopes.includes(scope)));
const form = reactive<BackupInput>({ name: "手动备份", encryption: "recipient", recipient: "", passphrase: "" });
const policy = reactive({ enabled: false, recipient: "", keySaved: false, interval: 24, keep: 7, days: 30, until: "" });
let keyFor = useIdempotency(), closed = false, timer: ReturnType<typeof setInterval> | undefined;
const stages: Record<string, string> = { queued: "已排队", draining: "等待写入完成", capturing: "捕获快照", releasing: "释放维护", encrypting: "正在加密", publishing: "发布归档", ready: "可下载", release_failed: "正在清理并释放维护", cleanup_failed: "清理待处理", failed: "已失败", deleted: "文件已删除", authorization_expired: "授权已失效" };
const active = computed(() => view.value?.records.some(r => !["succeeded", "failed", "cancelled", "rolled_back"].includes(r.state)));
function date(value: number) { return value ? new Date(value * 1000).toLocaleString() : "—"; }
function bytes(value: number) { return `${(value / 1048576).toFixed(1)} MiB`; }
function localDate(value: number) { const date = new Date(value * 1000); return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); }
function setPolicy(value: BackupPolicy) {
  policyVersion.value = value.version; policy.enabled = value.enabled; policy.recipient = value.recipient;
  policy.keySaved = value.key_saved_at > 0; policy.interval = value.interval_hours; policy.keep = value.keep_count; policy.days = value.retention_days;
  policy.until = localDate(value.authorization_until || Math.floor(Date.now() / 1000) + 30 * 86400);
}
async function load() {
  if (!canRead.value || closed) return;
  try { const result = await api.backups(); if (closed) return; view.value = result; error.value = ""; if (!policyVersion.value) setPolicy(result.policy); }
  catch (cause) { if (!closed) error.value = apiError(cause).message; }
}
async function create() {
  const input: BackupInput = { ...form, recipient: form.encryption === "recipient" ? form.recipient.trim() : "", passphrase: form.encryption === "passphrase" ? form.passphrase : "" };
  await run(async () => {
    uncertain.value = true;
    try { await api.createBackup(input, keyFor(input)); }
    catch (cause) { const error = apiError(cause); if (error.status >= 400 && error.status < 500) uncertain.value = false; throw cause; }
    uncertain.value = false; form.passphrase = ""; keyFor = useIdempotency();
  });
  await load();
}
async function savePolicy() {
  await run(async () => {
    const until = Math.floor(new Date(policy.until).getTime() / 1000);
    const result = await api.saveBackupPolicy({ base_version: policyVersion.value, enabled: policy.enabled, recipient: policy.recipient.trim(), key_saved: policy.keySaved, interval_hours: policy.interval, keep_count: policy.keep, retention_days: policy.days, authorization_until: policy.enabled && Number.isFinite(until) ? until : 0 });
    setPolicy(result);
  }, "备份设置已保存");
  await load();
}
async function download(id: string) {
  await run(async () => {
    const result = await api.backupDownload(id);
    if (closed) return;
    const url = new URL(result.url, window.location.origin);
    if (url.origin !== window.location.origin || url.pathname !== `/api/v1/backups/${id}/download` || result.expires_at <= Date.now() / 1000) throw new Error("下载凭据无效");
    const anchor = document.createElement("a"); anchor.href = url.toString(); anchor.download = `${id}.tar.age`; anchor.rel = "noreferrer";
    document.body.append(anchor); anchor.click(); anchor.remove();
  });
}
async function erase(id: string) { await run(() => api.deleteBackup(id), "备份文件已清理"); await load(); }
onMounted(async () => { await load(); if (!closed) timer = setInterval(() => { if (active.value && !busy.value) void load(); }, 3000); });
onUnmounted(() => { closed = true; if (timer) clearInterval(timer); form.passphrase = ""; keyFor = useIdempotency(); });
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="!canRead" type="warning">需要备份导出权限。</NAlert>
    <template v-else>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <NAlert type="info">完整备份包含业务数据库、凭据和证书。请将加密文件与恢复私钥或口令分开离线保管；跨环境业务配置迁移请使用“配置迁移”。</NAlert>
      <section v-if="canWrite" class="panel page-stack">
        <h2>创建备份</h2>
        <NAlert v-if="uncertain" type="warning">请求回执尚未确认。可重试原请求查询同一任务。</NAlert>
        <NFormItem label="备份名称"><NInput v-model:value="form.name" :disabled="busy || uncertain" maxlength="100" /></NFormItem>
        <NFormItem label="加密方式"><NRadioGroup v-model:value="form.encryption" :disabled="busy || uncertain"><NRadioButton value="recipient">离线恢复公钥</NRadioButton><NRadioButton value="passphrase">临时口令</NRadioButton></NRadioGroup></NFormItem>
        <NFormItem v-if="form.encryption === 'recipient'" label="age X25519 公钥"><NInput v-model:value="form.recipient" :disabled="busy || uncertain" placeholder="age1…" /></NFormItem>
        <NFormItem v-else label="恢复口令（16–256 字节）"><NInput v-model:value="form.passphrase" :disabled="busy || uncertain" type="password" show-password-on="click" autocomplete="new-password" /></NFormItem>
        <p v-if="form.encryption === 'passphrase'">临时口令不会保存；加密完成前进程重启会使本次任务失败。</p>
        <p>捕获快照期间暂停配置写入。定期备份仅使用离线恢复公钥。</p>
        <div><NButton type="primary" :loading="busy" :disabled="!!active && !uncertain" @click="create">{{ uncertain ? '重试原请求' : '创建加密备份' }}</NButton></div>
      </section>
      <section v-if="view" class="panel page-stack">
        <div class="toolbar"><h2>备份记录</h2><NButton :disabled="busy" @click="load">刷新</NButton></div>
        <p>单包上限 {{ bytes(view.archive_max) }}，存储上限 {{ bytes(view.store_max) }}。保留策略统一应用于本机已完成的归档；删除保留任务与审计记录。</p>
        <p v-if="!view.records.length">暂无备份记录。</p>
        <article v-for="record in view.records" :key="record.id" class="backup-record page-stack">
          <div class="toolbar"><strong>{{ record.name }}</strong><NTag :type="record.available ? 'success' : record.error ? 'warning' : 'default'">{{ stages[record.stage] || record.stage }}</NTag></div>
          <p>{{ record.scheduled ? '定期备份' : '手动备份' }} · {{ date(record.created_at) }} · {{ record.archive_size ? bytes(record.archive_size) : '尚无归档' }} · 到期 {{ date(record.expires_at) }}</p>
          <p v-if="record.archived_at">历史已归档 · {{ date(record.archived_at) }}</p>
          <p class="digest">{{ record.id }}<template v-if="record.archive_sha256"><br />SHA-256 {{ record.archive_sha256 }}</template></p>
          <NAlert v-if="record.error" type="warning">{{ record.error }}</NAlert>
          <p v-if="record.database">数据库版本 {{ record.database.schema_version }} · 配置版本 {{ record.database.head_version }}</p>
          <div class="toolbar">
            <NButton v-if="record.available && canDownload" :disabled="busy" @click="download(record.id)">下载加密归档</NButton>
            <NPopconfirm v-if="canWrite && !record.deleted_at && (['succeeded', 'failed', 'cancelled', 'rolled_back'].includes(record.state) || record.stage === 'cleanup_failed')" @positive-click="erase(record.id)">
              <template #trigger><NButton :disabled="busy" type="error" secondary>{{ record.stage === 'cleanup_failed' ? '继续清理' : '删除文件' }}</NButton></template>
              确认清理此备份的归档与暂存文件？此操作不可撤销。
            </NPopconfirm>
          </div>
        </article>
      </section>
      <section v-if="view && canWrite" class="panel page-stack">
        <div class="toolbar"><h2>定期备份与保留策略</h2><NButton :disabled="busy" @click="setPolicy(view.policy)">载入当前设置</NButton></div>
        <NAlert v-if="view.policy.error" type="warning">{{ view.policy.error }}</NAlert>
        <NCheckbox v-model:checked="policy.enabled" :disabled="busy">启用定期备份</NCheckbox>
        <NFormItem label="age X25519 恢复公钥"><NInput v-model:value="policy.recipient" :disabled="busy" placeholder="age1…" @update:value="policy.keySaved = false" /></NFormItem>
        <NCheckbox v-model:checked="policy.keySaved" :disabled="busy">已将对应恢复私钥离线保存</NCheckbox>
        <NFormItem label="备份间隔（小时）"><NInputNumber v-model:value="policy.interval" :min="1" :max="168" :precision="0" :disabled="busy" /></NFormItem>
        <NFormItem label="保留数量"><NInputNumber v-model:value="policy.keep" :min="1" :max="15" :precision="0" :disabled="busy" /></NFormItem>
        <NFormItem label="最长保留天数"><NInputNumber v-model:value="policy.days" :min="1" :max="90" :precision="0" :disabled="busy" /></NFormItem>
        <NFormItem v-if="policy.enabled" label="定期备份授权到期"><input v-model="policy.until" type="datetime-local" :disabled="busy" /></NFormItem>
        <p>授权到期、撤销或账户安全代次变化后停止新备份。数量与期限任一达到即清理归档；已下载的副本由您自行保管。</p>
        <p v-if="view.policy.enabled">下次计划 {{ date(view.policy.next_run_at) }} · 授权到期 {{ date(view.policy.authorization_until) }}</p>
        <div><NButton type="primary" :loading="busy" @click="savePolicy">保存设置与授权</NButton></div>
      </section>
    </template>
  </div>
</template>
<style scoped>
.backup-record { border-top: 1px solid var(--border-color, #d9dce3); padding-top: 16px; }
.digest { overflow-wrap: anywhere; font-family: monospace; font-size: 12px; }
p { margin: 0; }
</style>
