<route lang="json">
{
  "meta": {
    "title": "备份恢复",
    "subtitle": "备份系统数据，或从备份恢复",
    "nav": true,
    "localOnly": true,
    "order": 20,
    "symbol": "▣",
    "group": "数据与设置"
  }
}
</route>
<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NInput,
  NInputNumber,
  NPopconfirm,
  NRadioButton,
  NRadioGroup,
  NTag,
  NTabs,
  NTabPane,
  NForm,
} from "naive-ui";
import { RouterLink } from "vue-router";
import {
  apiError,
  useNodeAPI,
  type BackupInput,
  type BackupOverview,
  type BackupPolicy,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction();
const view = ref<BackupOverview | null>(null),
  error = ref(""),
  uncertain = ref(false),
  policyVersion = ref(0);
const canRead = computed(() =>
  session.localMe?.scopes.includes("backup.export"),
);
const canWrite = computed(() =>
  ["backup.export", "backup.secrets", "system.write"].every((scope) =>
    session.localMe?.scopes.includes(scope),
  ),
);
const canDownload = computed(() =>
  ["backup.export", "backup.secrets"].every((scope) =>
    session.localMe?.scopes.includes(scope),
  ),
);
const form = reactive<BackupInput>({
  name: "手动备份",
  encryption: "recipient",
  recipient: "",
  passphrase: "",
});
const policy = reactive({
  enabled: false,
  recipient: "",
  keySaved: false,
  interval: 24,
  keep: 7,
  days: 30,
  until: "",
});
let keyFor = useIdempotency(),
  closed = false;
const stages: Record<string, string> = {
  queued: "已排队",
  draining: "等待写入完成",
  capturing: "捕获快照",
  releasing: "释放维护",
  encrypting: "正在加密",
  publishing: "发布归档",
  ready: "可下载",
  release_failed: "正在清理并释放维护",
  cleanup_failed: "清理待处理",
  failed: "已失败",
  deleted: "文件已删除",
  authorization_expired: "授权已失效",
};
const active = computed(() =>
  view.value?.records.some(
    (r) =>
      !["succeeded", "failed", "cancelled", "rolled_back"].includes(r.state),
  ),
);
function date(value: number) {
  return value ? new Date(value * 1000).toLocaleString() : "—";
}
function bytes(value: number) {
  return `${(value / 1048576).toFixed(1)} MiB`;
}
function localDate(value: number) {
  const date = new Date(value * 1000);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
}
function setPolicy(value: BackupPolicy) {
  policyVersion.value = value.version;
  policy.enabled = value.enabled;
  policy.recipient = value.recipient;
  policy.keySaved = value.key_saved_at > 0;
  policy.interval = value.interval_hours;
  policy.keep = value.keep_count;
  policy.days = value.retention_days;
  policy.until = localDate(
    value.authorization_until || Math.floor(Date.now() / 1000) + 30 * 86400,
  );
}
async function load() {
  if (!canRead.value || closed) return;
  try {
    const result = await api.backups();
    if (closed) return;
    view.value = result;
    error.value = "";
    if (!policyVersion.value) setPolicy(result.policy);
  } catch (cause) {
    if (!closed) error.value = apiError(cause).message;
  }
}
async function create() {
  const input: BackupInput = {
    ...form,
    recipient: form.encryption === "recipient" ? form.recipient.trim() : "",
    passphrase: form.encryption === "passphrase" ? form.passphrase : "",
  };
  await run(async () => {
    uncertain.value = true;
    try {
      await api.createBackup(input, keyFor(input));
    } catch (cause) {
      const error = apiError(cause);
      if (error.status >= 400 && error.status < 500) uncertain.value = false;
      throw cause;
    }
    uncertain.value = false;
    form.passphrase = "";
    keyFor = useIdempotency();
  });
  await load();
}
async function savePolicy() {
  await run(async () => {
    const until = Math.floor(new Date(policy.until).getTime() / 1000);
    const result = await api.saveBackupPolicy({
      base_version: policyVersion.value,
      enabled: policy.enabled,
      recipient: policy.recipient.trim(),
      key_saved: policy.keySaved,
      interval_hours: policy.interval,
      keep_count: policy.keep,
      retention_days: policy.days,
      authorization_until: policy.enabled && Number.isFinite(until) ? until : 0,
    });
    setPolicy(result);
  }, "备份设置已保存");
  await load();
}
async function download(id: string) {
  await run(async () => {
    const result = await api.backupDownload(id);
    if (closed) return;
    const url = new URL(result.url, window.location.origin);
    if (
      url.origin !== window.location.origin ||
      url.pathname !== `/api/v1/backups/${id}/download` ||
      result.expires_at <= Date.now() / 1000
    )
      throw new Error("下载凭据无效");
    const anchor = document.createElement("a");
    anchor.href = url.toString();
    anchor.download = `${id}.tar.age`;
    anchor.rel = "noreferrer";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
  });
}
async function erase(id: string) {
  await run(() => api.deleteBackup(id), "备份文件已清理");
  await load();
}
onMounted(() => {
  void load();
});
onUnmounted(() => {
  closed = true;
  form.passphrase = "";
  keyFor = useIdempotency();
});
useLiveRefresh(api, ["tasks", "backups"], load);
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="!canRead" type="warning">需要备份读取权限。</NAlert>
    <template v-else>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <NAlert type="info"
        >备份包含系统数据、凭据和证书，请将备份与恢复密钥分开保存。在不同服务器之间迁移配置，可使用
        <RouterLink to="/migrations">配置迁移</RouterLink>。</NAlert
      >
      <section v-if="canWrite" class="panel page-stack">
        <h2>备份设置</h2>
        <NTabs type="line" animated>
          <NTabPane name="manual" tab="手动备份">
            <NForm
              label-placement="top"
              :disabled="busy || uncertain"
              @submit.prevent="create"
            >
              <NAlert v-if="uncertain" type="warning"
                >暂未收到任务结果，请重试原请求或刷新记录。</NAlert
              >
              <div class="form-grid">
                <NFormItem label="备份名称"
                  ><NInput v-model:value="form.name" maxlength="100"
                /></NFormItem>
                <NFormItem label="加密方式"
                  ><NRadioGroup v-model:value="form.encryption"
                    ><NRadioButton value="recipient">恢复公钥</NRadioButton
                    ><NRadioButton value="passphrase"
                      >恢复口令</NRadioButton
                    ></NRadioGroup
                  ></NFormItem
                >
                <NFormItem
                  v-if="form.encryption === 'recipient'"
                  class="full-width"
                  label="age X25519 恢复公钥"
                  ><NInput v-model:value="form.recipient" placeholder="age1…"
                /></NFormItem>
                <NFormItem
                  v-else
                  class="full-width"
                  label="恢复口令"
                  feedback="16–256 字节，请单独保存"
                  ><NInput
                    v-model:value="form.passphrase"
                    type="password"
                    show-password-on="click"
                    autocomplete="new-password"
                /></NFormItem>
              </div>
              <p class="section-note">
                创建备份时会短暂暂停配置修改。<template
                  v-if="form.encryption === 'passphrase'"
                  >恢复口令不会保存在系统中；加密完成前请勿重启面板。</template
                >
              </p>
              <div class="form-actions">
                <NButton
                  type="primary"
                  attr-type="submit"
                  :loading="busy"
                  :disabled="!!active && !uncertain"
                  >{{ uncertain ? "重试原请求" : "创建备份" }}</NButton
                >
              </div>
            </NForm>
          </NTabPane>
          <NTabPane v-if="view" name="schedule" tab="定期备份">
            <NForm
              label-placement="top"
              :disabled="busy"
              @submit.prevent="savePolicy"
            >
              <div class="page-stack">
                <NAlert v-if="view.policy.error" type="warning">{{
                  view.policy.error
                }}</NAlert>
                <NCheckbox v-model:checked="policy.enabled"
                  >启用定期备份</NCheckbox
                >
                <div class="form-grid">
                  <NFormItem class="full-width" label="age X25519 恢复公钥"
                    ><NInput
                      v-model:value="policy.recipient"
                      placeholder="age1…"
                      @update:value="policy.keySaved = false"
                  /></NFormItem>
                  <NFormItem label="备份间隔（小时）"
                    ><NInputNumber
                      v-model:value="policy.interval"
                      :min="1"
                      :max="168"
                      :precision="0"
                  /></NFormItem>
                  <NFormItem label="保留数量"
                    ><NInputNumber
                      v-model:value="policy.keep"
                      :min="1"
                      :max="15"
                      :precision="0"
                  /></NFormItem>
                  <NFormItem label="最长保留天数"
                    ><NInputNumber
                      v-model:value="policy.days"
                      :min="1"
                      :max="90"
                      :precision="0"
                  /></NFormItem>
                  <NFormItem v-if="policy.enabled" label="定期备份授权到期"
                    ><input v-model="policy.until" type="datetime-local"
                  /></NFormItem>
                </div>
                <NCheckbox v-model:checked="policy.keySaved"
                  >已将对应恢复私钥单独保存</NCheckbox
                >
                <p class="section-note">
                  达到保留数量或保留天数时，系统自动清理较早的备份。授权到期后停止创建新备份。
                </p>
                <p v-if="view.policy.enabled" class="muted">
                  下次备份 {{ date(view.policy.next_run_at) }} · 授权到期
                  {{ date(view.policy.authorization_until) }}
                </p>
              </div>
              <div class="form-actions">
                <NButton :disabled="busy" @click="setPolicy(view.policy)"
                  >重置修改</NButton
                ><NButton type="primary" attr-type="submit" :loading="busy"
                  >保存设置</NButton
                >
              </div>
            </NForm>
          </NTabPane>
        </NTabs>
      </section>
      <section v-if="view" class="panel page-stack">
        <div class="toolbar">
          <h2>备份记录</h2>
          <NButton :disabled="busy" @click="load">刷新</NButton>
        </div>
        <p class="muted">
          单个备份上限 {{ bytes(view.archive_max) }}，总存储上限
          {{ bytes(view.store_max) }}。
        </p>
        <p v-if="!view.records.length" class="empty-state">暂无备份记录</p>
        <div v-else class="record-list">
          <article
            v-for="record in view.records"
            :key="record.id"
            class="record-card"
          >
            <div class="toolbar">
              <strong>{{ record.name }}</strong
              ><NTag
                :type="
                  record.available
                    ? 'success'
                    : record.error
                      ? 'warning'
                      : 'default'
                "
                >{{ stages[record.stage] || record.stage }}</NTag
              >
            </div>
            <div class="record-meta">
              <span>{{ record.scheduled ? "定期备份" : "手动备份" }}</span
              ><span>{{ date(record.created_at) }}</span
              ><span>{{
                record.archive_size
                  ? bytes(record.archive_size)
                  : "正在准备文件"
              }}</span
              ><span>到期 {{ date(record.expires_at) }}</span>
            </div>
            <NAlert v-if="record.error" type="warning">{{
              record.error
            }}</NAlert>

            <div class="button-row">
              <NButton
                v-if="record.available && canDownload"
                :disabled="busy"
                @click="download(record.id)"
                >下载备份</NButton
              >
              <NPopconfirm
                v-if="
                  canWrite &&
                  !record.deleted_at &&
                  (['succeeded', 'failed', 'cancelled', 'rolled_back'].includes(
                    record.state,
                  ) ||
                    record.stage === 'cleanup_failed')
                "
                @positive-click="erase(record.id)"
              >
                <template #trigger
                  ><NButton :disabled="busy" type="error" secondary>{{
                    record.stage === "cleanup_failed" ? "继续清理" : "删除文件"
                  }}</NButton></template
                >确认删除此备份文件？删除后无法恢复。
              </NPopconfirm>
            </div>
          </article>
        </div>
      </section>
    </template>
  </div>
</template>
