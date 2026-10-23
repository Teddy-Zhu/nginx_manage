<route lang="json">
{
  "meta": {
    "title": "SSL 证书",
    "subtitle": "管理证书、申请和自动续期",
    "nav": true,
    "order": 2,
    "symbol": "▱",
    "group": "网站与安全"
  }
}
</route>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { onBeforeRouteLeave } from "vue-router";
import {
  NAlert,
  NButton,
  NDataTable,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSelect,
  NTag,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  type Certificate,
  type CertificateVersion,
  type CertificateInput,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
const api = useNodeAPI();

const { run, busy, message } = useAction(),
  keyFor = useIdempotency();
const items = ref<Certificate[]>([]),
  selected = ref<Certificate | null>(null),
  versionID = ref("");
const importing = ref(false),
  replaceID = ref<string | null>(null),
  baseVersion = ref(0),
  name = ref(""),
  notes = ref(""),
  fullchain = ref(""),
  privateKey = ref("");
const baseline = ref(""),
  now = ref(Date.now());
let timer: ReturnType<typeof setInterval> | undefined;
let importGeneration = 0;
const formJSON = computed(() =>
  JSON.stringify([name.value, notes.value, fullchain.value, privateKey.value]),
);
const dirty = computed(
  () => importing.value && formJSON.value !== baseline.value,
);
const version = computed(() =>
  selected.value?.versions.find((item) => item.id === versionID.value),
);
const versionOptions = computed(
  () =>
    selected.value?.versions.map((item) => ({
      label: `${item.environment === "staging" ? "测试 · " : ""}版本 ${item.ordinal} · ${new Date(item.summary.chain_not_after * 1000).toLocaleDateString()}`,
      value: item.id,
    })) ?? [],
);
const activeBindings = computed(() => {
  const seen = new Set<string>();
  return (
    selected.value?.bindings.filter((binding) => {
      const key = JSON.stringify([
        binding.version_id,
        binding.revision_id,
        binding.resource_id,
        binding.file_id,
      ]);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }) ?? []
  );
});
function latest(item: Certificate) {
  return item.versions.find((value) => value.id === item.latest_version_id);
}
function expiry(value: CertificateVersion | undefined) {
  if (!value) return "无证书版本";
  if (now.value < value.summary.chain_not_before * 1000) return "尚未生效";
  const remaining = value.summary.chain_not_after * 1000 - now.value;
  if (remaining <= 0) return "已过期";
  return `剩余 ${Math.ceil(remaining / 86400000)} 天`;
}
function date(value: number) {
  return new Date(value * 1000).toLocaleString();
}
const columns: DataTableColumns<Certificate> = [
  { title: "名称", key: "name" },
  {
    title: "域名 / IP",
    key: "domains",
    render: (row) => {
      const summary = latest(row)?.summary;
      return summary
        ? [...summary.dns_names, ...summary.ip_addresses].join("、")
        : "—";
    },
  },
  { title: "最新版本", key: "version", render: (row) => `#${row.version}` },
  {
    title: "来源",
    key: "source",
    render: (row) =>
      latest(row)?.environment === "staging"
        ? "ACME 测试"
        : row.source === "acme"
          ? "ACME 正式"
          : "手动导入",
  },
  { title: "有效期", key: "expiry", render: (row) => expiry(latest(row)) },
];
async function load() {
  await run(async () => {
    items.value = await api.certificates();
    if (selected.value) {
      const current = items.value.find(
        (item) => item.id === selected.value!.id,
      );
      selected.value = current ? await api.certificate(current.id) : null;
      versionID.value = selected.value?.latest_version_id ?? "";
    }
  });
}
async function open(item: Certificate) {
  if (busy.value) return;
  await run(async () => {
    selected.value = await api.certificate(item.id);
    versionID.value = selected.value.latest_version_id;
  });
}
function startImport(item: Certificate | null) {
  if (busy.value) return;
  importGeneration++;
  replaceID.value = item?.id ?? null;
  baseVersion.value = item?.version ?? 0;
  name.value = item?.name ?? "";
  notes.value = item?.notes ?? "";
  fullchain.value = "";
  privateKey.value = "";
  baseline.value = formJSON.value;
  importing.value = true;
}
function clearImport() {
  importGeneration++;
  name.value = "";
  notes.value = "";
  fullchain.value = "";
  privateKey.value = "";
  baseline.value = "";
  replaceID.value = null;
}
function closeImport() {
  if (busy.value) return false;
  if (dirty.value && !window.confirm("证书材料尚未导入，确认关闭？"))
    return false;
  importing.value = false;
  clearImport();
  return true;
}
async function readFile(event: Event, target: "chain" | "key") {
  const input = event.target as HTMLInputElement,
    file = input.files?.[0];
  input.value = "";
  if (!file) return;
  if (file.size > (target === "key" ? 16384 : 131072)) {
    message.error(
      target === "key" ? "私钥 PEM 不得超过 16 KiB" : "证书链不得超过 128 KiB",
    );
    return;
  }
  const generation = importGeneration;
  try {
    const value = await file.text();
    if (!importing.value || generation !== importGeneration || busy.value)
      return;
    if (target === "chain") fullchain.value = value;
    else privateKey.value = value;
  } catch {
    message.error("无法读取所选文件");
  }
}
async function save() {
  if (!importing.value || busy.value) return;
  const id = replaceID.value,
    input: CertificateInput = {
      base_version: baseVersion.value,
      name: name.value,
      notes: notes.value,
      fullchain_pem: fullchain.value,
      private_key_pem: privateKey.value,
    };
  await run(async () => {
    const bytes = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(JSON.stringify(input)),
    );
    const digest = Array.from(new Uint8Array(bytes), (value) =>
      value.toString(16).padStart(2, "0"),
    ).join("");
    const result = await api.importCertificate(
      id,
      input,
      keyFor({ id, digest }),
    );
    if (!result.certificate) throw new Error("证书导入未返回有效资源");
    selected.value = result.certificate;
    versionID.value = result.certificate.latest_version_id;
    items.value = [
      ...items.value.filter((item) => item.id !== result.certificate!.id),
      result.certificate,
    ];
    importing.value = false;
    clearImport();
  }, "证书版本已导入，请绑定站点并应用配置");
}
async function remove() {
  const item = selected.value;
  if (!item || busy.value || item.bindings.length || item.historical_references)
    return;
  if (!window.confirm(`确认删除 ${item.name} 及其所有未引用版本？`)) return;
  await run(async () => {
    await api.deleteCertificate(
      item.id,
      item.version,
      keyFor({
        action: "delete-certificate",
        id: item.id,
        version: item.version,
      }),
    );
    items.value = items.value.filter((value) => value.id !== item.id);
    selected.value = null;
    versionID.value = "";
  }, "证书已删除");
}
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (dirty.value) event.preventDefault();
};
onBeforeRouteLeave(
  () => !dirty.value || window.confirm("证书材料尚未导入，确认离开？"),
);
onMounted(() => {
  void load();
  timer = setInterval(() => (now.value = Date.now()), 60000);
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => {
  if (timer) clearInterval(timer);
  clearImport();
  window.removeEventListener("beforeunload", beforeUnload);
});
</script>

<template>
  <div class="toolbar">
    <span class="muted">{{ items.length }} 张证书</span>
    <div class="inline-gap">
      <router-link to="/certificate-requests"
        ><n-button :disabled="busy">ACME 签发</n-button></router-link
      >
      <router-link to="/certificate-deployments"
        ><n-button :disabled="busy">证书部署</n-button></router-link
      >
      <router-link to="/acme"
        ><n-button :disabled="busy">ACME 账户与 DNS 凭据</n-button></router-link
      >
      <n-button :loading="busy" @click="load">刷新</n-button
      ><n-button type="primary" :disabled="busy" @click="startImport(null)"
        >导入证书</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >手动证书需自行续期。首次绑定在
    <router-link to="/nginx">Nginx 配置</router-link>
    中保存并应用；已有绑定可通过证书部署切换到最新版本。</n-alert
  >
  <section class="surface">
    <n-data-table
      :columns="columns"
      :data="items"
      :bordered="false"
      :row-props="
        (row: Certificate) => ({
          onClick: () => open(row),
          style: 'cursor: pointer',
        })
      "
    />
  </section>
  <section v-if="selected" class="surface" style="margin-top: 20px">
    <div class="section-heading">
      <div>
        <h2>{{ selected.name }}</h2>
        <p class="muted">{{ selected.notes }}</p>
      </div>
      <div class="inline-gap">
        <n-button :disabled="busy" @click="startImport(selected)"
          >导入新版本</n-button
        ><n-button
          type="error"
          :disabled="
            busy ||
            !!selected.bindings.length ||
            !!selected.historical_references
          "
          @click="remove"
          >删除</n-button
        >
      </div>
    </div>
    <n-select
      v-model:value="versionID"
      :options="versionOptions"
      style="max-width: 440px; margin-bottom: 20px"
    />
    <template v-if="version">
      <div class="inline-gap" style="flex-wrap: wrap; margin-bottom: 16px">
        <n-tag :bordered="false">{{ expiry(version) }}</n-tag
        ><n-tag :bordered="false">{{ version.summary.key_algorithm }}</n-tag
        ><n-tag :bordered="false">{{
          version.summary.trust === "system"
            ? "系统信任链"
            : version.summary.trust === "private"
              ? "私有 CA"
              : version.summary.trust === "acme_staging"
                ? "ACME 测试证书"
                : "自签证书"
        }}</n-tag
        ><n-tag
          v-if="version.id === selected.latest_version_id"
          :bordered="false"
          >最新版本</n-tag
        >
      </div>
      <p v-if="version.environment === 'staging'" class="muted">
        测试证书不受浏览器信任，请申请正式环境证书用于公开站点。
      </p>
      <p v-else-if="version.summary.trust !== 'system'" class="muted">
        客户端需要信任相应证书或私有 CA。
      </p>
      <p>
        有效期：{{ date(version.summary.not_before) }} —
        {{ date(version.summary.not_after) }}
      </p>
      <p
        v-if="
          version.summary.chain_not_before !== version.summary.not_before ||
          version.summary.chain_not_after !== version.summary.not_after
        "
        class="muted"
      >
        证书链共同有效期：{{ date(version.summary.chain_not_before) }} —
        {{ date(version.summary.chain_not_after) }}
      </p>
      <p>签发者：{{ version.summary.issuer }}</p>
      <p>主体：{{ version.summary.subject }}</p>
      <p>证书链：{{ version.summary.chain_length }} 张</p>
      <div class="inline-gap" style="flex-wrap: wrap">
        <n-tag
          v-for="domain in [
            ...version.summary.dns_names,
            ...version.summary.ip_addresses,
          ]"
          :key="domain"
          size="small"
          >{{ domain }}</n-tag
        >
      </div>
      <p class="muted" style="overflow-wrap: anywhere">
        SHA-256：{{ version.summary.fingerprint }}
      </p>
    </template>
    <h3>当前引用</h3>
    <p v-if="!activeBindings.length" class="muted">
      当前没有网站使用此证书。
    </p>
    <p
      v-for="binding in activeBindings"
      :key="`${binding.revision_id}:${binding.resource_id}:${binding.file_id}:${binding.version_id}`"
    >
      修订 #{{ binding.revision_version }} ·
      {{
        binding.revision_state === "desired"
          ? "待应用"
          : binding.revision_state === "applied"
            ? "最近确认生效"
            : "已配置并应用"
      }}
      ·
      {{
        binding.resource_id
          ? `站点 ${binding.resource_id.slice(0, 8)}`
          : `自定义配置 ${binding.file_id.slice(0, 8)}`
      }}
      · 版本
      {{
        selected.versions.find((item) => item.id === binding.version_id)
          ?.ordinal ?? "—"
      }}
    </p>
    <p v-if="selected.historical_references" class="muted">
      另有
      {{ selected.historical_references }}
      条历史修订引用，证书版本保留用于回滚。
    </p>
    <p v-if="selected.bindings_truncated" class="muted">
      引用较多，当前仅显示部分记录。
    </p>
  </section>
  <n-empty
    v-else-if="items.length"
    description="选择证书查看版本和引用"
    style="margin-top: 40px"
  />
  <n-modal
    :show="importing"
    preset="card"
    :title="replaceID ? '导入证书新版本' : '导入证书'"
    style="width: 760px; max-width: 94vw"
    :mask-closable="false"
    :close-on-esc="false"
    @close="closeImport"
  >
    <n-form :disabled="busy" label-placement="top" @submit.prevent="save">
      <n-form-item label="名称"
        ><n-input v-model:value="name" :maxlength="128"
      /></n-form-item>
      <n-form-item label="备注"
        ><n-input v-model:value="notes" :maxlength="2048"
      /></n-form-item>
      <n-form-item label="PEM 证书链（终端证书在前，随后为中间证书）"
        ><div style="width: 100%">
          <input
            type="file"
            accept=".pem,.crt,.cer"
            :disabled="busy"
            @change="readFile($event, 'chain')"
          /><n-input
            v-model:value="fullchain"
            type="textarea"
            :maxlength="131072"
            :autosize="{ minRows: 6, maxRows: 12 }"
            :input-props="{ spellcheck: false, autocomplete: 'off' }"
            placeholder="-----BEGIN CERTIFICATE-----"
          /></div
      ></n-form-item>
      <n-form-item label="未加密 PEM 私钥"
        ><div style="width: 100%">
          <input
            type="file"
            accept=".pem,.key"
            :disabled="busy"
            @change="readFile($event, 'key')"
          /><n-input
            v-model:value="privateKey"
            type="textarea"
            :maxlength="16384"
            :autosize="{ minRows: 5, maxRows: 10 }"
            :input-props="{ spellcheck: false, autocomplete: 'off' }"
            placeholder="-----BEGIN PRIVATE KEY-----"
          /></div
      ></n-form-item>
      <p class="muted">
        证书链与私钥合计最多 128 KiB，证书链最多 16 张。私有 CA
        须包含自签根证书；私钥导入后不回显。
      </p>
      <div class="inline-gap">
        <n-button type="primary" attr-type="submit" :loading="busy"
          >导入版本</n-button
        ><n-button :disabled="busy" @click="closeImport">取消</n-button>
      </div>
    </n-form>
  </n-modal>
</template>
