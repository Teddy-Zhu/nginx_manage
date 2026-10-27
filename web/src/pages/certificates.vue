<route lang="json">
{
  "meta": {
    "title": "SSL 证书",
    "subtitle": "管理证书、申请和自动续期",
    "nav": true,
    "order": 11,
    "symbol": "▱",
    "group": "网站服务"
  }
}
</route>

<script setup lang="ts">
import FormDialog from "../components/FormDialog.vue";
import CertificateWorkspace from "../components/CertificateWorkspace.vue";
import { useLiveRefresh } from "../composables/live";
import { useRoute, useRouter } from "vue-router";
import { sha256Hex } from "../utils/crypto";
import { computed, h, onMounted, onUnmounted, ref, watch } from "vue";
import { onBeforeRouteLeave } from "vue-router";
import {
  NAlert,
  NButton,
  NDataTable,
  NEmpty,
  NFormItem,
  NInput,
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
const route = useRoute(),
  router = useRouter();
const selectedID = computed(() =>
  typeof route.query.certificate === "string" ? route.query.certificate : "",
);

const { run, busy, message } = useAction(),
  keyFor = useIdempotency();
const items = ref<Certificate[]>([]),
  selected = ref<Certificate | null>(null);
const importing = ref(false),
  replaceID = ref<string | null>(null),
  baseVersion = ref(0),
  name = ref(""),
  notes = ref(""),
  fullchain = ref(""),
  privateKey = ref("");
const chainName = ref(""),
  keyName = ref("");
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
  selected.value ? latest(selected.value) : undefined,
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
  if (!value) return "尚无证书";
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
  {
    title: "来源",
    key: "source",
    render: (row) =>
      latest(row)?.environment === "staging"
        ? "自动申请（测试）"
        : row.source === "acme"
          ? "自动申请"
          : "手动导入",
  },
  { title: "有效期", key: "expiry", render: (row) => expiry(latest(row)) },
];
async function loadSelected() {
  const id = selectedID.value;
  if (!id) {
    selected.value = null;
    return;
  }
  const item = await api.certificate(id);
  if (selectedID.value === id) selected.value = item;
}
async function load() {
  await run(async () => {
    items.value = await api.certificates();
    await loadSelected();
  });
}
function open(item: Certificate) {
  if (busy.value) return;
  void router.replace({ query: { ...route.query, certificate: item.id } });
}
let pendingSelection = false;
watch(selectedID, () => {
  selected.value = null;
  pendingSelection = true;
  if (!busy.value) {
    pendingSelection = false;
    void run(loadSelected);
  }
});
watch(busy, (working) => {
  if (!working && pendingSelection) {
    pendingSelection = false;
    void run(loadSelected);
  }
});
function startImport(item: Certificate | null) {
  if (busy.value) return;
  importGeneration++;
  replaceID.value = item?.id ?? null;
  baseVersion.value = item?.version ?? 0;
  name.value = item?.name ?? "";
  notes.value = item?.notes ?? "";
  fullchain.value = "";
  privateKey.value = "";
  chainName.value = keyName.value = "";
  baseline.value = formJSON.value;
  importing.value = true;
}
function clearImport() {
  importGeneration++;
  name.value = "";
  notes.value = "";
  fullchain.value = "";
  privateKey.value = "";
  chainName.value = keyName.value = "";
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
    if (target === "chain") {
      fullchain.value = value;
      chainName.value = file.name;
    } else {
      privateKey.value = value;
      keyName.value = file.name;
    }
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
    const digest = sha256Hex(new TextEncoder().encode(JSON.stringify(input)));
    const result = await api.importCertificate(
      id,
      input,
      keyFor({ id, digest }),
    );
    if (!result.certificate) throw new Error("证书导入未返回有效资源");
    selected.value = result.certificate;
    items.value = [
      ...items.value.filter((item) => item.id !== result.certificate!.id),
      result.certificate,
    ];
    importing.value = false;
    clearImport();
    void router.replace({
      query: { ...route.query, certificate: result.certificate.id },
    });
  }, "证书已导入，可前往网站设置使用");
}
async function remove() {
  const item = selected.value;
  if (!item || busy.value || item.bindings.length || item.historical_references)
    return;
  if (!window.confirm(`确认删除 ${item.name} 及其证书材料？`)) return;
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
    void router.replace({ query: { ...route.query, certificate: undefined } });
  }, "证书已删除");
}
columns.push({
  title: "操作",
  key: "actions",
  width: 90,
  render: (row) =>
    h(
      NButton,
      {
        size: "small",
        disabled: busy.value,
        onClick: (event: globalThis.MouseEvent) => {
          event.stopPropagation();
          open(row);
        },
      },
      () => "查看详情",
    ),
});
useLiveRefresh(api, ["tasks"], load, () => busy.value || importing.value);
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
  <CertificateWorkspace>
    <section class="surface">
      <ol class="cert-workflow">
        <li>
          <div>
            <h2>获取证书</h2>
            <p class="muted">自动申请，或导入已有证书。</p>
          </div>
        </li>
        <li>
          <div>
            <h2>用于网站</h2>
            <p class="muted">在网站设置中选择证书，保存并应用。</p>
          </div>
        </li>
        <li>
          <div>
            <h2>续期与更新</h2>
            <p class="muted">
              自动申请的证书可开启续期，导入的证书需手动更新。
            </p>
          </div>
        </li>
      </ol>
    </section>
    <section class="surface cert-section">
      <div class="cert-heading">
        <div>
          <h2>我的证书</h2>
          <p class="muted">共 {{ items.length }} 张证书</p>
        </div>
        <div class="cert-actions">
          <n-button :loading="busy" @click="load">刷新</n-button>
          <n-button :disabled="busy" @click="startImport(null)"
            >导入证书</n-button
          >
          <router-link
            :to="{ path: '/certificate-requests', query: { new: '1' } }"
            ><n-button type="primary" :disabled="busy"
              >申请证书</n-button
            ></router-link
          >
        </div>
      </div>
      <n-data-table
        v-if="items.length"
        :columns="columns"
        :data="items"
        :bordered="false"
        :scroll-x="720"
        :row-props="
          (row: Certificate) => ({
            onClick: () => open(row),
            style: 'cursor: pointer',
          })
        "
      />
      <n-empty
        v-else
        class="cert-empty"
        description="还没有证书，可自动申请或导入已有证书"
      />
    </section>
    <section v-if="selected" class="surface cert-section">
      <div class="cert-heading">
        <div>
          <h2>{{ selected.name }}</h2>
          <p v-if="selected.notes" class="muted">{{ selected.notes }}</p>
        </div>
        <div class="cert-actions">
          <router-link
            :to="{
              path: '/certificate-deployments',
              query: { certificate: selected.id },
            }"
            ><n-button type="primary">用于网站</n-button></router-link
          >
          <router-link
            v-if="selected.source === 'acme'"
            :to="{
              path: '/certificate-requests',
              query: { certificate: selected.id },
            }"
            ><n-button>续期设置</n-button></router-link
          >
          <n-button :disabled="busy" @click="startImport(selected)"
            >导入更新</n-button
          >
          <n-button
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
      <template v-if="version">
        <div class="cert-actions">
          <n-tag :bordered="false">{{ expiry(version) }}</n-tag
          ><n-tag :bordered="false">{{
            version.environment === "staging"
              ? "测试证书"
              : version.summary.trust === "system"
                ? "受信任证书"
                : version.summary.trust === "private"
                  ? "私有证书"
                  : "自签证书"
          }}</n-tag>
        </div>
        <n-alert
          v-if="version.environment === 'staging'"
          type="warning"
          :bordered="false"
          >测试证书不受浏览器信任，请申请正式证书用于网站。</n-alert
        >
        <dl class="cert-stats">
          <div>
            <dt>生效时间</dt>
            <dd>{{ date(version.summary.chain_not_before) }}</dd>
          </div>
          <div>
            <dt>到期时间</dt>
            <dd>{{ date(version.summary.chain_not_after) }}</dd>
          </div>
          <div>
            <dt>签发机构</dt>
            <dd>{{ version.summary.issuer }}</dd>
          </div>
        </dl>
        <div class="cert-section">
          <h3>适用域名与 IP</h3>
          <div class="cert-actions">
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
        </div>
      </template>
      <p class="muted">
        {{
          activeBindings.length
            ? "此证书已有网站使用，可在“网站证书”查看生效情况并更新。"
            : "此证书尚未用于网站，点击“用于网站”继续。"
        }}
      </p>
      <p
        v-if="selected.bindings.length || selected.historical_references"
        class="muted"
      >
        网站或历史配置仍在使用此证书，暂不能删除。
      </p>
    </section>
    <FormDialog
      :show="importing"
      :title="replaceID ? '更新证书文件' : '导入证书'"
      :busy="busy"
      width="760px"
      submit-text="确认导入"
      @submit="save"
      @cancel="closeImport"
    >
      <n-form-item label="名称"
        ><n-input v-model:value="name" :maxlength="128"
      /></n-form-item>
      <n-form-item label="备注"
        ><n-input v-model:value="notes" :maxlength="2048"
      /></n-form-item>
      <n-form-item label="证书文件"
        ><div style="width: 100%">
          <input
            type="file"
            accept=".pem,.crt,.cer"
            :disabled="busy"
            @change="readFile($event, 'chain')"
          />
          <p v-if="chainName" class="muted">已选择：{{ chainName }}</p>
        </div></n-form-item
      >
      <n-form-item label="私钥文件"
        ><div style="width: 100%">
          <input
            type="file"
            accept=".pem,.key"
            :disabled="busy"
            @change="readFile($event, 'key')"
          />
          <p v-if="keyName" class="muted">已选择：{{ keyName }}</p>
        </div></n-form-item
      >
      <p class="muted">请选择配套的证书和私钥文件。私钥导入后会加密保存。</p>
    </FormDialog>
  </CertificateWorkspace>
</template>
