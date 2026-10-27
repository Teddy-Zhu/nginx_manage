<route lang="json">
{
  "meta": {
    "title": "网站访问控制",
    "subtitle": "管理网站的 IP 与国家黑白名单",
    "nav": true,
    "order": 12,
    "symbol": "◈",
    "group": "网站服务",
    "software": "nginx"
  }
}
</route>

<script setup lang="ts">
import FormDialog from "../components/FormDialog.vue";
import ValueListInput from "../components/ValueListInput.vue";
import { cleanList } from "../utils/form";
import { computed, h, onMounted, onUnmounted, ref } from "vue";
import { onBeforeRouteLeave } from "vue-router";
import {
  NAlert,
  NButton,
  NDataTable,
  NFormItem,
  NInput,
  NModal,
  NRadio,
  NRadioGroup,
  NSelect,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  type AccessList,
  type Tree,
  type GeoIPState,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import GeoIPSourcePanel from "../components/GeoIPSourcePanel.vue";
import { countryOptions } from "../utils/countries";
const api = useNodeAPI();

const { run, busy } = useAction(),
  keyFor = useIdempotency();
const tree = ref<Tree | null>(null),
  selected = ref<AccessList | null>(null),
  editing = ref(false);
const name = ref(""),
  notes = ref(""),
  mode = ref<"allowlist" | "denylist">("denylist"),
  entries = ref<string[]>([]);
const countries = ref<string[]>([]);
const addressCount = computed(() => cleanList(entries.value).length);
const ruleSummary = computed(() =>
  mode.value === "allowlist"
    ? "仅允许名单中的 IP 或国家访问，其余访问将被拒绝。"
    : "阻止名单中的 IP 或国家访问，其余访问不受此名单限制。",
);
const geoIP = ref<GeoIPState | null>(null);
const geoError = ref("");
const sourceOpen = ref(false);
const usedCountries = computed(() => [
  ...new Set([
    ...(tree.value?.access_lists.flatMap((list) => list.countries) ?? []),
    ...countries.value,
  ]),
]);
const countryNames = (codes: string[]) =>
  codes
    .map(
      (code) =>
        countryOptions.find((option) => option.value === code)?.label ?? code,
    )
    .join("、");
const baseline = ref("");
const formJSON = computed(() =>
  JSON.stringify({
    name: name.value,
    notes: notes.value,
    mode: mode.value,
    entries: entries.value,
    countries: countries.value,
  }),
);
const dirty = computed(
  () => editing.value && baseline.value !== formJSON.value,
);
const affected = computed(
  () =>
    tree.value?.resources.filter((item) =>
      item.fields.access_list?.values.includes(selected.value?.id ?? ""),
    ) ?? [],
);
const columns: DataTableColumns<AccessList> = [
  {
    title: "名称",
    key: "name",
    render: (row) => row.name || row.id.slice(0, 8),
  },
  {
    title: "模式",
    key: "mode",
    render: (row) =>
      row.mode === "allowlist"
        ? "白名单"
        : row.mode === "denylist"
          ? "黑名单"
          : "自定义规则",
  },
  { title: "地址数", key: "entries", render: (row) => row.entries.length },
  {
    title: "国家和地区",
    key: "countries",
    render: (row) =>
      row.countries.length ? countryNames(row.countries) : "未添加",
  },
  {
    title: "状态",
    key: "editable",
    render: (row) => (row.editable ? "可编辑" : "通过高级配置编辑"),
  },
  {
    title: "操作",
    key: "actions",
    width: 90,
    render: (row) =>
      h(
        NButton,
        { size: "small", disabled: busy.value, onClick: () => open(row) },
        { default: () => (row.editable ? "编辑" : "查看") },
      ),
  },
];
function open(row: AccessList | null) {
  if (dirty.value && !window.confirm("修改尚未保存，确认切换？")) return;
  selected.value = row;
  editing.value = true;
  name.value = row?.name ?? "";
  notes.value = row?.notes ?? "";
  mode.value = row?.mode === "allowlist" ? "allowlist" : "denylist";
  entries.value = [...(row?.entries ?? [])];
  countries.value = [...(row?.countries ?? [])];
  baseline.value = formJSON.value;
}
function close() {
  if (
    busy.value ||
    (dirty.value && !window.confirm("修改尚未保存，确认取消？"))
  )
    return;
  editing.value = false;
  selected.value = null;
}
async function load() {
  if (dirty.value && !window.confirm("修改尚未保存，确认重新加载？")) return;
  await run(async () => {
    tree.value = await api.tree();
    selected.value = null;
    editing.value = false;
    try {
      geoIP.value = await api.firewallGeoIP();
      geoError.value = "";
    } catch (error) {
      geoError.value =
        error instanceof Error ? error.message : "国家 IP 数据加载失败";
    }
  });
}
async function save() {
  if (!tree.value || (selected.value && !selected.value.editable)) return;
  const id = selected.value?.id ?? null;
  const input = {
    base_version: tree.value.version,
    name: name.value,
    notes: notes.value,
    mode: mode.value,
    countries: countries.value,
    entries: cleanList(entries.value),
  };
  await run(async () => {
    const out = await api.saveAccessList(id, input, keyFor({ id, ...input }));
    tree.value = out.tree;
    baseline.value = formJSON.value;
    editing.value = false;
    selected.value = null;
  }, "访问名单已保存，尚未应用");
}
async function remove() {
  if (!selected.value || !tree.value || affected.value.length || dirty.value)
    return;
  const id = selected.value.id,
    version = tree.value.version;
  if (!window.confirm(`确认删除访问名单 ${selected.value.name || id}？`))
    return;
  await run(async () => {
    const out = await api.deleteAccessList(
      id,
      version,
      keyFor({ action: "delete-access-list", id, version }),
    );
    tree.value = out.tree;
    selected.value = null;
    editing.value = false;
  }, "访问名单已移除");
}
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (dirty.value) event.preventDefault();
};
onBeforeRouteLeave(
  () => !dirty.value || window.confirm("修改尚未保存，确认离开？"),
);
onMounted(() => {
  void load();
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => window.removeEventListener("beforeunload", beforeUnload));
</script>

<template>
  <div class="page-stack">
    <div class="page-toolbar">
      <p class="muted">
        创建访问名单后，在<router-link to="/nginx">网站与代理</router-link
        >中选择使用并应用。
      </p>
      <div class="inline-gap">
        <n-button :disabled="busy" @click="sourceOpen = true"
          >国家 IP 数据</n-button
        >
        <n-button :loading="busy" @click="load">刷新</n-button>
        <n-button type="primary" :disabled="busy" @click="open(null)"
          >新建访问名单</n-button
        >
      </div>
    </div>
    <section class="surface">
      <n-data-table
        :columns="columns"
        :data="tree?.access_lists ?? []"
        :bordered="false"
      />
    </section>
  </div>
  <NModal
    v-model:show="sourceOpen"
    preset="card"
    title="数据源与更新"
    style="width: 880px; max-width: calc(100vw - 32px)"
  >
    <n-alert
      v-if="geoError"
      type="warning"
      :bordered="false"
      class="access-notice"
      >{{ geoError }}</n-alert
    >
    <GeoIPSourcePanel
      :state="geoIP"
      :writable="!busy"
      :countries="usedCountries"
      @changed="geoIP = $event"
    />
  </NModal>
  <FormDialog
    :show="editing"
    :title="
      selected
        ? selected.editable
          ? '编辑访问名单'
          : '查看访问名单'
        : '新建访问名单'
    "
    :busy="busy"
    width="860px"
    :form-disabled="selected?.editable === false"
    :submit-disabled="
      selected?.editable === false ||
      (countries.length > 0 && !geoIP?.ready) ||
      (!!selected &&
        !dirty &&
        !(
          countries.length &&
          geoIP &&
          geoIP.updated_at !== selected.geoip_updated_at
        ))
    "
    @submit="save"
    @cancel="close"
  >
    <div class="access-editor">
      <n-alert
        v-if="selected && !selected.editable"
        type="warning"
        :bordered="false"
        >{{ selected.reason }}</n-alert
      >
      <n-form-item :show-feedback="false" label="名单名称">
        <n-input
          v-model:value="name"
          :maxlength="128"
          placeholder="例如：办公网络、网站访问黑名单"
        />
      </n-form-item>
      <section class="access-section">
        <h3>访问方式</h3>
        <template v-if="!selected || selected.editable">
          <NRadioGroup
            v-model:value="mode"
            :disabled="busy || selected?.editable === false"
            class="access-mode-options"
            aria-label="访问方式"
          >
            <NRadio
              value="denylist"
              class="access-mode"
              :class="{ active: mode === 'denylist' }"
            >
              <strong>黑名单</strong><span>阻止名单内访问</span>
            </NRadio>
            <NRadio
              value="allowlist"
              class="access-mode"
              :class="{ active: mode === 'allowlist' }"
            >
              <strong>白名单</strong><span>仅允许名单内访问</span>
            </NRadio>
          </NRadioGroup>
          <p class="section-note">{{ ruleSummary }}</p>
        </template>
        <p v-else>
          {{
            selected.mode === "allowlist"
              ? "白名单"
              : selected.mode === "denylist"
                ? "黑名单"
                : "自定义规则"
          }}
        </p>
      </section>
      <section class="access-section">
        <div class="access-section-heading">
          <h3>名单内容</h3>
          <span class="section-note"
            >{{ addressCount }} 个地址 ·
            {{ countries.length }} 个国家或地区</span
          >
        </div>
        <p class="section-note">
          IP 和国家可以同时添加，命中其中任意一项即可匹配名单。
        </p>
        <div class="access-criteria">
          <div class="access-criterion">
            <n-form-item :show-feedback="false" label="IP 地址与网段（可选）">
              <ValueListInput
                v-model:value="entries"
                item-label="地址"
                placeholder="192.0.2.1 或 2001:db8::/32"
                :maxlength="64"
                :max="128"
                :disabled="busy || selected?.editable === false"
              />
            </n-form-item>
            <p class="section-note">
              支持 IPv4、IPv6 和网段，最多添加 128 项。
            </p>
          </div>
          <div class="access-criterion">
            <n-form-item :show-feedback="false" label="国家和地区（可选）">
              <n-select
                v-model:value="countries"
                multiple
                filterable
                clearable
                :options="countryOptions"
                placeholder="搜索并选择国家或地区"
              />
            </n-form-item>
            <p class="section-note">使用国家 IP 数据识别访问来源。</p>
            <n-alert
              v-if="countries.length && (!geoIP?.ready || geoError)"
              type="warning"
              :bordered="false"
            >
              {{ geoError || "国家 IP 数据尚未就绪，请更新后保存。" }}
              <n-button
                text
                type="primary"
                :disabled="busy || selected?.editable === false"
                @click="sourceOpen = true"
                >管理国家数据</n-button
              >
            </n-alert>
            <p v-if="selected?.geoip_updated_at" class="section-note">
              名单数据更新于
              {{
                new Date(selected.geoip_updated_at * 1000).toLocaleString()
              }}。更新国家数据后，重新保存并应用此名单。
            </p>
          </div>
        </div>
        <n-alert
          v-if="
            mode === 'allowlist' &&
            !addressCount &&
            !countries.length &&
            (!selected || selected.editable)
          "
          type="warning"
          :bordered="false"
          >白名单为空时，将拒绝所有访问。</n-alert
        >
      </section>
      <n-form-item :show-feedback="false" label="备注（可选）">
        <n-input
          v-model:value="notes"
          type="textarea"
          :autosize="{ minRows: 2, maxRows: 4 }"
          :maxlength="2048"
          placeholder="填写这份名单的用途"
        />
      </n-form-item>
      <div v-if="selected" class="access-usage">
        <span class="section-note">使用此名单的网站</span>
        <p>
          {{
            affected
              .map(
                (item) =>
                  item.metadata.name ||
                  item.fields.domains?.values[0] ||
                  item.id.slice(0, 8),
              )
              .join("、") || "暂未使用"
          }}
        </p>
      </div>
    </div>
    <template #actions>
      <n-button
        v-if="selected"
        type="error"
        :disabled="busy || dirty || !!affected.length"
        @click="remove"
        >删除</n-button
      >
    </template>
  </FormDialog>
</template>

<style scoped>
.access-editor {
  display: grid;
  gap: 24px;
  container-type: inline-size;
}
.access-editor > .n-form-item {
  margin-bottom: 0;
}
.access-section {
  display: grid;
  gap: 14px;
}
.access-section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
}
.access-mode-options {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.access-mode {
  margin: 0;
  padding: 16px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
}
.access-mode.active {
  border-color: #087f68;
  background: #f5faf7;
}
.access-mode :deep(.n-radio__label) {
  display: grid;
  gap: 4px;
}
.access-mode span {
  font-size: 13px;
  color: var(--text-muted);
}
.access-criteria {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px;
  align-items: start;
}
.access-criterion {
  display: grid;
  gap: 12px;
  min-width: 0;
  padding: 18px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
}
.access-criterion :deep(.n-form-item) {
  margin-bottom: 0;
}
.access-usage {
  display: grid;
  gap: 6px;
  border-top: 1px solid var(--border-color);
  padding-top: 18px;
}
.access-notice {
  margin-bottom: 16px;
}
@container (max-width: 620px) {
  .access-criteria,
  .access-mode-options {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
