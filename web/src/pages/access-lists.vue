<route lang="json">
{
  "meta": {
    "title": "网站访问控制",
    "subtitle": "管理网站的 IP 与国家黑白名单",
    "nav": true,
    "order": 3,
    "symbol": "◈",
    "group": "网站与安全",
    "software": "nginx"
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
  entries = ref("");
const countries = ref<string[]>([]);
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
      row.countries.length ? countryNames(row.countries) : "未限制",
  },
  {
    title: "状态",
    key: "editable",
    render: (row) => (row.editable ? "可编辑" : "通过高级配置编辑"),
  },
];
function open(row: AccessList | null) {
  if (dirty.value && !window.confirm("修改尚未保存，确认切换？")) return;
  selected.value = row;
  editing.value = true;
  name.value = row?.name ?? "";
  notes.value = row?.notes ?? "";
  mode.value = row?.mode === "allowlist" ? "allowlist" : "denylist";
  entries.value = row?.entries.join("\n") ?? "";
  countries.value = [...(row?.countries ?? [])];
  baseline.value = formJSON.value;
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
  const previous = new Set(tree.value.access_lists.map((item) => item.id));
  const input = {
    base_version: tree.value.version,
    name: name.value,
    notes: notes.value,
    mode: mode.value,
    countries: countries.value,
    entries: entries.value
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  };
  await run(async () => {
    const out = await api.saveAccessList(id, input, keyFor({ id, ...input }));
    tree.value = out.tree;
    baseline.value = formJSON.value;
    const updated = out.tree.access_lists.find((item) =>
      id ? item.id === id : !previous.has(item.id),
    );
    if (updated) open(updated);
  }, "访问列表已保存，尚未应用");
}
async function remove() {
  if (!selected.value || !tree.value || affected.value.length || dirty.value)
    return;
  const id = selected.value.id,
    version = tree.value.version;
  if (!window.confirm(`确认删除访问列表 ${selected.value.name || id}？`))
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
  }, "访问列表已移除");
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
  <div class="toolbar" style="justify-content: flex-end">
    <div class="inline-gap">
      <n-button :loading="busy" @click="load">刷新</n-button
      ><n-button type="primary" :disabled="busy" @click="open(null)"
        >新建访问列表</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >白名单仅允许所选 IP 或国家访问，黑名单阻止所选 IP 或国家访问。保存后，在
    <router-link to="/nginx">网站与代理</router-link> 中绑定并应用。</n-alert
  >
  <section class="surface" style="margin-bottom: 20px">
    <div v-if="!sourceOpen" class="section-heading">
      <h2>国家 IP 数据</h2>
      <n-button @click="sourceOpen = true">管理数据源</n-button>
    </div>
    <n-alert v-if="geoError" type="warning" :bordered="false">{{
      geoError
    }}</n-alert>
    <GeoIPSourcePanel
      v-if="sourceOpen"
      :state="geoIP"
      :writable="!busy"
      :countries="usedCountries"
      @changed="geoIP = $event"
    >
      <template #actions
        ><n-button @click="sourceOpen = false">收起</n-button></template
      >
    </GeoIPSourcePanel>
    <p v-else class="muted">
      {{
        geoIP?.ready
          ? `${geoIP.source.name} · 最近更新 ${new Date(geoIP.updated_at * 1000).toLocaleString()}`
          : "添加国家规则前，请先更新国家 IP 数据。"
      }}
    </p>
  </section>
  <div class="two-columns">
    <section class="surface">
      <div class="section-heading"><h2>访问列表</h2></div>
      <n-data-table
        :columns="columns"
        :data="tree?.access_lists ?? []"
        :bordered="false"
        :row-props="
          (row: AccessList) => ({
            onClick: () => {
              if (!busy) open(row);
            },
            style: 'cursor: pointer',
          })
        "
      />
    </section>
    <section class="surface">
      <template v-if="editing">
        <div class="section-heading">
          <h2>{{ selected ? "编辑访问列表" : "新建访问列表" }}</h2>
          <n-button
            v-if="selected"
            type="error"
            :disabled="busy || dirty || !!affected.length"
            @click="remove"
            >删除</n-button
          >
        </div>
        <n-alert
          v-if="selected && !selected.editable"
          type="warning"
          :bordered="false"
          style="margin-bottom: 20px"
          >{{ selected.reason }}</n-alert
        >
        <n-form :disabled="busy" label-placement="top" @submit.prevent="save">
          <n-form-item label="名称"
            ><n-input
              v-model:value="name"
              :maxlength="128"
              :disabled="busy || selected?.editable === false"
          /></n-form-item>
          <n-form-item label="备注"
            ><n-input
              v-model:value="notes"
              type="textarea"
              :maxlength="2048"
              :disabled="busy || selected?.editable === false"
          /></n-form-item>
          <n-form-item label="模式"
            ><n-select
              v-model:value="mode"
              :options="[
                { label: '白名单', value: 'allowlist' },
                { label: '黑名单', value: 'denylist' },
              ]"
              :disabled="busy || selected?.editable === false"
          /></n-form-item>
          <n-form-item label="地址（每行一个 IP 或 CIDR，最多 128 项）"
            ><n-input
              v-model:value="entries"
              type="textarea"
              :autosize="{ minRows: 6, maxRows: 16 }"
              placeholder="192.0.2.1&#10;2001:db8::/32"
              :disabled="busy || selected?.editable === false"
          /></n-form-item>
          <n-form-item label="国家和地区"
            ><n-select
              v-model:value="countries"
              multiple
              filterable
              :options="countryOptions"
              :disabled="busy || selected?.editable === false"
              placeholder="选择国家和地区，可与 IP 地址一起使用"
          /></n-form-item>
          <n-alert
            v-if="countries.length && !geoIP?.ready"
            type="warning"
            :bordered="false"
            >请先在“管理数据源”中更新国家 IP 数据。</n-alert
          >
          <p v-if="selected?.geoip_updated_at" class="muted">
            当前规则的国家数据：{{
              new Date(selected.geoip_updated_at * 1000).toLocaleString()
            }}。更新数据后，重新保存并应用规则以同步。
          </p>
          <p
            v-if="mode === 'allowlist' && !entries.trim() && !countries.length"
            class="muted"
          >
            空白名单会拒绝全部地址。
          </p>
          <p class="muted">
            关联代理：{{
              affected
                .map((item) => item.metadata.name || item.id.slice(0, 8))
                .join("、") || "无"
            }}
          </p>
          <n-button
            type="primary"
            attr-type="submit"
            :loading="busy"
            :disabled="
              busy ||
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
            >保存规则</n-button
          >
        </n-form> </template
      ><n-empty v-else description="选择或新建访问列表" />
    </section>
  </div>
</template>
