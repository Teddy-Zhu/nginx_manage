<route lang="json">
{
  "meta": {
    "title": "访问列表",
    "subtitle": "复用 IPv4、IPv6 与 CIDR 访问规则",
    "nav": true,
    "order": 2,
    "symbol": "◈"
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
import { useNodeAPI, type AccessList, type Tree } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
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
const baseline = ref("");
const formJSON = computed(() =>
  JSON.stringify({
    name: name.value,
    notes: notes.value,
    mode: mode.value,
    entries: entries.value,
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
          : "原生规则",
  },
  { title: "地址数", key: "entries", render: (row) => row.entries.length },
  {
    title: "状态",
    key: "editable",
    render: (row) => (row.editable ? "可编辑" : "仅原生编辑"),
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
  baseline.value = formJSON.value;
}
async function load() {
  if (dirty.value && !window.confirm("修改尚未保存，确认重新加载？")) return;
  await run(async () => {
    tree.value = await api.tree();
    selected.value = null;
    editing.value = false;
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
  <div class="toolbar">
    <span class="muted"
      >期望修订 {{ tree?.version ? `#${tree.version}` : "尚未保存" }}</span
    >
    <div class="inline-gap">
      <n-button :loading="busy" @click="load">刷新</n-button
      ><n-button type="primary" :disabled="busy" @click="open(null)"
        >新建访问列表</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >访问列表绑定后才控制对应代理。白名单允许所列地址并拒绝其余地址，黑名单拒绝所列地址并允许其余地址。修改保存后需在
    <router-link to="/nginx">Nginx 配置</router-link> 中应用。</n-alert
  >
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
          <p v-if="mode === 'allowlist' && !entries.trim()" class="muted">
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
              busy || selected?.editable === false || (!!selected && !dirty)
            "
            >保存规则</n-button
          >
        </n-form> </template
      ><n-empty v-else description="选择或新建访问列表" />
    </section>
  </div>
</template>
