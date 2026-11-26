<script setup lang="ts">
import { computed, h, ref, watch } from "vue";
import {
  NButton,
  NDataTable,
  NEmpty,
  NInput,
  NSelect,
  NTag,
  NTooltip,
  type DataTableColumns,
} from "naive-ui";
import type { Resource } from "../api/types";
import { nginxArgs } from "../utils/form";
import { siteName } from "../utils/nginx";

const props = defineProps<{
  resources: Resource[];
  busy: boolean;
  dirty: boolean;
}>();
const emit = defineEmits<{
  edit: [resource: Resource, mode: "edit" | "copy"];
  create: [];
}>();

const siteSearch = ref(""),
  siteKind = ref("all"),
  siteState = ref("all"),
  sitePage = ref(1),
  sitePageSize = ref(20);
const filteredSites = computed(() => {
  const term = siteSearch.value.trim().toLowerCase();
  return props.resources.filter(
    (item) =>
      (siteKind.value === "all" || item.kind === siteKind.value) &&
      (siteState.value === "all" ||
        item.metadata.enabled === (siteState.value === "enabled")) &&
      (!term ||
        [
          item.metadata.name,
          item.metadata.notes,
          ...["domains", "listeners", "upstream", "upstream_servers"].flatMap(
            (key) => item.fields[key]?.values ?? [],
          ),
        ].some((value) => value.toLowerCase().includes(term))),
  );
});
watch([siteSearch, siteKind, siteState], () => {
  sitePage.value = 1;
});
watch(
  () => filteredSites.value.length,
  (count) => {
    sitePage.value = Math.max(
      1,
      Math.min(sitePage.value, Math.ceil(count / sitePageSize.value)),
    );
  },
);
function siteTarget(item: Resource) {
  const members = item.fields.upstream_servers?.values ?? [];
  return members.length
    ? members.join("\n")
    : item.fields.upstream?.values.join("、") || "未设置转发目标";
}
const siteColumns: DataTableColumns<Resource> = [
  {
    title: "网站 / 服务",
    key: "name",
    width: 220,
    ellipsis: { tooltip: true },
    render: (item) =>
      h("div", { class: "site-identity" }, [
        h("strong", { class: "site-name" }, siteName(item)),
        item.metadata.notes
          ? h(
              "span",
              { class: "site-notes", title: item.metadata.notes },
              item.metadata.notes,
            )
          : null,
      ]),
  },
  {
    title: "域名",
    key: "domains",
    minWidth: 180,
    ellipsis: { tooltip: true },
    render: (item) =>
      item.kind === "http"
        ? item.fields.domains?.values.join("、") || "未设置域名"
        : "—",
  },
  {
    title: "访问入口",
    key: "listeners",
    width: 190,
    ellipsis: { tooltip: true },
    render: (item) =>
      (item.fields.listeners?.values ?? [])
        .map((value) => {
          const args = nginxArgs(value);
          return `${args[0] ?? ""} · ${args.includes("ssl") ? "HTTPS" : args.includes("udp") ? "UDP" : item.kind === "http" ? "HTTP" : "TCP"}`;
        })
        .join("、"),
  },
  {
    title: "转发目标",
    key: "upstream",
    minWidth: 220,
    render: (item) =>
      h(NTooltip, null, {
        trigger: () =>
          h("div", { class: "site-target" }, [
            (item.fields.upstream_servers?.values.length ?? 0) > 0
              ? h(
                  "span",
                  { class: "site-target-label" },
                  `服务器组 · ${item.fields.upstream_servers?.values.length ?? 0} 台`,
                )
              : null,
            h(
              "span",
              { class: "site-truncate" },
              siteTarget(item).replaceAll("\n", "、"),
            ),
          ]),
        default: () =>
          h(
            "span",
            {
              style: {
                whiteSpace: "pre-line",
                overflowWrap: "anywhere",
                maxWidth: "420px",
                display: "block",
              },
            },
            siteTarget(item),
          ),
      }),
  },
  {
    title: "状态",
    key: "enabled",
    width: 85,
    render: (item) =>
      h(
        NTag,
        {
          size: "small",
          bordered: false,
          type: item.metadata.enabled ? "success" : "default",
        },
        { default: () => (item.metadata.enabled ? "启用" : "停用") },
      ),
  },
  {
    title: "操作",
    key: "actions",
    width: 165,
    render: (item) =>
      h("div", { class: "site-actions" }, [
        h(
          NButton,
          {
            size: "small",
            quaternary: true,
            type: "primary",
            disabled: props.busy,
            onClick: () => emit("edit", item, "edit"),
          },
          { default: () => "编辑" },
        ),
        h(
          NButton,
          {
            size: "small",
            quaternary: true,
            disabled: props.busy || props.dirty,
            onClick: () => emit("edit", item, "copy"),
          },
          { default: () => "复制配置" },
        ),
      ]),
  },
];
</script>

<template>
  <section class="surface site-list">
    <div class="site-list-toolbar">
      <NInput
        v-model:value="siteSearch"
        clearable
        placeholder="搜索名称、域名、端口或转发目标"
        aria-label="搜索网站"
        class="site-search"
      />
      <NSelect
        v-model:value="siteKind"
        aria-label="筛选代理类型"
        class="site-filter"
        :options="[
          { label: '全部类型', value: 'all' },
          { label: '网站代理', value: 'http' },
          { label: '端口转发', value: 'stream' },
        ]"
      />
      <NSelect
        v-model:value="siteState"
        aria-label="筛选启用状态"
        class="site-filter"
        :options="[
          { label: '全部状态', value: 'all' },
          { label: '启用', value: 'enabled' },
          { label: '停用', value: 'disabled' },
        ]"
      />
      <span class="section-note site-count">共 {{ filteredSites.length }} 项</span>
    </div>
    <NDataTable
      :data="filteredSites"
      :columns="siteColumns"
      :row-key="(item: Resource) => item.id"
      size="small"
      :bordered="false"
      :scroll-x="1060"
      table-layout="fixed"
      :pagination="{
        page: sitePage,
        pageSize: sitePageSize,
        showSizePicker: true,
        pageSizes: [10, 20, 50],
        onUpdatePage: (value: number) => (sitePage = value),
        onUpdatePageSize: (value: number) => {
          sitePageSize = value;
          sitePage = 1;
        },
      }"
    >
      <template #empty>
        <NEmpty
          :description="
            resources.length ? '没有符合条件的网站或代理' : '尚未添加网站或代理'
          "
        >
          <template v-if="!resources.length" #extra>
            <NButton :disabled="busy || dirty" @click="emit('create')">
              添加网站 / 代理
            </NButton>
          </template>
        </NEmpty>
      </template>
    </NDataTable>
  </section>
</template>

<style scoped>
.site-list {
  padding: 16px;
}
.site-list-toolbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
}
.site-search {
  width: 340px;
  max-width: 100%;
}
.site-filter {
  width: 132px;
}
.site-count {
  margin-inline-start: auto;
  white-space: nowrap;
}
.site-list :deep(.site-actions) {
  display: flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}
.site-list :deep(.site-identity),
.site-list :deep(.site-target) {
  display: flex;
  flex-direction: column;
  min-width: 0;
  gap: 2px;
}
.site-list :deep(.site-name) {
  font-size: 13px;
  font-weight: 600;
}
.site-list :deep(.site-notes) {
  font-size: 12px;
  color: var(--text-muted);
}
.site-list :deep(.site-name),
.site-list :deep(.site-notes),
.site-list :deep(.site-truncate) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.site-list :deep(.site-target-label) {
  font-size: 12px;
  color: var(--text-muted);
}
@media (max-width: 720px) {
  .site-search {
    width: 100%;
  }
  .site-filter {
    flex: 1;
  }
  .site-list {
    padding: 12px;
  }
}
</style>
