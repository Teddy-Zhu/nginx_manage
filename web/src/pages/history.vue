<route lang="json">
{
  "meta": {
    "title": "历史维护",
    "subtitle": "预览并清理不再使用的历史材料",
    "nav": true,
    "order": 5.2,
    "symbol": "◷"
  }
}
</route>

<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import {
  NAlert,
  NTabs,
  NTabPane,
  NButton,
  NDataTable,
  NFormItem,
  NInputNumber,
  NPopconfirm,
  type DataTableColumns,
} from "naive-ui";
import {
  ApiError,
  useNodeAPI,
  type HistoryFilter,
  type HistoryItem,
  type HistoryPreview,
  type HistoryResult,
  type HistoryScope,
} from "../api/client";
import { useAction } from "../composables/action";
import RuntimeHistory from "../components/RuntimeHistory.vue";

const api = useNodeAPI();
const { busy, run } = useAction();
const initial = new Date(Date.now() - 30 * 86400_000);
const filter = reactive({
  before: new Date(initial.getTime() - initial.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16),
  revision_keep: 20,
  certificate_keep: 3,
  order_keep: 10,
  migration_keep: 0,
  maintenance_keep: 20,
  backup_keep: 0,
});
const preview = ref<HistoryPreview | null>(null);
const result = ref<HistoryResult | null>(null);
const pending = ref<{ token: string; key: string } | null>(null);
const total = computed(() => preview.value?.items.length ?? 0);
const names: Record<string, string> = {
  revision: "配置修订",
  certificate: "证书版本",
  order: "ACME 订单",
  migration: "迁移计划载荷",
  maintenance: "维护会话",
  backup: "已删除备份历史",
};
function bytes(value: number) {
  return `${(value / 1024).toFixed(1)} KiB`;
}
const scopeColumns: DataTableColumns<HistoryScope> = [
  { title: "材料类别", key: "kind", render: (r) => names[r.kind] },
  { title: "本批处理", key: "selected" },
  { title: "处理后保留", key: "retained" },
  { title: "本批材料大小", key: "bytes", render: (r) => bytes(r.bytes) },
  { title: "后续批次", key: "more", render: (r) => (r.more ? "有" : "无") },
];
const itemColumns: DataTableColumns<HistoryItem> = [
  { title: "类别", key: "kind", render: (r) => names[r.kind] },
  { title: "标识", key: "id", ellipsis: { tooltip: true } },
  { title: "所属资源", key: "resource_id", ellipsis: { tooltip: true } },
  {
    title: "版本",
    key: "version",
    render: (r) => (r.version ? `#${r.version}` : "—"),
  },
  {
    title: "创建时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
  { title: "材料大小", key: "bytes", render: (r) => bytes(r.bytes) },
];
watch(filter, () => {
  if (!pending.value) preview.value = null;
});

async function inspect() {
  await run(async () => {
    if (pending.value) throw new Error("请先核对上次维护结果");
    preview.value = null;
    const before = new Date(filter.before).getTime() / 1000;
    if (!Number.isFinite(before) || before < 1 || before > Date.now() / 1000)
      throw new Error("请选择过去的截止时间");
    const input: HistoryFilter = { ...filter, before: Math.floor(before) };
    preview.value = await api.previewHistory(input);
    result.value = null;
  });
}
async function execute() {
  await run(async () => {
    if (!pending.value) {
      if (!preview.value || !total.value)
        throw new Error("请先预览可处理的历史记录");
      pending.value = { token: preview.value.token, key: crypto.randomUUID() };
    }
    try {
      result.value = await api.executeHistory(
        { token: pending.value.token },
        pending.value.key,
      );
      pending.value = null;
      preview.value = null;
    } catch (error) {
      // An uncertain response must keep the original request for idempotent replay.
      if (
        error instanceof ApiError &&
        error.originNodeId === preview.value?.node_id &&
        ["CONFLICT", "VALIDATION_FAILED"].includes(error.code)
      ) {
        pending.value = null;
        preview.value = null;
      }
      throw error;
    }
  }, "历史维护已完成");
}
</script>

<template>
  <NTabs type="line" animated>
    <NTabPane name="database" tab="数据库材料">
      <div class="page-stack">
        <NAlert type="info" :bordered="false">
          仅清理截止时间之前、超出保留数量且不再被使用的历史材料。当前配置、最新证书、未完成任务和待清理的外部验证记录会保留。迁移材料仅在依赖、安装、维护与自动迁入均结束后可清理，计划摘要及原操作回执保留。
          已结束且相关任务均已完成的维护会话，以及文件已清理且维护已结束的备份历史可归档，归档后保留原查询及回执。修订、任务及审计记录仍保留；已清理材料无法再加载。本操作不回收运行文件，也不保证数据库文件缩小。
        </NAlert>
        <section class="surface">
          <div class="grid-2">
            <NFormItem label="截止时间">
              <input
                v-model="filter.before"
                type="datetime-local"
                :disabled="busy || !!pending"
              />
            </NFormItem>
            <NFormItem label="至少保留配置修订数">
              <NInputNumber
                v-model:value="filter.revision_keep"
                :min="2"
                :max="100"
                :precision="0"
                :clearable="false"
                :disabled="busy || !!pending"
              />
            </NFormItem>
            <NFormItem label="每份证书至少保留版本数">
              <NInputNumber
                v-model:value="filter.certificate_keep"
                :min="2"
                :max="16"
                :precision="0"
                :clearable="false"
                :disabled="busy || !!pending"
              />
            </NFormItem>
            <NFormItem label="每个签发配置至少保留订单数">
              <NInputNumber
                v-model:value="filter.order_keep"
                :min="2"
                :max="100"
                :precision="0"
                :clearable="false"
                :disabled="busy || !!pending"
              />
            </NFormItem>
            <NFormItem
              label="每个操作者保留迁移计划数（0 不清理，启用时至少 2 份）"
            >
              <NInputNumber
                v-model:value="filter.migration_keep"
                :min="0"
                :max="100"
                :precision="0"
                :clearable="false"
                :disabled="busy || !!pending"
              />
            </NFormItem>
            <NFormItem label="保留维护会话数（0 不归档，启用时至少 2 份）">
              <NInputNumber
                v-model:value="filter.maintenance_keep"
                :min="0"
                :max="63"
                :precision="0"
                :clearable="false"
                :disabled="busy || !!pending"
              />
            </NFormItem>
            <NFormItem label="保留近期备份记录数（0 不归档，启用时至少 2 份）">
              <NInputNumber
                v-model:value="filter.backup_keep"
                :min="0"
                :max="128"
                :precision="0"
                :clearable="false"
                :disabled="busy || !!pending"
              />
            </NFormItem>
          </div>
          <NButton :loading="busy" :disabled="!!pending" @click="inspect"
            >预览维护范围</NButton
          >
        </section>
        <NAlert v-if="pending" type="warning" :bordered="false">
          上次维护结果待确认。请使用原请求核对结果。
          <NButton :loading="busy" @click="execute">核对原操作结果</NButton>
        </NAlert>
        <section v-if="preview" class="surface page-stack">
          <div class="toolbar">
            <span>本批 {{ total }} 项，每类最多 100 项</span>
            <NPopconfirm v-if="!pending" @positive-click="execute">
              <template #trigger>
                <NButton type="error" :loading="busy" :disabled="!total"
                  >执行本批维护</NButton
                >
              </template>
              确认处理本批 {{ total }} 项记录？维护会话与备份历史归档后保留查询，其余材料清理后无法再加载。
            </NPopconfirm>
          </div>
          <NDataTable
            :columns="scopeColumns"
            :data="preview.scopes"
            :bordered="false"
          />
          <p class="muted">
            预览有效至
            {{
              new Date(preview.expires_at * 1000).toLocaleString()
            }}；引用或候选材料变化后须重新预览。
          </p>
          <NDataTable
            :columns="itemColumns"
            :data="preview.items"
            :row-key="(row: HistoryItem) => `${row.kind}:${row.id}`"
            :pagination="{ pageSize: 20 }"
            :scroll-x="1000"
            :bordered="false"
          />
        </section>
        <section v-if="result" class="surface page-stack">
          <NAlert type="success" :bordered="false"
            >已完成维护，记录标识：{{ result.id }}</NAlert
          >
          <NDataTable
            :columns="scopeColumns"
            :data="result.scopes"
            :bordered="false"
          />
        </section>
      </div>
    </NTabPane>
    <NTabPane name="runtime" tab="运行文件" display-directive="if"
      ><RuntimeHistory
    /></NTabPane>
  </NTabs>
</template>

<style scoped>
input[type="datetime-local"] {
  width: 100%;
  min-height: 34px;
  padding: 6px 10px;
  border: 1px solid #d8dee8;
  border-radius: 3px;
  background: transparent;
  color: inherit;
  font: inherit;
  box-sizing: border-box;
}
</style>
