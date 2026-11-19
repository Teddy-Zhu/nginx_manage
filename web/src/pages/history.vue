<route lang="json">
{
  "meta": {
    "title": "清理存储",
    "subtitle": "清理不再使用的历史文件",
    "nav": false,
    "order": 5.2,
    "symbol": "◷",
    "parent": "/settings"
  }
}
</route>

<script setup lang="ts">
import { randomUUID } from "../utils/crypto";

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
});
const preview = ref<HistoryPreview | null>(null);
const result = ref<HistoryResult | null>(null);
const pending = ref<{ token: string; key: string } | null>(null);
const total = computed(() => preview.value?.items.length ?? 0);
const names: Record<string, string> = {
  revision: "旧配置文件",
  certificate: "证书版本",
  order: "ACME 订单",
  migration: "迁移计划载荷",
};
function bytes(value: number) {
  return `${(value / 1024).toFixed(1)} KiB`;
}
const scopeColumns: DataTableColumns<HistoryScope> = [
  { title: "材料类别", key: "kind", render: (r) => names[r.kind] },
  { title: "本批清理", key: "selected" },
  { title: "清理后保留", key: "retained" },
  { title: "本批材料大小", key: "bytes", render: (r) => bytes(r.bytes) },
  { title: "后续批次", key: "more", render: (r) => (r.more ? "有" : "无") },
];
const itemColumns: DataTableColumns<HistoryItem> = [
  { title: "类别", key: "kind", render: (r) => names[r.kind] },
  {
    title: "证书版本",
    key: "version",
    render: (r) =>
      r.kind === "certificate" && r.version ? `#${r.version}` : "—",
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
    if (pending.value) throw new Error("请先核对上次清理结果");
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
        throw new Error("请先预览可清理的历史材料");
      pending.value = { token: preview.value.token, key: randomUUID() };
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
  }, "历史材料已清理");
}
</script>

<template>
  <NTabs type="line" animated>
    <NTabPane name="database" tab="历史记录">
      <div class="page-stack">
        <NAlert type="info" :bordered="false">
          清理超过保留期限且不再使用的旧记录。当前配置、最新证书和未完成任务会保留，操作日志仍可查询。清理后无法恢复。
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
          </div>
          <NButton :loading="busy" :disabled="!!pending" @click="inspect">
            预览清理范围
          </NButton>
        </section>
        <NAlert v-if="pending" type="warning" :bordered="false">
          上次清理结果待确认。请使用原请求核对结果。
          <NButton :loading="busy" @click="execute">
            核对原操作结果
          </NButton>
        </NAlert>
        <section v-if="preview" class="surface page-stack">
          <div class="toolbar">
            <span>本批 {{ total }} 项，每类最多 100 项</span>
            <NPopconfirm v-if="!pending" @positive-click="execute">
              <template #trigger>
                <NButton type="error" :loading="busy" :disabled="!total">
                  清理本批材料
                </NButton>
              </template>
              确认清理本批 {{ total }} 项历史材料？清理后无法再加载。
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
          <NAlert type="success" :bordered="false">
            已完成清理
          </NAlert>
          <NDataTable
            :columns="scopeColumns"
            :data="result.scopes"
            :bordered="false"
          />
        </section>
      </div>
    </NTabPane>
    <NTabPane name="runtime" tab="旧文件" display-directive="if">
      <RuntimeHistory />
    </NTabPane>
  </NTabs>
</template>
