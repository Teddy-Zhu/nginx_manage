<script setup lang="ts">
import { randomUUID } from "../utils/crypto";

import { computed, h, onMounted, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NFormItem,
  NInputNumber,
  NPopconfirm,
  NSelect,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  type RuntimeHistoryExecuteInput,
  type RuntimeHistoryPreview,
  type RuntimeHistoryStatus,
} from "../api/client";
import { useAction } from "../composables/action";

const api = useNodeAPI();
const { busy, run } = useAction();
const records = ref<RuntimeHistoryStatus[]>([]);
const preview = ref<RuntimeHistoryPreview | null>(null);
const pending = ref<RuntimeHistoryExecuteInput | null>(null);
const kind = ref("publication"),
  keep = ref<number | null>(20);
const initial = new Date(Date.now() - 30 * 86400_000);
const before = ref(
  new Date(initial.getTime() - initial.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16),
);
const savedPending = computed(() =>
  records.value.find((r) => r.state !== "succeeded"),
);
const options = [
  { label: "Nginx 发布目录", value: "publication" },
  { label: "证书运行副本", value: "certificate" },
];
const states: Record<string, string> = {
  running: "清理中",
  recovery_required: "待续办",
  succeeded: "已清理",
};
const columns: DataTableColumns<RuntimeHistoryStatus> = [
  {
    title: "材料",
    key: "preview.filter.kind",
    render: (r) =>
      r.preview.filter.kind === "publication" ? "发布目录" : "证书副本",
  },
  { title: "状态", key: "state", render: (r) => states[r.state] },
  {
    title: "目录数",
    key: "preview.targets",
    render: (r) => r.preview.targets.length,
  },
  {
    title: "更新时间",
    key: "updated_at",
    render: (r) => new Date(r.updated_at * 1000).toLocaleString(),
  },
  {
    title: "操作",
    key: "actions",
    render: (r) =>
      r.state === "succeeded"
        ? "—"
        : h(
            NButton,
            {
              size: "small",
              disabled: busy.value,
              onClick: () => execute(r),
            },
            { default: () => "继续清理" },
          ),
  },
];
watch([kind, keep, before], () => {
  preview.value = null;
});
async function refresh() {
  records.value = await api.runtimeHistory();
  const completed =
    pending.value &&
    records.value.find(
      (r) =>
        r.operation_id === pending.value?.operation_id &&
        r.state === "succeeded",
    );
  if (completed) {
    pending.value = null;
    preview.value = null;
  }
}
async function load() {
  await run(refresh);
}
async function inspect() {
  await run(async () => {
    await refresh();
    if (savedPending.value) throw new Error("请先继续清理已有清理操作");
    const cutoff = new Date(before.value).getTime() / 1000;
    if (
      !Number.isFinite(cutoff) ||
      cutoff < 1 ||
      cutoff > Date.now() / 1000 ||
      keep.value === null
    )
      throw new Error("请选择过去的截止时间及保留数量");
    preview.value = null;
    pending.value = null;
    preview.value = await api.previewRuntimeHistory({
      kind: kind.value,
      before: Math.floor(cutoff),
      keep: keep.value,
    });
  });
}
async function execute(record?: RuntimeHistoryStatus) {
  await run(async () => {
    if (record)
      pending.value = {
        operation_id: record.operation_id,
        filter: record.preview.filter,
        sha256: record.preview.sha256,
      };
    if (!pending.value) {
      if (!preview.value?.targets.length) throw new Error("请先预览运行材料");
      pending.value = {
        operation_id: randomUUID(),
        filter: preview.value.filter,
        sha256: preview.value.sha256,
      };
    }
    try {
      await api.executeRuntimeHistory(pending.value);
      pending.value = null;
      preview.value = null;
    } finally {
      await refresh();
    }
  }, "运行材料清理已确认");
}
onMounted(load);
</script>

<template>
  <div class="page-stack">
    <NAlert type="info" :bordered="false">
      清理不再使用的旧配置文件和证书副本，保留当前运行所需的文件。未完成的清理可以继续执行。
    </NAlert>
    <div class="toolbar">
      <NButton :loading="busy" @click="load">
        刷新状态
      </NButton>
    </div>
    <section class="surface">
      <div class="grid-2">
        <NFormItem label="材料类别">
          <NSelect
            v-model:value="kind"
            :options="options"
            :disabled="busy || !!savedPending"
          />
        </NFormItem>
        <NFormItem label="截止时间">
          <input
            v-model="before"
            type="datetime-local"
            :disabled="busy || !!savedPending"
          />
        </NFormItem>
        <NFormItem
          :label="
            kind === 'certificate'
              ? '每张证书至少保留副本数'
              : '至少保留发布目录数'
          "
        >
          <NInputNumber
            v-model:value="keep"
            :min="2"
            :max="32"
            :precision="0"
            :clearable="false"
            :disabled="busy || !!savedPending"
          />
        </NFormItem>
      </div>
      <NButton :loading="busy" :disabled="!!savedPending" @click="inspect">
        查看可清理文件
      </NButton>
    </section>
    <NAlert v-if="pending" type="warning" :bordered="false">
      上次清理的结果尚未确认，请继续核对。
      <NButton :loading="busy" :disabled="busy" @click="execute()">
        核对并继续清理
      </NButton>
    </NAlert>
    <section v-if="preview" class="surface page-stack">
      <div class="toolbar">
        <span>{{ preview.targets.length }} 个目录，{{ preview.entries }} 个条目，{{
          (preview.bytes / 1024).toFixed(1)
        }}
          KiB{{ preview.more ? "；还有后续批次" : "" }}</span>
        <NPopconfirm v-if="!pending" @positive-click="() => execute()">
          <template #trigger>
            <NButton type="error" :disabled="busy || !preview.targets.length">
              清理本批文件
            </NButton>
          </template>
          确认清理所选旧文件？清理后无法恢复。
        </NPopconfirm>
      </div>
    </section>
    <section class="surface page-stack">
      <h3>最近清理记录</h3>
      <NDataTable
        :columns="columns"
        :data="records"
        :row-key="(row: RuntimeHistoryStatus) => row.operation_id"
        :bordered="false"
        :scroll-x="1000"
      />
      <NAlert v-if="savedPending" type="warning" :bordered="false">
        {{
          savedPending.error || "原清理操作尚未结束"
        }}
      </NAlert>
    </section>
  </div>
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
