<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NButton, NEmpty, NModal, NSelect, NTag } from "naive-ui";
import { api, type ExternalSnapshot, type SaveResult } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import SourceDiff from "./SourceDiff.vue";
const show = defineModel<boolean>("show", { required: true });
const props = defineProps<{ baseVersion: number }>();
const emit = defineEmits<{ captured: [result: SaveResult] }>();
const { run, busy } = useAction(),
  keyFor = useIdempotency();
const snapshot = ref<ExternalSnapshot | null>(null),
  selected = ref("");
const changed = computed(
  () =>
    snapshot.value?.files.filter((file) => file.status !== "unchanged") ?? [],
);
const dependencies = computed(
  () =>
    snapshot.value?.dependencies.filter(
      (file) => file.status !== "unchanged",
    ) ?? [],
);
const options = computed(() =>
  changed.value.map((file) => ({
    label: `${file.path} · ${status(file.status)}`,
    value: file.path,
  })),
);
const current = computed(() =>
  snapshot.value?.files.find((file) => file.path === selected.value),
);
function status(value: string) {
  return (
    (
      {
        modified: "修改",
        missing: "缺失",
        added: "额外文件",
        unsafe: "类型或权限异常",
        unreadable: "无法读取",
      } as Record<string, string>
    )[value] ?? value
  );
}
async function load() {
  snapshot.value = null;
  selected.value = "";
  await run(async () => {
    snapshot.value = await api.external();
  });
}
async function detail(value: unknown) {
  if (typeof value !== "string" || busy.value) return;
  selected.value = value;
  if (snapshot.value) snapshot.value.detail = null;
  await run(async () => {
    snapshot.value = await api.external(value);
  });
}
async function capture() {
  const report = snapshot.value;
  if (!report?.detail?.capture_allowed || !report.complete || busy.value)
    return;
  if (
    !window.confirm(
      `将 ${report.detail.path} 的外部变更保存为独立草稿？当前期望及运行配置不会因此改变。`,
    )
  )
    return;
  const input = {
    base_version: props.baseVersion,
    snapshot: report.snapshot,
    path: report.detail.path,
  };
  await run(async () => {
    const result = await api.captureExternal(input, keyFor(input));
    emit("captured", result);
    show.value = false;
    snapshot.value = null;
  }, "外部内容已保存为草稿，尚未应用");
}
watch(show, (visible) => {
  if (visible) void load();
  else snapshot.value = null;
});
</script>
<template>
  <n-modal
    v-model:show="show"
    preset="card"
    title="发布副本与外部修改"
    style="width: 1160px; max-width: 96vw"
    :mask-closable="!busy"
    :closable="!busy"
    :close-on-esc="!busy"
  >
    <div class="toolbar">
      <span class="muted">仅检查专用受管实例的发布目录</span
      ><n-button :loading="busy" @click="load">重新检查</n-button>
    </div>
    <n-alert type="info" :bordered="false" style="margin-bottom: 16px"
      >差异基于磁盘副本，不代表这些内容已经被 Nginx
      加载。冲突期间继续暂停应用；捕获只保存草稿，证书材料需通过证书管理导入新版本。</n-alert
    >
    <template v-if="snapshot">
      <n-alert
        v-if="!snapshot.complete"
        type="warning"
        :bordered="false"
        style="margin-bottom: 16px"
        >目录无法完整检查，禁止捕获草稿。请在本机检查目录权限、链接及文件数量。</n-alert
      >
      <n-empty
        v-if="snapshot.integrity"
        description="已记录文件与证书依赖均未发现外部修改"
      />
      <template v-if="dependencies.length"
        ><h3>证书依赖</h3>
        <div v-for="file in dependencies" :key="file.path" class="dependency">
          <n-tag type="warning" :bordered="false">{{
            status(file.status)
          }}</n-tag
          ><span class="mono">{{ file.path }}</span>
          <p class="muted">{{ file.reason }}</p>
          <p class="muted mono">
            预期 {{ file.expected_sha256 }}<br />磁盘
            {{ file.observed_sha256 || "不可读取" }}
          </p>
        </div></template
      >
      <n-select
        v-if="options.length"
        :value="selected || null"
        :options="options"
        :disabled="busy"
        placeholder="选择有外部变更的文件"
        style="margin: 16px 0"
        @update:value="detail"
      />
      <template v-if="snapshot.detail"
        ><n-alert
          v-if="current?.reason"
          type="warning"
          :bordered="false"
          style="margin-bottom: 16px"
          >{{ current.reason }}</n-alert
        ><source-diff
          :before="snapshot.detail.before_content"
          :after="snapshot.detail.after_content"
          before-label="预期发布副本"
          after-label="磁盘内容"
        />
        <p class="muted">{{ snapshot.detail.note }}</p>
        <n-button
          type="primary"
          :disabled="
            busy || !snapshot.detail.capture_allowed || !snapshot.complete
          "
          :loading="busy"
          @click="capture"
          >保存选中文件为草稿</n-button
        ></template
      >
    </template>
  </n-modal>
</template>
<style scoped>
.dependency {
  padding: 12px 0;
  border-bottom: 1px solid #e2e9e5;
  overflow-wrap: anywhere;
}
.dependency > .mono {
  margin-left: 10px;
}
.dependency p {
  margin-bottom: 0;
}
</style>
