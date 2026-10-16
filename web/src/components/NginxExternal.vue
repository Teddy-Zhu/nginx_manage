<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NButton, NEmpty, NModal, NSelect, NTag } from "naive-ui";
import {
  useNodeAPI,
  type Difference,
  type ExternalSnapshot,
  type SaveResult,
  type Tree,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import SourceDiff from "./SourceDiff.vue";
const api = useNodeAPI();
const show = defineModel<boolean>("show", { required: true });
const props = defineProps<{ tree: Tree | null }>();
const emit = defineEmits<{
  captured: [result: SaveResult];
  restored: [result: SaveResult];
}>();
const { run, busy } = useAction(),
  keyFor = useIdempotency();
const snapshot = ref<ExternalSnapshot | null>(null),
  selected = ref("");
const restoreReview = ref<{
    difference: Difference;
    snapshot: string;
    version: number;
    revision: string;
  } | null>(null),
  restoreSelected = ref("");
const restorable = computed(
  () =>
    !!props.tree?.revision_id &&
    props.tree.state === "desired" &&
    !!snapshot.value?.complete &&
    !snapshot.value.integrity,
);
const reviewed = computed(
  () =>
    restorable.value &&
    restoreReview.value?.snapshot === snapshot.value?.snapshot &&
    restoreReview.value?.version === props.tree?.version &&
    restoreReview.value?.revision === props.tree?.revision_id,
);
const restoreOptions = computed(
  () =>
    restoreReview.value?.difference.files.map((file) => ({
      label: file.after_path || file.before_path,
      value: file.file_id,
    })) ?? [],
);
const restoreFile = computed(() =>
  restoreReview.value?.difference.files.find(
    (file) => file.file_id === restoreSelected.value,
  ),
);
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
const moduleDependencies = computed(
  () =>
    snapshot.value?.module_dependencies.filter(
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
  restoreReview.value = null;
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
    const next = await api.external(value);
    if (snapshot.value?.snapshot !== next.snapshot) restoreReview.value = null;
    snapshot.value = next;
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
    base_version: props.tree?.version ?? 0,
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
async function previewRestore() {
  const report = snapshot.value,
    tree = props.tree;
  if (!restorable.value || !report || !tree || busy.value) return;
  restoreReview.value = null;
  await run(async () => {
    const difference = await api.diff(report.revision_id, tree.files);
    if (
      snapshot.value?.snapshot !== report.snapshot ||
      props.tree?.version !== tree.version ||
      !show.value
    )
      return;
    restoreReview.value = {
      difference,
      snapshot: report.snapshot,
      version: tree.version,
      revision: tree.revision_id,
    };
    restoreSelected.value = difference.files[0]?.file_id ?? "";
  });
}
async function restore() {
  const review = restoreReview.value;
  if (
    !reviewed.value ||
    !review ||
    review.difference.diagnostics.length ||
    busy.value
  )
    return;
  if (
    !window.confirm(
      `发布已保存期望修订 #${review.version} 并重新加载 Nginx？原外部副本会保留；切换后若无法确认运行结果，将暂停后续配置操作。`,
    )
  )
    return;
  const input = { base_version: review.version, snapshot: review.snapshot };
  await run(async () => {
    const result = await api.restoreExternal(input, keyFor(input));
    emit("restored", result);
    show.value = false;
  }, "受管恢复已加入队列，请在任务中查看运行确认结果");
}
watch(
  () => props.tree?.version,
  () => {
    restoreReview.value = null;
  },
);
watch(show, (visible) => {
  if (visible) void load();
  else {
    snapshot.value = null;
    restoreReview.value = null;
  }
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
      加载。捕获只保存草稿；恢复会发布已保存期望修订并重新加载。损坏的证书或模块须选择有效的新版本并保存，或由本机管理员修复。</n-alert
    >
    <template v-if="snapshot">
      <n-alert
        v-if="!snapshot.complete"
        type="warning"
        :bordered="false"
        style="margin-bottom: 16px"
        >目录无法完整检查，禁止捕获和恢复。请在本机检查目录权限、链接及文件数量。</n-alert
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
      <template v-if="moduleDependencies.length">
        <h3>模块与 Nginx 二进制依赖</h3>
        <div
          v-for="file in moduleDependencies"
          :key="`${file.path}:${file.expected_sha256}`"
          class="dependency"
        >
          <n-tag type="warning" :bordered="false">{{
            status(file.status)
          }}</n-tag
          ><span class="mono">{{ file.path }}</span>
          <p class="muted">{{ file.reason }}</p>
          <p class="muted mono">
            预期 {{ file.expected_sha256 }}<br />磁盘
            {{ file.observed_sha256 || "不可读取" }}
          </p>
        </div>
      </template>
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
      <section v-if="!snapshot.integrity" class="restore-section">
        <h3>恢复受管配置</h3>
        <p class="muted">
          恢复目标为已保存期望修订。请先查看它与最近生效修订的原文差异；原外部发布副本保留，恢复后若无法确认运行结果，将暂停后续配置操作。
        </p>
        <n-alert v-if="!tree?.revision_id" type="warning" :bordered="false"
          >请先保存有效的期望修订。</n-alert
        >
        <n-button
          :disabled="busy || !restorable"
          :loading="busy"
          @click="previewRestore"
          >预览恢复目标</n-button
        >
        <template v-if="reviewed && restoreReview">
          <p>
            目标：期望修订 #{{ restoreReview.version
            }}<span class="muted mono"> · {{ restoreReview.revision }}</span>
          </p>
          <n-alert
            v-if="restoreReview.difference.diagnostics.length"
            type="warning"
            :bordered="false"
            >目标原文存在诊断，请整理并保存有效修订后再恢复。</n-alert
          >
          <n-select
            v-if="restoreOptions.length"
            v-model:value="restoreSelected"
            :options="restoreOptions"
            :disabled="busy"
            style="margin: 16px 0"
          />
          <source-diff
            v-if="restoreFile"
            :before="restoreFile.before_content"
            :after="restoreFile.after_content"
            before-label="最近生效修订原文"
            after-label="恢复目标原文"
          />
          <n-empty
            v-else
            description="目标与最近生效修订原文一致；恢复将重新生成受管发布副本"
          />
          <n-button
            type="warning"
            :disabled="busy || !!restoreReview.difference.diagnostics.length"
            :loading="busy"
            style="margin-top: 16px"
            @click="restore"
            >确认恢复并重新加载</n-button
          >
        </template>
      </section>
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
.restore-section {
  margin-top: 24px;
  border-top: 1px solid #e2e9e5;
  padding-top: 12px;
}
</style>
