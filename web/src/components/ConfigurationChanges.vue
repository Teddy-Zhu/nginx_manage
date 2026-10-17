<script setup lang="ts">
import { computed, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NEmpty,
  NFormItem,
  NModal,
  NSelect,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  type ConfigFile,
  type Difference,
  type Revision,
  type Tree,
} from "../api/client";
import { useAction } from "../composables/action";
import SourceDiff from "./SourceDiff.vue";
const api = useNodeAPI();
const show = defineModel<boolean>("show", { required: true });
const props = defineProps<{
  tree: Tree | null;
  files: ConfigFile[];
  appliedRevision: string;
}>();
const { run, busy } = useAction();
const revisions = ref<Revision[]>([]),
  base = ref(""),
  target = ref("editor"),
  difference = ref<Difference | null>(null),
  selected = ref("");
const options = computed(() => {
  const rows = revisions.value
    .filter((row) => !row.pruned_at)
    .map((row) => ({
      label: `修订 #${row.version}${row.state === "draft" ? "（草稿）" : ""}`,
      value: row.id,
    }));
  if (
    props.tree?.revision_id &&
    !rows.some((row) => row.value === props.tree!.revision_id)
  )
    rows.unshift({
      label: `期望修订 #${props.tree.version}`,
      value: props.tree.revision_id,
    });
  return [{ label: "初始配置", value: "" }, ...rows];
});
const targets = computed(() => [
  { label: "当前编辑原文", value: "editor" },
  ...options.value.filter((item) => item.value),
]);
const fileOptions = computed(
  () =>
    difference.value?.files.map((file) => ({
      label: `${file.after_path || file.before_path} · ${status(file.status)}`,
      value: file.file_id,
    })) ?? [],
);
const file = computed(() =>
  difference.value?.files.find((item) => item.file_id === selected.value),
);
watch([base, target], () => {
  difference.value = null;
});
function status(value: string) {
  return (
    (
      {
        added: "新增",
        removed: "移除",
        modified: "修改",
        moved: "移动",
      } as Record<string, string>
    )[value] ?? value
  );
}
async function compare() {
  difference.value = null;
  await run(async () => {
    const files =
      target.value === "editor"
        ? props.files
        : (await api.revision(target.value)).files;
    difference.value = await api.diff(base.value, files);
    selected.value = difference.value.files[0]?.file_id ?? "";
  });
}
watch(show, async (visible) => {
  if (!visible) {
    difference.value = null;
    return;
  }
  base.value = props.tree?.revision_id ?? "";
  target.value = "editor";
  await run(async () => {
    revisions.value = await api.revisions();
  });
  await compare();
});
function resourceName(id: string) {
  const item = props.tree?.resources.find((item) => item.id === id);
  return item?.metadata.name || id.slice(0, 8);
}
</script>
<template>
  <n-modal
    v-model:show="show"
    preset="card"
    title="配置差异"
    style="width: 1160px; max-width: 96vw"
    :mask-closable="!busy"
    :closable="!busy"
    :close-on-esc="!busy"
  >
    <div class="comparison-selectors">
      <n-form-item label="比较基准"
        ><n-select
          v-model:value="base"
          :options="options"
          :disabled="busy" /></n-form-item
      ><n-form-item label="比较目标"
        ><n-select
          v-model:value="target"
          :options="targets"
          :disabled="busy" /></n-form-item
      ><n-button type="primary" :loading="busy" @click="compare">比较</n-button>
    </div>
    <n-button
      v-if="appliedRevision"
      size="small"
      :disabled="busy"
      style="margin-bottom: 16px"
      @click="
        base = appliedRevision;
        target = 'editor';
        compare();
      "
      >与最近生效修订比较</n-button
    >
    <template v-if="difference">
      <n-alert
        v-if="difference.diagnostics.length"
        type="warning"
        :bordered="false"
        style="margin-bottom: 16px"
        >目标原文存在
        {{ difference.diagnostics.length }}
        项解析或映射诊断。差异查看不会保存或应用配置。</n-alert
      >
      <n-select
        v-if="fileOptions.length"
        v-model:value="selected"
        :options="fileOptions"
        style="margin-bottom: 16px"
      />
      <template v-if="file"
        ><p v-if="file.before_path !== file.after_path" class="muted">
          {{ file.before_path || "不存在" }} → {{ file.after_path || "不存在" }}
        </p>
        <div v-if="file.affected_resources.length" class="impact">
          <span class="muted">可能受影响：</span
          ><n-tag
            v-for="id in file.affected_resources"
            :key="id"
            size="small"
            :bordered="false"
            >{{ resourceName(id) }}</n-tag
          ><span v-if="file.affected_resources_truncated" class="muted"
            >共 {{ file.affected_resource_count }} 个资源，仅展示前 100 个</span
          >
        </div>
        <source-diff
          :before="file.before_content"
          :after="file.after_content"
          before-label="基准原文"
          after-label="目标原文"
      /></template>
      <n-empty v-else description="两个配置树没有原文或路径差异" />
    </template>
  </n-modal>
</template>
<style scoped>
.comparison-selectors {
  display: grid;
  grid-template-columns: 1fr 1fr auto;
  align-items: center;
  gap: 16px;
}
.impact {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 0 0 16px;
}
@media (max-width: 760px) {
  .comparison-selectors {
    grid-template-columns: 1fr;
  }
}
</style>
