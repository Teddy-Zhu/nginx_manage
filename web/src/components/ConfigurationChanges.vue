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
const base = ref(""),
  difference = ref<Difference | null>(null),
  selected = ref("");
const options = computed(() => {
  const rows = [
    {
      label: "已保存配置",
      value: props.tree?.revision_id ?? "",
    },
  ];
  if (
    props.appliedRevision &&
    props.appliedRevision !== props.tree?.revision_id
  )
    rows.push({
      label: "已生效配置",
      value: props.appliedRevision,
    });
  return rows;
});
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
watch(base, () => {
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
    difference.value = await api.diff(base.value, props.files);
    selected.value = difference.value.files[0]?.file_id ?? "";
  });
}
watch(show, async (visible) => {
  if (!visible) {
    difference.value = null;
    return;
  }
  base.value = props.appliedRevision || props.tree?.revision_id || "";
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
      <n-form-item label="比较基准">
        <n-select
          v-model:value="base"
          :options="options"
          :disabled="busy"
        />
      </n-form-item><n-button type="primary" :loading="busy" @click="compare">
        比较
      </n-button>
    </div>
    <p class="muted">
      与当前编辑的配置内容比较。
    </p>
    <template v-if="difference">
      <n-alert
        v-if="difference.diagnostics.length"
        type="warning"
        :bordered="false"
        style="margin-bottom: 16px"
      >
        目标原文存在
        {{ difference.diagnostics.length }}
        项解析或映射诊断。差异查看不会保存或应用配置。
      </n-alert>
      <n-select
        v-if="fileOptions.length"
        v-model:value="selected"
        :options="fileOptions"
        style="margin-bottom: 16px"
      />
      <template v-if="file">
        <p v-if="file.before_path !== file.after_path" class="muted">
          {{ file.before_path || "不存在" }} → {{ file.after_path || "不存在" }}
        </p>
        <div v-if="file.affected_resources.length" class="impact">
          <span class="muted">可能受影响：</span><n-tag
            v-for="id in file.affected_resources"
            :key="id"
            size="small"
            :bordered="false"
          >
            {{ resourceName(id) }}
          </n-tag><span v-if="file.affected_resources_truncated" class="muted">共 {{ file.affected_resource_count }} 个资源，仅展示前 100 个</span>
        </div>
        <source-diff
          :before="file.before_content"
          :after="file.after_content"
          :before-label="
            options.find((option) => option.value === base)?.label || '原配置'
          "
          after-label="当前编辑内容"
        />
      </template>
      <n-empty v-else description="配置内容没有变化" />
    </template>
  </n-modal>
</template>
<style scoped>
.comparison-selectors {
  display: grid;
  grid-template-columns: 1fr auto;
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
