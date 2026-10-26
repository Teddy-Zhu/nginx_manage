<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NButton, NEmpty, NModal, NSelect, NTag } from "naive-ui";
import {
  useNodeAPI,
  type NginxFeatures,
  type SaveResult,
  type Tree,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
const api = useNodeAPI();
const show = defineModel<boolean>("show", { required: true });
const props = defineProps<{ tree: Tree | null }>();
const emit = defineEmits<{ saved: [result: SaveResult] }>();
const { run, busy } = useAction(),
  keyFor = useIdempotency();
const report = ref<NginxFeatures | null>(null),
  selected = ref<string[]>([]);
const options = computed(() => {
  const items = (report.value?.modules ?? []).map((item) => ({
    label: item.name,
    value: item.path,
    disabled: !item.available && !selected.value.includes(item.path),
  }));
  for (const path of props.tree?.module_paths ?? []) {
    if (!items.some((item) => item.value === path))
      items.push({
        label: "不可用模块",
        value: path,
        disabled: !selected.value.includes(path),
      });
  }
  return items;
});
const invalid = computed(() =>
  selected.value.some(
    (path) =>
      !report.value?.modules.some(
        (item) => item.path === path && item.available,
      ),
  ),
);
const changed = computed(
  () =>
    JSON.stringify([...selected.value].sort()) !==
    JSON.stringify([...(props.tree?.module_paths ?? [])].sort()),
);
async function load() {
  if (busy.value) return;
  report.value = null;
  selected.value = [...(props.tree?.module_paths ?? [])];
  await run(async () => {
    report.value = await api.nginxFeatures();
  });
}
async function save() {
  if (
    !props.tree ||
    !report.value ||
    invalid.value ||
    !changed.value ||
    busy.value
  )
    return;
  const input = {
    base_version: props.tree.version,
    paths: [...selected.value],
  };
  await run(async () => {
    const result = await api.setNativeModules(input, keyFor(input));
    emit("saved", result);
    show.value = false;
  }, "模块选择已保存，请应用配置并在任务中查看结果");
}
watch(show, (visible) => {
  if (visible) void load();
  else report.value = null;
});
watch(
  () => props.tree?.version,
  () => {
    if (show.value) void load();
  },
);
</script>
<template>
  <n-modal
    v-model:show="show"
    preset="card"
    title="Nginx 可选模块"
    style="width: 820px; max-width: 94vw"
    :mask-closable="!busy"
    :closable="!busy"
    :close-on-esc="!busy"
  >
    <n-alert type="info" :bordered="false"
      >常用模块已内置。启用可选功能后，请应用配置使其生效。</n-alert
    >
    <div class="toolbar" style="margin-top: 16px">
      <span class="muted">Nginx {{ report?.version || "版本未知" }}</span
      ><n-button :loading="busy" @click="load">刷新</n-button>
    </div>
    <template v-if="report">
      <n-alert
        v-if="report.reason"
        type="warning"
        :bordered="false"
        style="margin-bottom: 16px"
        >{{ report.reason }}</n-alert
      >
      <n-empty
        v-if="!options.length"
        description="当前没有可选模块，内置功能已可使用。"
      />
      <template v-else>
        <n-select
          v-model:value="selected"
          multiple
          :options="options"
          :disabled="busy"
          placeholder="选择可选功能"
        />
        <div v-for="item in report.modules" :key="item.path" class="module-row">
          <div>
            <strong>{{ item.name }}</strong>

            <p v-if="item.features.length" class="muted">
              提供能力：{{ item.features.join("、") }}
            </p>
            <p v-if="item.reason" class="muted">{{ item.reason }}</p>
          </div>
          <div class="inline-gap">
            <n-tag
              :type="item.available ? 'success' : 'warning'"
              :bordered="false"
              >{{ item.available ? "可选择" : "不可选择" }}</n-tag
            ><n-tag
              :type="item.running ? 'success' : 'default'"
              :bordered="false"
              >{{ item.running ? "已启用" : "未启用" }}</n-tag
            >
          </div>
        </div>
        <n-alert
          v-if="invalid"
          type="warning"
          :bordered="false"
          style="margin-top: 16px"
          >所选模块包含未批准或不可用版本。请移除或选择可用版本后保存。</n-alert
        >
        <n-button
          type="primary"
          :loading="busy"
          :disabled="busy || invalid || !changed || !tree"
          style="margin-top: 16px"
          @click="save"
          >保存模块选择</n-button
        >
      </template>
    </template>
  </n-modal>
</template>
<style scoped>
.module-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  border-bottom: 1px solid #e2e9e5;
  padding: 16px 0;
}
.module-row > div:first-child {
  min-width: 0;
}
.module-row p {
  margin: 6px 0 0;
  overflow-wrap: anywhere;
}
@media (max-width: 640px) {
  .module-row {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
