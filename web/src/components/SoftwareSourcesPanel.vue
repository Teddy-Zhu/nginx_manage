<script setup lang="ts">
import FormDialog from "./FormDialog.vue";
import { computed, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NEmpty,
  NFormItem,
  NInput,
  NModal,
  NSelect,
  NTag,
} from "naive-ui";
import {
  type ComponentTask,
  type SoftwareCatalog,
  type SoftwareRequest,
  type SoftwareSource,
  type ComponentVersion,
} from "../api/client";
import { useSoftwareOperations } from "../composables/software";
import { useNodes } from "../stores/node";
import TaskLogButton from "./TaskLogButton.vue";
import SoftwareCard from "./SoftwareCard.vue";
import {
  softwareCatalogEntries,
  applicationView,
  softwareConfirmation,
  applicationActions,
  softwareApplicationTask,
  type CatalogEntry,
  type SoftwareOperation,
} from "../utils/software";
import SoftwareActions from "./SoftwareActions.vue";
import SoftwareManagementPanel from "./SoftwareManagementPanel.vue";
import ComponentVersionDialog from "./ComponentVersionDialog.vue";
const props = defineProps<{
  catalog?: SoftwareCatalog;
  tasks: ComponentTask[];
  active: boolean;
  visible: boolean;
  search: string;
  statusFilter: string;
}>();
const emit = defineEmits<{ changed: []; task: [task: ComponentTask] }>();
const {
  run,
  busy,
  permitted,
  submit: submitTask,
} = useSoftwareOperations(
  () => emit("changed"),
  ["components.manage", "system.write"],
);
const nodes = useNodes();
const origin = computed(() =>
  nodes.selected
    ? (nodes.connections.find((item) => item.id === nodes.selected?.connection)
        ?.url ?? "")
    : window.location.origin,
);
const selected = ref("");
const versionChoice = ref<{
  entry: CatalogEntry;
  action: "install" | "update";
} | null>(null);
const selectedEntry = computed(() =>
  entries.value.find(
    (entry) => `${entry.source.id}/${entry.application.id}` === selected.value,
  ),
);
function view(entry: CatalogEntry) {
  return applicationView(entry, props.tasks, origin.value);
}
const manageSources = ref(false);
const selectedSource = ref("");
const showImport = ref(false),
  url = ref(""),
  source = ref<SoftwareSource | null>(null),
  fileName = ref(""),
  fileInput = ref<HTMLInputElement | null>(null),
  latest = ref("");
const job = computed(() => props.tasks.find((t) => t.id === latest.value));
const entries = computed(() => softwareCatalogEntries(props.catalog));
const sourceOptions = computed(() => [
  { label: "全部软件源", value: "" },
  ...(props.catalog?.sources ?? []).map((item) => ({
    label: item.name,
    value: item.id,
  })),
]);
watch(
  () => props.catalog?.sources,
  (sources) => {
    if (
      selectedSource.value &&
      sources &&
      !sources.some((source) => source.id === selectedSource.value)
    )
      selectedSource.value = "";
  },
);
const visibleEntries = computed(() => {
  const query = props.search.trim().toLocaleLowerCase();
  return entries.value.filter(
    (entry) =>
      (!selectedSource.value || entry.source.id === selectedSource.value) &&
      (!query ||
        `${entry.application.name} ${entry.application.description} ${entry.source.name}`
          .toLocaleLowerCase()
          .includes(query)) &&
      (props.statusFilter === "all" ||
        (props.statusFilter === "installed"
          ? !!entry.installation
          : !entry.installation)),
  );
});
function openImport() {
  manageSources.value = false;
  url.value = fileName.value = "";
  source.value = null;
  showImport.value = true;
}
async function chooseFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (!file) return;
  await run(async () => {
    if (file.size > 24 * 1024) throw new Error("配置文件不能超过 24 KB");
    source.value = JSON.parse(await file.text()) as SoftwareSource;
    fileName.value = file.name;
    url.value = "";
  });
  (event.target as HTMLInputElement).value = "";
}
async function submit(request: SoftwareRequest) {
  const task = await submitTask(request, "软件操作日志");
  if (!task) return;
  emit("task", task);
  latest.value = task.id;
  showImport.value = false;
  source.value = null;
  url.value = fileName.value = "";
  emit("changed");
  return task;
}
async function removeSource(id: string) {
  if (!window.confirm("删除此软件源？已安装的软件需要先卸载。")) return;
  await submit({ action: "delete", source_id: id });
}
async function operate(action: SoftwareOperation, entry: CatalogEntry) {
  if (
    (action === "install" || action === "update") &&
    (entry.application.versions_url ||
      entry.application.versions?.length ||
      entry.installation?.version)
  ) {
    versionChoice.value = { entry, action };
    return;
  }
  const definition =
    action === "install" || action === "update"
      ? entry.application
      : entry.installation?.application;
  const description = definition?.actions[action]?.description;
  const prompt = softwareConfirmation(action, entry.application.name);
  const confirmation =
    prompt && [prompt, description].filter(Boolean).join("\n");
  if (confirmation && !window.confirm(confirmation)) return;
  await submit({
    action,
    source_id: entry.source.id,
    app_id: entry.application.id,
  });
}
async function chooseVersion(version: ComponentVersion) {
  const choice = versionChoice.value;
  if (!choice) return;
  const task = await submit({
    action: choice.action,
    source_id: choice.entry.source.id,
    app_id: choice.entry.application.id,
    version: version.id,
  });
  if (task) versionChoice.value = null;
}
</script>
<template>
  <ComponentVersionDialog
    v-if="versionChoice"
    :show="true"
    :name="versionChoice.entry.application.name"
    :source-id="versionChoice.entry.source.id"
    :app-id="versionChoice.entry.application.id"
    :submit-text="versionChoice.action === 'install' ? '安装此版本' : '切换版本'"
    :busy="busy || active"
    @choose="chooseVersion"
    @cancel="versionChoice = null"
  />
  <Teleport defer to="#software-source-actions">
    <div v-if="visible" class="source-tools">
      <NSelect
        v-model:value="selectedSource"
        :options="sourceOptions"
        aria-label="软件源"
        class="source-select"
      />
      <NButton @click="manageSources = true">
        管理软件源<span class="source-count">{{
          catalog?.sources.length ?? 0
        }}</span>
      </NButton>
    </div>
  </Teleport>
  <div v-show="visible" class="page-stack">
    <NAlert v-if="catalog?.error" type="error">
      暂时无法读取第三方软件，请刷新后重试。
    </NAlert>
    <template v-else-if="!catalog?.sources.length">
      <section class="store-empty">
        <NEmpty description="尚未添加第三方软件源" />
        <p class="muted">
          添加软件源，即可浏览和安装其中的应用。
        </p>
        <NButton
          type="primary"
          :disabled="!permitted || busy || active"
          @click="openImport"
        >
          添加软件源
        </NButton>
      </section>
    </template>
    <div v-else-if="visibleEntries.length" class="store-grid">
      <SoftwareCard
        v-for="entry in visibleEntries"
        :key="entry.source.id + '/' + entry.application.id"
        :name="entry.application.name"
        :description="entry.application.description || '暂无软件介绍'"
        category="第三方应用"
        accent="amber"
        :status="view(entry).status.label"
        :status-type="view(entry).status.tone"
      >
        <div class="app-meta">
          <span>来自 {{ entry.source.name }}</span>
        </div>
        <template #actions>
          <SoftwareActions
            :app="view(entry)"
            :permitted="permitted"
            :active="active || busy"
            @manage="selected = view(entry).id"
          />
        </template>
      </SoftwareCard>
    </div>
    <section v-else class="store-empty">
      <NEmpty
        :description="
          entries.length ? '没有符合条件的软件' : '软件源中暂无软件'
        "
      /><NButton v-if="selectedSource" @click="selectedSource = ''">
        查看全部软件源
      </NButton>
      <p v-else class="muted">
        可调整搜索条件，或在“管理软件源”中更新软件列表。
      </p>
    </section>
    <div v-if="job" class="operation-feedback">
      <NTag
        :bordered="false"
        :type="
          job.state === 'succeeded'
            ? 'success'
            : job.state === 'failed'
              ? 'error'
              : 'info'
        "
      >
        {{
          job.state === "succeeded"
            ? "操作已完成"
            : job.state === "failed"
              ? "操作未完成"
              : "正在处理"
        }}
      </NTag><TaskLogButton :task-id="job.id" /><span
        v-if="job.error"
        class="error"
      >{{ job.error }}</span>
    </div>
  </div>
  <NModal
    :show="!!selectedEntry"
    preset="card"
    :title="
      selectedEntry
        ? `软件管理 · ${selectedEntry.application.name}`
        : '软件管理'
    "
    style="width: 760px; max-width: calc(100vw - 32px)"
    :mask-closable="false"
    :closable="!busy"
    :close-on-esc="!busy"
    @update:show="
      (show: boolean) => {
        if (!show && !busy) selected = '';
      }
    "
  >
    <SoftwareManagementPanel
      v-if="selectedEntry"
      :app="view(selectedEntry)"
      :runtime="selectedEntry.installation?.state ?? 'unknown'"
      :actions="applicationActions(selectedEntry)"
      :permitted="permitted"
      :busy="busy || active"
      :task="
        softwareApplicationTask(
          tasks,
          selectedEntry.source.id,
          selectedEntry.application.id,
        )
      "
      :error="
        selectedEntry.installation?.error ||
          (!selectedEntry.listed
            ? '软件源已不再提供此软件，仍可启停、查看日志或卸载。'
            : '')
      "
      @operate="operate($event, selectedEntry!)"
    />
    <template #footer>
      <div class="dialog-footer">
        <NButton :disabled="busy" @click="selected = ''">
          关闭
        </NButton>
      </div>
    </template>
  </NModal>
  <NModal
    v-model:show="manageSources"
    preset="card"
    title="第三方软件源"
    style="width: 760px; max-width: calc(100vw - 32px)"
    :mask-closable="false"
    :closable="!busy"
    :close-on-esc="!busy"
  >
    <div class="sources-body page-stack">
      <div class="section-heading">
        <span class="muted">{{ catalog?.sources.length ?? 0 }} 个软件源</span><NButton
          type="primary"
          :disabled="!permitted || busy || active"
          @click="openImport"
        >
          添加软件源
        </NButton>
      </div>
      <NAlert v-if="catalog?.error" type="error">
        暂时无法读取软件源，请关闭后刷新重试。
      </NAlert>
      <NEmpty
        v-else-if="!catalog?.sources.length"
        description="尚未添加软件源"
      />
      <article
        v-for="item in catalog?.sources ?? []"
        :key="item.id"
        class="record-card page-stack"
      >
        <div>
          <strong>{{ item.name }}</strong>
          <p class="muted source-address">
            {{ item.url || "本地文件导入" }}
          </p>
        </div>
        <div class="source-footer">
          <span class="muted">{{ item.applications.length }} 款软件</span>
          <div class="button-row">
            <NButton
              v-if="item.url"
              size="small"
              :disabled="!permitted || busy || active"
              @click="submit({ action: 'refresh', source_id: item.id })"
            >
              更新列表
            </NButton><NButton
              size="small"
              type="error"
              secondary
              :disabled="
                !permitted ||
                  busy ||
                  active ||
                  catalog?.installed.some(
                    (installed) => installed.source_id === item.id,
                  )
              "
              @click="removeSource(item.id)"
            >
              删除
            </NButton>
          </div>
        </div>
        <p
          v-if="
            catalog?.installed.some(
              (installed) => installed.source_id === item.id,
            )
          "
          class="muted"
        >
          卸载此源已安装的软件后，可删除该软件源。
        </p>
      </article>
    </div>
  </NModal>
  <FormDialog
    :show="showImport"
    title="添加软件源"
    :busy="busy"
    :draft="[url, source]"
    :submit-disabled="!permitted || active || (!source && !url.trim())"
    submit-text="添加"
    @submit="
      submit(
        source
          ? { action: 'import', source }
          : { action: 'import', url: url.trim() },
      )
    "
    @cancel="
      showImport = false;
      source = null;
      url = fileName = '';
    "
  >
    <div class="page-stack">
      <NFormItem label="软件源地址">
        <NInput
          v-model:value="url"
          placeholder="输入配置文件地址或 GitHub 文件链接"
          :disabled="busy"
          @input="
            source = null;
            fileName = '';
          "
        />
      </NFormItem>
      <div class="button-row">
        <span class="muted">或从文件导入</span><NButton :disabled="busy" @click="fileInput?.click()">
          选择 JSON 文件
        </NButton><span>{{ fileName }}</span><input
          ref="fileInput"
          type="file"
          accept=".json,application/json"
          hidden
          @change="chooseFile"
        />
      </div>
      <p class="muted">
        添加后可查看软件介绍，再选择安装。
      </p>
    </div>
  </FormDialog>
</template>
<style scoped>
.source-tools {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.source-select {
  width: 180px;
}
.source-count {
  margin-left: 8px;
  color: var(--text-muted);
}
.store-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 280px), 1fr));
  gap: 20px;
}
.store-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 18px;
  padding: 56px 20px;
  border: 1px dashed var(--border-color);
  border-radius: 12px;
  background: var(--bg-surface);
}
.app-meta {
  display: grid;
  gap: 4px;
}
.operation-feedback {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.sources-body {
  max-height: calc(100dvh - 200px);
  overflow-y: auto;
}
.source-address {
  overflow-wrap: anywhere;
  margin-top: 4px;
}
.source-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
@media (max-width: 560px) {
  .source-select {
    width: 100%;
  }
  .source-tools {
    width: 100%;
  }
}
</style>
