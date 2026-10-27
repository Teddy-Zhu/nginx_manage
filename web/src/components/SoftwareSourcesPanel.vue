<script setup lang="ts">
import FormDialog from "./FormDialog.vue";
import { computed, ref, watch } from "vue";
import { NAlert, NButton, NEmpty, NFormItem, NInput, NTag } from "naive-ui";
import {
  useNodeAPI,
  type ComponentTask,
  type SoftwareCatalog,
  type SoftwareRequest,
  type SoftwareSource,
} from "../api/client";
import { useAction } from "../composables/action";
import { useSession } from "../stores/session";
import { inspectTask } from "../stores/operation";
import { randomUUID } from "../utils/crypto";
import TaskLogButton from "./TaskLogButton.vue";
const props = defineProps<{
  catalog?: SoftwareCatalog;
  tasks: ComponentTask[];
  active: boolean;
}>();
const emit = defineEmits<{ changed: [] }>();
const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction();
const showImport = ref(false),
  url = ref(""),
  source = ref<SoftwareSource | null>(null),
  fileName = ref(""),
  fileInput = ref<HTMLInputElement | null>(null),
  latest = ref("");
const permitted = computed(
  () =>
    session.me?.scopes.includes("components.manage") &&
    session.me.scopes.includes("system.write"),
);
const job = computed(() => props.tasks.find((t) => t.id === latest.value));
watch(
  () => job.value?.state,
  (state, old) => {
    if (state && state !== old && ["succeeded", "failed"].includes(state))
      emit("changed");
  },
);
const sources = computed(() =>
  (props.catalog?.sources ?? []).map((s) => ({
    ...s,
    applications: [
      ...s.applications,
      ...(props.catalog?.installed ?? [])
        .filter(
          (i) =>
            i.source_id === s.id &&
            !s.applications.some((a) => a.id === i.application.id),
        )
        .map((i) => i.application),
    ],
  })),
);
function installed(sourceID: string, appID: string) {
  return (
    props.catalog?.installed.some(
      (i) => i.source_id === sourceID && i.application.id === appID,
    ) ?? false
  );
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
  await run(async () => {
    const input = {
      action: "software" as const,
      tag: "",
      prerelease: false,
      plan_id: "",
      manifest_sha256: "",
      trust_sha256: "",
      software: request,
    };
    const task = await api.createComponentTask({ input }, randomUUID());
    latest.value = task.id;
    showImport.value = false;
    source.value = null;
    url.value = "";
    fileName.value = "";
    emit("changed");
    inspectTask(task.id, "软件操作日志");
  });
}
async function removeSource(id: string) {
  if (!window.confirm("删除此软件源？已安装的软件需要先卸载。")) return;
  await submit({ action: "delete", source_id: id });
}
async function install(
  sourceID: string,
  appID: string,
  name: string,
  exists: boolean,
) {
  if (
    !window.confirm(
      exists
        ? `更新 ${name}？软件将短暂重启，已有数据卷会保留。`
        : `安装 ${name}？将下载镜像并开放配置中列出的端口。`,
    )
  )
    return;
  await submit({
    action: exists ? "update" : "install",
    source_id: sourceID,
    app_id: appID,
  });
}
async function uninstall(sourceID: string, appID: string, name: string) {
  if (!window.confirm(`卸载 ${name}？软件会停止，数据卷将保留。`)) return;
  await submit({ action: "uninstall", source_id: sourceID, app_id: appID });
}
</script>
<template>
  <section class="panel page-stack">
    <div class="section-heading">
      <div>
        <h3>第三方软件</h3>
        <p class="muted">导入软件源后，选择需要安装的软件。</p>
      </div>
      <NButton :disabled="!permitted || active" @click="showImport = true"
        >添加软件源</NButton
      >
    </div>
    <NAlert v-if="catalog?.error" type="error"
      >暂时无法读取软件源，请查看服务日志。</NAlert
    >
    <NEmpty v-else-if="!sources.length" description="尚未添加第三方软件源" />
    <article
      v-for="item in sources"
      :key="item.id"
      class="source-group page-stack"
    >
      <div class="section-heading">
        <h4>{{ item.name }}</h4>
        <div class="button-row">
          <NButton
            v-if="item.url"
            size="small"
            :disabled="!permitted || busy || active"
            @click="submit({ action: 'refresh', source_id: item.id })"
            >更新列表</NButton
          ><NButton
            size="small"
            :disabled="!permitted || busy || active"
            @click="removeSource(item.id)"
            >删除软件源</NButton
          >
        </div>
      </div>
      <div class="software-grid">
        <article
          v-for="app in item.applications"
          :key="app.id"
          class="software-card page-stack"
        >
          <div class="section-heading">
            <h4>{{ app.name }}</h4>
            <NTag
              :type="installed(item.id, app.id) ? 'success' : 'default'"
              size="small"
              >{{ installed(item.id, app.id) ? "已安装" : "未安装" }}</NTag
            >
          </div>
          <p v-if="app.description" class="muted">{{ app.description }}</p>
          <p v-if="app.ports?.length" class="muted">
            访问端口：{{
              app.ports
                .map((p) => `${p.host}/${p.protocol.toUpperCase()}`)
                .join("、")
            }}
          </p>
          <div class="button-row">
            <NButton
              type="primary"
              :loading="busy"
              :disabled="!permitted || active"
              @click="
                install(item.id, app.id, app.name, installed(item.id, app.id))
              "
              >{{ installed(item.id, app.id) ? "更新软件" : "安装" }}</NButton
            ><NButton
              v-if="installed(item.id, app.id)"
              :disabled="!permitted || busy || active"
              @click="uninstall(item.id, app.id, app.name)"
              >卸载</NButton
            >
          </div>
        </article>
      </div>
    </article>
    <div v-if="job" class="button-row">
      <span>{{
        job.state === "succeeded"
          ? "操作已完成"
          : job.state === "failed"
            ? "操作未完成"
            : "正在处理"
      }}</span
      ><TaskLogButton :task-id="job.id" />
    </div>
    <NAlert v-if="job?.error" type="error">{{ job.error }}</NAlert>
  </section>
  <FormDialog
    :show="showImport"
    title="添加软件源"
    :busy="busy"
    :draft="[url, source]"
    :submit-disabled="!source && !url.trim()"
    submit-text="添加"
    @submit="
      submit(
        source
          ? { action: 'import', source }
          : { action: 'import', url: url.trim() },
      )
    "
    @cancel="showImport = false"
  >
    <div class="page-stack">
      <NFormItem label="软件源地址"
        ><NInput
          v-model:value="url"
          placeholder="输入配置文件地址或 GitHub 文件链接"
          :disabled="busy"
          @input="
            source = null;
            fileName = '';
          "
      /></NFormItem>
      <div class="button-row">
        <span class="muted">或从文件导入</span
        ><NButton :disabled="busy" @click="fileInput?.click()"
          >选择 JSON 文件</NButton
        ><span>{{ fileName }}</span
        ><input
          ref="fileInput"
          type="file"
          accept=".json,application/json"
          hidden
          @change="chooseFile"
        />
      </div>
      <p class="muted">
        请使用可信的软件源。添加后可查看软件和端口，再选择安装。
      </p>
    </div></FormDialog
  >
</template>
<style scoped>
.source-group {
  border-top: 1px solid var(--border-color);
  padding-top: 20px;
}
.source-group h4,
.software-card p {
  margin: 0;
}
.software-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr));
  gap: 16px;
}
.software-card {
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 18px;
}
.software-card .button-row {
  margin-top: auto;
}
:deep(.software-import) {
  width: min(620px, calc(100vw - 32px));
}
.software-import {
  width: min(620px, calc(100vw - 32px));
}
</style>
