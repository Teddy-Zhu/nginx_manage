<route lang="json">
{
  "meta": {
    "title": "Nginx 配置",
    "subtitle": "配置原文、常用字段与不可变修订",
    "nav": true,
    "order": 1,
    "symbol": "⌘"
  }
}
</route>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from "vue";
import { onBeforeRouteLeave } from "vue-router";
import {
  NButton,
  NInput,
  NAlert,
  NTag,
  NTabs,
  NTabPane,
  NEmpty,
  NModal,
  NForm,
  NFormItem,
  NSelect,
  NDataTable,
  type DataTableColumns,
} from "naive-ui";
import {
  api,
  request,
  ApiError,
  type Tree,
  type ConfigFile,
  type Resource,
  type SaveResult,
  type NginxRuntime,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";

const { run, busy, message } = useAction(),
  keyFor = useIdempotency();
const runtime = ref<NginxRuntime | null>(null);
const runtimeError = ref("");
const tree = ref<Tree | null>(null),
  files = ref<ConfigFile[]>([]),
  selected = ref(""),
  persisted = ref(""),
  draftNote = ref("");
const diagnostics = ref<Tree["diagnostics"]>([]),
  historyVisible = ref(false);
const createVisible = ref(false),
  fileVisible = ref(false),
  newPath = ref("");
const createKind = ref<"http" | "stream">("http"),
  createListen = ref("8080"),
  createDomains = ref(""),
  createUpstream = ref("");
const resource = ref<Resource | null>(null),
  fieldInputs = ref<Record<string, string>>({});
const currentFile = computed(() =>
  files.value.find((f) => f.id === selected.value),
);
const sourceJSON = computed(() =>
  JSON.stringify(
    files.value.map(({ id, path, content }) => ({ id, path, content })),
  ),
);
const formDirty = computed(
  () =>
    resource.value &&
    Object.entries(resource.value.fields).some(
      ([name, field]) =>
        field.editable &&
        (fieldInputs.value[name] ?? "") !== field.values.join(" "),
    ),
);
const dirty = computed(
  () => sourceJSON.value !== persisted.value || !!formDirty.value,
);
const differsFromDesired = computed(
  () =>
    sourceJSON.value !==
    JSON.stringify(
      tree.value?.files.map(({ id, path, content }) => ({
        id,
        path,
        content,
      })) ?? [],
    ),
);
const fieldLabels: Record<string, string> = {
  listen: "监听地址 / 端口与选项",
  domains: "域名",
  upstream: "上游地址",
  body_size: "最大请求体",
  connect_timeout: "连接超时",
  read_timeout: "读取超时",
  session_timeout: "会话超时",
};
interface Revision {
  id: string;
  version: number;
  state: string;
  created_at: number;
}
const revisions = ref<Revision[]>([]);
const revisionColumns: DataTableColumns<Revision> = [
  { title: "修订", key: "version", render: (r) => `#${r.version}` },
  {
    title: "类型",
    key: "state",
    render: (r) => (r.state === "draft" ? "草稿" : "有效配置"),
  },
  {
    title: "保存时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];

function setTree(value: Tree) {
  tree.value = value;
  files.value = structuredClone(value.files);
  if (!files.value.some((f) => f.id === selected.value))
    selected.value = files.value[0]?.id ?? "";
  persisted.value = sourceJSON.value;
  diagnostics.value = value.diagnostics;
  draftNote.value = "";
  resource.value = null;
  fieldInputs.value = {};
}
async function load() {
  if (dirty.value && !window.confirm("有未保存修改，确认重新加载？")) return;
  await run(async () => {
    setTree(await api.tree());
    await loadRuntime();
  });
}
async function loadRuntime() {
  try {
    runtime.value = await api.nginxRuntime();
    runtimeError.value = "";
  } catch (error) {
    runtime.value = null;
    runtimeError.value =
      error instanceof Error ? error.message : "无法查询运行状态";
  }
}
async function applySaved() {
  if (dirty.value || !tree.value?.revision_id) return;
  await run(async () => {
    const input = { action: "apply", base_version: tree.value!.version };
    await api.apply(input.base_version, keyFor(input));
    message.success("配置已加入应用队列，可在任务中查看结果");
  });
}
async function preview() {
  await run(async () => {
    const result = await api.preview({
      base_version: tree.value?.version ?? 0,
      files: files.value,
      draft: false,
      validate: false,
    });
    diagnostics.value = result.diagnostics;
    if (!result.diagnostics.length) message.success("配置解析与安全校验通过");
  });
}
async function save(draft = false, validate = false, apply = false) {
  const input = {
    base_version: tree.value?.version ?? 0,
    files: files.value,
    draft,
    validate,
    apply,
  };
  await run(async () => {
    try {
      const result = await api.save(input, keyFor(input));
      if (draft) {
        draftNote.value = `草稿 #${result.tree.version} 已保存`;
        diagnostics.value = result.tree.diagnostics;
        persisted.value = sourceJSON.value;
      } else {
        setTree(result.tree);
        message.success(
          result.task_id
            ? apply
              ? "修订已保存并加入应用队列"
              : "修订已保存并加入 Nginx 校验队列"
            : "有效修订已保存",
        );
      }
    } catch (error) {
      if (error instanceof ApiError && error.code === "CONFIG_INVALID") {
        const data = error.data as SaveResult | null;
        if (data?.tree) diagnostics.value = data.tree.diagnostics;
      }
      throw error;
    }
  });
}
function selectResource(value: Resource) {
  if (formDirty.value && !window.confirm("字段修改尚未保存，确认切换？"))
    return;
  resource.value = value;
  fieldInputs.value = Object.fromEntries(
    Object.entries(value.fields).map(([key, field]) => [
      key,
      field.values.join(" "),
    ]),
  );
}
async function saveFields() {
  if (!resource.value || !tree.value) return;
  const changes: Record<string, string[]> = {};
  for (const [name, field] of Object.entries(resource.value.fields)) {
    const value = fieldInputs.value[name] ?? "";
    if (field.editable && value !== field.values.join(" "))
      changes[name] = value.trim()
        ? name === "listen" || name === "domains"
          ? value.trim().split(/\s+/)
          : [value.trim()]
        : [];
  }
  const id = resource.value.id,
    version = tree.value.version;
  await run(async () => {
    const result = await api.patch(
      id,
      version,
      changes,
      keyFor({ id, version, changes }),
    );
    setTree(result.tree);
    const updated = result.tree.resources.find((r) => r.id === id);
    if (updated) selectResource(updated);
  }, "常用字段已保存");
}
function addFile() {
  const path = newPath.value.trim();
  if (!path) return;
  if (files.value.some((f) => f.path === path)) {
    message.error("文件路径已存在");
    return;
  }
  const file = { id: crypto.randomUUID(), path, content: "", sha256: "" };
  files.value.push(file);
  selected.value = file.id;
  newPath.value = "";
  fileVisible.value = false;
}
function removeFile() {
  if (!currentFile.value || currentFile.value.path === "nginx.conf") return;
  if (!window.confirm(`确认从配置树移除 ${currentFile.value.path}？`)) return;
  files.value = files.value.filter((f) => f.id !== selected.value);
  selected.value = files.value[0]?.id ?? "";
}
async function createResource() {
  const input = {
    base_version: tree.value?.version ?? 0,
    kind: createKind.value,
    listen: createListen.value.trim().split(/\s+/),
    domains:
      createKind.value === "http"
        ? createDomains.value.trim().split(/\s+/)
        : [],
    upstream: createUpstream.value.trim(),
  };
  await run(async () => {
    const result = await api.createResource(input, keyFor(input));
    setTree(result.tree);
    createVisible.value = false;
  }, "代理配置已保存，尚未应用");
}
async function showHistory() {
  await run(async () => {
    revisions.value = await request<Revision[]>({
      url: "/nginx/revisions",
      params: { limit: 100 },
    });
    historyVisible.value = true;
  });
}
async function loadRevision(row: Revision) {
  if (dirty.value && !window.confirm("有未保存修改，确认加载历史原文？"))
    return;
  await run(async () => {
    const result = await request<Tree>({ url: `/nginx/revisions/${row.id}` });
    files.value = structuredClone(result.files);
    selected.value = files.value[0]?.id ?? "";
    diagnostics.value = result.diagnostics;
    draftNote.value = `基于历史修订 #${row.version} 编辑`;
    resource.value = null;
    historyVisible.value = false;
  });
}
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (dirty.value) event.preventDefault();
};
onBeforeRouteLeave(
  () => !dirty.value || window.confirm("修改尚未保存，确认离开？"),
);
onMounted(() => {
  void load();
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => window.removeEventListener("beforeunload", beforeUnload));
</script>

<template>
  <div class="toolbar">
    <div class="inline-gap">
      <n-tag size="small" :bordered="false">{{
        tree?.version ? `期望修订 #${tree.version}` : "尚未保存"
      }}</n-tag
      ><n-tag v-if="dirty" size="small" type="warning" :bordered="false"
        >未保存修改</n-tag
      ><n-tag
        v-if="runtime?.running && runtime.integrity"
        size="small"
        :type="
          runtime.revision_id === tree?.revision_id ? 'success' : 'warning'
        "
        :bordered="false"
        >{{
          runtime.revision_id === tree?.revision_id ? "已生效" : "待应用"
        }}</n-tag
      ><span class="muted">{{ draftNote }}</span>
    </div>
    <div class="inline-gap">
      <n-button :disabled="busy" @click="showHistory">修订历史</n-button
      ><n-button :disabled="busy" @click="load">重新加载</n-button
      ><n-button
        :disabled="
          busy ||
          dirty ||
          !tree?.revision_id ||
          !runtime?.available ||
          !runtime.integrity ||
          !runtime.running
        "
        @click="applySaved"
        >应用已保存修订</n-button
      ><n-button
        type="primary"
        :disabled="busy || differsFromDesired"
        @click="createVisible = true"
        >＋ 新建代理配置</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >配置保存后成为期望修订，应用结果以任务记录和运行确认状态为准。</n-alert
  >
  <n-alert
    v-if="runtimeError || runtime?.reason"
    type="warning"
    :bordered="false"
    style="margin-bottom: 20px"
    >{{ runtimeError || runtime?.reason }}</n-alert
  >
  <n-tabs type="line" animated
    ><n-tab-pane name="native" tab="原生配置">
      <div class="editor-layout surface">
        <aside class="file-tree">
          <div class="section-heading">
            <h2>配置文件</h2>
            <n-button text title="添加文件" @click="fileVisible = true"
              >＋</n-button
            >
          </div>
          <button
            v-for="file in files"
            :key="file.id"
            class="file-item"
            :class="{ selected: selected === file.id }"
            @click="selected = file.id"
          >
            <span>▤</span>{{ file.path }}
          </button>
          <div class="file-budget">{{ files.length }} / 128 个文件</div>
        </aside>
        <div class="editor-main">
          <template v-if="currentFile"
            ><div class="editor-title">
              <span class="mono">{{ currentFile.path }}</span>
              <div class="inline-gap">
                <span class="muted"
                  >{{ currentFile.content.split("\n").length }} 行</span
                ><n-button
                  v-if="currentFile.path !== 'nginx.conf'"
                  text
                  type="error"
                  @click="removeFile"
                  >移除</n-button
                >
              </div>
            </div>
            <textarea
              v-model="currentFile.content"
              class="code-editor"
              spellcheck="false"
              :aria-label="currentFile.path"
              :maxlength="262144"
            /></template
          ><n-empty v-else description="请选择配置文件" />
        </div>
      </div>
      <div v-if="diagnostics.length" class="diagnostics surface">
        <div class="section-heading">
          <h2>配置诊断</h2>
          <n-tag type="error" size="small">{{ diagnostics.length }} 项</n-tag>
        </div>
        <div
          v-for="(item, index) in diagnostics"
          :key="index"
          class="diagnostic-row"
        >
          <span class="mono"
            >{{ files.find((f) => f.id === item.file_id)?.path }}:{{
              item.line
            }}</span
          ><span>{{ item.message }}</span>
        </div>
      </div>
      <div class="save-bar">
        <span class="muted"
          >{{ files.length }} 个文件 · 原文与字段共享修订</span
        >
        <div class="inline-gap">
          <n-button :loading="busy" @click="preview">解析与预览</n-button
          ><n-button :disabled="busy" @click="save(true)">保存草稿</n-button
          ><n-button :disabled="busy" @click="save(false, true)"
            >保存并校验</n-button
          ><n-button
            type="primary"
            :disabled="
              busy ||
              !runtime?.available ||
              !runtime.integrity ||
              !runtime.running
            "
            @click="save(false, false, true)"
            >保存并应用</n-button
          ><n-button type="primary" :loading="busy" @click="save()"
            >保存有效修订</n-button
          >
        </div>
      </div> </n-tab-pane
    ><n-tab-pane name="fields" tab="常用字段">
      <n-alert
        v-if="differsFromDesired"
        type="warning"
        :bordered="false"
        style="margin-bottom: 20px"
        >原文与当前有效修订不同。先保存为有效修订，再修改常用字段。</n-alert
      >
      <div v-if="tree?.resources.length" class="editor-layout surface">
        <aside class="file-tree">
          <div class="section-heading"><h2>受管资源</h2></div>
          <button
            v-for="item in tree.resources"
            :key="item.id"
            class="file-item"
            :class="{ selected: resource?.id === item.id }"
            @click="selectResource(item)"
          >
            {{ item.kind.toUpperCase() }} ·
            {{ item.fields.domains?.values[0] ?? item.id.slice(0, 8) }}
          </button>
        </aside>
        <div class="resource-form">
          <template v-if="resource"
            ><div class="section-heading">
              <h2>{{ resource.kind.toUpperCase() }} 代理</h2>
              <span class="mono muted">{{ resource.id.slice(0, 8) }}</span>
            </div>
            <n-form label-placement="top"
              ><n-form-item
                v-for="(field, name) in resource.fields"
                :key="name"
                :label="fieldLabels[name] ?? name"
                :feedback="field.reason"
                ><n-input
                  v-model:value="fieldInputs[name]"
                  :disabled="!field.editable || differsFromDesired"
                  placeholder="未设置" /></n-form-item
              ><n-button
                type="primary"
                :loading="busy"
                :disabled="differsFromDesired || !formDirty"
                @click="saveFields"
                >保存字段</n-button
              ></n-form
            ></template
          ><n-empty v-else description="选择一个资源查看常用字段" />
        </div>
      </div>
      <n-empty v-else description="暂无受管代理配置"
        ><template #extra
          ><n-button
            :disabled="differsFromDesired"
            @click="createVisible = true"
            >新建代理配置</n-button
          ></template
        ></n-empty
      >
    </n-tab-pane></n-tabs
  >
  <n-modal
    v-model:show="createVisible"
    preset="card"
    title="新建代理配置"
    style="width: 480px; max-width: 94vw"
    ><n-form @submit.prevent="createResource"
      ><n-form-item label="类型"
        ><n-select
          v-model:value="createKind"
          :options="[
            { label: 'HTTP 反向代理', value: 'http' },
            { label: 'TCP / UDP Stream', value: 'stream' },
          ]" /></n-form-item
      ><n-form-item label="监听"
        ><n-input
          v-model:value="createListen"
          placeholder="8080 或 [::]:8080；UDP 添加 udp" /></n-form-item
      ><n-form-item v-if="createKind === 'http'" label="域名"
        ><n-input
          v-model:value="createDomains"
          placeholder="多个域名使用空格分隔" /></n-form-item
      ><n-form-item label="上游地址"
        ><n-input
          v-model:value="createUpstream"
          :placeholder="
            createKind === 'http' ? 'http://127.0.0.1:3000' : '127.0.0.1:5432'
          " /></n-form-item
      ><n-button block type="primary" attr-type="submit" :loading="busy"
        >保存配置</n-button
      ></n-form
    ></n-modal
  >
  <n-modal
    v-model:show="fileVisible"
    preset="card"
    title="添加配置文件"
    style="width: 420px; max-width: 94vw"
    ><n-form @submit.prevent="addFile"
      ><n-form-item label="受管相对路径"
        ><n-input
          v-model:value="newPath"
          placeholder="http/site.conf" /></n-form-item
      ><n-button block type="primary" attr-type="submit">添加</n-button></n-form
    ></n-modal
  >
  <n-modal
    v-model:show="historyVisible"
    preset="card"
    title="修订历史"
    style="width: 720px; max-width: 94vw"
    ><p class="muted">选择一行加载历史原文，保存时会创建新修订。</p>
    <n-data-table
      :columns="revisionColumns"
      :data="revisions"
      :row-props="
        (row: Revision) => ({
          onClick: () => loadRevision(row),
          style: 'cursor: pointer',
        })
      "
      :bordered="false"
  /></n-modal>
</template>
