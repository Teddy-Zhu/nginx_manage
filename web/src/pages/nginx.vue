<route lang="json">
{
  "meta": {
    "title": "网站与代理",
    "subtitle": "创建网站和反向代理，管理域名与 HTTPS",
    "nav": true,
    "order": 1,
    "symbol": "⌘",
    "group": "网站与安全",
    "software": "nginx"
  }
}
</route>

<script setup lang="ts">
import { randomUUID } from "../utils/crypto";

import AdvancedDetails from "../components/AdvancedDetails.vue";
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
  NSwitch,
  NDataTable,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  ApiError,
  type Tree,
  type Revision,
  type ConfigFile,
  type Resource,
  type SaveResult,
  type NginxRuntime,
  type ResourceMetadata,
  type Certificate,
  type NginxFeatures,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import ConfigurationChanges from "../components/ConfigurationChanges.vue";
import NginxExternal from "../components/NginxExternal.vue";
import NginxModules from "../components/NginxModules.vue";
const api = useNodeAPI();
const { request } = api;

const { run, busy, message } = useAction(),
  keyFor = useIdempotency();
const runtime = ref<NginxRuntime | null>(null);
const runtimeError = ref("");
const certificateItems = ref<Certificate[]>([]),
  certificateDetail = ref<Certificate | null>(null),
  certificateChoice = ref(""),
  certificateLoading = ref(false),
  certificateError = ref("");
const nginxFeatures = ref<NginxFeatures | null>(null),
  featureError = ref("");
let certificateRequest = 0;
const tlsAvailable = computed(
  () =>
    nginxFeatures.value?.available === true &&
    nginxFeatures.value.features.tls?.available === true,
);
const tlsReason = computed(
  () =>
    featureError.value ||
    nginxFeatures.value?.features.tls?.reason ||
    nginxFeatures.value?.reason ||
    "尚未确认 HTTPS 模块能力",
);
const tree = ref<Tree | null>(null),
  files = ref<ConfigFile[]>([]),
  selected = ref(""),
  persisted = ref(""),
  draftNote = ref("");
const diagnostics = ref<Tree["diagnostics"]>([]),
  historyVisible = ref(false);
const changesVisible = ref(false),
  externalVisible = ref(false);
const modulesVisible = ref(false);
const createVisible = ref(false),
  fileVisible = ref(false),
  newPath = ref("");
const createName = ref(""),
  createNotes = ref(""),
  createMembers = ref("");
const metadata = ref<ResourceMetadata>({ name: "", notes: "", enabled: true, client_deny: false });
const createKind = ref<"http" | "stream">("http"),
  createListen = ref("8080"),
  createDomains = ref(""),
  createUpstream = ref("");
const resource = ref<Resource | null>(null),
  fieldInputs = ref<Record<string, string>>({});
const regularFields = computed(() =>
  Object.fromEntries(
    Object.entries(resource.value?.fields ?? {}).filter(
      ([name]) => name !== "certificate" && name !== "certificate_key",
    ),
  ),
);
const certificateEditable = computed(
  () =>
    !busy.value &&
    !differsFromDesired.value &&
    resource.value?.fields.certificate?.editable === true &&
    resource.value?.fields.certificate_key?.editable === true,
);
const certificateOptions = computed(() => [
  { label: "不绑定", value: "" },
  ...certificateItems.value.map((item) => ({
    label: item.name,
    value: item.id,
  })),
]);
const certificateVersionOptions = computed(
  () =>
    certificateDetail.value?.versions.map((item) => ({
      label: `${item.environment === "staging" ? "测试 · " : ""}版本 ${item.ordinal} · ${new Date(item.summary.chain_not_after * 1000).toLocaleDateString()} 到期`,
      value: item.certificate_path,
    })) ?? [],
);
const boundCertificateVersion = computed(() =>
  certificateDetail.value?.versions.find(
    (item) => item.certificate_path === fieldInputs.value.certificate,
  ),
);
async function loadCertificateDetail(id: string, chooseLatest: boolean) {
  const current = ++certificateRequest;
  certificateLoading.value = true;
  certificateError.value = "";
  try {
    const detail = await api.certificate(id);
    if (certificateChoice.value !== id || current !== certificateRequest)
      return;
    certificateDetail.value = detail;
    if (chooseLatest) {
      const version = detail.versions.find(
        (item) => item.id === detail.latest_version_id,
      );
      if (version) chooseCertificateVersion(version.certificate_path);
    }
  } catch (error) {
    if (certificateChoice.value === id && current === certificateRequest)
      certificateError.value =
        error instanceof Error ? error.message : "无法读取证书版本";
  } finally {
    if (certificateChoice.value === id && current === certificateRequest)
      certificateLoading.value = false;
  }
}
function chooseCertificate(id: unknown) {
  if (
    typeof id !== "string" ||
    !certificateEditable.value ||
    !tlsAvailable.value
  )
    return;
  certificateRequest++;
  certificateChoice.value = id;
  certificateDetail.value = null;
  certificateError.value = "";
  if (!id) {
    certificateLoading.value = false;
    fieldInputs.value.certificate = "";
    fieldInputs.value.certificate_key = "";
    return;
  }
  void loadCertificateDetail(id, true);
}
function chooseCertificateVersion(value: unknown) {
  if (typeof value !== "string") return;
  const version = certificateDetail.value?.versions.find(
    (item) => item.certificate_path === value,
  );
  if (!version) return;
  fieldInputs.value.certificate = version.certificate_path;
  fieldInputs.value.certificate_key = version.private_key_path;
}
function fieldFeatureReason(name: string) {
  if (name !== "https_redirect" && name !== "hsts" && name !== "http01")
    return "";
  const feature = nginxFeatures.value?.features[name];
  return nginxFeatures.value?.available && feature?.available
    ? ""
    : feature?.reason ||
        (name === "http01"
          ? "无法确认 HTTP-01 所需 Nginx 能力"
          : tlsReason.value);
}
function addHTTPSListener() {
  if (
    !resource.value?.fields.listeners?.editable ||
    busy.value ||
    differsFromDesired.value ||
    !tlsAvailable.value
  )
    return;
  const lines = (fieldInputs.value.listeners ?? "")
    .split("\n")
    .filter((line) => line.trim());
  let found = false;
  const updated = lines.map((line) => {
    if (!/(?:^|:)443(?:\s|$)/.test(line)) return line;
    found = true;
    return /(?:^|\s)ssl(?:\s|$)/.test(line) ? line : line + " ssl";
  });
  if (!found) updated.push("443 ssl");
  fieldInputs.value.listeners = updated.join("\n");
}
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
    (JSON.stringify(metadata.value) !==
      JSON.stringify(resource.value.metadata) ||
      Object.entries(resource.value.fields).some(
        ([name, field]) =>
          field.editable &&
          (fieldInputs.value[name] ?? "") !== fieldText(field),
      )),
);
const dirty = computed(
  () =>
    tree.value !== null &&
    (sourceJSON.value !== persisted.value || !!formDirty.value),
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
function fieldText(field: Resource["fields"][string]) {
  return field.values.join(field.format === "lines" ? "\n" : " ");
}
const fieldLabels: Record<string, string> = {
  http01: "HTTP-01 验证入口（需 80 端口，保存并应用）",
  listeners: "监听（每行一项）",
  domains: "域名",
  upstream: "上游地址",
  upstream_servers: "上游组成员（每行一项，支持 weight=权重）",
  location_prefix: "匹配路径前缀",
  body_size: "最大请求体",
  connect_timeout: "连接超时",
  read_timeout: "读取超时",
  send_timeout: "发送超时",
  session_timeout: "会话超时",
  responses: "UDP 会话预期响应次数",
  http_version: "上游 HTTP 版本",
  buffering: "响应缓冲",
  request_buffering: "请求缓冲",
  request_headers: "转发请求头（每行：名称 参数值）",
  response_headers: "响应头（每行：名称 参数值 [always]）",
  upstream_tls_verify: "校验上游 TLS",
  upstream_tls_sni: "发送上游 SNI",
  upstream_tls_name: "上游 TLS 校验名称",
  upstream_tls_ca: "上游受信 CA 路径",
  certificate: "证书链路径",
  certificate_key: "证书私钥路径",
  https_redirect: "HTTP 跳转 HTTPS（目标端口，留空关闭）",
  hsts: "HSTS",
  tls_protocols: "TLS 协议",
  access_log: "访问日志路径及格式，或 off",
  error_log: "错误日志路径及级别",
  cache: "响应缓存",
  trusted_sources: "可信代理来源（每行一个 IP/CIDR）",
  real_ip_header: "真实 IP 头",
  real_ip_recursive: "递归解析真实 IP",
  access_list: "访问列表",
  waf_policy: "基础 WAF 策略",
};
const toggleFields = new Set([
  "buffering",
  "request_buffering",
  "upstream_tls_verify",
  "upstream_tls_sni",
  "real_ip_recursive",
]);
function fieldOptions(name: string) {
  if (name === "http01")
    return [
      { label: "关闭", value: "" },
      { label: "启用", value: "on" },
    ];
  if (name === "hsts")
    return [
      { label: "继承默认", value: "" },
      { label: "清除 HSTS（max-age=0）", value: "max-age=0" },
      { label: "启用一年", value: "max-age=31536000" },
      {
        label: "启用一年，含所有子域名",
        value: "max-age=31536000; includeSubDomains",
      },
      {
        label: "启用一年、子域名及 preload",
        value: "max-age=31536000; includeSubDomains; preload",
      },
    ];
  if (toggleFields.has(name))
    return [
      { label: "继承默认", value: "" },
      { label: "开启", value: "on" },
      { label: "关闭", value: "off" },
    ];
  if (name === "cache")
    return [
      { label: "继承默认", value: "" },
      { label: "关闭", value: "off" },
      { label: "受管缓存", value: "nginxpanel_http" },
    ];
  if (name === "waf_policy")
    return [
      { label: "不绑定", value: "" },
      ...(tree.value?.waf_policies
        .filter((item) => item.editable)
        .map((item) => ({
          label: `${item.config.metadata.name || item.id.slice(0, 8)}${item.config.metadata.enabled ? "" : "（停用）"}`,
          value: item.id,
        })) ?? []),
    ];
  if (name === "access_list")
    return [
      { label: "不绑定", value: "" },
      ...(tree.value?.access_lists
        .filter((item) => item.editable)
        .map((item) => ({
          label: item.name || item.id.slice(0, 8),
          value: item.id,
        })) ?? []),
    ];
  return null;
}
function canPreset(kind: "websocket" | "streaming" | "http") {
  const fields =
    kind === "streaming"
      ? ["buffering", "request_buffering", "cache", "read_timeout"]
      : ["request_headers", "http_version"];
  return fields.every((field) => resource.value?.fields[field]?.editable);
}
function preset(kind: "websocket" | "streaming" | "http") {
  if (
    !resource.value ||
    busy.value ||
    differsFromDesired.value ||
    !canPreset(kind)
  )
    return;
  if (kind === "streaming") {
    for (const [name, value] of Object.entries({
      buffering: "off",
      request_buffering: "off",
      cache: "off",
      read_timeout: "3600s",
    }))
      if (resource.value.fields[name]?.editable)
        fieldInputs.value[name] = value;
  } else if (
    resource.value.fields.request_headers?.editable &&
    resource.value.fields.http_version?.editable
  ) {
    const headers = (fieldInputs.value.request_headers ?? "")
      .split("\n")
      .filter((line) => !/^(Upgrade|Connection)\s/i.test(line.trim()));
    if (kind === "websocket")
      headers.push("Upgrade $http_upgrade", "Connection upgrade");
    fieldInputs.value.request_headers = headers.filter(Boolean).join("\n");
    fieldInputs.value.http_version = "1.1";
  }
}
const upstreamURI = computed({
  get: () =>
    fieldInputs.value.upstream?.match(/^https?:\/\/[^/]+(\/.*)$/)?.[1] ?? "",
  set: (value: string) => {
    const origin =
      fieldInputs.value.upstream?.match(/^(https?:\/\/[^/]+)/)?.[1];
    if (origin) fieldInputs.value.upstream = origin + value;
  },
});
const rewritePrefix = computed({
  get: () => !!upstreamURI.value,
  set: (value: boolean) => {
    upstreamURI.value = value ? upstreamURI.value || "/" : "";
  },
});
const pathExample = computed(() => {
  const prefix = fieldInputs.value.location_prefix || "/";
  const incoming = prefix + (prefix.endsWith("/") ? "" : "/") + "example";
  const uri = upstreamURI.value;
  return `${incoming} → ${uri ? uri + incoming.slice(prefix.length) : incoming}`;
});

const revisions = ref<Revision[]>([]);
const revisionColumns: DataTableColumns<Revision> = [
  { title: "修订", key: "version", render: (r) => `#${r.version}` },
  {
    title: "类型",
    key: "state",
    render: (r) =>
      r.pruned_at ? "材料已清理" : r.state === "draft" ? "草稿" : "有效配置",
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
  certificateRequest++;
  certificateChoice.value = "";
  certificateDetail.value = null;
  certificateLoading.value = false;
  certificateError.value = "";
}
async function load() {
  if (dirty.value && !window.confirm("有未保存修改，确认重新加载？")) return;
  await run(async () => {
    setTree(await api.tree());
    await Promise.all([loadRuntime(), loadTLSChoices()]);
  });
}
async function loadTLSChoices() {
  await Promise.all([
    api
      .certificates()
      .then((items) => {
        certificateItems.value = items;
        certificateError.value = "";
      })
      .catch((error: unknown) => {
        certificateItems.value = [];
        certificateError.value =
          error instanceof Error ? error.message : "无法读取证书列表";
      }),
    api
      .nginxFeatures()
      .then((features) => {
        nginxFeatures.value = features;
        featureError.value = "";
      })
      .catch((error: unknown) => {
        nginxFeatures.value = null;
        featureError.value =
          error instanceof Error ? error.message : "无法读取 HTTPS 模块能力";
      }),
  ]);
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
      apply: false,
    });
    diagnostics.value = result.diagnostics;
    if (!result.diagnostics.length) message.success("配置解析与安全校验通过");
  });
}
async function save(draft = false, validate = false, apply = false) {
  if (formDirty.value) return;
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
  metadata.value = { ...value.metadata };
  fieldInputs.value = Object.fromEntries(
    Object.entries(value.fields).map(([key, field]) => [key, fieldText(field)]),
  );
  certificateRequest++;
  certificateChoice.value =
    (value.fields.certificate?.values[0] ?? "").split("/")[1] ?? "";
  certificateDetail.value = null;
  certificateError.value = "";
  certificateLoading.value = false;
  if (certificateChoice.value)
    void loadCertificateDetail(certificateChoice.value, false);
}
async function saveFields() {
  if (!resource.value || !tree.value || differsFromDesired.value) return;
  const changes: Record<string, string[]> = {};
  for (const [name, field] of Object.entries(resource.value.fields)) {
    const value = fieldInputs.value[name] ?? "";
    if (field.editable && value !== fieldText(field))
      changes[name] = value.trim()
        ? field.format === "tokens"
          ? value.trim().split(/\s+/)
          : field.format === "lines"
            ? value
                .split("\n")
                .map((line) => line.trim())
                .filter(Boolean)
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
      keyFor({ id, version, changes, metadata: metadata.value }),
      metadata.value,
    );
    setTree(result.tree);
    const updated = result.tree.resources.find((r) => r.id === id);
    if (updated) selectResource(updated);
  }, "常用字段已保存");
}
async function resourceAction(action: "copy" | "delete") {
  if (!resource.value || !tree.value || dirty.value) return;
  const id = resource.value.id,
    version = tree.value.version;
  if (
    action === "delete" &&
    !window.confirm(
      `确认从期望配置移除 ${resource.value.metadata.name || id}？`,
    )
  )
    return;
  const previous = new Set(tree.value.resources.map((item) => item.id));
  await run(
    async () => {
      const result = await api.resourceAction(
        id,
        action,
        version,
        keyFor({ action, id, version }),
      );
      setTree(result.tree);
      if (action === "copy") {
        const copy = result.tree.resources.find(
          (item) => !previous.has(item.id),
        );
        if (copy) selectResource(copy);
      }
    },
    action === "copy"
      ? "副本已保存为停用状态"
      : "代理已从期望配置移除，尚未应用",
  );
}
function addFile() {
  const path = newPath.value.trim();
  if (!path) return;
  if (files.value.some((f) => f.path === path)) {
    message.error("文件路径已存在");
    return;
  }
  const file = { id: randomUUID(), path, content: "", sha256: "" };
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
  if (dirty.value) return;
  const input = {
    base_version: tree.value?.version ?? 0,
    kind: createKind.value,
    listen: createListen.value
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
    upstream_servers: createMembers.value
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
    metadata: {
      name: createName.value.trim(),
      notes: createNotes.value,
      enabled: true,
      client_deny: false,
    },
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
  if (row.pruned_at) return;
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
function capturedExternal(result: SaveResult) {
  files.value = structuredClone(result.tree.files);
  selected.value = files.value[0]?.id ?? "";
  diagnostics.value = result.tree.diagnostics;
  draftNote.value = `外部草稿 #${result.tree.version} 已保存，尚未应用`;
  resource.value = null;
  fieldInputs.value = {};
  certificateRequest++;
  certificateDetail.value = null;
  certificateChoice.value = "";
  certificateLoading.value = false;
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
        tree?.version ? `配置版本 #${tree.version}` : "尚未保存"
      }}</n-tag
      ><n-tag
        v-if="runtime?.external_change"
        size="small"
        type="error"
        :bordered="false"
        >存在外部修改</n-tag
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
      <AdvancedDetails title="更多操作">
      <n-button :disabled="busy || !!formDirty" @click="changesVisible = true"
        >配置差异</n-button
      >
      <n-button :disabled="busy || dirty" @click="externalVisible = true"
        >外部修改</n-button
      >
      <n-button :disabled="busy || dirty" @click="modulesVisible = true"
        >模块管理</n-button
      >
      <n-button :disabled="busy" @click="showHistory">修改记录</n-button>
      </AdvancedDetails>
      <n-button :disabled="busy" @click="load">刷新</n-button
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
        >应用配置</n-button
      ><n-button
        type="primary"
        :disabled="busy || dirty"
        @click="createVisible = true"
        >＋ 添加网站 / 代理</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >保存修改后，点击“应用配置”使设置生效。</n-alert
  >
  <n-alert
    v-if="runtimeError || runtime?.reason"
    type="warning"
    :bordered="false"
    style="margin-bottom: 20px"
    >{{ runtimeError || runtime?.reason }}</n-alert
  >
  <n-tabs type="line" animated default-value="fields"
    ><n-tab-pane name="native" tab="高级配置">
      <div class="editor-layout surface">
        <aside class="file-tree">
          <div class="section-heading">
            <h2>配置文件</h2>
            <n-button
              text
              title="添加文件"
              :disabled="busy || !!formDirty"
              @click="fileVisible = true"
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
                  :disabled="busy || !!formDirty"
                  @click="removeFile"
                  >移除</n-button
                >
              </div>
            </div>
            <textarea
              v-model="currentFile.content"
              class="code-editor"
              :disabled="busy || !!formDirty"
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
          <n-button :loading="busy" :disabled="!!formDirty" @click="preview"
            >解析与预览</n-button
          ><n-button :disabled="busy || !!formDirty" @click="save(true)"
            >保存草稿</n-button
          ><n-button :disabled="busy || !!formDirty" @click="save(false, true)"
            >保存并校验</n-button
          ><n-button
            type="primary"
            :disabled="
              busy ||
              !!formDirty ||
              !runtime?.available ||
              !runtime.integrity ||
              !runtime.running
            "
            @click="save(false, false, true)"
            >保存并应用</n-button
          ><n-button
            type="primary"
            :loading="busy"
            :disabled="!!formDirty"
            @click="save()"
            >保存配置</n-button
          >
        </div>
      </div> </n-tab-pane
    ><n-tab-pane name="fields" tab="网站与代理">
      <n-alert
        v-if="differsFromDesired"
        type="warning"
        :bordered="false"
        style="margin-bottom: 20px"
        >配置文件有未保存修改，请先保存后再修改表单。</n-alert
      >
      <div v-if="tree?.resources.length" class="editor-layout surface">
        <aside class="file-tree">
          <div class="section-heading"><h2>网站与代理</h2></div>
          <button
            v-for="item in tree.resources"
            :key="item.id"
            class="file-item"
            :class="{ selected: resource?.id === item.id }"
            :disabled="busy"
            @click="selectResource(item)"
          >
            {{ item.kind.toUpperCase() }} ·
            {{
              item.metadata.name ||
              item.fields.domains?.values[0] ||
              item.id.slice(0, 8)
            }}
            · {{ item.metadata.enabled ? "启用" : "停用" }}
          </button>
        </aside>
        <div class="resource-form">
          <template v-if="resource"
            ><div class="section-heading">
              <h2>{{ resource.kind.toUpperCase() }} 代理</h2>

            </div>
            <div class="toolbar">
              <n-button
                :disabled="busy || dirty"
                @click="resourceAction('copy')"
                >复制</n-button
              >
              <n-button
                type="error"
                :disabled="busy || dirty"
                @click="resourceAction('delete')"
                >移除</n-button
              >
            </div>
            <n-form label-placement="top">
              <n-form-item label="名称"
                ><n-input
                  v-model:value="metadata.name"
                  :disabled="busy || differsFromDesired"
                  :maxlength="128"
              /></n-form-item>
              <n-form-item label="备注"
                ><n-input
                  v-model:value="metadata.notes"
                  type="textarea"
                  :disabled="busy || differsFromDesired"
                  :maxlength="2048"
              /></n-form-item>
              <n-form-item label="启用"
                ><n-switch
                  v-model:value="metadata.enabled"
                  :disabled="busy || differsFromDesired"
              /></n-form-item>
              <template v-if="resource.kind === 'http'">
                <n-form-item label="动态 IP 封禁">
                  <n-switch
                    :value="metadata.client_deny === true"
                    @update:value="metadata.client_deny = $event === true"
                    :disabled="busy || differsFromDesired"
                  />
                </n-form-item>
                <div class="toolbar">
                  <n-button
                    :disabled="
                      busy || differsFromDesired || !canPreset('websocket')
                    "
                    @click="preset('websocket')"
                    >WebSocket</n-button
                  ><n-button
                    :disabled="
                      busy || differsFromDesired || !canPreset('streaming')
                    "
                    @click="preset('streaming')"
                    >SSE / 流式响应</n-button
                  ><n-button
                    :disabled="busy || differsFromDesired || !canPreset('http')"
                    @click="preset('http')"
                    >普通 HTTP</n-button
                  >
                </div>
                <n-form-item label="替换匹配前缀"
                  ><n-switch
                    v-model:value="rewritePrefix"
                    :disabled="
                      busy ||
                      differsFromDesired ||
                      !resource.fields.upstream?.editable
                    "
                /></n-form-item>
                <n-form-item v-if="rewritePrefix" label="转发到上游子路径"
                  ><n-input
                    v-model:value="upstreamURI"
                    :disabled="
                      busy ||
                      differsFromDesired ||
                      !resource.fields.upstream?.editable
                    "
                    placeholder="/"
                /></n-form-item>
                <p class="muted">路径示例：{{ pathExample }}</p>
                <h3>HTTPS 证书</h3>
                <n-alert
                  v-if="!tlsAvailable"
                  type="warning"
                  :bordered="false"
                  style="margin-bottom: 16px"
                  >{{ tlsReason }}</n-alert
                >
                <n-alert
                  v-if="certificateError"
                  type="warning"
                  :bordered="false"
                  style="margin-bottom: 16px"
                  >{{ certificateError }}</n-alert
                >
                <n-form-item
                  label="证书"
                  :feedback="
                    resource.fields.certificate?.reason ||
                    resource.fields.certificate_key?.reason
                  "
                  ><n-select
                    :value="certificateChoice"
                    :options="certificateOptions"
                    :disabled="
                      !certificateEditable ||
                      !tlsAvailable ||
                      certificateLoading
                    "
                    @update:value="chooseCertificate"
                /></n-form-item>
                <n-form-item v-if="certificateChoice" label="证书版本"
                  ><n-select
                    :value="fieldInputs.certificate || null"
                    :options="certificateVersionOptions"
                    :loading="certificateLoading"
                    :disabled="
                      !certificateEditable ||
                      !tlsAvailable ||
                      certificateLoading
                    "
                    @update:value="chooseCertificateVersion"
                /></n-form-item>
                <p v-if="boundCertificateVersion" class="muted">
                  SAN：{{
                    [
                      ...boundCertificateVersion.summary.dns_names,
                      ...boundCertificateVersion.summary.ip_addresses,
                    ].join("、")
                  }}
                </p>
                <n-button
                  :disabled="
                    busy ||
                    differsFromDesired ||
                    !tlsAvailable ||
                    !resource.fields.listeners?.editable ||
                    !fieldInputs.certificate
                  "
                  @click="addHTTPSListener"
                  >添加 443 HTTPS 监听</n-button
                >
                <p class="muted">
                  证书链与私钥成对保存。更换版本后须应用配置；移除证书前先移除
                  SSL 监听。HSTS 仅对 HTTPS 客户端生效；包含子域名或 preload
                  前须确认相应域名都支持 HTTPS。preload
                  标记不会自动提交预加载名单。<router-link to="/certificates"
                    >管理证书</router-link
                  >
                </p>
              </template>
              <n-form-item
                v-for="(field, name) in regularFields"
                :key="name"
                :label="fieldLabels[name] ?? name"
                :feedback="field.reason || fieldFeatureReason(name)"
                ><n-select
                  v-if="fieldOptions(name)"
                  v-model:value="fieldInputs[name]"
                  :options="fieldOptions(name) ?? []"
                  :disabled="
                    busy ||
                    !field.editable ||
                    differsFromDesired ||
                    !!fieldFeatureReason(name)
                  " />
                <n-input
                  v-else
                  v-model:value="fieldInputs[name]"
                  :type="field.format === 'lines' ? 'textarea' : 'text'"
                  :disabled="
                    busy ||
                    !field.editable ||
                    differsFromDesired ||
                    !!fieldFeatureReason(name)
                  "
                  placeholder="未设置" /></n-form-item
              ><n-button
                type="primary"
                :loading="busy"
                :disabled="busy || differsFromDesired || !formDirty"
                @click="saveFields"
                >保存字段</n-button
              ></n-form
            ></template
          ><n-empty v-else description="选择一个资源查看常用字段" />
        </div>
      </div>
      <n-empty v-else description="暂无受管代理配置"
        ><template #extra
          ><n-button :disabled="busy || dirty" @click="createVisible = true"
            >新建代理配置</n-button
          ></template
        ></n-empty
      >
    </n-tab-pane></n-tabs
  >
  <configuration-changes
    v-model:show="changesVisible"
    :tree="tree"
    :files="files"
    :applied-revision="runtime?.revision_id ?? ''"
  />
  <nginx-external
    v-model:show="externalVisible"
    :tree="tree"
    @captured="capturedExternal"
    @restored="loadRuntime"
  />
  <nginx-modules
    v-model:show="modulesVisible"
    :tree="tree"
    @saved="setTree($event.tree)"
  />
  <n-modal
    v-model:show="createVisible"
    preset="card"
    title="新建代理配置"
    style="width: 480px; max-width: 94vw"
    ><n-form :disabled="busy" @submit.prevent="createResource">
      <n-form-item label="名称"
        ><n-input v-model:value="createName" :maxlength="128"
      /></n-form-item>
      <n-form-item label="备注"
        ><n-input v-model:value="createNotes" type="textarea" :maxlength="2048"
      /></n-form-item>
      <n-form-item label="类型"
        ><n-select
          v-model:value="createKind"
          :options="[
            { label: 'HTTP 反向代理', value: 'http' },
            { label: 'TCP / UDP Stream', value: 'stream' },
          ]" /></n-form-item
      ><n-form-item label="监听"
        ><n-input
          v-model:value="createListen"
          type="textarea"
          placeholder="每行一项：8080 或 [::]:8080；UDP 添加 udp" /></n-form-item
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
      ><n-form-item label="可选上游组成员"
        ><n-input
          v-model:value="createMembers"
          type="textarea"
          placeholder="127.0.0.1:3000 weight=2&#10;127.0.0.1:3001 weight=1"
      /></n-form-item>
      <p class="muted">
        上游组成员留空时使用单一地址。HTTPS 上游地址的主机名用于 TLS 校验。
      </p>
      <n-button block type="primary" attr-type="submit" :loading="busy"
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
    ><p class="muted">选择保留材料的修订加载原文，保存时会创建新修订。</p>
    <n-data-table
      :columns="revisionColumns"
      :data="revisions"
      :row-props="
        (row: Revision) => ({
          onClick: () => loadRevision(row),
          style: row.pruned_at
            ? 'cursor: default; opacity: .6'
            : 'cursor: pointer',
        })
      "
      :bordered="false"
  /></n-modal>
</template>
