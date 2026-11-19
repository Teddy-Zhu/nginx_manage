<route lang="json">
{
  "meta": {
    "title": "网站管理",
    "nav": true,
    "order": 10,
    "symbol": "⌘",
    "group": "网站服务",
    "software": "nginx"
  }
}
</route>

<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import FormDialog from "../components/FormDialog.vue";
import { randomUUID } from "../utils/crypto";

import NginxFieldInput from "../components/NginxFieldInput.vue";
import { nginxArgs } from "../utils/form";
import { ref, computed, h, onMounted, onUnmounted, watch } from "vue";
import { onBeforeRouteLeave } from "vue-router";
import {
  NButton,
  NInput,
  NAlert,
  NTag,
  NEmpty,
  NModal,
  NFormItem,
  NSelect,
  NSwitch,
  NDropdown,
  NTabs,
  NTabPane,
  NRadioGroup,
  NRadioButton,
  NDataTable,
  NTooltip,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  ApiError,
  type Tree,
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
import UpstreamMembers from "../components/UpstreamMembers.vue";
const api = useNodeAPI();

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
const diagnostics = ref<Tree["diagnostics"]>([]);
const changesVisible = ref(false),
  externalVisible = ref(false);
const modulesVisible = ref(false);
const sourceVisible = ref(false);
const resourceVisible = ref(false);
const fileVisible = ref(false),
  newPath = ref("");
const editorOpen = computed(() => resourceVisible.value || sourceVisible.value);
const metadata = ref<ResourceMetadata>({
  name: "",
  notes: "",
  enabled: true,
  client_deny: false,
});
const editorMode = ref<"create" | "edit" | "copy">("edit");
const editorTab = ref("basic");
const editorError = ref("");
const resource = ref<Resource | null>(null),
  fieldInputs = ref<Record<string, string>>({});
const enablingGroup = ref(false);
const editorSnapshot = computed(() =>
  JSON.stringify([metadata.value, fieldInputs.value, enablingGroup.value]),
);
const editorBaseline = ref("");
const siteSearch = ref(""),
  siteKind = ref("all"),
  siteState = ref("all"),
  sitePage = ref(1),
  sitePageSize = ref(20);
const filteredSites = computed(() => {
  const term = siteSearch.value.trim().toLowerCase();
  return (tree.value?.resources ?? []).filter(
    (item) =>
      (siteKind.value === "all" || item.kind === siteKind.value) &&
      (siteState.value === "all" ||
        item.metadata.enabled === (siteState.value === "enabled")) &&
      (!term ||
        [
          item.metadata.name,
          item.metadata.notes,
          ...["domains", "listeners", "upstream", "upstream_servers"].flatMap(
            (key) => item.fields[key]?.values ?? [],
          ),
        ].some((value) => value.toLowerCase().includes(term))),
  );
});
watch([siteSearch, siteKind, siteState], () => {
  sitePage.value = 1;
});
watch(
  () => filteredSites.value.length,
  (count) => {
    sitePage.value = Math.max(
      1,
      Math.min(sitePage.value, Math.ceil(count / sitePageSize.value)),
    );
  },
);
function siteName(item: Resource) {
  return (
    item.metadata.name ||
    item.fields.domains?.values[0] ||
    (item.kind === "http" ? "未命名网站" : "未命名端口转发")
  );
}
function siteTarget(item: Resource) {
  const members = item.fields.upstream_servers?.values ?? [];
  return members.length
    ? members.join("\n")
    : item.fields.upstream?.values.join("、") || "未设置转发目标";
}
const siteColumns: DataTableColumns<Resource> = [
  {
    title: "网站 / 服务",
    key: "name",
    width: 220,
    ellipsis: { tooltip: true },
    render: (item) =>
      h("div", { class: "site-identity" }, [
        h("strong", { class: "site-name" }, siteName(item)),
        item.metadata.notes
          ? h(
              "span",
              { class: "site-notes", title: item.metadata.notes },
              item.metadata.notes,
            )
          : null,
      ]),
  },
  {
    title: "域名",
    key: "domains",
    minWidth: 180,
    ellipsis: { tooltip: true },
    render: (item) =>
      item.kind === "http"
        ? item.fields.domains?.values.join("、") || "未设置域名"
        : "—",
  },
  {
    title: "访问入口",
    key: "listeners",
    width: 190,
    ellipsis: { tooltip: true },
    render: (item) =>
      (item.fields.listeners?.values ?? [])
        .map((value) => {
          const args = nginxArgs(value);
          return `${args[0] ?? ""} · ${args.includes("ssl") ? "HTTPS" : args.includes("udp") ? "UDP" : item.kind === "http" ? "HTTP" : "TCP"}`;
        })
        .join("、"),
  },
  {
    title: "转发目标",
    key: "upstream",
    minWidth: 220,
    render: (item) =>
      h(NTooltip, null, {
        trigger: () =>
          h("div", { class: "site-target" }, [
            (item.fields.upstream_servers?.values.length ?? 0) > 0
              ? h(
                  "span",
                  { class: "site-target-label" },
                  `服务器组 · ${item.fields.upstream_servers?.values.length ?? 0} 台`,
                )
              : null,
            h(
              "span",
              { class: "site-truncate" },
              siteTarget(item).replaceAll("\n", "、"),
            ),
          ]),
        default: () =>
          h(
            "span",
            {
              style: {
                whiteSpace: "pre-line",
                overflowWrap: "anywhere",
                maxWidth: "420px",
                display: "block",
              },
            },
            siteTarget(item),
          ),
      }),
  },
  {
    title: "状态",
    key: "enabled",
    width: 85,
    render: (item) =>
      h(
        NTag,
        {
          size: "small",
          bordered: false,
          type: item.metadata.enabled ? "success" : "default",
        },
        { default: () => (item.metadata.enabled ? "启用" : "停用") },
      ),
  },
  {
    title: "操作",
    key: "actions",
    width: 165,
    render: (item) =>
      h("div", { class: "site-actions" }, [
        h(
          NButton,
          {
            size: "small",
            quaternary: true,
            type: "primary",
            disabled: busy.value,
            onClick: () => selectResource(item),
          },
          { default: () => "编辑" },
        ),
        h(
          NButton,
          {
            size: "small",
            quaternary: true,
            disabled: busy.value || dirty.value,
            onClick: () => selectResource(item, "copy"),
          },
          { default: () => "复制配置" },
        ),
      ]),
  },
];
const regularFields = computed(() =>
  Object.fromEntries(
    Object.entries(resource.value?.fields ?? {}).filter(
      ([name, field]) =>
        name !== "certificate" &&
        name !== "certificate_key" &&
        (name !== "upstream_servers" ||
          enablingGroup.value ||
          field.editable ||
          field.values.length > 0),
    ),
  ),
);
const groupedUpstream = computed(
  () =>
    enablingGroup.value ||
    (resource.value?.fields.upstream_servers?.editable === true &&
      resource.value.fields.upstream_servers.values.length > 0),
);
const groupedHTTP = computed(
  () =>
    !enablingGroup.value &&
    (resource.value?.fields.upstream_servers?.values.length ?? 0) > 0 &&
    resource.value?.kind === "http" &&
    /^https?:\/\//.test(fieldInputs.value.upstream ?? ""),
);
const newGroupHost = computed(() => {
  if (!enablingGroup.value || resource.value?.kind !== "http")
    return "$proxy_host";
  try {
    return new URL(fieldInputs.value.upstream ?? "").host || "$proxy_host";
  } catch {
    return "$proxy_host";
  }
});
watch(
  newGroupHost,
  (host, previous) => {
    // Keep the default Host aligned with the target when enabling a server group.
    // Explicit custom headers remain untouched.
    if (!resource.value || resource.value.kind !== "http") return;
    fieldInputs.value.request_headers = (
      fieldInputs.value.request_headers ?? ""
    )
      .split("\n")
      .map((line) => {
        const args = nginxArgs(line);
        return args[0]?.toLowerCase() === "host" && args[1] === previous
          ? `Host ${host}`
          : line;
      })
      .join("\n");
  },
  { flush: "sync" },
);
const upstreamProtocol = computed({
  get: () => fieldInputs.value.upstream?.match(/^(https?):\/\//)?.[1] ?? null,
  set: (value: string | null) => {
    if (value === "http" || value === "https")
      fieldInputs.value.upstream = (fieldInputs.value.upstream ?? "").replace(
        /^https?:/,
        `${value}:`,
      );
  },
});
const editorTabs = computed(() => [
  { key: "basic", title: "基本设置" },
  ...(resource.value?.kind === "http"
    ? [
        { key: "forwarding", title: "转发设置" },
        { key: "https", title: "HTTPS" },
        { key: "security", title: "访问控制" },
      ]
    : []),
  {
    key: "performance",
    title: resource.value?.kind === "http" ? "性能与日志" : "连接与日志",
  },
]);
const fieldGroups = computed(() => {
  const groups = [
    {
      key: "entry",
      tab: "basic",
      title: "访问入口",
      names: ["domains", "listeners"],
    },
    {
      key: "target",
      tab: "basic",
      title: "转发目标",
      names: ["upstream", "upstream_servers"],
    },
    {
      key: "paths",
      tab: "forwarding",
      title: "路径转发",
      names: ["location_prefix"],
    },
    {
      key: "headers",
      tab: "forwarding",
      title: "请求与响应",
      names: ["http_version", "request_headers", "response_headers"],
    },
    {
      key: "target-tls",
      tab: "forwarding",
      title: "后端 HTTPS",
      names: [
        "upstream_tls_verify",
        "upstream_tls_sni",
        "upstream_tls_name",
        "upstream_tls_ca",
      ],
    },
    {
      key: "https",
      tab: "https",
      title: "HTTPS 与证书",
      names: ["https_redirect", "tls_protocols", "hsts", "http01"],
    },
    {
      key: "access",
      tab: "security",
      title: "访问防护",
      names: ["access_list", "waf_policy"],
    },
    {
      key: "client",
      tab: "security",
      title: "访问来源识别",
      names: ["trusted_sources", "real_ip_header", "real_ip_recursive"],
    },
    {
      key: "limits",
      tab: "performance",
      title: "容量与超时",
      names: [
        "body_size",
        "connect_timeout",
        "read_timeout",
        "send_timeout",
        "session_timeout",
        "responses",
      ],
    },
    {
      key: "buffer",
      tab: "performance",
      title: "缓存与缓冲",
      names: ["cache", "buffering", "request_buffering"],
    },
    {
      key: "logs",
      tab: "performance",
      title: "日志记录",
      names: ["access_log", "error_log"],
    },
  ];
  const assigned = new Set(groups.flatMap((group) => group.names));
  groups.push({
    key: "other",
    tab: "performance",
    title: "其他设置",
    names: Object.keys(regularFields.value).filter(
      (name) => !assigned.has(name),
    ),
  });
  return groups
    .map((group) => ({
      ...group,
      fields: Object.fromEntries(
        group.names
          .filter((name) => name in regularFields.value)
          .map((name) => [name, regularFields.value[name]]),
      ),
    }))
    .filter(
      (group) =>
        Object.keys(group.fields).length ||
        (group.key === "https" && resource.value?.kind === "http"),
    );
});
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
  () => !!resource.value && editorSnapshot.value !== editorBaseline.value,
);
const dirty = computed(
  () =>
    tree.value !== null &&
    (sourceJSON.value !== persisted.value || !!formDirty.value),
);
const runtimeActions = computed(() => [
  { label: "外部修改", key: "external", disabled: busy.value || dirty.value },
  { label: "模块管理", key: "modules", disabled: busy.value || dirty.value },
]);
function selectRuntimeAction(key: string) {
  if (key === "external") externalVisible.value = true;
  else if (key === "modules") modulesVisible.value = true;
}
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
  listeners: "访问端口与监听地址",
  domains: "域名",
  upstream: "目标网站地址",
  upstream_servers: "目标服务器",
  location_prefix: "网站访问路径",
  body_size: "最大请求体",
  connect_timeout: "连接超时",
  read_timeout: "读取超时",
  send_timeout: "发送超时",
  session_timeout: "会话超时",
  responses: "UDP 会话预期响应次数",
  http_version: "上游 HTTP 版本",
  buffering: "响应缓冲",
  request_buffering: "请求缓冲",
  request_headers: "转发请求头",
  response_headers: "响应头",
  upstream_tls_verify: "校验上游 TLS",
  upstream_tls_sni: "发送上游 SNI",
  upstream_tls_name: "上游 TLS 校验名称",
  upstream_tls_ca: "上游受信 CA 路径",
  certificate: "证书链路径",
  certificate_key: "证书私钥路径",
  https_redirect: "HTTPS 跳转端口",
  hsts: "HSTS",
  tls_protocols: "TLS 协议",
  access_log: "访问日志",
  error_log: "错误日志",
  cache: "响应缓存",
  trusted_sources: "可信代理来源",
  real_ip_header: "真实 IP 头",
  real_ip_recursive: "递归解析真实 IP",
  access_list: "IP 与国家访问控制",
  waf_policy: "网站防护策略",
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
          label: `${item.name || item.id.slice(0, 8)} · ${item.mode === "allowlist" ? "白名单" : "黑名单"}`,
          value: item.id,
        })) ?? []),
    ];
  return null;
}
function canPreset(kind: "websocket" | "streaming" | "http") {
  const fields =
    kind === "streaming"
      ? ["buffering", "request_buffering", "cache", "read_timeout"]
      : [
          "request_headers",
          "http_version",
          ...(kind === "websocket" ? ["read_timeout"] : []),
        ];
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
      .filter(
        (line) =>
          !["upgrade", "connection"].includes(
            nginxArgs(line)[0]?.toLowerCase() ?? "",
          ),
      );
    if (kind === "websocket")
      headers.push("Upgrade $http_upgrade", "Connection upgrade");
    if (kind === "websocket") fieldInputs.value.read_timeout = "3600s";
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
async function load(refresh = false) {
  if (dirty.value && !window.confirm("有未保存修改，确认重新加载？")) return;
  if (refresh) api.reloadLive();
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
async function save(validate = false, apply = false) {
  if (formDirty.value) return;
  const input = {
    base_version: tree.value?.version ?? 0,
    files: files.value,
    draft: false,
    validate,
    apply,
  };
  await run(async () => {
    try {
      const result = await api.save(input, keyFor(input));
      setTree(result.tree);
      message.success(
        result.task_id
          ? apply
            ? "配置已保存并加入应用队列"
            : "配置已保存并加入 Nginx 校验队列"
          : "配置已保存，尚未应用",
      );
    } catch (error) {
      if (error instanceof ApiError && error.code === "CONFIG_INVALID") {
        const data = error.data as SaveResult | null;
        if (data?.tree) diagnostics.value = data.tree.diagnostics;
      }
      throw error;
    }
  });
}
function selectResource(
  value: Resource,
  mode: "create" | "edit" | "copy" = "edit",
) {
  if (formDirty.value && !window.confirm("字段修改尚未保存，确认切换？"))
    return;
  resourceVisible.value = true;
  editorMode.value = mode;
  editorError.value = "";
  editorTab.value = "basic";
  resource.value = value;
  enablingGroup.value = false;
  metadata.value = { ...value.metadata };
  fieldInputs.value = Object.fromEntries(
    Object.entries(value.fields).map(([key, field]) => [key, fieldText(field)]),
  );
  if (mode === "create") {
    fieldInputs.value.domains = "";
    fieldInputs.value.upstream = "";
    if (value.kind === "stream") fieldInputs.value.listeners = "";
  } else if (mode === "copy") {
    metadata.value.name =
      Array.from(siteName(value)).slice(0, 125).join("") + " 副本";
    metadata.value.enabled = false;
  }
  editorBaseline.value = editorSnapshot.value;
  certificateRequest++;
  certificateChoice.value =
    (value.fields.certificate?.values[0] ?? "").split("/")[1] ?? "";
  certificateDetail.value = null;
  certificateError.value = "";
  certificateLoading.value = false;
  if (certificateChoice.value)
    void loadCertificateDetail(certificateChoice.value, false);
}
function closeResource() {
  if (
    busy.value ||
    (formDirty.value && !window.confirm("修改尚未保存，确认取消？"))
  )
    return;
  resourceVisible.value = false;
  resource.value = null;
  fieldInputs.value = {};
  certificateRequest++;
  certificateChoice.value = "";
  certificateDetail.value = null;
}
async function startCreate(kind: "http" | "stream" = "http") {
  if (differsFromDesired.value) return;
  await run(async () => {
    const template = await api.resourceTemplate(kind);
    selectResource(template, "create");
  });
}
function changeCreateKind(value: unknown) {
  if (
    (value === "http" || value === "stream") &&
    value !== resource.value?.kind
  )
    void startCreate(value);
}
function inputValues(name: string): string[] {
  const value = fieldInputs.value[name]?.trim() ?? "";
  if (!value) return [];
  const format = resource.value?.fields[name]?.format;
  return format === "tokens"
    ? value.split(/\s+/)
    : format === "lines"
      ? value
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean)
      : [value];
}
async function saveFields() {
  if (!resource.value || !tree.value || differsFromDesired.value) return;
  editorError.value = "";
  const changes: Record<string, string[]> = {};
  for (const [name, field] of Object.entries(resource.value.fields)) {
    if (
      (field.editable ||
        (name === "upstream_servers" && enablingGroup.value)) &&
      (fieldInputs.value[name] ?? "") !== fieldText(field)
    )
      changes[name] = inputValues(name);
  }
  const id = resource.value.id,
    version = tree.value.version,
    mode = editorMode.value;
  const savedMetadata = { ...metadata.value };
  if (mode === "create") {
    const input = {
      base_version: version,
      kind: resource.value.kind as "http" | "stream",
      listen: inputValues("listeners"),
      domains: inputValues("domains"),
      upstream: inputValues("upstream")[0] ?? "",
      preserve_host: false,
      upstream_servers: enablingGroup.value
        ? inputValues("upstream_servers")
        : [],
      metadata: savedMetadata,
      changes: { ...changes },
    };
    if (!input.listen.length) editorError.value = "请至少添加一个访问端口。";
    else if (input.kind === "http" && !input.domains.length)
      editorError.value = "请填写网站域名。";
    else if (enablingGroup.value && !input.upstream_servers.length)
      editorError.value = "请至少添加一台目标服务器。";
    else if (
      !(input.kind === "stream" && enablingGroup.value) &&
      !input.upstream
    )
      editorError.value =
        input.kind === "http"
          ? "请填写目标网站地址。"
          : "请填写目标服务器地址与端口。";
    if (editorError.value) {
      editorTab.value = "basic";
      return;
    }
    for (const name of ["listeners", "domains", "upstream", "upstream_servers"])
      delete input.changes[name];
    await run(async () => {
      const result = await api.createResource(input, keyFor(input));
      setTree(result.tree);
      resourceVisible.value = false;
    }, "网站或代理已创建，尚未应用");
    return;
  }
  const details = { changes, metadata: savedMetadata };
  await run(
    async () => {
      const result =
        mode === "copy"
          ? await api.resourceAction(
              id,
              "copy",
              version,
              keyFor({ id, version, ...details, action: "copy" }),
              details,
            )
          : await api.patch(
              id,
              version,
              changes,
              keyFor({ id, version, ...details }),
              savedMetadata,
            );
      setTree(result.tree);
      resourceVisible.value = false;
    },
    mode === "copy" ? "配置副本已创建，尚未应用" : "代理配置已保存，尚未应用",
  );
}
async function deleteResource() {
  if (!resource.value || !tree.value || dirty.value) return;
  const id = resource.value.id,
    version = tree.value.version;
  if (
    !window.confirm(`确认删除“${siteName(resource.value)}”？应用配置后生效。`)
  )
    return;
  await run(async () => {
    const result = await api.resourceAction(
      id,
      "delete",
      version,
      keyFor({ action: "delete", id, version }),
    );
    setTree(result.tree);
    resourceVisible.value = false;
  }, "代理已删除，尚未应用");
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
function capturedExternal(result: SaveResult) {
  sourceVisible.value = true;
  files.value = structuredClone(result.tree.files);
  selected.value = files.value[0]?.id ?? "";
  diagnostics.value = result.tree.diagnostics;
  draftNote.value = "外部配置已载入编辑区，请检查后保存";
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
useLiveRefresh(
  api,
  ["nginx"],
  async () => {
    await loadRuntime();
    await loadTLSChoices();
    if (!dirty.value && !editorOpen.value) {
      const next = await api.tree();
      if (!dirty.value && !editorOpen.value) setTree(next);
    }
  },
  () => busy.value || editorOpen.value,
);
onMounted(() => {
  void load();
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => window.removeEventListener("beforeunload", beforeUnload));
</script>

<template>
  <div class="nginx-page page-stack">
    <div class="site-summary">
      <div class="inline-gap">
        <n-tag
          v-if="runtime?.external_change"
          size="small"
          type="error"
          :bordered="false"
        >
          存在外部修改
        </n-tag><n-tag v-if="dirty" size="small" type="warning" :bordered="false">
          未保存修改
        </n-tag><n-tag
          v-if="runtime?.running && runtime.integrity"
          size="small"
          :type="
            runtime.revision_id === tree?.revision_id ? 'success' : 'warning'
          "
          :bordered="false"
        >
          {{
            runtime.revision_id === tree?.revision_id ? "已生效" : "待应用"
          }}
        </n-tag><span class="muted">{{ draftNote }}</span>
      </div>
      <Teleport to="#page-heading-actions" defer>
        <div class="inline-gap">
          <NButton :disabled="busy || !!formDirty" @click="sourceVisible = true">
            源文件
          </NButton>
          <NButton :disabled="busy || !!formDirty" @click="changesVisible = true">
            配置差异
          </NButton>
          <NDropdown
            trigger="click"
            :options="runtimeActions"
            @select="selectRuntimeAction"
          >
            <NButton :disabled="busy">
              运行环境
            </NButton>
          </NDropdown>
          <n-button :disabled="busy" @click="load(true)">
            刷新
          </n-button><n-button
            :disabled="
              busy ||
                dirty ||
                !tree?.revision_id ||
                !runtime?.available ||
                !runtime.integrity ||
                !runtime.running
            "
            @click="applySaved"
          >
            应用配置
          </n-button><n-button
            type="primary"
            :disabled="busy || dirty"
            @click="startCreate()"
          >
            ＋ 添加网站 / 代理
          </n-button>
        </div>
      </Teleport>
      <span class="section-note">修改后需应用配置</span>
    </div>
    <n-alert
      v-if="runtimeError || runtime?.reason"
      type="warning"
      :bordered="false"
      class="site-alert"
    >
      {{ runtimeError || runtime?.reason }}
    </n-alert>

    <n-alert
      v-if="differsFromDesired"
      type="warning"
      :bordered="false"
      class="site-alert"
    >
      源文件有未保存修改，请先保存后再修改表单。<NButton
        text
        type="primary"
        @click="sourceVisible = true"
      >
        继续编辑源文件
      </NButton>
    </n-alert>
    <section class="surface site-list">
      <div class="site-list-toolbar">
        <NInput
          v-model:value="siteSearch"
          clearable
          placeholder="搜索名称、域名、端口或转发目标"
          aria-label="搜索网站"
          class="site-search"
        />
        <NSelect
          v-model:value="siteKind"
          aria-label="筛选代理类型"
          class="site-filter"
          :options="[
            { label: '全部类型', value: 'all' },
            { label: '网站代理', value: 'http' },
            { label: '端口转发', value: 'stream' },
          ]"
        />
        <NSelect
          v-model:value="siteState"
          aria-label="筛选启用状态"
          class="site-filter"
          :options="[
            { label: '全部状态', value: 'all' },
            { label: '启用', value: 'enabled' },
            { label: '停用', value: 'disabled' },
          ]"
        />
        <span class="section-note site-count">共 {{ filteredSites.length }} 项</span>
      </div>
      <NDataTable
        :data="filteredSites"
        :columns="siteColumns"
        :row-key="(item: Resource) => item.id"
        size="small"
        :bordered="false"
        :scroll-x="1060"
        table-layout="fixed"
        :pagination="{
          page: sitePage,
          pageSize: sitePageSize,
          showSizePicker: true,
          pageSizes: [10, 20, 50],
          onUpdatePage: (value: number) => (sitePage = value),
          onUpdatePageSize: (value: number) => {
            sitePageSize = value;
            sitePage = 1;
          },
        }"
      >
        <template #empty>
          <NEmpty
            :description="
              tree?.resources.length
                ? '没有符合条件的网站或代理'
                : '尚未添加网站或代理'
            "
          >
            <template v-if="!tree?.resources.length" #extra>
              <NButton :disabled="busy || dirty" @click="startCreate()">
                添加网站 / 代理
              </NButton>
            </template>
          </NEmpty>
        </template>
      </NDataTable>
    </section>
    <FormDialog
      :show="resourceVisible"
      :title="`${editorMode === 'create' ? '添加' : editorMode === 'copy' ? '复制' : '编辑'}${resource?.kind === 'stream' ? '端口转发' : '网站代理'}`"
      :busy="busy"
      width="980px"
      :submit-disabled="
        differsFromDesired || (editorMode === 'edit' && !formDirty)
      "
      :submit-text="
        editorMode === 'create'
          ? '创建'
          : editorMode === 'copy'
            ? '创建副本'
            : '保存'
      "
      @submit="saveFields"
      @cancel="closeResource"
    >
      <div v-if="resource" class="proxy-editor">
        <NAlert
          v-if="editorError"
          type="warning"
          :bordered="false"
          class="proxy-form-error"
        >
          {{ editorError }}
        </NAlert>
        <NTabs v-model:value="editorTab" type="line">
          <NTabPane
            v-for="tab in editorTabs"
            :key="tab.key"
            :name="tab.key"
            :tab="tab.title"
            display-directive="show"
          >
            <div class="proxy-form">
              <NFormItem
                v-if="tab.key === 'basic' && editorMode === 'create'"
                label="代理类型"
                :show-feedback="false"
              >
                <NRadioGroup
                  :value="resource.kind"
                  :disabled="busy"
                  @update:value="changeCreateKind"
                >
                  <NRadioButton value="http">
                    网站代理
                  </NRadioButton>
                  <NRadioButton value="stream">
                    TCP / UDP 端口转发
                  </NRadioButton>
                </NRadioGroup>
              </NFormItem>
              <div v-if="tab.key === 'basic'" class="proxy-field-grid">
                <n-form-item :show-feedback="false" label="名称">
                  <n-input
                    v-model:value="metadata.name"
                    :disabled="busy || differsFromDesired"
                    :maxlength="128"
                    placeholder="用于识别这个网站或服务"
                  />
                </n-form-item>
                <n-form-item :show-feedback="false" label="运行状态">
                  <div class="proxy-toggle">
                    <n-switch
                      v-model:value="metadata.enabled"
                      :disabled="busy || differsFromDesired"
                      aria-label="启用网站或代理"
                    />
                    <span class="section-note">{{
                      metadata.enabled ? "启用" : "停用"
                    }}</span>
                  </div>
                </n-form-item>
              </div>
              <section
                v-for="group in fieldGroups.filter(
                  (item) => item.tab === tab.key,
                )"
                :key="group.key"
                class="proxy-settings"
              >
                <div class="proxy-section-heading">
                  <h3>{{ group.title }}</h3>
                  <n-button
                    v-if="
                      group.key === 'target' &&
                        !resource.fields.upstream_servers?.editable
                    "
                    size="small"
                    :disabled="
                      busy ||
                        differsFromDesired ||
                        !resource.fields.upstream?.editable
                    "
                    @click="enablingGroup = !enablingGroup"
                  >
                    {{ enablingGroup ? "返回单个目标" : "改用服务器组" }}
                  </n-button>
                  <n-tag
                    v-else-if="group.key === 'target' && groupedUpstream"
                    size="small"
                    :bordered="false"
                  >
                    服务器组
                  </n-tag>
                </div>
                <p v-if="group.key === 'target'" class="section-note">
                  {{
                    groupedUpstream
                      ? "访问请求会转发至下面的目标服务器。"
                      : resource.kind === "http"
                        ? "填写要转发到的网站地址，支持 HTTP 和 HTTPS。"
                        : "填写目标服务的地址与端口。"
                  }}
                </p>
                <p v-if="group.key === 'client'" class="section-note">
                  网站前方使用 CDN 或其他代理时，在这里设置可信来源。
                </p>
                <template v-if="group.key === 'https'">
                  <n-alert
                    v-if="!tlsAvailable"
                    type="warning"
                    :bordered="false"
                    style="margin-bottom: 16px"
                  >
                    {{ tlsReason }}
                  </n-alert>
                  <n-alert
                    v-if="certificateError"
                    type="warning"
                    :bordered="false"
                    style="margin-bottom: 16px"
                  >
                    {{ certificateError }}
                  </n-alert>
                  <n-form-item
                    label="证书"
                    :feedback="
                      resource.fields.certificate?.reason ||
                        resource.fields.certificate_key?.reason
                    "
                  >
                    <n-select
                      :value="certificateChoice"
                      :options="certificateOptions"
                      :disabled="
                        !certificateEditable ||
                          !tlsAvailable ||
                          certificateLoading
                      "
                      @update:value="chooseCertificate"
                    />
                  </n-form-item>
                  <n-form-item
                    v-if="certificateChoice"
                    :show-feedback="false"
                    label="证书版本"
                  >
                    <n-select
                      :value="fieldInputs.certificate || null"
                      :options="certificateVersionOptions"
                      :loading="certificateLoading"
                      :disabled="
                        !certificateEditable ||
                          !tlsAvailable ||
                          certificateLoading
                      "
                      @update:value="chooseCertificateVersion"
                    />
                  </n-form-item>
                  <p v-if="boundCertificateVersion" class="muted">
                    证书覆盖域名：{{
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
                  >
                    添加 443 HTTPS 监听
                  </n-button>
                  <p class="muted">
                    更换证书后需应用配置。移除证书前，请先关闭 HTTPS 监听。
                    启用包含子域名的 HSTS 前，请确认所有子域名均支持
                    HTTPS。<router-link to="/certificates">
                      管理证书
                    </router-link>
                  </p>
                </template>

                <div v-if="group.key === 'headers'" class="proxy-presets">
                  <span class="section-note">常用转发配置</span>
                  <div class="inline-gap">
                    <n-button
                      size="small"
                      :disabled="
                        busy || differsFromDesired || !canPreset('http')
                      "
                      @click="preset('http')"
                    >
                      普通网站
                    </n-button>
                    <n-button
                      size="small"
                      :disabled="
                        busy || differsFromDesired || !canPreset('websocket')
                      "
                      @click="preset('websocket')"
                    >
                      WebSocket
                    </n-button>
                    <n-button
                      size="small"
                      :disabled="
                        busy || differsFromDesired || !canPreset('streaming')
                      "
                      @click="preset('streaming')"
                    >
                      SSE / 流式响应
                    </n-button>
                  </div>
                </div>
                <div class="proxy-field-grid">
                  <n-form-item
                    v-for="(field, name) in group.fields"
                    :key="`${resource.id}:${name}`"
                    :class="{
                      'wide-field':
                        field.format === 'lines' ||
                        field.format === 'tokens' ||
                        name === 'upstream_servers' ||
                        name === 'upstream' ||
                        name === 'access_list' ||
                        name === 'waf_policy',
                      'access-list-field': name === 'access_list',
                    }"
                    :label="
                      name === 'upstream' && groupedHTTP
                        ? '后端协议'
                        : name === 'upstream' && resource.kind === 'stream'
                          ? '目标服务器'
                          : (fieldLabels[name] ?? name)
                    "
                    :feedback="
                      (name === 'upstream_servers' && enablingGroup
                        ? ''
                        : field.reason) || fieldFeatureReason(name)
                    "
                    :show-feedback="
                      !!(
                        (name === 'upstream_servers' && enablingGroup
                          ? ''
                          : field.reason) || fieldFeatureReason(name)
                      )
                    "
                  >
                    <n-select
                      v-if="name === 'upstream' && groupedHTTP"
                      v-model:value="upstreamProtocol"
                      :options="[
                        { label: 'HTTP', value: 'http' },
                        { label: 'HTTPS', value: 'https' },
                      ]"
                      :disabled="busy || differsFromDesired || !field.editable"
                    /><n-tag
                      v-else-if="
                        name === 'upstream' &&
                          groupedUpstream &&
                          resource.kind === 'stream'
                      "
                    >
                      服务器组
                    </n-tag>
                    <upstream-members
                      v-else-if="
                        name === 'upstream_servers' &&
                          (field.editable || enablingGroup)
                      "
                      v-model:value="fieldInputs[name]"
                      :disabled="busy || differsFromDesired"
                    /><n-select
                      v-else-if="fieldOptions(name)"
                      v-model:value="fieldInputs[name]"
                      :options="fieldOptions(name) ?? []"
                      :disabled="
                        busy ||
                          !field.editable ||
                          differsFromDesired ||
                          !!fieldFeatureReason(name)
                      "
                    />
                    <NginxFieldInput
                      v-else
                      :value="fieldInputs[name] ?? ''"
                      :name="name"
                      :format="field.format"
                      :kind="resource.kind"
                      :resource-id="resource.id"
                      :disabled="
                        busy ||
                          !field.editable ||
                          differsFromDesired ||
                          !!fieldFeatureReason(name)
                      "
                      @update:value="fieldInputs[name] = $event"
                    />
                    <router-link
                      v-if="name === 'access_list'"
                      class="access-list-link"
                      to="/access-lists"
                    >
                      管理访问名单
                    </router-link>
                  </n-form-item>
                </div>

                <template v-if="group.key === 'paths'">
                  <n-form-item :show-feedback="false" label="替换访问路径前缀">
                    <n-switch
                      v-model:value="rewritePrefix"
                      :disabled="
                        busy ||
                          differsFromDesired ||
                          !resource.fields.upstream?.editable
                      "
                    />
                  </n-form-item>
                  <n-form-item
                    v-if="rewritePrefix"
                    :show-feedback="false"
                    label="目标路径"
                  >
                    <n-input
                      v-model:value="upstreamURI"
                      :disabled="
                        busy ||
                          differsFromDesired ||
                          !resource.fields.upstream?.editable
                      "
                      placeholder="/"
                    />
                  </n-form-item>
                  <p class="muted">
                    路径示例：{{ pathExample }}
                  </p>
                </template>
                <n-form-item
                  v-if="group.key === 'access'"
                  :show-feedback="false"
                  label="自动封禁"
                >
                  <div class="proxy-toggle">
                    <n-switch
                      :value="metadata.client_deny === true"
                      :disabled="busy || differsFromDesired"
                      @update:value="metadata.client_deny = $event === true"
                    />
                    <span class="section-note">对本网站应用自动封禁名单</span>
                  </div>
                </n-form-item>
              </section>
              <n-form-item
                v-if="tab.key === 'basic'"
                :show-feedback="false"
                label="备注（可选）"
              >
                <n-input
                  v-model:value="metadata.notes"
                  type="textarea"
                  :autosize="{ minRows: 2, maxRows: 4 }"
                  :disabled="busy || differsFromDesired"
                  :maxlength="2048"
                  placeholder="记录网站用途或其他说明"
                />
              </n-form-item>
            </div>
          </NTabPane>
        </NTabs>
      </div>
      <template #actions>
        <div v-if="editorMode === 'edit' && resource" class="inline-gap">
          <n-button
            :disabled="busy || dirty"
            @click="resource && selectResource(resource, 'copy')"
          >
            复制配置
          </n-button>
          <n-button
            type="error"
            :disabled="busy || dirty"
            @click="deleteResource"
          >
            删除
          </n-button>
        </div>
      </template>
    </FormDialog>
    <NModal
      v-model:show="sourceVisible"
      preset="card"
      title="Nginx 高级配置"
      style="width: 1400px; max-width: 96vw"
    >
      <NAlert type="warning" :bordered="false" style="margin-bottom: 16px">
        源文件修改会影响代理服务，请在保存前校验配置。
      </NAlert>
      <div class="editor-layout surface">
        <aside class="file-tree">
          <div class="section-heading">
            <h2>配置文件</h2>
            <n-button
              text
              title="添加文件"
              :disabled="busy || !!formDirty"
              @click="fileVisible = true"
            >
              ＋
            </n-button>
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
          <div class="file-budget">
            {{ files.length }} / 128 个文件
          </div>
        </aside>
        <div class="editor-main">
          <template v-if="currentFile">
            <div class="editor-title">
              <span class="mono">{{ currentFile.path }}</span>
              <div class="inline-gap">
                <span class="muted">{{ currentFile.content.split("\n").length }} 行</span><n-button
                  v-if="currentFile.path !== 'nginx.conf'"
                  text
                  type="error"
                  :disabled="busy || !!formDirty"
                  @click="removeFile"
                >
                  移除
                </n-button>
              </div>
            </div>
            <textarea
              v-model="currentFile.content"
              class="code-editor"
              :disabled="busy || !!formDirty"
              spellcheck="false"
              :aria-label="currentFile.path"
              :maxlength="262144"
            />
          </template><n-empty v-else description="请选择配置文件" />
        </div>
      </div>
      <div v-if="diagnostics.length" class="diagnostics surface">
        <div class="section-heading">
          <h2>配置诊断</h2>
          <n-tag type="error" size="small">
            {{ diagnostics.length }} 项
          </n-tag>
        </div>
        <div
          v-for="(item, index) in diagnostics"
          :key="index"
          class="diagnostic-row"
        >
          <span class="mono">{{ files.find((f) => f.id === item.file_id)?.path }}:{{
            item.line
          }}</span><span>{{ item.message }}</span>
        </div>
      </div>
      <div class="save-bar">
        <span class="muted">{{ files.length }} 个配置文件</span>
        <div class="inline-gap">
          <n-button :loading="busy" :disabled="!!formDirty" @click="preview">
            解析与预览
          </n-button><n-button :disabled="busy || !!formDirty" @click="save(true)">
            保存并校验
          </n-button><n-button
            type="primary"
            :disabled="
              busy ||
                !!formDirty ||
                !runtime?.available ||
                !runtime.integrity ||
                !runtime.running
            "
            @click="save(false, true)"
          >
            保存并应用
          </n-button><n-button
            type="primary"
            :loading="busy"
            :disabled="!!formDirty"
            @click="save()"
          >
            保存配置
          </n-button>
        </div>
      </div>
    </NModal>

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
    <FormDialog
      :show="fileVisible"
      title="添加配置文件"
      :busy="busy"
      :dirty="!!newPath.trim()"
      :submit-disabled="!newPath.trim()"
      submit-text="添加"
      @submit="addFile"
      @cancel="
        fileVisible = false;
        newPath = '';
      "
    >
      <n-form-item :show-feedback="false" label="受管相对路径">
        <n-input v-model:value="newPath" placeholder="http/site.conf" />
      </n-form-item>
    </FormDialog>
  </div>
</template>

<style scoped>
.nginx-page {
  gap: 12px;
}
.site-summary {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 16px;
  min-height: 24px;
}
.site-summary > .inline-gap {
  gap: 8px;
}
.site-alert {
  margin: 0;
}
.site-list {
  padding: 16px;
}
.site-list-toolbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
}
.site-search {
  width: 340px;
  max-width: 100%;
}
.site-filter {
  width: 132px;
}
.site-count {
  margin-inline-start: auto;
  white-space: nowrap;
}
.site-list :deep(.site-actions) {
  display: flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}
.site-list :deep(.site-identity),
.site-list :deep(.site-target) {
  display: flex;
  flex-direction: column;
  min-width: 0;
  gap: 2px;
}
.site-list :deep(.site-name) {
  font-size: 13px;
  font-weight: 600;
}
.site-list :deep(.site-notes) {
  font-size: 12px;
  color: var(--text-muted);
}
.site-list :deep(.site-name),
.site-list :deep(.site-notes),
.site-list :deep(.site-truncate) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.site-list :deep(.site-target-label) {
  font-size: 12px;
  color: var(--text-muted);
}
@media (max-width: 720px) {
  .site-search {
    width: 100%;
  }
  .site-filter {
    flex: 1;
  }
  .site-list {
    padding: 12px;
  }
}
.proxy-editor {
  container: proxy-editor / inline-size;
  min-width: 0;
}
.proxy-form {
  display: grid;
  gap: 24px;
  padding-top: 12px;
}
.proxy-form > .n-form-item {
  margin-bottom: 0;
}
.proxy-settings {
  display: grid;
  gap: 18px;
  min-width: 0;
  padding: 20px;
  border: 1px solid var(--border-color);
  border-radius: 10px;
}
.proxy-section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}
.proxy-settings > .n-button {
  justify-self: start;
}
.proxy-settings > .n-form-item:last-child {
  margin-bottom: 0;
}
.proxy-field-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px 24px;
}
.proxy-field-grid > * {
  min-width: 0;
}
.proxy-field-grid .wide-field {
  grid-column: 1 / -1;
}
.proxy-toggle {
  display: flex;
  align-items: center;
  gap: 12px;
  min-height: 34px;
}
.proxy-presets {
  display: grid;
  gap: 10px;
}
.proxy-target-mode {
  justify-self: start;
}
.proxy-form-error {
  position: sticky;
  top: 0;
  z-index: 2;
}
.access-list-link {
  white-space: nowrap;
  flex-shrink: 0;
}
.access-list-field :deep(.n-form-item-blank) {
  flex-wrap: wrap;
  gap: 8px;
}
.access-list-field :deep(.n-select) {
  flex: 1;
  min-width: 160px;
}
@container proxy-editor (max-width: 600px) {
  .proxy-field-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .proxy-settings {
    padding: 16px;
  }
  .proxy-toggle {
    flex-wrap: wrap;
  }
}
</style>
