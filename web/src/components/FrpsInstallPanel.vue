<script setup lang="ts">
import { computed, onMounted, ref, watch, toRaw } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import {
  NAlert,
  NButton,
  NEmpty,
  NFormItem,
  NInput,
  NInputNumber,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NSkeleton,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  useMessage,
} from "naive-ui";
import {
  ApiError,
  type FrpsConfig,
  type FrpsStatus,
  type FrpsRequest,
} from "../api/client";
import { useSoftwareOperations } from "../composables/software";
import { useLiveRefresh } from "../composables/live";
import { useNodes } from "../stores/node";
import { randomUUID } from "../utils/crypto";
import type { PortRange } from "../utils/form";
import { softwareStatus } from "../utils/software";
import FormDialog from "./FormDialog.vue";
import PortRangesInput from "./PortRangesInput.vue";
import TaskLogButton from "./TaskLogButton.vue";

const emit = defineEmits<{ changed: []; busy: [value: boolean] }>();
const message = useMessage(),
  route = useRoute(),
  router = useRouter();
const status = ref<FrpsStatus | null>(null),
  reading = ref(false),
  readError = ref("");
type SettingsTab = "connection" | "ports" | "web";
const editing = ref(false),
  tab = ref<SettingsTab>("connection"),
  draft = ref<FrpsConfig | null>(null),
  ranges = ref<PortRange[]>([]),
  unrestricted = ref(false),
  addressMode = ref("all");
const httpEnabled = ref(false),
  httpsEnabled = ref(false);
const addressOptions = [
  { label: "所有 IPv4 地址（推荐）", value: "all" },
  { label: "所有 IPv6 地址", value: "ipv6" },
  { label: "指定 IP 地址", value: "custom" },
];
const { api, run, busy, permitted, active, last, tasks, submit } =
  useSoftwareOperations(load, ["components.manage", "system.write"]);
const processing = computed(() => busy.value || active.value);
const editorDraft = computed(() => ({
  config: draft.value,
  ranges: ranges.value,
  unrestricted: unrestricted.value,
  httpEnabled: httpEnabled.value,
  httpsEnabled: httpsEnabled.value,
  addressMode: addressMode.value,
}));
const currentTask = computed(() =>
  tasks.value.find((task) => task.result?.input.software?.action === "frps"),
);
const display = computed(() =>
  softwareStatus(
    status.value?.installed ?? null,
    status.value?.state ?? "unknown",
    currentTask.value,
  ),
);
const nodes = useNodes();
const endpoint = computed(() => {
  if (!status.value) return "";
  let host = status.value.config.bind_address;
  if (host === "0.0.0.0" || host === "::") {
    const origin = nodes.selected
      ? nodes.connections.find((item) => item.id === nodes.selected?.connection)
          ?.url
      : window.location.origin;
    try {
      host = new URL(origin || window.location.origin).hostname;
    } catch {
      return "";
    }
  }
  if (host.includes(":") && !host.startsWith("[")) host = `[${host}]`;
  return `${host}:${status.value.config.bind_port}`;
});
const allowed = computed(
  () =>
    status.value?.config.allow_ports
      .map((row) =>
        row.from === row.to ? String(row.from) : `${row.from}–${row.to}`,
      )
      .join("、") || "不限制",
);
const websites = computed(() => {
  const config = status.value?.config;
  return [
    { name: "HTTP", port: config?.http_port ?? 0 },
    { name: "HTTPS", port: config?.https_port ?? 0 },
  ];
});
const metrics = computed(() => {
  const s = status.value?.stats;
  return [
    { label: "在线客户端", value: s?.clients ?? "—" },
    { label: "映射数量", value: s?.proxies ?? "—" },
    { label: "当前连接", value: s?.connections ?? "—" },
    {
      label: "累计流入 / 流出",
      value: s ? `${bytes(s.traffic_in)} / ${bytes(s.traffic_out)}` : "—",
    },
  ];
});
function bytes(value: number) {
  const unit =
    value >= 1073741824
      ? "GB"
      : value >= 1048576
        ? "MB"
        : value >= 1024
          ? "KB"
          : "B";
  const divisor = { GB: 1073741824, MB: 1048576, KB: 1024, B: 1 }[unit];
  return `${Number((value / divisor).toFixed(1))} ${unit}`;
}
async function copy(value: string) {
  try {
    if (window.isSecureContext && navigator.clipboard) {
      await navigator.clipboard.writeText(value);
    } else {
      // The panel also supports HTTP, where the Clipboard API is unavailable.
      const previous = document.activeElement;
      const input = document.createElement("textarea");
      input.value = value;
      input.style.cssText = "position:fixed;left:-9999px;top:0";
      document.body.append(input);
      try {
        input.focus();
        input.select();
        if (!document.execCommand("copy")) throw new Error("copy failed");
      } finally {
        input.remove();
        if (previous instanceof window.HTMLElement) previous.focus();
      }
    }
    message.success("已复制");
  } catch {
    message.error("复制失败，请手动选择并复制");
  }
}
watch(processing, (value) => emit("busy", value));
async function load() {
  if (reading.value) return;
  reading.value = true;
  try {
    const result = await api.components();
    if (!result.frps) throw new Error("FRP 服务端管理暂时不可用");
    status.value = result.frps;
    readError.value = "";
    emit("changed");
  } catch (error) {
    if (error instanceof ApiError && error.code === "CANCELLED") return;
    readError.value =
      error instanceof Error ? error.message : "无法读取 FRP 状态";
  } finally {
    reading.value = false;
  }
}
function settings() {
  if (!status.value || processing.value) return;
  draft.value = structuredClone(toRaw(status.value.config));
  draft.value.token = status.value.token_set
    ? ""
    : randomUUID().replaceAll("-", "");
  ranges.value = draft.value.allow_ports.map((row) => ({
    from: row.from,
    to: row.to === row.from ? null : row.to,
  }));
  unrestricted.value = ranges.value.length === 0;
  httpEnabled.value = draft.value.http_port > 0;
  httpsEnabled.value = draft.value.https_port > 0;
  addressMode.value =
    draft.value.bind_address === "0.0.0.0"
      ? "all"
      : draft.value.bind_address === "::"
        ? "ipv6"
        : "custom";
  tab.value = "connection";
  editing.value = true;
}
function selectAddress(value: string) {
  if (!draft.value) return;
  addressMode.value = value;
  draft.value.bind_address =
    value === "all" ? "0.0.0.0" : value === "ipv6" ? "::" : "";
}
watch(
  [
    () => route.query.install,
    () => status.value?.installed,
    processing,
    permitted,
  ],
  ([intent, installed, locked, writable]) => {
    if (intent !== "1" || installed === undefined || locked || !writable)
      return;
    if (!installed) settings();
    void router.replace({ query: { ...route.query, install: undefined } });
  },
);
async function save() {
  const config = draft.value;
  if (!config || !status.value || processing.value || !permitted.value) return;
  const valid = await run(async () => {
    const invalid = (section: SettingsTab, text: string): never => {
      tab.value = section;
      throw new Error(text);
    };
    if (!config.bind_address.trim())
      invalid("connection", "请填写接收连接的 IP 地址");
    if (!config.token.trim() && !status.value?.token_set)
      invalid("connection", "请填写访问密钥");
    if (!status.value?.installed && !config.image.trim())
      invalid("connection", "请填写软件下载来源");
    const ports = unrestricted.value
      ? []
      : ranges.value.map((row) => {
          if (!row.from || (row.to !== null && row.to < row.from))
            invalid("ports", "请填写完整的映射端口范围");
          return { from: row.from!, to: row.to ?? row.from! };
        });
    if (!unrestricted.value && ports.length === 0)
      invalid("ports", "请添加允许映射的端口，或选择不限制");
    if (
      (httpEnabled.value && !config.http_port) ||
      (httpsEnabled.value && !config.https_port)
    )
      invalid("web", "请填写已启用的网站入口端口");
    return {
      ...config,
      image: config.image.trim(),
      bind_address: config.bind_address.trim(),
      subdomain_host: config.subdomain_host.trim(),
      allow_ports: ports,
      http_port: httpEnabled.value ? config.http_port : 0,
      https_port: httpsEnabled.value ? config.https_port : 0,
    };
  });
  if (!valid) return;
  const action: FrpsRequest["action"] = status.value.installed
    ? "configure"
    : "install";
  const task = await submit(
    { action: "frps", frps: { action, config: valid } },
    action === "install" ? "FRP 服务端安装日志" : "FRP 设置操作日志",
  );
  if (task) editing.value = false;
}
useLiveRefresh(api, ["software"], load, () => reading.value);
onMounted(load);
</script>
<template>
  <section class="page-stack panel frps-panel">
    <div class="frps-toolbar">
      <div class="frps-service-status">
        <h3>服务状态</h3>
        <NTag :type="display.tone" :bordered="false">{{ display.label }}</NTag>
        <span v-if="status?.stats?.version" class="muted"
          >v{{ status.stats.version }}</span
        >
      </div>
      <div v-if="status?.installed" class="button-row">
        <NButton
          type="primary"
          :disabled="!permitted || processing"
          @click="settings"
          >服务设置</NButton
        >
        <RouterLink :to="{ path: '/components', query: { software: 'frps' } }"
          ><NButton>软件管理</NButton></RouterLink
        >
      </div>
    </div>
    <NSkeleton v-if="!status && reading" text :repeat="3" />
    <NAlert v-if="readError" type="error">{{ readError }}</NAlert>
    <NAlert v-if="status?.error" type="warning">{{ status.error }}</NAlert>
    <template v-if="status?.installed">
      <div class="frps-metrics">
        <div v-for="item in metrics" :key="item.label" class="frps-metric">
          <span class="muted">{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
        </div>
      </div>
      <section class="frps-connection">
        <div>
          <h4>客户端连接地址</h4>
          <div class="frps-address">
            <span>{{ endpoint || "—" }}</span>
            <NButton
              text
              type="primary"
              :disabled="!endpoint"
              @click="copy(endpoint)"
              >复制地址</NButton
            >
          </div>
        </div>
        <span class="frps-connection-security">{{
          status.config.tls_only ? "仅允许加密连接" : "允许非加密连接"
        }}</span>
      </section>
      <dl class="frps-summary">
        <div>
          <dt>允许映射的端口</dt>
          <dd>{{ allowed }}</dd>
        </div>
        <div>
          <dt>网站转发</dt>
          <dd class="frps-website-status">
            <span v-for="website in websites" :key="website.name"
              >{{ website.name
              }}<span :class="{ muted: !website.port }">{{
                website.port ? `端口 ${website.port}` : "未开启"
              }}</span></span
            >
          </dd>
        </div>
        <div>
          <dt>开机启动</dt>
          <dd>{{ status.config.auto_start ? "已开启" : "未开启" }}</dd>
        </div>
      </dl>
      <div class="frps-note">
        客户端需填写相同的访问密钥，连接与映射端口需在<RouterLink to="/firewall"
          >防火墙</RouterLink
        >中放行。
      </div>
    </template>
    <NEmpty
      v-else-if="status"
      class="frps-empty"
      description="尚未安装 FRP 服务端"
    >
      <template #extra>
        <p class="muted">安装后可连接其他设备，使用端口映射和网站转发。</p>
        <NButton
          type="primary"
          :disabled="!permitted || processing || status.state === 'unknown'"
          @click="settings"
          >安装 FRP 服务端</NButton
        >
      </template>
    </NEmpty>
    <NAlert v-if="last?.error" type="error">{{ last.error }}</NAlert>
    <div v-if="last" class="frps-task">
      <span class="muted">{{
        last.state === "succeeded"
          ? "操作已完成"
          : last.state === "failed"
            ? "操作未完成"
            : "正在处理，请稍候"
      }}</span>
      <TaskLogButton :task-id="last.id" />
    </div>
    <FormDialog
      :show="editing"
      :title="status?.installed ? 'FRP 服务设置' : '安装 FRP 服务端'"
      :busy="busy"
      :form-disabled="processing || !permitted"
      :submit-disabled="!permitted || processing"
      :submit-text="status?.installed ? '保存设置' : '安装并启动'"
      :draft="editorDraft"
      width="720px"
      @submit="save"
      @cancel="editing = false"
    >
      <NTabs
        v-if="draft"
        v-model:value="tab"
        type="line"
        animated
        class="frps-settings-tabs"
      >
        <NTabPane name="connection" tab="基本设置" display-directive="show">
          <div class="frps-settings-content">
            <div class="frps-form-grid">
              <NFormItem label="接收连接的地址" required>
                <div class="frps-address-input">
                  <NSelect
                    :value="addressMode"
                    :options="addressOptions"
                    :disabled="processing || !permitted"
                    @update:value="selectAddress"
                  />
                  <NInput
                    v-if="addressMode === 'custom'"
                    v-model:value="draft.bind_address"
                    placeholder="填写服务器的 IP 地址"
                    :disabled="processing || !permitted"
                  />
                </div>
              </NFormItem>
              <NFormItem label="客户端连接端口" required>
                <NInputNumber
                  v-model:value="draft.bind_port"
                  :min="1"
                  :max="65535"
                  :precision="0"
                  :clearable="false"
                  :disabled="processing || !permitted"
                />
              </NFormItem>
            </div>
            <NFormItem
              :label="status?.token_set ? '更换访问密钥' : '访问密钥'"
              :required="!status?.token_set"
            >
              <div class="frps-key-field">
                <NInput
                  v-model:value="draft.token"
                  type="password"
                  show-password-on="click"
                  autocomplete="new-password"
                  :maxlength="512"
                  :placeholder="
                    status?.token_set
                      ? '留空保留当前密钥'
                      : '客户端连接时使用的密钥'
                  "
                  :disabled="processing || !permitted"
                />
                <div class="button-row">
                  <NButton
                    :disabled="processing || !permitted"
                    @click="draft.token = randomUUID().replaceAll('-', '')"
                    >随机生成</NButton
                  >
                  <NButton
                    :disabled="processing || !draft.token"
                    @click="copy(draft.token)"
                    >复制密钥</NButton
                  >
                </div>
                <span class="frps-field-hint">{{
                  status?.token_set
                    ? "更换密钥后，已连接的客户端也需要更新密钥。"
                    : "请保存此密钥，客户端连接时需要填写。"
                }}</span>
              </div>
            </NFormItem>
            <div class="frps-switch-list">
              <div class="frps-setting-row">
                <div>
                  <span>仅允许加密连接</span>
                  <p>客户端需要开启 TLS 加密。</p>
                </div>
                <NSwitch
                  v-model:value="draft.tls_only"
                  aria-label="仅允许加密连接"
                  :disabled="processing || !permitted"
                />
              </div>
              <div v-if="!status?.installed" class="frps-setting-row">
                <span>开机自动启动</span>
                <NSwitch
                  v-model:value="draft.auto_start"
                  aria-label="开机自动启动"
                  :disabled="processing || !permitted"
                />
              </div>
            </div>
            <NFormItem v-if="!status?.installed" label="软件下载来源" required>
              <NInput
                v-model:value="draft.image"
                placeholder="默认使用官方发布版本"
                :disabled="processing || !permitted"
              />
            </NFormItem>
          </div>
        </NTabPane>
        <NTabPane name="ports" tab="端口映射" display-directive="show">
          <div class="frps-settings-content">
            <NFormItem label="客户端可使用的映射端口">
              <NRadioGroup
                :value="unrestricted ? 'all' : 'selected'"
                :disabled="processing || !permitted"
                @update:value="unrestricted = $event === 'all'"
              >
                <NRadioButton value="selected">指定端口</NRadioButton>
                <NRadioButton value="all">不限制</NRadioButton>
              </NRadioGroup>
            </NFormItem>
            <template v-if="!unrestricted">
              <p class="frps-field-hint">
                可以添加单个端口或一段连续端口，同时适用于 TCP 和 UDP 映射。
              </p>
              <PortRangesInput
                v-model:value="ranges"
                :disabled="processing || !permitted"
              />
            </template>
            <NAlert v-else type="info" :show-icon="false"
              >客户端可使用任意可用端口进行映射。对外访问仍受服务器防火墙限制。</NAlert
            >
          </div>
        </NTabPane>
        <NTabPane name="web" tab="网站转发" display-directive="show">
          <div class="frps-settings-content">
            <section class="frps-website-setting">
              <div class="frps-setting-row">
                <div>
                  <h4>HTTP 网站转发</h4>
                  <p>通过域名访问客户端提供的 HTTP 网站。</p>
                </div>
                <NSwitch
                  v-model:value="httpEnabled"
                  aria-label="HTTP 网站转发"
                  :disabled="processing || !permitted"
                  @update:value="draft.http_port ||= 8080"
                />
              </div>
              <NFormItem v-if="httpEnabled" label="HTTP 入口端口" required>
                <NInputNumber
                  v-model:value="draft.http_port"
                  :min="1"
                  :max="65535"
                  :precision="0"
                  :clearable="false"
                  :disabled="processing || !permitted"
                />
              </NFormItem>
            </section>
            <section class="frps-website-setting">
              <div class="frps-setting-row">
                <div>
                  <h4>HTTPS 网站转发</h4>
                  <p>通过域名访问客户端提供的 HTTPS 网站。</p>
                </div>
                <NSwitch
                  v-model:value="httpsEnabled"
                  aria-label="HTTPS 网站转发"
                  :disabled="processing || !permitted"
                  @update:value="draft.https_port ||= 8443"
                />
              </div>
              <NFormItem v-if="httpsEnabled" label="HTTPS 入口端口" required>
                <NInputNumber
                  v-model:value="draft.https_port"
                  :min="1"
                  :max="65535"
                  :precision="0"
                  :clearable="false"
                  :disabled="processing || !permitted"
                />
              </NFormItem>
            </section>
            <NFormItem
              v-if="httpEnabled || httpsEnabled"
              label="子域名后缀（可选）"
            >
              <div class="frps-key-field">
                <NInput
                  v-model:value="draft.subdomain_host"
                  placeholder="例如 example.com"
                  :disabled="processing || !permitted"
                />
                <span class="frps-field-hint"
                  >设置后，客户端可使用 app.example.com
                  等子域名。域名需解析到此服务器。</span
                >
              </div>
            </NFormItem>
            <p v-if="httpEnabled || httpsEnabled" class="frps-field-hint">
              入口端口不能与其他服务重复。HTTPS 网站的证书需在客户端配置。
            </p>
          </div>
        </NTabPane>
      </NTabs>
      <template #actions>
        <span v-if="status?.installed" class="frps-save-hint">{{
          status.state === "stopped"
            ? "保存后服务保持停止。"
            : "保存后运行中的服务会重启。"
        }}</span>
      </template>
    </FormDialog>
  </section>
</template>
<style scoped>
.frps-toolbar,
.frps-service-status,
.frps-address,
.frps-task,
.frps-setting-row {
  display: flex;
  align-items: center;
  gap: 12px;
}
.frps-toolbar,
.frps-setting-row {
  justify-content: space-between;
}
.frps-toolbar,
.frps-service-status,
.frps-address {
  flex-wrap: wrap;
}
.frps-panel h3,
.frps-panel h4,
.frps-settings-content h4,
.frps-summary,
.frps-summary dd,
.frps-setting-row p {
  margin: 0;
}
.frps-service-status h3 {
  font-size: 16px;
}
.frps-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}
.frps-metric {
  min-width: 0;
  padding: 20px;
  border-radius: 10px;
  background: var(--surface-soft);
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.frps-metric strong {
  font-size: clamp(18px, 1.8vw, 24px);
  font-weight: 600;
  overflow-wrap: anywhere;
}
.frps-connection {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  padding: 20px;
  border: 1px solid var(--border-color);
  border-radius: 10px;
}
.frps-connection h4 {
  font-size: 13px;
  font-weight: 400;
  color: var(--text-muted);
  margin-bottom: 8px;
}
.frps-connection > div,
.frps-setting-row > div {
  min-width: 0;
}
.frps-address > span {
  font-size: 18px;
  font-weight: 600;
  overflow-wrap: anywhere;
  user-select: all;
}
.frps-connection-security,
.frps-field-hint,
.frps-save-hint,
.frps-setting-row p,
.frps-note {
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.6;
}
.frps-summary {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
  gap: 24px;
}
.frps-summary > div {
  min-width: 0;
}
.frps-summary dt {
  color: var(--text-muted);
  margin-bottom: 10px;
}
.frps-summary dd {
  overflow-wrap: anywhere;
}
.frps-website-status,
.frps-website-status > span {
  display: flex;
  gap: 12px;
}
.frps-website-status {
  flex-direction: column;
  gap: 6px;
}
.frps-note {
  border-top: 1px solid var(--border-color);
  padding-top: 16px;
}
.frps-empty {
  padding: 36px 0;
}
.frps-task {
  justify-content: space-between;
}
.frps-settings-tabs :deep(.n-tabs-pane-wrapper) {
  overflow: visible;
}
.frps-settings-content {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding-top: 12px;
}
.frps-settings-content :deep(.n-form-item-feedback-wrapper) {
  min-height: 0;
}
.frps-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px;
}
.frps-settings-content :deep(.n-input-number) {
  width: 100%;
}
.frps-key-field,
.frps-address-input {
  display: flex;
  flex-direction: column;
  gap: 10px;
  width: 100%;
}
.frps-field-hint {
  margin: 0;
}
.frps-switch-list,
.frps-website-setting {
  border: 1px solid var(--border-color);
  border-radius: 10px;
}
.frps-setting-row {
  padding: 16px;
  gap: 20px;
}
.frps-setting-row p {
  margin-top: 4px;
}
.frps-setting-row h4 {
  font-size: 14px;
  font-weight: 500;
}
.frps-switch-list .frps-setting-row + .frps-setting-row {
  border-top: 1px solid var(--border-color);
}
.frps-website-setting :deep(.n-form-item) {
  padding: 0 16px 16px;
  max-width: 280px;
}
@media (max-width: 900px) {
  .frps-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 560px) {
  .frps-form-grid,
  .frps-summary {
    grid-template-columns: minmax(0, 1fr);
  }
  .frps-metric {
    padding: 14px;
  }
  .frps-summary {
    gap: 20px;
  }
  .frps-connection {
    padding: 16px;
  }
  .frps-setting-row {
    padding: 14px;
  }
}
</style>
