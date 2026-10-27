<script setup lang="ts">
import { computed, onMounted, ref, watch, toRaw } from "vue";
import { RouterLink } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NSkeleton,
  NTag,
} from "naive-ui";
import type { FrpsConfig, FrpsStatus, FrpsRequest } from "../api/client";
import { useSoftwareOperations } from "../composables/software";
import { useLiveRefresh } from "../composables/live";
import { useNodes } from "../stores/node";
import { randomUUID } from "../utils/crypto";
import type { PortRange } from "../utils/form";
import {
  softwareStatus,
  softwareConfirmation,
  standardServiceActions,
  type SoftwareOperation,
} from "../utils/software";
import PortRangesInput from "./PortRangesInput.vue";
import SoftwareControls from "./SoftwareControls.vue";
import TaskLogButton from "./TaskLogButton.vue";

defineProps<{ embedded?: boolean }>();
const emit = defineEmits<{ changed: []; busy: [value: boolean] }>();
const status = ref<FrpsStatus | null>(null),
  reading = ref(false),
  readError = ref("");
const editing = ref(false),
  draft = ref<FrpsConfig | null>(null),
  ranges = ref<PortRange[]>([]),
  unrestricted = ref(false);
const httpEnabled = ref(false),
  httpsEnabled = ref(false);
const { api, run, busy, permitted, active, last, tasks, submit } =
  useSoftwareOperations(load, ["components.manage", "system.write"]);
const processing = computed(() => busy.value || active.value);
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
      .join("、") || "不限制映射端口",
);
const metrics = computed(() => {
  const s = status.value?.stats;
  return [
    { label: "在线客户端", value: s?.clients ?? "—" },
    { label: "端口与网站映射", value: s?.proxies ?? "—" },
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
  editing.value = true;
}
async function operate(action: SoftwareOperation) {
  if (action === "install") {
    settings();
    return;
  }
  const confirmation =
    action === "uninstall"
      ? "卸载 FRP 服务端？所有客户端连接将断开，服务配置和访问密钥会保留。"
      : softwareConfirmation(action, "FRP 服务端");
  if (confirmation && !window.confirm(confirmation)) return;
  await submit({ action: "frps", frps: { action } }, "FRP 服务端操作日志");
}
async function save() {
  const config = draft.value;
  if (!config || !status.value) return;
  const valid = await run(async () => {
    if (!config.token.trim() && !status.value?.token_set)
      throw new Error("请填写访问密钥");
    const ports = unrestricted.value
      ? []
      : ranges.value.map((row) => {
          if (!row.from || (row.to !== null && row.to < row.from))
            throw new Error("请填写完整的映射端口范围");
          return { from: row.from, to: row.to ?? row.from };
        });
    if (!unrestricted.value && ports.length === 0)
      throw new Error("请添加允许映射的端口，或选择不限制映射端口");
    if (
      (httpEnabled.value && !config.http_port) ||
      (httpsEnabled.value && !config.https_port)
    )
      throw new Error("请填写网站转发端口");
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
  if (
    status.value.installed &&
    !window.confirm("保存 FRP 设置？正在运行的服务会重启，客户端将重新连接。")
  )
    return;
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
  <section class="page-stack" :class="{ surface: !embedded }">
    <div class="section-heading frps-heading">
      <div>
        <h3>{{ status?.installed ? "FRP 服务端" : "安装 FRP 服务端" }}</h3>
        <p class="muted">为其他设备提供端口映射和网站转发入口。</p>
      </div>
      <NTag :type="display.tone" :bordered="false">{{ display.label }}</NTag>
    </div>
    <NSkeleton v-if="!status && reading" text :repeat="3" />
    <NAlert v-if="readError" type="error">{{ readError }}</NAlert>
    <NAlert v-if="status?.error" type="warning">{{ status.error }}</NAlert>
    <template v-if="status">
      <div v-if="status.installed" class="frps-metrics">
        <div v-for="item in metrics" :key="item.label" class="frps-metric">
          <span class="muted">{{ item.label }}</span
          ><strong>{{ item.value }}</strong>
        </div>
      </div>
      <div class="button-row">
        <NButton
          v-if="status.installed"
          type="primary"
          :disabled="!permitted || processing"
          @click="settings"
          >服务设置</NButton
        >
        <SoftwareControls
          :installed="status.installed"
          :runtime="status.state"
          :permitted="permitted && status.state !== 'unknown'"
          :busy="processing"
          :actions="standardServiceActions"
          @operate="operate"
        />
      </div>
      <div v-if="status.installed" class="frps-summary">
        <div>
          <span class="muted">客户端连接地址</span
          ><strong>{{ endpoint }}</strong>
        </div>
        <div>
          <span class="muted">允许映射的端口</span
          ><strong>{{ allowed }}</strong>
        </div>
        <div>
          <span class="muted">网站转发</span
          ><strong>{{
            status.config.http_port || status.config.https_port
              ? [
                  status.config.http_port
                    ? `HTTP ${status.config.http_port}`
                    : "",
                  status.config.https_port
                    ? `HTTPS ${status.config.https_port}`
                    : "",
                ]
                  .filter(Boolean)
                  .join("、")
              : "未开启"
          }}</strong>
        </div>
        <div>
          <span class="muted">开机自动启动</span
          ><strong>{{ status.config.auto_start ? "已开启" : "未开启" }}</strong>
        </div>
      </div>
      <p class="muted">
        客户端使用相同的访问密钥连接此服务。需要对外开放的端口可在<RouterLink
          to="/firewall"
          >防火墙</RouterLink
        >中放行。
      </p>
    </template>
    <NAlert v-if="last?.error" type="error">{{ last.error }}</NAlert>
    <div v-if="last" class="button-row">
      <TaskLogButton :task-id="last.id" />
    </div>
    <NModal
      v-model:show="editing"
      preset="card"
      :title="status?.installed ? 'FRP 服务设置' : '安装 FRP 服务端'"
      class="frps-dialog"
      :style="{ width: 'min(720px, calc(100vw - 32px))' }"
      :mask-closable="!busy"
      :closable="!busy"
    >
      <NForm v-if="draft" class="page-stack" @submit.prevent="save">
        <div class="frps-form-grid">
          <NFormItem label="监听地址"
            ><NInput
              v-model:value="draft.bind_address"
              placeholder="0.0.0.0"
              :disabled="busy"
          /></NFormItem>
          <NFormItem label="客户端连接端口"
            ><NInputNumber
              v-model:value="draft.bind_port"
              :min="1"
              :max="65535"
              :precision="0"
              :clearable="false"
              :disabled="busy"
          /></NFormItem>
        </div>
        <NFormItem label="访问密钥"
          ><div class="frps-token">
            <NInput
              v-model:value="draft.token"
              type="password"
              show-password-on="click"
              :maxlength="512"
              :placeholder="
                status?.token_set
                  ? '已设置，留空保持不变'
                  : '客户端连接时使用的密钥'
              "
              :disabled="busy"
            /><NButton
              :disabled="busy"
              @click="draft.token = randomUUID().replaceAll('-', '')"
              >生成密钥</NButton
            >
          </div></NFormItem
        >
        <p v-if="!status?.token_set" class="muted">
          请保存访问密钥，客户端连接时需要填写。
        </p>
        <p v-if="status?.token_set && draft.token" class="muted">
          更换密钥后，客户端也需要更新密钥。
        </p>
        <div class="button-row">
          <NCheckbox v-model:checked="draft.auto_start" :disabled="busy"
            >开机自动启动</NCheckbox
          ><NCheckbox v-model:checked="draft.tls_only" :disabled="busy"
            >仅允许加密连接</NCheckbox
          >
        </div>
        <section class="frps-settings-section">
          <h4>允许映射的端口</h4>
          <NCheckbox v-model:checked="unrestricted" :disabled="busy"
            >不限制映射端口</NCheckbox
          ><PortRangesInput
            v-if="!unrestricted"
            v-model:value="ranges"
            :disabled="busy"
          />
        </section>
        <section class="frps-settings-section">
          <h4>网站转发</h4>
          <div class="frps-form-grid">
            <div>
              <NCheckbox
                v-model:checked="httpEnabled"
                :disabled="busy"
                @update:checked="draft.http_port ||= 8080"
                >HTTP 网站</NCheckbox
              ><NFormItem v-if="httpEnabled" label="HTTP 转发端口"
                ><NInputNumber
                  v-model:value="draft.http_port"
                  :min="1"
                  :max="65535"
                  :precision="0"
                  :clearable="false"
                  :disabled="busy"
              /></NFormItem>
            </div>
            <div>
              <NCheckbox
                v-model:checked="httpsEnabled"
                :disabled="busy"
                @update:checked="draft.https_port ||= 8443"
                >HTTPS 网站</NCheckbox
              ><NFormItem v-if="httpsEnabled" label="HTTPS 转发端口"
                ><NInputNumber
                  v-model:value="draft.https_port"
                  :min="1"
                  :max="65535"
                  :precision="0"
                  :clearable="false"
                  :disabled="busy"
              /></NFormItem>
            </div>
          </div>
          <NFormItem
            v-if="httpEnabled || httpsEnabled"
            label="子域名后缀（可选）"
            ><NInput
              v-model:value="draft.subdomain_host"
              placeholder="例如 example.com"
              :disabled="busy"
          /></NFormItem>
        </section>
        <NFormItem label="下载来源"
          ><NInput
            v-model:value="draft.image"
            :disabled="busy"
            placeholder="默认使用官方发布版本"
        /></NFormItem>
        <div class="dialog-footer">
          <NButton :disabled="busy" @click="editing = false">取消</NButton
          ><NButton
            type="primary"
            attr-type="submit"
            :loading="busy"
            :disabled="!permitted || processing"
            >{{ status?.installed ? "保存设置" : "安装并启动" }}</NButton
          >
        </div>
      </NForm>
    </NModal>
  </section>
</template>
<style scoped>
.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding-top: 8px;
}
.frps-heading {
  align-items: center;
}
.frps-heading h3,
.frps-settings-section h4 {
  margin: 0;
}
.frps-heading p {
  margin: 8px 0 0;
}
.frps-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}
.frps-metric {
  min-width: 0;
  padding: 18px;
  border: 1px solid var(--border-color, #e5e7eb);
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.frps-metric strong {
  font-size: 22px;
  font-weight: 600;
  overflow-wrap: anywhere;
}
.frps-summary {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px;
}
.frps-summary > div {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.frps-summary strong {
  font-weight: 500;
  overflow-wrap: anywhere;
}
.frps-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
.frps-form-grid .n-input-number {
  width: 100%;
}
.frps-token {
  display: flex;
  gap: 12px;
  width: 100%;
}
.frps-settings-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
@media (max-width: 900px) {
  .frps-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 560px) {
  .frps-form-grid,
  .frps-summary,
  .frps-metrics {
    grid-template-columns: minmax(0, 1fr);
  }
  .frps-token {
    flex-direction: column;
  }
}
</style>
