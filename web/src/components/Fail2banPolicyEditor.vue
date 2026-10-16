<script setup lang="ts">
import Fail2banTemplateCatalog from "./Fail2banTemplateCatalog.vue";
import Fail2banApplyPanel from "./Fail2banApplyPanel.vue";
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NFormItem,
  NInput,
  NInputNumber,
  NSelect,
  NSwitch,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banDesiredJail,
  type Fail2banPolicyView,
  type Fail2banPolicyPreview,
  type Fail2banTemplate,
  type LogSource,
} from "../api/client";

const api = useNodeAPI(),
  controller = new AbortController();
const view = ref<Fail2banPolicyView | null>(null),
  jails = ref<Fail2banDesiredJail[]>([]);
const templates = ref<Fail2banTemplate[]>([]),
  sources = ref<LogSource[]>([]);
const ignoreText = ref<Record<string, string>>({}),
  preview = ref<Fail2banPolicyPreview | null>(null);
const busy = ref(false),
  error = ref(""),
  notice = ref("");
let closed = false,
  savedEditor = "",
  pending: { digest: string; key: string } | null = null;
const serialize = () =>
  JSON.stringify({ jails: jails.value, ignore: ignoreText.value });
const dirty = computed(() => !!view.value && serialize() !== savedEditor);
const templateOptions = computed(() =>
  templates.value.map((template) => ({
    label: template.name,
    value: template.id,
  })),
);
const actions = [
  { label: "宿主机入口", value: "host-input" },
  { label: "Docker 转发", value: "docker-forward" },
  { label: "Nginx 客户端", value: "nginx-client" },
];
const panelTemplate = "panel-login-failure";
function selectTemplate(jail: Fail2banDesiredJail, value: string) {
  if (jail.template === value) return;
  const panelSourceChanged =
    jail.template === panelTemplate || value === panelTemplate;
  jail.template = value as Fail2banDesiredJail["template"];
  if (panelSourceChanged) {
    jail.resource_id = "";
    jail.action = value === panelTemplate ? "host-input" : "nginx-client";
  }
  preview.value = null;
}
const sourceOptions = computed(() => {
  const known = new Map<string, string>();
  for (const source of sources.value)
    if (
      source.active &&
      source.resource_id &&
      source.category === "http_access" &&
      source.format === "nginxpanel_http" &&
      source.auth_presence
    )
      known.set(source.resource_id, source.label);
  for (const jail of jails.value)
    if (jail.resource_id && !known.has(jail.resource_id))
      known.set(
        jail.resource_id,
        `未发现含认证标记的运行日志 · ${jail.resource_id}`,
      );
  return [...known].map(([value, label]) => ({ value, label }));
});
function accept(value: Fail2banPolicyView) {
  view.value = value;
  jails.value = value.policy.jails.map((jail) => ({
    ...jail,
    ignore_ips: [...jail.ignore_ips],
  }));
  ignoreText.value = Object.fromEntries(
    jails.value.map((jail) => [jail.id, jail.ignore_ips.join("\n")]),
  );
  savedEditor = serialize();
  preview.value = null;
}
async function load() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  notice.value = "";
  const [policy, catalog, logs] = await Promise.allSettled([
    api.fail2banPolicy(controller.signal),
    api.fail2banTemplates(controller.signal),
    api.logSources(controller.signal),
  ]);
  if (closed) return;
  if (policy.status === "fulfilled") {
    accept(policy.value);
    pending = null;
  } else error.value = apiError(policy.reason).message;
  if (catalog.status === "fulfilled") templates.value = catalog.value;
  else notice.value = "内置模板暂不可读取";
  if (logs.status === "fulfilled") sources.value = logs.value;
  else notice.value += `${notice.value ? "；" : ""}运行日志来源暂不可读取`;
  busy.value = false;
}
function add() {
  const template = templates.value[0];
  if (!template || busy.value || jails.value.length >= 32) return;
  const id = crypto.randomUUID();
  jails.value.push({
    id,
    name: template.name,
    enabled: false,
    template: template.id,
    resource_id: "",
    action: template.id === panelTemplate ? "host-input" : "nginx-client",
    ban_time: template.ban_time,
    find_time: template.find_time,
    max_retry: template.max_retry,
    ignore_ips: [],
  });
  ignoreText.value[id] = "";
  preview.value = null;
}
function setNumber(
  jail: Fail2banDesiredJail,
  field: "ban_time" | "find_time" | "max_retry",
  value: number | null,
) {
  if (value !== null) jail[field] = value;
}
function remove(id: string) {
  jails.value = jails.value.filter((jail) => jail.id !== id);
  delete ignoreText.value[id];
  preview.value = null;
}
async function save() {
  if (!view.value || busy.value) return;
  busy.value = true;
  error.value = "";
  notice.value = "";
  try {
    const input = {
      base_version: view.value.version,
      policy: {
        jails: jails.value.map((jail) => ({
          ...jail,
          ignore_ips: (ignoreText.value[jail.id] || "")
            .split(/[\n,]/)
            .map((value) => value.trim())
            .filter(Boolean),
        })),
      },
    };
    const digest = JSON.stringify(input);
    if (!pending || pending.digest !== digest)
      pending = { digest, key: crypto.randomUUID() };
    const result = await api.saveFail2banPolicy(input, pending.key);
    if (closed) return;
    accept(result);
    pending = null;
    notice.value = "jail 期望配置已保存，尚未应用";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    if (!closed) busy.value = false;
  }
}
async function inspect() {
  if (!view.value || dirty.value || busy.value) return;
  busy.value = true;
  error.value = "";
  preview.value = null;
  try {
    const result = await api.previewFail2ban(
      view.value.version,
      controller.signal,
    );
    if (!closed) preview.value = result;
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    if (!closed) busy.value = false;
  }
}
onMounted(() => {
  void load();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
});
</script>
<template>
  <section class="panel page-stack">
    <div class="toolbar">
      <h3>jail 期望配置</h3>
      <span v-if="view" class="muted">版本 {{ view.version }}</span>
    </div>
    <NAlert type="info"
      >配置保存后需预览并确认应用。当前支持独立受管实例的 Nginx
      客户端动作，已有实例的 jail 保持只读。</NAlert
    >
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="notice" type="info">{{ notice }}</NAlert>
    <Fail2banTemplateCatalog
      :templates="templates"
      :checks="preview?.template_checks"
    />
    <div v-for="jail in jails" :key="jail.id" class="surface page-stack">
      <div class="toolbar">
        <h4>{{ jail.name || "未命名 jail" }}</h4>
        <NButton
          :disabled="busy"
          size="small"
          type="error"
          @click="remove(jail.id)"
          >移除配置</NButton
        >
      </div>
      <NFormItem label="名称"
        ><NInput v-model:value="jail.name" :disabled="busy" :maxlength="120"
      /></NFormItem>
      <NFormItem label="内置模板">
        <NSelect
          :value="jail.template"
          @update:value="selectTemplate(jail, $event)"
          :disabled="busy"
          :options="templateOptions"
        />
      </NFormItem>
      <NFormItem label="期望启用"
        ><NSwitch v-model:value="jail.enabled" :disabled="busy"
      /></NFormItem>
      <NAlert v-if="jail.template === panelTemplate" type="warning">
        来源为面板密码认证失败日志，仅记录 TCP
        对端。面板登录保护仅适用于本机直连；启用前须核对宿主机动作授权和持续同步状态。
      </NAlert>
      <NFormItem v-else label="站点结构化访问日志"
        ><NSelect
          v-model:value="jail.resource_id"
          :disabled="busy"
          :options="sourceOptions"
          filterable
      /></NFormItem>
      <NFormItem label="期望动作"
        ><NSelect
          v-model:value="jail.action"
          :disabled="busy || jail.template === panelTemplate"
          :options="actions"
      /></NFormItem>
      <div class="actions">
        <NFormItem label="封禁秒数（-1 为永久）"
          ><NInputNumber
            :value="jail.ban_time"
            @update:value="setNumber(jail, 'ban_time', $event)"
            :disabled="busy"
            :min="-1"
            :max="31536000"
            :precision="0"
        /></NFormItem>
        <NFormItem label="统计窗口（秒）"
          ><NInputNumber
            :value="jail.find_time"
            @update:value="setNumber(jail, 'find_time', $event)"
            :disabled="busy"
            :min="1"
            :max="86400"
            :precision="0"
        /></NFormItem>
        <NFormItem label="失败阈值"
          ><NInputNumber
            :value="jail.max_retry"
            @update:value="setNumber(jail, 'max_retry', $event)"
            :disabled="busy"
            :min="1"
            :max="1000"
            :precision="0"
        /></NFormItem>
      </div>
      <NFormItem label="白名单 IP / CIDR（每行一个）"
        ><NInput
          v-model:value="ignoreText[jail.id]"
          :disabled="busy"
          type="textarea"
          :autosize="{ minRows: 2, maxRows: 6 }"
      /></NFormItem>
    </div>
    <div class="actions">
      <NButton
        :disabled="busy || !view || !templates.length || jails.length >= 32"
        @click="add"
        >新增 jail 配置</NButton
      >
      <NButton
        type="primary"
        :disabled="busy || !view || !dirty"
        :loading="busy"
        @click="save"
        >保存期望配置</NButton
      >
      <NButton :disabled="busy || !view?.version || dirty" @click="inspect"
        >预览保存配置</NButton
      >
      <NButton :disabled="busy" @click="load">{{
        dirty ? "放弃修改并重新读取" : "重新读取"
      }}</NButton>
    </div>
    <template v-if="preview && !dirty">
      <NAlert
        v-for="warning in preview.warnings"
        :key="warning"
        type="warning"
        >{{ warning }}</NAlert
      >
      <div v-for="entry in preview.entries" :key="entry.id">
        <strong>{{
          jails.find((jail) => jail.id === entry.id)?.name || entry.jail_name
        }}</strong>
        <span>
          · {{ entry.enabled ? "期望启用" : "期望停用" }} · 模板{{
            entry.template_ready ? "已核对" : "未就绪"
          }}
          · 日志{{ entry.source_ready ? "已核对" : "未就绪" }}</span
        >
        <p v-for="issue in entry.errors" :key="issue" class="muted">
          {{ issue }}
        </p>
      </div>
    </template>
    <Fail2banApplyPanel
      :preview="dirty ? null : preview"
      :disabled="busy || dirty"
      @submitted="preview = null"
    />
  </section>
</template>
