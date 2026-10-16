<route lang="json">
{
  "meta": {
    "title": "配置迁移",
    "subtitle": "加密导出、导入与节点迁入",
    "nav": true,
    "order": 7,
    "symbol": "⇄"
  }
}
</route>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NInput,
  NPopconfirm,
  NSelect,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  ApiError,
  type MigrationPlan,
  type MigrationExecuteInput,
  type MigrationPullInput,
  type MigrationFirewallInput,
  type MigrationFail2banInput,
  type MigrationMonitoringInput,
} from "../api/client";
import MigrationDependencies from "../components/MigrationDependencies.vue";
import MigrationFirewallOptions from "../components/MigrationFirewallOptions.vue";
import MigrationFirewallPreview from "../components/MigrationFirewallPreview.vue";
import MigrationMonitoringOptions from "../components/MigrationMonitoringOptions.vue";
import MigrationMonitoringPreview from "../components/MigrationMonitoringPreview.vue";
import MigrationFail2banOptions from "../components/MigrationFail2banOptions.vue";
import MigrationFail2banPreview from "../components/MigrationFail2banPreview.vue";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();

const { run, busy, message } = useAction(),
  keyFor = useIdempotency(),
  session = useSession();
const passphrase = ref(""),
  importPassphrase = ref(""),
  file = ref<File | null>(null),
  mappings = ref("{}");
const includeCertificates = ref(false),
  includeCredentials = ref(false),
  remoteCertificates = ref(false),
  remoteCredentials = ref(false);
const includeAutomation = ref(false),
  includeNotifications = ref(false),
  remoteAutomation = ref(false),
  remoteNotifications = ref(false),
  includeFirewall = ref(false),
  includeFail2ban = ref(false),
  includeMonitoring = ref(false),
  remoteFirewall = ref(false),
  remoteFail2ban = ref(false),
  remoteMonitoring = ref(false);
const monitoringSettings = ref<MigrationMonitoringInput>({ mode: "preserve" });
const fail2banSettings = ref<MigrationFail2banInput>({ mode: "preserve" });
const firewallSettings = ref<MigrationFirewallInput>({
    mode: "preserve",
    backend: "",
    interfaces: {},
  }),
  firewallValid = ref(true);
function firewallOptions(): MigrationFirewallInput {
  if (!firewallValid.value) throw new Error("请修正防火墙网卡映射");
  return {
    ...firewallSettings.value,
    interfaces: { ...firewallSettings.value.interfaces },
  };
}
watch(includeAutomation, (v) => {
  if (v) {
    includeCertificates.value = true;
    includeCredentials.value = true;
  }
});
watch(remoteAutomation, (v) => {
  if (v) {
    remoteCertificates.value = true;
    remoteCredentials.value = true;
  }
});
watch([includeCertificates, includeCredentials], ([a, b]) => {
  if (!a || !b) includeAutomation.value = false;
});
watch([remoteCertificates, remoteCredentials], ([a, b]) => {
  if (!a || !b) remoteAutomation.value = false;
});
const remoteURL = ref(""),
  remoteKey = ref(""),
  fingerprint = ref(""),
  sourceNode = ref("");
const mode = ref<MigrationExecuteInput["mode"]>("draft"),
  enableNginx = ref(false),
  baseVersion = ref(0),
  plan = ref<MigrationPlan | null>(null),
  history = ref<MigrationPlan[]>([]),
  error = ref("");
const dependencyTag = ref(""),
  dependencyPrerelease = ref(false),
  dependencyInstall = ref(false),
  dependencyStart = ref(true),
  dependencyEnable = ref(false);
const preparingDependencies = computed(
  () =>
    !!plan.value?.dependencies &&
    ["queued", "running", "recovery_required"].includes(
      plan.value.dependencies.state,
    ),
);
const controller = new AbortController();
let timer: ReturnType<typeof setInterval> | undefined;
let loading = false;
const has = (scope: string) => session.me?.scopes.includes(scope) ?? false;
const canExport = computed(
  () => has("backup.export") && has("backup.secrets") && has("config.secrets"),
);
const canImport = computed(() =>
  [
    "backup.restore",
    "backup.secrets",
    "config.write",
    "config.secrets",
    "security.write",
  ].every(has),
);
const canPull = computed(() => canImport.value && has("nodes.manage"));
const options = [
  { label: "仅保存草稿", value: "draft" },
  { label: "保存期望配置", value: "save" },
  { label: "保存并应用 Nginx", value: "apply" },
];
const states: Record<string, string> = {
  planned: "待执行",
  draft: "已保存草稿",
  saved: "已保存配置",
  applying: "应用中",
  succeeded: "迁移成功",
  failed: "失败",
  rolled_back: "已恢复",
  recovery_required: "需要恢复",
};
const stepStates: Record<string, string> = {
  ready: "就绪",
  blocked: "冲突",
  unavailable: "缺少依赖",
  authorization: "需要授权",
  review: "核对",
};
const time = (n: number) => new Date(n * 1000).toLocaleString();
function mappingObject(): Record<string, string> {
  const value: unknown = JSON.parse(mappings.value);
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.values(value).some((v) => typeof v !== "string")
  )
    throw new Error("映射须为原参数到目标参数的 JSON 对象");
  return value as Record<string, string>;
}
async function load() {
  if (loading || busy.value || document.hidden) return;
  loading = true;
  try {
    const items = await api.migrations(controller.signal);
    history.value = items;
    const selected = plan.value;
    if (selected) {
      const updated = await api.migration(selected.id, controller.signal);
      if (selected.state !== "planned" || updated.state !== "planned")
        plan.value = updated;
    }
    error.value = "";
  } catch (e) {
    if (!controller.signal.aborted) error.value = apiError(e).message;
  } finally {
    loading = false;
  }
}
async function currentVersion() {
  const tree = await api.tree();
  baseVersion.value = tree.version;
  return tree.version;
}
async function selectPlan(id: string) {
  await run(async () => {
    plan.value = await api.migration(id, controller.signal);
  });
}
function selectFile(event: Event) {
  file.value = (event.target as HTMLInputElement).files?.[0] ?? null;
  plan.value = null;
}
async function exportPackage() {
  await run(async () => {
    const out = await api.exportMigration({
      passphrase: passphrase.value,
      selection: {
        certificates: includeCertificates.value,
        dns_credentials: includeCredentials.value,
        automation: includeAutomation.value,
        notifications: includeNotifications.value,
        firewall: includeFirewall.value,
        fail2ban: includeFail2ban.value,
        monitoring: includeMonitoring.value,
      },
    });
    const bytes = Uint8Array.from(atob(out.content), (c) => c.charCodeAt(0));
    const url = URL.createObjectURL(
      new Blob([bytes], { type: "application/octet-stream" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = out.filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    passphrase.value = "";
    message.success("加密配置包已导出，请单独保管口令");
  });
}
async function previewFile() {
  await run(async () => {
    if (!file.value) throw new Error("请选择配置包");
    const firewall = firewallOptions();
    if (file.value.size > 8 * 1024 * 1024)
      throw new Error("配置包不能超过 8 MiB");
    const buffer = new Uint8Array(await file.value.arrayBuffer());
    let binary = "";
    for (let i = 0; i < buffer.length; i += 0x8000)
      binary += String.fromCharCode(...buffer.subarray(i, i + 0x8000));
    const version = await currentVersion();
    plan.value = await api.prepareMigration({
      content: btoa(binary),
      passphrase: importPassphrase.value,
      base_version: version,
      mappings: mappingObject(),
      firewall,
      fail2ban: { ...fail2banSettings.value },
      monitoring: { ...monitoringSettings.value },
    });
    importPassphrase.value = "";
  });
  await load();
}
function remoteInput(execute: boolean, version: number): MigrationPullInput {
  return {
    remote: {
      url: remoteURL.value,
      api_key: remoteKey.value,
      fingerprint: fingerprint.value,
      node_id: sourceNode.value,
      selection: {
        certificates: remoteCertificates.value,
        dns_credentials: remoteCredentials.value,
        automation: remoteAutomation.value,
        notifications: remoteNotifications.value,
        firewall: remoteFirewall.value,
        fail2ban: remoteFail2ban.value,
        monitoring: remoteMonitoring.value,
      },
    },
    base_version: version,
    mappings: mappingObject(),
    firewall: firewallOptions(),
    fail2ban: { ...fail2banSettings.value },
    monitoring: { ...monitoringSettings.value },
    mode: execute ? mode.value : "preview",
    enable_nginx: enableNginx.value,
  };
}
let pendingPull: {
  digest: string;
  key: string;
  input: MigrationPullInput;
} | null = null;
function showBlockedPlan(error: unknown): boolean {
  if (!(error instanceof ApiError) || error.code !== "MIGRATION_BLOCKED")
    return false;
  const data = error.data;
  if (
    !data ||
    typeof data !== "object" ||
    !("id" in data) ||
    typeof data.id !== "string" ||
    !("steps" in data) ||
    !Array.isArray(data.steps)
  )
    return false;
  plan.value = data as MigrationPlan;
  return true;
}
async function pull(execute: boolean) {
  await run(async () => {
    const candidate = remoteInput(execute, 0);
    const digest = JSON.stringify(candidate);
    if (!pendingPull || pendingPull.digest !== digest) {
      pendingPull = {
        digest,
        key: crypto.randomUUID(),
        input: remoteInput(execute, await currentVersion()),
      };
    }
    try {
      plan.value = await api.pullMigration(pendingPull.input, pendingPull.key);
    } catch (error) {
      if (showBlockedPlan(error)) {
        pendingPull = null;
        remoteKey.value = "";
      }
      throw error;
    }
    pendingPull = null;
    remoteKey.value = "";
  });
  await load();
}
async function prepareDependencies() {
  const id = plan.value?.id;
  if (!id) return;
  await run(async () => {
    const input = {
      tag: dependencyTag.value.trim(),
      prerelease: dependencyPrerelease.value,
      ...(dependencyInstall.value
        ? {
            install: {
              start: dependencyStart.value,
              enable: dependencyEnable.value,
            },
          }
        : {}),
    };
    plan.value = await api.prepareMigrationDependencies(
      id,
      input,
      keyFor({ action: "dependencies", id, input }),
    );
  }, "依赖准备任务已受理");
  await load();
}
async function preflight() {
  const id = plan.value?.id;
  if (!id) return;
  await run(async () => {
    plan.value = await api.preflightMigration(id);
  });
}
async function execute() {
  const selected = plan.value;
  if (!selected) return;
  await run(async () => {
    const input = { mode: mode.value, enable_nginx: enableNginx.value };
    try {
      plan.value = await api.executeMigration(
        selected.id,
        input,
        keyFor({ id: selected.id, ...input }),
      );
    } catch (error) {
      showBlockedPlan(error);
      throw error;
    }
  });
  await load();
}
onMounted(async () => {
  if (has("backup.restore") && has("backup.secrets")) await load();
  timer = setInterval(() => {
    if (has("backup.restore") && has("backup.secrets")) void load();
  }, 5000);
});
onUnmounted(() => {
  controller.abort();
  if (timer) clearInterval(timer);
  remoteKey.value = "";
  passphrase.value = "";
  importPassphrase.value = "";
  pendingPull = null;
});
</script>

<template>
  <div class="page-stack">
    <NAlert type="info" title="迁移范围"
      >迁移 Nginx 原生配置、HTTP/Stream、访问列表及 WAF，可选择证书、DNS
      凭据、ACME 账户与签发配置及通知渠道。导入替换目标 Nginx
      配置；节点身份、管理入口与主机 DNS
      保留。监控设置保留目标值；导入的通知渠道、自动续期和自动部署保持停用，HTTP-01
      须重新确认公网条件。</NAlert
    >
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section v-if="canExport" class="panel">
      <h2>导出配置</h2>
      <NFormItem label="加密口令"
        ><NInput
          v-model:value="passphrase"
          type="password"
          show-password-on="click"
          placeholder="16–256 字节，单独保管"
          autocomplete="new-password"
      /></NFormItem>
      <div class="actions">
        <NCheckbox v-model:checked="includeCertificates"
          >包含证书与私钥</NCheckbox
        ><NCheckbox v-model:checked="includeCredentials"
          >包含 DNS 凭据</NCheckbox
        ><NCheckbox v-model:checked="includeAutomation"
          >包含 ACME 账户与签发配置</NCheckbox
        ><NCheckbox v-model:checked="includeNotifications"
          >包含通知渠道及凭据</NCheckbox
        ><NCheckbox v-model:checked="includeMonitoring">包含监控配置</NCheckbox
        ><NCheckbox v-model:checked="includeFail2ban"
          >包含 jail 期望配置</NCheckbox
        ><NCheckbox v-model:checked="includeFirewall"
          >包含防火墙期望规则</NCheckbox
        ><NButton
          :disabled="busy || passphrase.length < 16"
          :loading="busy"
          @click="exportPackage"
          >导出加密包</NButton
        >
      </div>
    </section>
    <section v-if="canImport" class="panel">
      <h2>导入配置包</h2>
      <NFormItem label="配置包"
        ><input type="file" accept=".age" :disabled="busy" @change="selectFile"
      /></NFormItem>
      <NFormItem label="解密口令"
        ><NInput
          v-model:value="importPassphrase"
          type="password"
          show-password-on="click"
          autocomplete="off"
      /></NFormItem>
      <NButton
        :disabled="
          busy || !file || importPassphrase.length < 16 || !firewallValid
        "
        :loading="busy"
        @click="previewFile"
        >预检配置包</NButton
      >
    </section>
    <section v-if="canPull" class="panel">
      <h2>从源节点迁入</h2>
      <NFormItem label="源节点 API"
        ><NInput
          v-model:value="remoteURL"
          placeholder="https://source.example.com:9443/api/v1"
          autocomplete="off"
      /></NFormItem>
      <NFormItem label="源节点 API Key"
        ><NInput
          v-model:value="remoteKey"
          type="password"
          show-password-on="click"
          autocomplete="off"
      /></NFormItem>
      <NFormItem label="TLS 证书 SHA-256（自签名证书必填）"
        ><NInput v-model:value="fingerprint" autocomplete="off"
      /></NFormItem>
      <NFormItem label="预期源节点 ID（可选）"
        ><NInput v-model:value="sourceNode"
      /></NFormItem>
      <div class="actions">
        <NCheckbox v-model:checked="remoteCertificates"
          >包含证书与私钥</NCheckbox
        ><NCheckbox v-model:checked="remoteCredentials">包含 DNS 凭据</NCheckbox
        ><NCheckbox v-model:checked="remoteAutomation"
          >包含 ACME 账户与签发配置</NCheckbox
        ><NCheckbox
          v-if="has('notifications.write')"
          v-model:checked="remoteNotifications"
          >包含通知渠道及凭据</NCheckbox
        ><NCheckbox v-model:checked="remoteMonitoring">包含监控配置</NCheckbox
        ><NCheckbox v-model:checked="remoteFail2ban">jail 期望配置</NCheckbox
        ><NCheckbox v-model:checked="remoteFirewall"
          >包含防火墙期望规则</NCheckbox
        ><NButton
          :disabled="busy || !remoteURL || !remoteKey || !firewallValid"
          @click="pull(false)"
          >拉取并预检</NButton
        ><NPopconfirm @positive-click="pull(true)"
          ><template #trigger
            ><NButton
              type="primary"
              :disabled="busy || !remoteURL || !remoteKey || !firewallValid"
              >一键迁入</NButton
            ></template
          >按所选模式迁入。保存或应用将替换目标 Nginx 配置。</NPopconfirm
        >
      </div>
    </section>
    <section v-if="canImport" class="panel">
      <h2>导入选项</h2>
      <NFormItem label="执行模式"
        ><NSelect v-model:value="mode" :options="options"
      /></NFormItem>
      <NCheckbox v-if="has('system.write')" v-model:checked="enableNginx"
        >允许启用目标 Nginx 配置模块</NCheckbox
      >
      <NFormItem label="参数映射（原参数 → 目标参数）"
        ><NInput
          v-model:value="mappings"
          type="textarea"
          :autosize="{ minRows: 3, maxRows: 10 }"
          placeholder='{"192.168.1.10:80":"0.0.0.0:80"}'
      /></NFormItem>
      <MigrationMonitoringOptions
        v-model="monitoringSettings"
        :allow-replace="has('monitoring.write')"
        :disabled="busy"
      />
      <MigrationFail2banOptions v-model="fail2banSettings" :disabled="busy" />
      <MigrationFirewallOptions
        v-model="firewallSettings"
        @update:valid="firewallValid = $event"
        :disabled="busy"
      />
      <p class="muted">
        映射在预检时生效；修改后需重新预检。源 Key 需要
        backup.export、backup.secrets 和 config.secrets 权限。
      </p>
    </section>
    <section v-if="plan" class="panel">
      <div class="actions">
        <h2>迁移计划</h2>
        <NTag>{{ states[plan.state] ?? plan.state }}</NTag>
      </div>
      <p>
        源节点 {{ plan.source_node }} · {{ plan.source_version }} · 目标基础版本
        {{ plan.base_version }}
      </p>
      <p v-if="plan.state === 'planned'" class="muted">
        有效期至 {{ time(plan.expires_at) }}
      </p>
      <NAlert
        v-if="plan.last_error"
        :type="plan.state === 'rolled_back' ? 'warning' : 'error'"
        >{{ plan.last_error }}</NAlert
      >
      <MigrationMonitoringPreview
        v-if="plan.monitoring"
        :info="plan.monitoring"
      />
      <MigrationFail2banPreview v-if="plan.fail2ban" :info="plan.fail2ban" />
      <MigrationFirewallPreview v-if="plan.firewall" :info="plan.firewall" />
      <MigrationDependencies
        v-if="plan.dependencies"
        :status="plan.dependencies"
      />
      <div v-if="plan.state === 'planned'" class="actions">
        <NButton :disabled="busy" @click="preflight">重新预检</NButton>
      </div>
      <div
        v-if="
          plan.state === 'planned' &&
          has('components.manage') &&
          !plan.dependencies
        "
      >
        <NFormItem label="可信组件发行标签（可选）"
          ><NInput v-model:value="dependencyTag" placeholder="留空使用稳定版"
        /></NFormItem>
        <NCheckbox v-model:checked="dependencyPrerelease"
          >允许指定的预发布版本</NCheckbox
        >
        <div v-if="has('system.write')">
          <NCheckbox v-model:checked="dependencyInstall"
            >授权缺失时首次安装 Nginx</NCheckbox
          >
          <template v-if="dependencyInstall">
            <NCheckbox v-model:checked="dependencyStart">安装后启动</NCheckbox>
            <NCheckbox v-model:checked="dependencyEnable"
              >开机自动启动</NCheckbox
            >
            <p>安装期间暂停配置写入，完成后恢复并重新预检。</p>
          </template>
        </div>
        <NPopconfirm @positive-click="prepareDependencies"
          ><template #trigger
            ><NButton :disabled="busy">准备缺失依赖</NButton></template
          >按所选选项准备缺失依赖？首次安装仅适用于未安装 Nginx
          的原生部署，Docker 模块由镜像提供。</NPopconfirm
        >
      </div>
      <div class="migration-steps">
        <div v-for="(step, i) in plan.steps" :key="i">
          <NTag
            :type="
              step.state === 'blocked' || step.state === 'unavailable'
                ? 'error'
                : step.state === 'review'
                  ? 'warning'
                  : 'default'
            "
            >{{ stepStates[step.state] ?? step.state }}</NTag
          ><code>{{ step.resource }}</code
          ><span>{{ step.message }}</span>
        </div>
      </div>
      <ul>
        <li v-for="item in plan.omissions" :key="item">{{ item }}</li>
      </ul>
      <p v-if="plan.revision_id">配置修订：{{ plan.revision_id }}</p>
      <p v-if="plan.task_id">应用任务：{{ plan.task_id }}</p>
      <NPopconfirm v-if="plan.state === 'planned'" @positive-click="execute"
        ><template #trigger
          ><NButton
            type="primary"
            :loading="busy"
            :disabled="
              busy ||
              preparingDependencies ||
              (mode === 'save' && !plan.can_save) ||
              (mode === 'apply' && !plan.can_apply)
            "
            >执行计划</NButton
          ></template
        >{{
          mode === "draft"
            ? "保存为独立草稿。"
            : "替换目标 Nginx 配置；应用失败时恢复原配置。"
        }}</NPopconfirm
      >
    </section>
    <section v-if="history.length" class="panel">
      <h2>迁移记录</h2>
      <div v-for="item in history" :key="item.id" class="actions">
        <NButton text :disabled="busy" @click="selectPlan(item.id)">{{
          item.id
        }}</NButton
        ><NTag>{{ states[item.state] ?? item.state }}</NTag
        ><span>{{ item.source_node }}</span>
      </div>
    </section>
  </div>
</template>

<style scoped>
.migration-steps {
  display: grid;
  gap: 10px;
  margin: 16px 0;
}
.migration-steps > div {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.migration-steps code {
  overflow-wrap: anywhere;
}
h2 {
  font-size: 18px;
}
ul {
  padding-left: 20px;
}
li {
  margin: 6px 0;
}
.actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  margin: 12px 0;
}
</style>
