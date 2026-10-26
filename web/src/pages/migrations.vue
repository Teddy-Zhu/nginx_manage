<route lang="json">
{
  "meta": {
    "title": "配置迁移",
    "subtitle": "在服务器之间导出、导入配置",
    "nav": true,
    "order": 21,
    "symbol": "⇄",
    "group": "数据与设置"
  }
}
</route>

<script setup lang="ts">
import MappingInput from "../components/MappingInput.vue";
import { mappingRecord, type MappingRow } from "../utils/form";
import { randomUUID } from "../utils/crypto";

import { RouterLink } from "vue-router";
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
  type MigrationExportInput,
  type MigrationPackage,
  type MigrationExecuteInput,
  type MigrationPullInput,
  type MigrationFirewallInput,
  type MigrationFail2banInput,
  type MigrationMonitoringInput,
  type MigrationHostDNSInput,
} from "../api/client";
import MigrationDependencies from "../components/MigrationDependencies.vue";
import MigrationFirewallOptions from "../components/MigrationFirewallOptions.vue";
import MigrationFirewallPreview from "../components/MigrationFirewallPreview.vue";
import MigrationHostDNSOptions from "../components/MigrationHostDNSOptions.vue";
import MigrationHostDNSPreview from "../components/MigrationHostDNSPreview.vue";
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
  mappings = ref<MappingRow[]>([]);
const exportMode = ref<MigrationExportInput["mode"]>("portable");
const exported = ref<MigrationPackage | null>(null);
const fileEncrypted = ref<boolean | null>(null);
watch(exportMode, () => {
  passphrase.value = "";
  exported.value = null;
});
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
  includeHostDNS = ref(false),
  remoteFirewall = ref(false),
  remoteFail2ban = ref(false),
  remoteMonitoring = ref(false),
  remoteHostDNS = ref(false);
const hostDNSSettings = ref<MigrationHostDNSInput>({
  mode: "preserve",
  mappings: {},
});
const hostDNSValid = ref(true);
function hostDNSOptions(): MigrationHostDNSInput {
  if (!hostDNSValid.value) throw new Error("请修正主机 DNS 目标映射");
  return JSON.parse(
    JSON.stringify(hostDNSSettings.value),
  ) as MigrationHostDNSInput;
}
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
  remoteDependencies = ref(false),
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
const continuingPull = computed(
  () =>
    !!plan.value?.pull &&
    ["queued", "running", "recovery_required"].includes(plan.value.pull.state),
);
const controller = new AbortController();
let timer: ReturnType<typeof setInterval> | undefined;
let loading = false;
const has = (scope: string) => session.me?.scopes.includes(scope) ?? false;
const canExport = computed(() => has("backup.export"));
const canEncryptedExport = computed(
  () => canExport.value && has("backup.secrets") && has("config.secrets"),
);
const exportOptions = computed(() => [
  { label: "可移植配置（普通归档）", value: "portable" },
  {
    label: "完整原文与所选材料（加密包）",
    value: "encrypted",
    disabled: !canEncryptedExport.value,
  },
]);
const exportReady = computed(
  () =>
    exportMode.value === "portable" ||
    (canEncryptedExport.value &&
      new TextEncoder().encode(passphrase.value).length >= 16 &&
      new TextEncoder().encode(passphrase.value).length <= 256),
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
  { label: "保存配置", value: "save" },
  { label: "保存并应用 Nginx", value: "apply" },
];
const states: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  planned: "待执行",
  draft: "已保存草稿",
  saved: "已保存配置",
  applying: "应用中",
  succeeded: "迁移成功",
  failed: "失败",
  rolled_back: "已恢复",
  recovery_required: "需要恢复",
};
const pullStages: Record<string, string> = {
  preparing_dependencies: "等待依赖准备",
  dependencies: "准备目标依赖",
  executing: "提交迁移配置",
  observing: "核对应用结果",
  draft: "已保存草稿",
  saved: "已保存配置",
  succeeded: "迁入完成",
  rolled_back: "已恢复原配置",
  grant_expired: "迁入授权已过期",
  grant_invalid: "迁入授权无效",
  dependency_missing: "依赖任务缺失",
  dependency_invalid: "依赖任务不匹配",
  dependencies_failed: "依赖准备失败",
  dependencies_blocked: "依赖准备未获准",
  execution_blocked: "迁入条件未满足",
  target_changed: "目标配置已变化",
  plan_failed: "迁移计划已结束",
  unavailable: "依赖服务不可用",
};
const stepStates: Record<string, string> = {
  ready: "就绪",
  blocked: "冲突",
  unavailable: "缺少依赖",
  authorization: "需要授权",
  review: "核对",
};
const time = (n: number) => new Date(n * 1000).toLocaleString();
const mappingError = computed(() => {
  try { mappingRecord(mappings.value); return ""; }
  catch (cause) { return (cause as Error).message; }
});
function mappingObject(): Record<string, string> { return mappingRecord(mappings.value); }
async function load() {
  if (loading || busy.value || document.hidden) return;
  loading = true;
  try {
    const items = await api.migrations(controller.signal);
    history.value = items;
    const selected = plan.value;
    if (selected) {
      const updated = await api.migration(selected.id, controller.signal);
      if (
        selected.pull ||
        updated.pull ||
        selected.dependencies ||
        selected.state !== "planned" ||
        updated.state !== "planned"
      )
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
async function selectFile(event: Event) {
  const selected = (event.target as HTMLInputElement).files?.[0] ?? null;
  file.value = selected;
  fileEncrypted.value = null;
  importPassphrase.value = "";
  plan.value = null;
  if (!selected) return;
  try {
    const header = await selected.slice(0, 24).text();
    if (file.value === selected)
      fileEncrypted.value = header.startsWith("age-encryption.org/v1\n");
  } catch {
    if (file.value === selected) error.value = "无法读取配置包";
  }
}
async function exportPackage() {
  exported.value = null;
  await run(async () => {
    const out = await api.exportMigration({
      mode: exportMode.value,
      passphrase: exportMode.value === "encrypted" ? passphrase.value : "",
      selection: {
        certificates:
          exportMode.value === "encrypted" && includeCertificates.value,
        dns_credentials:
          exportMode.value === "encrypted" && includeCredentials.value,
        automation: exportMode.value === "encrypted" && includeAutomation.value,
        notifications:
          exportMode.value === "encrypted" && includeNotifications.value,
        firewall: exportMode.value === "encrypted" && includeFirewall.value,
        fail2ban: exportMode.value === "encrypted" && includeFail2ban.value,
        monitoring: exportMode.value === "encrypted" && includeMonitoring.value,
        host_dns: exportMode.value === "encrypted" && includeHostDNS.value,
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
    exported.value = out;
    message.success(
      out.manifest.mode === "portable"
        ? "可移植配置已导出"
        : "加密配置包已导出，请单独保管口令",
    );
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
      passphrase: fileEncrypted.value ? importPassphrase.value : "",
      base_version: version,
      mappings: mappingObject(),
      firewall,
      fail2ban: { ...fail2banSettings.value },
      monitoring: { ...monitoringSettings.value },
      host_dns: hostDNSOptions(),
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
        host_dns: remoteHostDNS.value,
      },
    },
    base_version: version,
    mappings: mappingObject(),
    firewall: firewallOptions(),
    fail2ban: { ...fail2banSettings.value },
    monitoring: { ...monitoringSettings.value },
    host_dns: hostDNSOptions(),
    mode: execute ? mode.value : "preview",
    enable_nginx: enableNginx.value,
    ...(execute && remoteDependencies.value && has("components.manage")
      ? { dependencies: dependencyInput() }
      : {}),
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
        key: randomUUID(),
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
    const input = dependencyInput();
    plan.value = await api.prepareMigrationDependencies(
      id,
      input,
      keyFor({ action: "dependencies", id, input }),
    );
  }, "依赖准备任务已受理");
  await load();
}
function dependencyInput() {
  return {
    tag: dependencyTag.value.trim(),
    prerelease: dependencyPrerelease.value,
    ...(dependencyInstall.value && has("system.write")
      ? {
          install: {
            start: dependencyStart.value,
            enable: dependencyEnable.value,
          },
        }
      : {}),
  };
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
    <div class="toolbar"><RouterLink to="/migration-push">迁移到其他服务器</RouterLink></div>
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
      <NFormItem label="配置包类型"
        ><NSelect
          v-model:value="exportMode"
          :options="exportOptions"
          :disabled="busy"
      /></NFormItem>
      <NAlert v-if="exportMode === 'portable'" type="warning">
        仅导出可识别的受管字段、IP 访问列表和基础
        WAF，不包含完整原文、凭据或可选材料。原生认证、自定义路径、头常量及备注等内容会省略；迁入站点保持停用，须检查并补齐保护后再启用。
      </NAlert>
      <NFormItem v-if="exportMode === 'encrypted'" label="加密口令"
        ><NInput
          v-model:value="passphrase"
          type="password"
          show-password-on="click"
          placeholder="16–256 字节，单独保管"
          autocomplete="new-password"
      /></NFormItem>
      <div v-if="exportMode === 'encrypted'" class="actions">
        <NCheckbox v-model:checked="includeCertificates"
          >包含证书与私钥</NCheckbox
        ><NCheckbox v-model:checked="includeCredentials"
          >包含 DNS 凭据</NCheckbox
        ><NCheckbox v-model:checked="includeAutomation"
          >包含 ACME 账户与签发配置</NCheckbox
        ><NCheckbox v-model:checked="includeNotifications"
          >包含通知渠道及凭据</NCheckbox
        ><NCheckbox v-model:checked="includeHostDNS"
          >主机 DNS 已保存配置</NCheckbox
        ><NCheckbox v-model:checked="includeMonitoring">包含监控配置</NCheckbox
        ><NCheckbox v-model:checked="includeFail2ban"
          >包含登录防护配置</NCheckbox
        ><NCheckbox v-model:checked="includeFirewall"
          >包含防火墙规则</NCheckbox
        >
      </div>
      <NButton
        :disabled="busy || !exportReady"
        :loading="busy"
        @click="exportPackage"
        >{{
          exportMode === "portable" ? "导出普通归档" : "导出加密包"
        }}</NButton
      >
      <template v-if="exported">
        <h3>导出范围与省略内容</h3>
        <ul>
          <li v-for="item in exported.manifest.omissions" :key="item">
            {{ item }}
          </li>
        </ul>
      </template>
    </section>
    <section v-if="canImport" class="panel">
      <h2>导入配置包</h2>
      <NFormItem label="配置包"
        ><input
          type="file"
          accept=".age,.tar"
          :disabled="busy"
          @change="selectFile"
      /></NFormItem>
      <NFormItem v-if="fileEncrypted === true" label="解密口令"
        ><NInput
          v-model:value="importPassphrase"
          type="password"
          show-password-on="click"
          autocomplete="off"
      /></NFormItem>
      <NButton
        :disabled="
          busy ||
          !file ||
          fileEncrypted === null ||
          (fileEncrypted && importPassphrase.length < 16) ||
          !firewallValid ||
          !!mappingError || !hostDNSValid
        "
        :loading="busy"
        @click="previewFile"
        >预检配置包</NButton
      >
    </section>
    <section v-if="canPull" class="panel">
      <h2>从其他服务器迁入</h2>
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
      <div v-if="has('components.manage')">
        <NCheckbox v-model:checked="remoteDependencies"
          >迁入前自动准备 Nginx 依赖</NCheckbox
        >
        <template v-if="remoteDependencies">
          <NFormItem label="Nginx 组件发行标签（可选）">
            <NInput
              v-model:value="dependencyTag"
              placeholder="留空使用稳定版"
            />
          </NFormItem>
          <NCheckbox v-model:checked="dependencyPrerelease"
            >允许指定的预发布版本</NCheckbox
          >
          <div v-if="has('system.write')">
            <NCheckbox v-model:checked="dependencyInstall"
              >授权缺失时首次安装 Nginx</NCheckbox
            >
            <template v-if="dependencyInstall">
              <NCheckbox v-model:checked="dependencyStart"
                >安装后启动</NCheckbox
              >
              <NCheckbox v-model:checked="dependencyEnable"
                >开机自动启动</NCheckbox
              >
            </template>
          </div>
          <p class="muted">
            首次安装仅适用于尚未安装 Nginx 的原生部署。Docker 使用预置模块镜像。
          </p>
        </template>
      </div>
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
        ><NCheckbox v-model:checked="remoteHostDNS"
          >主机 DNS 已保存配置</NCheckbox
        ><NCheckbox v-model:checked="remoteMonitoring">包含监控配置</NCheckbox
        ><NCheckbox v-model:checked="remoteFail2ban">登录防护配置</NCheckbox
        ><NCheckbox v-model:checked="remoteFirewall"
          >包含防火墙规则</NCheckbox
        ><NButton
          :disabled="
            busy || !remoteURL || !remoteKey || !firewallValid || !!mappingError || !hostDNSValid
          "
          @click="pull(false)"
          >拉取并预检</NButton
        ><NPopconfirm @positive-click="pull(true)"
          ><template #trigger
            ><NButton
              type="primary"
              :disabled="
                busy ||
                !remoteURL ||
                !remoteKey ||
                !firewallValid ||
                !!mappingError || !hostDNSValid
              "
              >一键迁入</NButton
            ></template
          >按所选模式迁入，并执行已授权的依赖准备与首次安装。保存或应用将替换目标
          Nginx 配置。</NPopconfirm
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
      <NFormItem label="参数映射（原参数 → 目标参数）" :validation-status="mappingError ? 'error' : undefined" :feedback="mappingError"
        ><MappingInput :max="128" v-model:value="mappings" :disabled="busy" /></NFormItem>
      <MigrationHostDNSOptions
        v-model="hostDNSSettings"
        @update:valid="hostDNSValid = $event"
        :disabled="busy"
        :allow-map="has('host.dns.write')"
      />
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
      <NAlert v-if="plan.mode === 'portable'" type="warning"
        >此计划来自可移植配置。迁入站点均已停用，须检查省略项并补齐保护后再启用。</NAlert
      >
      <div class="actions">
        <h2>迁移计划</h2>
        <NTag>{{ states[plan.state] ?? plan.state }}</NTag>
        <NTag v-if="plan.pruned_at" type="warning">材料已清理</NTag>
      </div>
      <p>
        源节点 {{ plan.source_node }} · {{ plan.source_version }}
      </p>
      <NAlert v-if="plan.pruned_at" type="info">
        迁移材料已于
        {{
          time(plan.pruned_at)
        }}
        清理，无法重新预检或执行。原计划摘要与执行结果仍可查询。
      </NAlert>
      <p v-if="plan.state === 'planned'" class="muted">
        有效期至 {{ time(plan.expires_at) }}
      </p>
      <NAlert
        v-if="plan.last_error"
        :type="plan.state === 'rolled_back' ? 'warning' : 'error'"
        >{{ plan.last_error }}</NAlert
      >
      <NAlert
        v-if="plan.pull"
        :type="
          ['failed', 'recovery_required'].includes(plan.pull.state)
            ? 'error'
            : plan.pull.state === 'succeeded'
              ? 'success'
              : 'info'
        "
        title="自动迁入"
      >
        {{ states[plan.pull.state] ?? plan.pull.state }} ·
        {{ pullStages[plan.pull.stage] ?? plan.pull.stage }} ·
        {{ options.find((item) => item.value === plan?.pull?.mode)?.label }}
        <p>迁入授权有效期至 {{ time(plan.pull.deadline) }}</p>
        <p v-if="plan.pull.error">{{ plan.pull.error }}</p>
      </NAlert>
      <MigrationHostDNSPreview
        v-if="plan.host_dns"
        :info="plan.host_dns"
        :plan-id="
          !plan.pruned_at &&
          ['draft', 'saved', 'succeeded', 'rolled_back'].includes(plan.state)
            ? plan.id
            : undefined
        "
      />
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
          !continuingPull &&
          !plan.dependencies
        "
      >
        <NFormItem label="Nginx 组件发行标签（可选）"
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
            ><NButton :disabled="busy">准备 Nginx 依赖</NButton></template
          >按所选选项准备 Nginx 依赖？首次安装仅适用于未安装 Nginx
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
      <p v-if="plan.task_id">应用任务：{{ plan.task_id }}</p>
      <NPopconfirm v-if="plan.state === 'planned'" @positive-click="execute"
        ><template #trigger
          ><NButton
            type="primary"
            :loading="busy"
            :disabled="
              busy ||
              preparingDependencies ||
              continuingPull ||
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
        ><NTag v-if="item.pruned_at" type="warning">材料已清理</NTag
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
