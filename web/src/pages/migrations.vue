<route lang="json">
{
  "meta": {
    "title": "配置迁移",
    "nav": true,
    "order": 51,
    "symbol": "⇄",
    "group": "面板管理"
  }
}
</route>

<script setup lang="ts">
import DetailDialog from "../components/DetailDialog.vue";
import { useLiveRefresh } from "../composables/live";
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
  NTabs,
  NTabPane,
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
import TaskLogButton from "../components/TaskLogButton.vue";
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
  sourceNode = ref("");
const mode = ref<MigrationExecuteInput["mode"]>("draft"),
  enableNginx = ref(false),
  baseVersion = ref(0),
  plan = ref<MigrationPlan | null>(null),
  history = ref<MigrationPlan[]>([]),
  error = ref("");
const showPlan = ref(false);
const showOptions = ref(false);
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
const loading = ref(false);
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
const transferTab = ref(canExport.value ? "export" : "file");
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
  try {
    mappingRecord(mappings.value);
    return "";
  } catch (cause) {
    return (cause as Error).message;
  }
});
function mappingObject(): Record<string, string> {
  return mappingRecord(mappings.value);
}
async function load() {
  if (loading.value || busy.value || document.hidden) return;
  loading.value = true;
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
      ) {
        if (plan.value === selected) plan.value = updated;
      }
    }
    error.value = "";
  } catch (e) {
    if (!controller.signal.aborted) error.value = apiError(e).message;
  } finally {
    loading.value = false;
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
    showPlan.value = true;
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
    showPlan.value = true;
  });
  await load();
}
function remoteInput(execute: boolean, version: number): MigrationPullInput {
  return {
    remote: {
      url: remoteURL.value,
      api_key: remoteKey.value,
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
  showPlan.value = true;
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
      showPlan.value = true;
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
onMounted(() => {
  if (has("backup.restore") && has("backup.secrets")) void load();
});
onUnmounted(() => {
  controller.abort();
  remoteKey.value = "";
  passphrase.value = "";
  importPassphrase.value = "";
  pendingPull = null;
});
useLiveRefresh(api, ["tasks"], () => {
  if (has("backup.restore") && has("backup.secrets")) return load();
}, () => loading.value || busy.value);
</script>

<template>
  <div class="page-stack">
    <div class="toolbar">
      <RouterLink to="/migration-push">
        迁移到其他服务器 →
      </RouterLink>
    </div>
    <NAlert type="info">
      保存或应用迁入配置将替换目标 Nginx 配置，请先备份。
    </NAlert>
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <section class="panel page-stack">
      <NTabs v-model:value="transferTab" type="line" animated>
        <NTabPane v-if="canExport" name="export" tab="导出配置">
          <div class="page-stack">
            <NFormItem label="配置包类型">
              <NSelect
                v-model:value="exportMode"
                :options="exportOptions"
                :disabled="busy"
              />
            </NFormItem>
            <NAlert v-if="exportMode === 'portable'" type="warning">
              仅导出网站基础设置和访问规则，不包含自定义配置、密码等敏感信息。导入的网站默认停用，请检查配置后再启用。
            </NAlert>
            <NFormItem v-if="exportMode === 'encrypted'" label="加密口令">
              <NInput
                v-model:value="passphrase"
                type="password"
                show-password-on="click"
                placeholder="16–256 字节，单独保管"
                autocomplete="new-password"
              />
            </NFormItem>
            <div v-if="exportMode === 'encrypted'" class="choice-grid">
              <NCheckbox v-model:checked="includeCertificates">
                包含证书与私钥
              </NCheckbox><NCheckbox v-model:checked="includeCredentials">
                包含 DNS 凭据
              </NCheckbox><NCheckbox v-model:checked="includeAutomation">
                包含 ACME 账户与签发配置
              </NCheckbox><NCheckbox v-model:checked="includeNotifications">
                包含通知渠道及凭据
              </NCheckbox><NCheckbox v-model:checked="includeHostDNS">
                主机 DNS 已保存配置
              </NCheckbox><NCheckbox v-model:checked="includeMonitoring">
                包含监控配置
              </NCheckbox><NCheckbox v-model:checked="includeFail2ban">
                包含登录防护配置
              </NCheckbox><NCheckbox v-model:checked="includeFirewall">
                包含防火墙规则
              </NCheckbox>
            </div>
            <div class="button-row">
              <NButton
                type="primary"
                :disabled="busy || !exportReady"
                :loading="busy"
                @click="exportPackage"
              >
                {{
                  exportMode === "portable" ? "导出配置包" : "导出加密包"
                }}
              </NButton>
            </div>
          </div>
        </NTabPane>
        <NTabPane v-if="canImport" name="file" tab="从文件导入">
          <div class="page-stack">
            <NFormItem label="配置包">
              <input
                type="file"
                accept=".age,.tar"
                :disabled="busy"
                @change="selectFile"
              />
            </NFormItem>
            <NFormItem v-if="fileEncrypted === true" label="解密口令">
              <NInput
                v-model:value="importPassphrase"
                type="password"
                show-password-on="click"
                autocomplete="off"
              />
            </NFormItem>
            <div class="button-row">
              <NButton
                type="primary"
                :disabled="
                  busy ||
                    !file ||
                    fileEncrypted === null ||
                    (fileEncrypted && importPassphrase.length < 16) ||
                    !firewallValid ||
                    !!mappingError ||
                    !hostDNSValid
                "
                :loading="busy"
                @click="previewFile"
              >
                预检配置包
              </NButton>
            </div>
          </div>
        </NTabPane>
        <NTabPane v-if="canPull" name="remote" tab="从服务器迁入">
          <div class="page-stack">
            <div class="form-grid">
              <NFormItem label="源节点 API">
                <NInput
                  v-model:value="remoteURL"
                  placeholder="https://source.example.com:9443/api/v1"
                  autocomplete="off"
                />
              </NFormItem>
              <NFormItem label="源节点 API Key">
                <NInput
                  v-model:value="remoteKey"
                  type="password"
                  show-password-on="click"
                  autocomplete="off"
                />
              </NFormItem>
            </div>
            <div class="choice-grid">
              <NCheckbox v-model:checked="remoteCertificates">
                包含证书与私钥
              </NCheckbox><NCheckbox v-model:checked="remoteCredentials">
                包含 DNS 凭据
              </NCheckbox><NCheckbox v-model:checked="remoteAutomation">
                包含 ACME 账户与签发配置
              </NCheckbox><NCheckbox
                v-if="has('notifications.write')"
                v-model:checked="remoteNotifications"
              >
                包含通知渠道及凭据
              </NCheckbox><NCheckbox v-model:checked="remoteHostDNS">
                主机 DNS 已保存配置
              </NCheckbox><NCheckbox v-model:checked="remoteMonitoring">
                包含监控配置
              </NCheckbox><NCheckbox v-model:checked="remoteFail2ban">
                登录防护配置
              </NCheckbox><NCheckbox v-model:checked="remoteFirewall">
                包含防火墙规则
              </NCheckbox>
            </div>
            <div class="button-row">
              <NButton
                :disabled="
                  busy ||
                    !remoteURL ||
                    !remoteKey ||
                    !firewallValid ||
                    !!mappingError ||
                    !hostDNSValid
                "
                @click="pull(false)"
              >
                拉取并预检
              </NButton><NPopconfirm @positive-click="pull(true)">
                <template #trigger>
                  <NButton
                    type="primary"
                    :disabled="
                      busy ||
                        !remoteURL ||
                        !remoteKey ||
                        !firewallValid ||
                        !!mappingError ||
                        !hostDNSValid
                    "
                  >
                    一键迁入
                  </NButton>
                </template>按所选模式迁入，并执行已授权的依赖准备与首次安装。保存或应用将替换目标
                Nginx 配置。
              </NPopconfirm>
            </div>
          </div>
        </NTabPane>
      </NTabs>
    </section>
    <section
      v-if="canImport && transferTab !== 'export'"
      class="panel page-stack"
    >
      <h2>导入设置</h2>
      <NFormItem label="执行模式">
        <NSelect v-model:value="mode" :options="options" />
      </NFormItem>
      <NCheckbox v-if="has('system.write')" v-model:checked="enableNginx">
        允许启用目标 Nginx 配置模块
      </NCheckbox>
      <div class="button-row">
        <NButton :disabled="busy" @click="showOptions = true">
          迁移设置
        </NButton>
      </div>
    </section>
    <DetailDialog v-model:show="showOptions" title="迁移设置" body-height="420px">
      <div class="page-stack">
        <NFormItem
          label="参数映射（原参数 → 目标参数）"
          :validation-status="mappingError ? 'error' : undefined"
          :feedback="mappingError"
        >
          <MappingInput v-model:value="mappings" :max="128" :disabled="busy" />
        </NFormItem>
        <MigrationHostDNSOptions
          v-model="hostDNSSettings"
          :sources="plan?.host_dns?.entries.map((item) => item.source) ?? []"
          :disabled="busy"
          :allow-map="has('host.dns.write')"
          @update:valid="hostDNSValid = $event"
        />
        <MigrationMonitoringOptions
          v-model="monitoringSettings"
          :allow-replace="has('monitoring.write')"
          :disabled="busy"
        />
        <MigrationFail2banOptions
          v-model="fail2banSettings"
          :disabled="busy"
        />
        <MigrationFirewallOptions
          v-model="firewallSettings"
          :disabled="busy"
          @update:valid="firewallValid = $event"
        />
        <p class="muted">
          修改目标映射后，请重新检查。
        </p>
        <div
          v-if="transferTab === 'remote' && has('components.manage')"
          class="full-width page-stack"
        >
          <NCheckbox v-model:checked="remoteDependencies">
            迁入前自动准备 Nginx 依赖
          </NCheckbox>
          <template v-if="remoteDependencies">
            <NFormItem label="Nginx 组件发行标签（可选）">
              <NInput
                v-model:value="dependencyTag"
                placeholder="留空使用稳定版"
              />
            </NFormItem>
            <NCheckbox v-model:checked="dependencyPrerelease">
              允许指定的预发布版本
            </NCheckbox>
            <div v-if="has('system.write')">
              <NCheckbox v-model:checked="dependencyInstall">
                授权缺失时安装 Nginx
              </NCheckbox>
              <template v-if="dependencyInstall">
                <NCheckbox v-model:checked="dependencyStart">
                  安装后启动
                </NCheckbox>
                <NCheckbox v-model:checked="dependencyEnable">
                  开机自动启动
                </NCheckbox>
              </template>
            </div>
            <p class="muted">
              仅在目标服务器尚未安装 Nginx 时执行安装。
            </p>
          </template>
        </div>
      </div>
    </DetailDialog>
    <section v-if="plan" class="panel section-heading">
      <h2>当前迁移计划</h2>
      <div class="button-row">
        <NTag>{{ states[plan.state] ?? plan.state }}</NTag>
        <NButton @click="showPlan = true">
          查看计划
        </NButton>
      </div>
    </section>
    <DetailDialog
      v-model:show="showPlan"
      :busy="busy"
      title="迁移计划"
      width="920px"
    >
      <div v-if="plan" class="page-stack">
        <NAlert v-if="plan.mode === 'portable'" type="warning">
          此计划来自可移植配置。迁入站点均已停用，须检查省略项并补齐保护后再启用。
        </NAlert>
        <div class="actions">
          <NTag>{{ states[plan.state] ?? plan.state }}</NTag>
          <NTag v-if="plan.pruned_at" type="warning">
            材料已清理
          </NTag>
        </div>
        <NAlert v-if="plan.pruned_at" type="info">
          迁移材料已于
          {{ time(plan.pruned_at) }}
          清理，无法重新预检或执行，迁移记录和执行结果仍可查询。
        </NAlert>
        <p v-if="plan.state === 'planned'" class="muted">
          有效期至 {{ time(plan.expires_at) }}
        </p>
        <NAlert
          v-if="plan.last_error"
          :type="plan.state === 'rolled_back' ? 'warning' : 'error'"
        >
          {{ plan.last_error }}
        </NAlert>
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
          <p v-if="plan.pull.error">
            {{ plan.pull.error }}
          </p>
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
          <NButton :disabled="busy" @click="preflight">
            重新预检
          </NButton>
        </div>
        <div
          v-if="
            plan.state === 'planned' &&
              has('components.manage') &&
              !continuingPull &&
              !plan.dependencies
          "
        >
          <NFormItem label="Nginx 组件发行标签（可选）">
            <NInput v-model:value="dependencyTag" placeholder="留空使用稳定版" />
          </NFormItem>
          <NCheckbox v-model:checked="dependencyPrerelease">
            允许指定的预发布版本
          </NCheckbox>
          <div v-if="has('system.write')">
            <NCheckbox v-model:checked="dependencyInstall">
              授权缺失时安装 Nginx
            </NCheckbox>
            <template v-if="dependencyInstall">
              <NCheckbox v-model:checked="dependencyStart">
                安装后启动
              </NCheckbox>
              <NCheckbox v-model:checked="dependencyEnable">
                开机自动启动
              </NCheckbox>
              <p>安装期间暂停配置写入，完成后恢复并重新预检。</p>
            </template>
          </div>
          <NPopconfirm @positive-click="prepareDependencies">
            <template #trigger>
              <NButton :disabled="busy">
                准备 Nginx 依赖
              </NButton>
            </template>确认准备 Nginx？仅在目标服务器尚未安装 Nginx 时执行安装。
          </NPopconfirm>
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
            >
              {{ stepStates[step.state] ?? step.state }}
            </NTag><span>{{ step.message }}</span>
          </div>
        </div>
        <ul>
          <li v-for="item in plan.omissions" :key="item">
            {{ item }}
          </li>
        </ul>
        <TaskLogButton v-if="plan.task_id" :task-id="plan.task_id" />
      </div>
      <template #actions>
        <NPopconfirm v-if="plan?.state === 'planned'" @positive-click="execute">
          <template #trigger>
            <NButton
              type="primary"
              :loading="busy"
              :disabled="
                busy ||
                  preparingDependencies ||
                  continuingPull ||
                  (mode === 'save' && !plan.can_save) ||
                  (mode === 'apply' && !plan.can_apply)
              "
            >
              执行计划
            </NButton>
          </template>{{
            mode === "draft"
              ? "保存为独立草稿。"
              : "替换目标 Nginx 配置；应用失败时恢复原配置。"
          }}
        </NPopconfirm>
      </template>
    </DetailDialog>
    <section v-if="history.length" class="panel page-stack">
      <h2>迁移记录</h2>
      <div v-for="item in history" :key="item.id" class="actions">
        <NButton text :disabled="busy" @click="selectPlan(item.id)">
          {{
            `查看记录 · ${time(item.expires_at)}`
          }}
        </NButton><NTag>{{ states[item.state] ?? item.state }}</NTag><NTag v-if="item.pruned_at" type="warning">
          材料已清理
        </NTag>
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
