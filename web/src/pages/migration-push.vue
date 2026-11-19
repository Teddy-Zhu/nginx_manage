<route lang="json">
{
  "meta": {
    "title": "迁出到节点",
    "nav": false,
    "order": 7.1,
    "symbol": "↗",
    "parent": "/migrations"
  }
}
</route>
<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import MappingInput from "../components/MappingInput.vue";
import { mappingRecord, type MappingRow } from "../utils/form";
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
  type MigrationPushInput,
  type MigrationPushTask,
  type MigrationFirewallInput,
  type MigrationFail2banInput,
  type MigrationMonitoringInput,
  type MigrationHostDNSInput,
} from "../api/client";
import MigrationDependencies from "../components/MigrationDependencies.vue";
import TaskLogButton from "../components/TaskLogButton.vue";
import MigrationFirewallOptions from "../components/MigrationFirewallOptions.vue";
import MigrationFirewallPreview from "../components/MigrationFirewallPreview.vue";
import MigrationHostDNSPreview from "../components/MigrationHostDNSPreview.vue";
import MigrationMonitoringOptions from "../components/MigrationMonitoringOptions.vue";
import MigrationMonitoringPreview from "../components/MigrationMonitoringPreview.vue";
import MigrationFail2banOptions from "../components/MigrationFail2banOptions.vue";
import MigrationFail2banPreview from "../components/MigrationFail2banPreview.vue";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();

const session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const url = ref(""),
  key = ref(""),
  node = ref(""),
  mappings = ref<MappingRow[]>([]),
  resumeKey = ref("");
const certificates = ref(false),
  credentials = ref(false),
  automation = ref(false),
  notifications = ref(false),
  includeFirewall = ref(false),
  includeFail2ban = ref(false),
  includeMonitoring = ref(false),
  includeHostDNS = ref(false),
  enableNginx = ref(false);
function hostDNSOptions(): MigrationHostDNSInput {
  return { mode: "preserve", mappings: {} };
}
const monitoringSettings = ref<MigrationMonitoringInput>({ mode: "preserve" });
const fail2banSettings = ref<MigrationFail2banInput>({ mode: "preserve" });
const firewallSettings = ref<MigrationFirewallInput>({
    mode: "preserve",
    backend: "",
    interfaces: {},
  }),
  firewallValid = ref(true);
const prepareDependencies = ref(false),
  dependencyTag = ref(""),
  dependencyPrerelease = ref(false),
  dependencyInstall = ref(false),
  dependencyStart = ref(true),
  dependencyEnable = ref(false);
const mode = ref<MigrationPushInput["mode"]>("preview"),
  selected = ref<MigrationPushTask | null>(null),
  history = ref<MigrationPushTask[]>([]),
  error = ref("");
const permitted = computed(() =>
  ["backup.export", "backup.secrets", "config.secrets", "nodes.manage"].every(
    (scope) => session.me?.scopes.includes(scope),
  ),
);
const canResume = computed(
  () =>
    selected.value &&
    ["waiting_confirmation", "recovery_required"].includes(
      selected.value.state,
    ),
);
watch(automation, (value) => {
  if (value) {
    certificates.value = true;
    credentials.value = true;
  }
});
watch([certificates, credentials], ([a, b]) => {
  if (!a || !b) automation.value = false;
});
const modes = [
  { label: "仅预检", value: "preview" },
  { label: "迁入为草稿", value: "draft" },
  { label: "迁入并保存期望配置", value: "save" },
  { label: "迁入并应用 Nginx", value: "apply" },
];
const labels: Record<string, string> = {
  connecting: "连接目标",
  preparing: "传输与预检",
  dependencies: "准备目标依赖",
  dependencies_failed: "目标依赖准备失败",
  dependency_recovery: "目标依赖需要恢复",
  executing: "提交目标执行",
  observing: "核对目标结果",
  preview: "预检完成",
  draft: "目标草稿已保存",
  saved: "目标配置已保存",
  succeeded: "目标已确认应用",
  rolled_back: "目标已确认补偿",
  failed: "失败",
  preflight_blocked: "预检待处理",
  target_blocked: "目标拒绝当前步骤",
  target_permissions: "需要目标授权",
  target_recovery: "目标待恢复",
  target_missing: "目标记录缺失",
  identity_mismatch: "目标身份待核对",
  grant_expired: "本次授权已过期",
  request_budget: "需要重新授权",
  target_changed: "目标状态已变化",
  unknown_stage: "阶段待恢复",
  invalid_binding: "目标绑定待恢复",
};
const stepStates: Record<string, string> = {
  ready: "就绪",
  blocked: "冲突",
  unavailable: "缺少依赖",
  authorization: "需要授权",
  review: "待核对",
};
const stateLabels: Record<string, string> = {
  queued: "已排队",
  running: "执行中",
  waiting_confirmation: "待处理",
  recovery_required: "待恢复",
  succeeded: "已完成",
  failed: "失败",
  rolled_back: "已补偿",
};
const date = (value: number) => new Date(value * 1000).toLocaleString();
const reading = ref(false);
let controller: AbortController | null = null,
  closed = false;
async function load() {
  if (reading.value || closed || busy.value || !permitted.value || document.hidden)
    return;
  reading.value = true;
  controller = new AbortController();
  try {
    history.value = await api.migrationPushes(controller.signal);
    if (selected.value)
      selected.value = await api.migrationPush(
        selected.value.id,
        controller.signal,
      );
    error.value = "";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    reading.value = false;
  }
}
async function inspect(id: string) {
  await run(async () => {
    selected.value = await api.migrationPush(id);
    resumeKey.value = "";
  });
}
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
async function submit() {
  await run(async () => {
    if (!firewallValid.value) throw new Error("请修正防火墙网卡映射");
    const input: MigrationPushInput = {
      remote: {
        url: url.value.trim(),
        api_key: key.value,
        node_id: node.value.trim(),
        selection: {
          certificates: certificates.value,
          dns_credentials: credentials.value,
          automation: automation.value,
          notifications: notifications.value,
          firewall: includeFirewall.value,
          fail2ban: includeFail2ban.value,
          monitoring: includeMonitoring.value,
          host_dns: includeHostDNS.value,
        },
      },
      mappings: mappingObject(),
      fail2ban: { ...fail2banSettings.value },
      monitoring: { ...monitoringSettings.value },
      host_dns: hostDNSOptions(),
      firewall: {
        ...firewallSettings.value,
        interfaces: { ...firewallSettings.value.interfaces },
      },
      mode: mode.value,
      enable_nginx: enableNginx.value,
      ...(prepareDependencies.value && mode.value !== "preview"
        ? {
            dependencies: {
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
            },
          }
        : {}),
    };
    selected.value = await api.startMigrationPush(input, keyFor(input));
    keyFor = useIdempotency();
    key.value = "";
  }, "迁出任务已受理");
  await load();
}
async function resume() {
  const id = selected.value?.id;
  if (!id) return;
  await run(async () => {
    const input = { api_key: resumeKey.value };
    selected.value = await api.resumeMigrationPush(
      id,
      input,
      keyFor({ id, ...input }),
    );
    keyFor = useIdempotency();
    resumeKey.value = "";
  }, "原迁出任务已恢复");
  await load();
}
onMounted(() => {
  void load();
});
onUnmounted(() => {
  closed = true;
  controller?.abort();
});
useLiveRefresh(api, ["tasks"], load, () => reading.value || busy.value);
</script>
<template>
  <div class="stack">
    <NAlert v-if="!permitted" type="warning">
      需要配置秘密导出与节点管理权限。
    </NAlert>
    <template v-else>
      <NAlert v-if="error" type="error">
        {{ error }}
      </NAlert>
      <section class="panel stack">
        <h2>迁移到其他服务器</h2>
        <div class="form-grid">
          <NFormItem label="服务器地址">
            <NInput
              v-model:value="url"
              placeholder="https://target.example.com:9443/api/v1"
            />
          </NFormItem>
          <NFormItem label="目标 API Key">
            <NInput
              v-model:value="key"
              type="password"
              show-password-on="click"
              autocomplete="off"
            />
          </NFormItem>
        </div>
        <NFormItem label="导出范围">
          <div class="choice-grid">
            <NCheckbox v-model:checked="certificates">
              证书与私钥
            </NCheckbox><NCheckbox v-model:checked="credentials">
              DNS 凭据
            </NCheckbox><NCheckbox v-model:checked="automation">
              ACME 配置
            </NCheckbox><NCheckbox v-model:checked="notifications">
              通知渠道
            </NCheckbox><NCheckbox v-model:checked="includeHostDNS">
              主机 DNS 已保存配置
            </NCheckbox><NCheckbox v-model:checked="includeMonitoring">
              监控配置
            </NCheckbox><NCheckbox v-model:checked="includeFail2ban">
              jail 期望配置
            </NCheckbox><NCheckbox v-model:checked="includeFirewall">
              防火墙期望规则
            </NCheckbox>
          </div>
        </NFormItem>
        <section>
          <h3>迁移设置</h3>
          <div class="page-stack">
            <NFormItem
              label="目标参数映射"
              :validation-status="mappingError ? 'error' : undefined"
              :feedback="mappingError"
            >
              <MappingInput
                v-model:value="mappings"
                :max="128"
                :disabled="busy"
              />
            </NFormItem>
            <p class="muted">
              保留目标服务器的网络设置。DNS
              可在迁移完成后，到目标服务器的网络设置中调整。
            </p>
            <MigrationMonitoringOptions
              v-model="monitoringSettings"
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
          </div>
        </section>
        <NFormItem label="执行方式">
          <NSelect v-model:value="mode" :options="modes" />
        </NFormItem>
        <NCheckbox v-model:checked="enableNginx">
          授权启用目标 Nginx 配置模块
        </NCheckbox>
        <div v-if="mode !== 'preview'" class="page-stack">
          <NCheckbox v-model:checked="prepareDependencies">
            授权目标准备 Nginx 可信组件
          </NCheckbox>
          <div v-if="prepareDependencies" class="page-stack">
            <NFormItem label="目标 Nginx 组件发行标签（可选）">
              <NInput
                v-model:value="dependencyTag"
                placeholder="留空使用稳定版"
              />
            </NFormItem>
            <NCheckbox v-model:checked="dependencyPrerelease">
              允许指定的预发布版本
            </NCheckbox>
            <div>
              <NCheckbox v-model:checked="dependencyInstall">
                授权目标缺失时安装 Nginx
              </NCheckbox>
              <template v-if="dependencyInstall">
                <NCheckbox v-model:checked="dependencyStart">
                  安装后启动
                </NCheckbox>
                <NCheckbox v-model:checked="dependencyEnable">
                  开机自动启动
                </NCheckbox>
                <p>
                  目标 Key
                  须具备系统写入权限。安装期间暂停目标配置写入，完成后恢复并重新预检。
                </p>
              </template>
            </div>
            <p>目标服务器的访问密钥需要具备安装软件的权限。</p>
          </div>
        </div>
        <p class="section-note">
          迁移期间原服务器继续运行。目标保留管理员账户和网络设置；迁入的自动任务和通知默认停用。
        </p>
        <div class="form-actions">
          <NPopconfirm @positive-click="submit">
            <template #trigger>
              <NButton
                type="primary"
                :disabled="
                  busy ||
                    !url ||
                    !key ||
                    !firewallValid ||
                    !!mappingError
                "
              >
                创建迁出任务
              </NButton>
            </template>{{
              mode === "preview"
                ? "确认将加密配置包发送到目标进行预检？"
                : "确认按所选方式迁入目标？保存或应用会替换目标 Nginx 业务配置。"
            }}
          </NPopconfirm>
        </div>
      </section>
      <section v-if="selected" class="panel stack">
        <div class="toolbar">
          <h2>迁出进度</h2>
          <NTag
            :type="
              selected.state === 'succeeded'
                ? 'success'
                : selected.state === 'failed'
                  ? 'error'
                  : 'warning'
            "
          >
            {{ stateLabels[selected.state] || selected.state }}
          </NTag><NButton :disabled="busy || reading" @click="load">
            刷新
          </NButton>
        </div>
        <dl class="detail-list">
          <dt>阶段</dt>
          <dd>{{ labels[selected.stage] || selected.stage }}</dd>
          <dt>目标</dt>
          <dd>{{ selected.target_url }}</dd>

          <dt>授权截止</dt>
          <dd>{{ date(selected.expires_at) }}</dd>
        </dl>
        <NAlert v-if="selected.error" type="warning">
          {{
            selected.error
          }}
        </NAlert>
        <template v-if="selected.plan">
          <MigrationHostDNSPreview
            v-if="selected.plan.host_dns"
            :info="selected.plan.host_dns"
          />
          <MigrationMonitoringPreview
            v-if="selected.plan.monitoring"
            :info="selected.plan.monitoring"
          />
          <MigrationFail2banPreview
            v-if="selected.plan.fail2ban"
            :info="selected.plan.fail2ban"
          />
          <MigrationFirewallPreview
            v-if="selected.plan.firewall"
            :info="selected.plan.firewall"
          />
          <MigrationDependencies
            v-if="selected.plan.dependencies"
            :status="selected.plan.dependencies"
          />
          <TaskLogButton
            v-if="selected.plan.task_id"
            :task-id="selected.plan.task_id"
          />
          <NAlert v-if="selected.plan.pruned_at" type="info">
            迁移文件已清理，当前保留迁移记录和执行结果。
          </NAlert>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>状态</th>
                  <th>结果</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(step, index) in selected.plan.steps" :key="index">
                  <td>{{ stepStates[step.state] || step.state }}</td>
                  <td>{{ step.message }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p
            v-for="(item, index) in selected.plan.omissions"
            :key="index"
            class="muted"
          >
            {{ item }}
          </p>
        </template>
        <template v-if="canResume">
          <NFormItem label="重新授权目标 Key">
            <NInput
              v-model:value="resumeKey"
              type="password"
              show-password-on="click"
              autocomplete="off"
            />
          </NFormItem><NPopconfirm @positive-click="resume">
            <template #trigger>
              <NButton :disabled="busy || !resumeKey">
                核对并继续原任务
              </NButton>
            </template>确认使用原配置包、原目标和原执行方式继续？目标缺失原计划时将保留待恢复状态。
          </NPopconfirm>
        </template>
      </section>
      <section class="panel stack">
        <h2>迁出记录</h2>
        <p v-if="history.length === 0" class="muted">
          暂无迁出记录
        </p>
        <div v-for="item in history" :key="item.id" class="record-card">
          <NButton text @click="inspect(item.id)">
            {{ date(item.created_at) }} · {{ item.target_url }}
          </NButton><NTag>
            {{
              labels[item.stage] || stateLabels[item.state] || item.state
            }}
          </NTag>
        </div>
      </section>
    </template>
  </div>
</template>
