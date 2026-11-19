<script setup lang="ts">
import SettingsSection from "./SettingsSection.vue";
import FormDialog from "./FormDialog.vue";
import { computed, onMounted, onScopeDispose, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
  NDropdown,
  NEmpty,
  NFormItem,
  NInput,
  NInputNumber,
  NSelect,
  NSwitch,
  NTag,
} from "naive-ui";
import {
  type Fail2banContainerStatus,
  type Fail2banContainerRule,
  type Fail2banContainerConfig,
} from "../api/client";
import { selectedTarget } from "../api/context";
import { useSoftwareOperations } from "../composables/software";
import { randomUUID } from "../utils/crypto";
import ValueListInput from "./ValueListInput.vue";
import TaskLogButton from "./TaskLogButton.vue";
import { operationVisible } from "../stores/operation";
import ServiceLogsDialog from "./ServiceLogsDialog.vue";
import { useSession } from "../stores/session";
import { fail2banRuntime, softwareStatus } from "../utils/software";
type RuleKind = Fail2banContainerRule["kind"];
type RuleDraft = Omit<Fail2banContainerRule, "ports" | "max_retry" | "find_time" | "ban_time"> & {
  ports: (number | null)[];
  max_retry: number | null;
  find_time: number | null;
  ban_time: number | null;
};
const templates = {
  ssh: {
    label: "SSH 登录",
    ports: [22],
    max_retry: 5,
    find_time: 600,
    ban_time: 3600,
    hint: "建议确认 SSH 实际监听端口。",
  },
  panel: {
    label: "面板登录",
    ports: [],
    max_retry: 5,
    find_time: 300,
    ban_time: 900,
    hint: "填写目标服务器的面板监听端口。",
  },
  nginx: {
    label: "网站 HTTP 401",
    ports: [80, 443],
    max_retry: 12,
    find_time: 600,
    ban_time: 600,
    hint: "统计访问日志中的 HTTP 401，包括首次认证请求。启用前须应用网站配置并生成访问日志。",
  },
} satisfies Record<RuleKind, Omit<RuleDraft, "id" | "kind" | "name" | "enabled"> & {
  label: string;
  hint: string;
}>;
const options = (Object.keys(templates) as RuleKind[]).map((kind) => ({
  label: templates[kind].label,
  value: kind,
}));
const templateOptions = options.map(({ label, value }) => ({ label, key: value }));
const reading = ref(false),
  readError = ref("");
const status = ref<Fail2banContainerStatus | null>(null),
  editing = ref<RuleDraft | null>(null),
  whitelist = ref<string[] | null>(null),
  addresses = ref<string[]>([]),
  banRule = ref<string | null>(null),
  showBan = ref(false);
const { api, busy, permitted, active, last, submit, control } =
  useSoftwareOperations(load);
const session = useSession();
const showLogs = ref(false);
const logsPermitted = computed(
  () => session.me?.scopes.includes("read") === true &&
    session.me.scopes.includes("components.manage"),
);
const displayStatus = computed(() =>
  softwareStatus(
    status.value ? status.value.installed : null,
    fail2banRuntime(status.value),
  ),
);
const blocked = computed(() => busy.value || active.value);
const canEditRules = computed(() => status.value?.installed === true && permitted.value && !blocked.value);
const canAddRule = computed(() => canEditRules.value && (status.value?.config.rules.length ?? 0) < 32);
const editBase = ref<Fail2banContainerConfig | null>(null);
const editingExisting = ref(false);
const draftTaskId = ref("");
const portStatus = ref("");
const findingPorts = ref(false);
let detection: AbortController | undefined;
const changedConfig = computed(() =>
  editBase.value !== null && status.value?.config.revision !== editBase.value.revision,
);
const portError = computed(() => {
  const ports = editing.value?.ports ?? [];
  if (!ports.length || !ports.every((port) => inRange(port, 1, 65535)))
    return "请填写 1–65535 的端口。";
  if (new Set(ports).size !== ports.length) return "保护端口不能重复。";
  return "";
});
const validRule = computed<Fail2banContainerRule | null>(() => {
  const rule = editing.value;
  if (!rule || !rule.name.trim() || portError.value) return null;
  const { ports, max_retry, find_time, ban_time } = rule;
  if (
    !ports.every((port) => inRange(port, 1, 65535)) ||
    !inRange(max_retry, 1, 1000) ||
    !inRange(find_time, 10, 604800) ||
    !inRange(ban_time, 10, 31536000)
  ) return null;
  return { ...rule, name: rule.name.trim(), ports, max_retry, find_time, ban_time };
});

function formatDuration(seconds: number) {
  if (seconds % 3600 === 0) return (seconds / 3600) + " 小时";
  if (seconds % 60 === 0) return (seconds / 60) + " 分钟";
  return seconds + " 秒";
}
function inRange(value: number | null, min: number, max: number): value is number {
  return value !== null && Number.isInteger(value) && value >= min && value <= max;
}
function stopDetection() {
  detection?.abort();
  detection = undefined;
  findingPorts.value = false;
}
onScopeDispose(stopDetection);

async function setAutoStart(autoStart: boolean) {
  if (!status.value?.installed || blocked.value || !permitted.value) return;
  await control({
    action: "fail2ban",
    fail2ban: {
      action: "auto-start",
      auto_start: autoStart,
      revision: status.value.config.revision,
    },
  });
}
const ruleOptions = computed(() =>
  (status.value?.config.rules ?? [])
    .filter((r) => r.enabled)
    .map((r) => ({ label: r.name, value: r.id })),
);
const totalBanned = computed(() =>
  (status.value?.jails ?? []).reduce((n, j) => n + j.current_banned, 0),
);
const banned = computed(() =>
  (status.value?.jails ?? []).flatMap((j) =>
    j.banned.map((address) => ({
      jail: j.id,
      address,
      name:
        status.value?.config.rules.find((r) => r.id === j.id)?.name ||
        "防护规则",
    })),
  ),
);
const banMode = ref<"ban" | "unban">("ban");
async function load() {
  if (reading.value) return;
  reading.value = true;
  try {
    status.value = await api.fail2banContainer();
    readError.value = "";
  } catch (error) {
    readError.value =
      error instanceof Error ? error.message : "无法读取防护状态";
  } finally {
    reading.value = false;
  }
}
function copyConfig(): Fail2banContainerConfig | null {
  const c = status.value?.config;
  return c
    ? {
        ...c,
        whitelist: [...c.whitelist],
        rules: c.rules.map((r) => ({ ...r, ports: [...r.ports] })),
      }
    : null;
}
function closeRule() {
  stopDetection();
  editing.value = null;
  draftTaskId.value = "";
  portStatus.value = "";
}
function editWhitelist() {
  if (!canEditRules.value) return;
  closeRule();
  editBase.value = copyConfig();
  whitelist.value = [...(editBase.value?.whitelist ?? [])];
}
function start(kind?: RuleKind, source?: Fail2banContainerRule) {
  if (source ? !canEditRules.value : !canAddRule.value) return;
  stopDetection();
  portStatus.value = "";
  draftTaskId.value = "";
  editBase.value = copyConfig();
  editingExisting.value = !!source;
  if (source) {
    editing.value = { ...source, ports: [...source.ports] };
    return;
  }
  const template = templates[kind ?? "ssh"];
  editing.value = {
    id: randomUUID(),
    name: kind ? template.label : "",
    kind: kind ?? "ssh",
    ports: kind ? [...template.ports] : [],
    enabled: true,
    max_retry: template.max_retry,
    find_time: template.find_time,
    ban_time: template.ban_time,
  };
  if (kind && kind !== "nginx" && !selectedTarget.value) void detectPorts();
}
function changeKind(kind: RuleKind) {
  const rule = editing.value;
  if (!rule || rule.kind === kind) return;
  stopDetection();
  portStatus.value = "";
  rule.kind = kind;
}
async function detectPorts() {
  const rule = editing.value;
  if (!rule || rule.kind === "nginx" || selectedTarget.value || findingPorts.value) return;
  const kind = rule.kind, id = rule.id, previous = [...rule.ports];
  const controller = new AbortController();
  detection = controller;
  findingPorts.value = true;
  portStatus.value = "";
  try {
    const { shortcuts } = await api.firewallRuntime(controller.signal);
    const current = editing.value;
    if (controller.signal.aborted || current?.id !== id || current.kind !== kind) return;
    const detected = kind === "ssh" ? shortcuts.ssh : shortcuts.management;
    if (!detected.length) {
      portStatus.value = "未检测到监听端口，请手动填写。";
    } else if (
      current.ports.length === previous.length &&
      current.ports.every((port, index) => port === previous[index])
    ) {
      current.ports = detected.slice(0, 15);
    }
  } catch {
    if (!controller.signal.aborted) portStatus.value = "端口检测暂不可用，请手动填写。";
  } finally {
    if (detection === controller) stopDetection();
  }
}
async function save(config: Fail2banContainerConfig, title = "更新登录防护配置") {
  return await submit(
    { action: "fail2ban", fail2ban: { action: "configure", config } },
    title,
  );
}
async function saveWhitelist() {
  if (!editBase.value || !whitelist.value || changedConfig.value) return;
  const config = { ...editBase.value, whitelist: whitelist.value.map((address) => address.trim()).filter(Boolean) };
  if (await save(config, "更新信任名单")) whitelist.value = null;
}
async function saveRule() {
  const rule = validRule.value, config = editBase.value;
  if (!rule || !config || changedConfig.value || !canEditRules.value) return;
  const rules = config.rules.some(({ id }) => rule.id === id)
    ? config.rules.map((current) => current.id === rule.id ? rule : current)
    : [...config.rules, rule];
  stopDetection();
  const task = await save({ ...config, rules }, editingExisting.value ? "更新防护规则" : "添加防护规则");
  if (task) draftTaskId.value = task.id;
}
watch([last, draftTaskId], ([task, id]) => {
  if (id && task?.id === id && task.state === "succeeded") closeRule();
});
async function removeRule(rule: Fail2banContainerRule) {
  const c = status.value?.config;
  if (!canEditRules.value || !c || !window.confirm(`删除“${rule.name}”？该规则的封禁将解除。`)) return;
  await save({ ...c, rules: c.rules.filter((r) => r.id !== rule.id) });
}
async function toggle(rule: Fail2banContainerRule) {
  const c = status.value?.config;
  if (!canEditRules.value || !c) return;
  await save({
    ...c,
    rules: c.rules.map((r) =>
      r.id === rule.id ? { ...r, enabled: !r.enabled } : r,
    ),
  });
}
async function unban(jail: string, address: string) {
  if (!window.confirm(`解除 ${address} 的封禁？`)) return;
  await control({
    action: "fail2ban",
    fail2ban: { action: "unban", jail_id: jail, address },
  });
}
async function ban() {
  if (!banRule.value) return;
  const values = addresses.value.map((a) => a.trim()).filter(Boolean);
  if (values.length !== 1) return;
  if (
    banMode.value === "ban" &&
    !window.confirm(`封禁 ${values[0]}？该地址将无法访问所选规则的保护端口。`)
  )
    return;
  if (
    await control({
      action: "fail2ban",
      fail2ban: {
        action: banMode.value,
        jail_id: banRule.value,
        address: values[0],
      },
    })
  ) {
    showBan.value = false;
    addresses.value = [];
  }
}
onMounted(load);
</script>
<template>
  <div class="page-stack">
    <section class="panel page-stack">
      <div class="section-heading">
        <h3>防护概况</h3>
        <div class="button-row">
          <NTag :type="displayStatus.tone">
            {{ displayStatus.label }}
          </NTag><NButton :disabled="blocked" @click="load">
            刷新
          </NButton><RouterLink
            :to="{ path: '/components', query: { software: 'fail2ban' } }"
          >
            <NButton>软件管理</NButton>
          </RouterLink>
          <NButton v-if="status?.installed && logsPermitted" @click="showLogs = true">
            服务日志
          </NButton>
        </div>
      </div>
      <NAlert v-if="status?.error" type="warning">
        {{ status.error }}
      </NAlert>
      <div v-if="status?.installed" class="button-row">
        <NSwitch
          :value="status.config.auto_start"
          :disabled="blocked || !permitted"
          aria-label="开机自动启动"
          @update:value="setAutoStart"
        />
        <span>开机自动启动</span>
      </div>
      <div class="defense-stats">
        <div>
          <span>已启用规则</span><strong>{{
            status?.config.rules.filter((r) => r.enabled).length ?? 0
          }}</strong>
        </div>
        <div>
          <span>当前封禁</span><strong>{{ totalBanned }}</strong>
        </div>
      </div>
    </section>
    <NAlert v-if="readError" type="error">
      {{ readError }}
    </NAlert><NAlert v-if="last?.error" type="error">
      {{ last.error }}
    </NAlert>
    <div v-if="last && last.state !== 'succeeded'" class="button-row">
      <TaskLogButton :task-id="last.id" />
    </div>
    <section class="panel page-stack">
      <div class="section-heading">
        <h3>防护规则</h3>
        <div class="button-row">
          <NDropdown :options="templateOptions" :disabled="!canAddRule" @select="start($event as RuleKind)">
            <NButton :disabled="!canAddRule">
              快速添加
            </NButton>
          </NDropdown>
          <NButton type="primary" :disabled="!canAddRule" @click="start()">
            添加规则
          </NButton>
        </div>
      </div>
      <NEmpty v-if="status && !status.installed" description="安装 Fail2ban 后可添加防护规则" />
      <NEmpty v-else-if="status && !status.config.rules.length" description="暂无防护规则" />
      <p v-if="status?.config.rules.length === 32" class="muted">
        已达到 32 条规则上限
      </p>
      <article
        v-for="rule in status?.config.rules"
        :key="rule.id"
        class="rule-card"
      >
        <div>
          <div class="record-heading">
            <strong>{{ rule.name }}</strong><NTag :type="rule.enabled ? 'success' : 'default'" size="small">
              {{ rule.enabled ? "已启用" : "已停用" }}
            </NTag>
          </div>
          <p class="muted">
            {{ options.find((o) => o.value === rule.kind)?.label }} · 端口
            {{ rule.ports.join("、") }} ·
            {{ formatDuration(rule.find_time) }}内失败
            {{ rule.max_retry }} 次，封禁
            {{ formatDuration(rule.ban_time) }}
          </p>
          <p
            v-if="status?.jails.find((j) => j.id === rule.id)?.error"
            class="error-text"
          >
            {{ status.jails.find((j) => j.id === rule.id)?.error }}
          </p>
        </div>
        <div class="button-row">
          <NButton
            size="small"
            :disabled="!canEditRules"
            @click="start(rule.kind, rule)"
          >
            编辑
          </NButton><NButton
            size="small"
            :disabled="!canEditRules"
            @click="toggle(rule)"
          >
            {{ rule.enabled ? "停用" : "启用" }}
          </NButton><NButton
            size="small"
            :disabled="!canEditRules"
            @click="removeRule(rule)"
          >
            删除
          </NButton>
        </div>
      </article>
    </section>
    <section class="panel page-stack">
      <div class="section-heading">
        <div>
          <h3>信任名单</h3>
          <p class="muted">
            名单中的地址不会因登录失败被自动封禁。
          </p>
        </div>
        <NButton :disabled="!canEditRules" @click="editWhitelist()">
          编辑名单
        </NButton>
      </div>
      <div class="button-row">
        <NTag v-for="ip in status?.config.whitelist" :key="ip">
          {{ ip }}
        </NTag><span v-if="!status?.config.whitelist.length" class="muted">尚未添加地址</span>
      </div>
    </section>
    <section class="panel page-stack">
      <div class="section-heading">
        <h3>封禁名单</h3>
        <NButton
          :disabled="
            !permitted || blocked || !status?.ready || !ruleOptions.length
          "
          @click="
            banMode = 'ban';
            showBan = true;
            banRule = ruleOptions[0]?.value ?? null;
          "
        >
          添加封禁
        </NButton><NButton
          :disabled="
            !permitted || blocked || !status?.ready || !ruleOptions.length
          "
          @click="
            banMode = 'unban';
            showBan = true;
            banRule = ruleOptions[0]?.value ?? null;
          "
        >
          解除指定地址
        </NButton>
      </div>
      <NAlert v-if="totalBanned > banned.length" type="info">
        封禁数量较多，当前显示前 128 个地址。
      </NAlert><NEmpty v-if="!banned.length" description="当前没有封禁地址" />
      <article
        v-for="item in banned"
        :key="item.jail + item.address"
        class="ban-row"
      >
        <div>
          <strong>{{ item.address }}</strong><span class="muted">{{ item.name }}</span>
        </div>
        <NButton
          size="small"
          :disabled="!permitted || blocked"
          @click="unban(item.jail, item.address)"
        >
          解除封禁
        </NButton>
      </article>
    </section>
  </div>
  <ServiceLogsDialog v-model:show="showLogs" app="fail2ban" name="Fail2ban" />
  <FormDialog
    :show="!!editing && (!draftTaskId || (!blocked && !operationVisible))"
    :title="editingExisting ? '编辑防护规则' : '添加防护规则'"
    :busy="busy"
    :draft="editing"
    :dirty="!!draftTaskId && !!editing ? true : undefined"
    :submit-disabled="!canEditRules || changedConfig || !validRule"
    @submit="saveRule"
    @cancel="closeRule"
  >
    <div v-if="editing" class="settings-stack">
      <NAlert v-if="changedConfig" type="warning">
        配置已更新，请重新打开规则编辑。
      </NAlert>
      <NAlert v-else-if="draftTaskId && last?.id === draftTaskId && last.error" type="error">
        {{ last.error }}
      </NAlert>
      <SettingsSection title="保护对象">
        <div class="settings-fields">
          <NFormItem label="规则名称" :show-feedback="false">
            <NInput
              v-model:value="editing.name"
              maxlength="40"
              placeholder="例如 SSH 登录保护"
            />
          </NFormItem>
          <NFormItem label="保护入口" :show-feedback="false">
            <NSelect :value="editing.kind" :options="options" @update:value="changeKind" />
          </NFormItem>
          <NFormItem class="full-width" label="保护端口" :feedback="portStatus || portError">
            <div class="port-list">
              <div
                v-for="(port, index) in editing.ports"
                :key="index"
                class="port-row"
              >
                <NInputNumber
                  :value="port"
                  :min="1"
                  :max="65535"
                  :precision="0"
                  :show-button="false"
                  placeholder="端口"
                  @update:value="editing.ports[index] = $event"
                /><NButton @click="editing.ports.splice(index, 1)">
                  移除
                </NButton>
              </div>
              <div class="button-row">
                <NButton dashed :disabled="editing.ports.length >= 15" @click="editing.ports.push(null)">
                  添加端口
                </NButton>
                <NButton
                  v-if="editing.kind !== 'nginx' && !selectedTarget"
                  :loading="findingPorts"
                  @click="detectPorts"
                >
                  检测端口
                </NButton>
              </div>
            </div>
          </NFormItem>
        </div>
        <p class="section-note">
          {{ templates[editing.kind].hint }}
        </p>
      </SettingsSection>
      <SettingsSection
        title="封禁条件"
        description="同一来源在统计时间内达到失败次数后，按设置时长封禁。"
      >
        <div class="settings-fields">
          <NFormItem label="失败次数" :show-feedback="false">
            <NInputNumber
              v-model:value="editing.max_retry"
              :min="1"
              :max="1000"
              :precision="0"
            />
          </NFormItem><NFormItem label="统计时间（秒）" :show-feedback="false">
            <NInputNumber
              v-model:value="editing.find_time"
              :min="10"
              :max="604800"
              :precision="0"
            />
          </NFormItem><NFormItem label="封禁时间（秒）" :show-feedback="false">
            <NInputNumber
              v-model:value="editing.ban_time"
              :min="10"
              :max="31536000"
              :precision="0"
            />
          </NFormItem><NFormItem label="规则状态" :show-feedback="false">
            <NCheckbox v-model:checked="editing.enabled">
              启用规则
            </NCheckbox>
          </NFormItem>
        </div>
      </SettingsSection>
    </div>
  </FormDialog>
  <FormDialog
    :show="whitelist !== null"
    title="编辑信任名单"
    :busy="busy"
    :draft="whitelist"
    :submit-disabled="!canEditRules || !editBase || changedConfig"
    @submit="saveWhitelist"
    @cancel="whitelist = null"
  >
    <div v-if="whitelist" class="page-stack">
      <NAlert v-if="changedConfig" type="warning">
        配置已更新，请重新打开名单编辑。
      </NAlert>
      <ValueListInput
        v-model:value="whitelist"
        item-label="地址"
        placeholder="例如 192.168.1.10 或 192.168.1.0/24"
        :max="128"
        :maxlength="64"
        :disabled="busy"
      />
    </div>
  </FormDialog>
  <FormDialog
    :show="showBan"
    :submit-text="banMode === 'ban' ? '确认封禁' : '解除封禁'"
    :title="banMode === 'ban' ? '添加封禁' : '解除封禁'"
    :busy="busy"
    :draft="[banRule, addresses]"
    :submit-disabled="
      !permitted || blocked || !banRule || !addresses[0]?.trim()
    "
    @submit="ban"
    @cancel="showBan = false"
  >
    <div class="page-stack">
      <NFormItem label="防护规则">
        <NSelect v-model:value="banRule" :options="ruleOptions" />
      </NFormItem><NFormItem label="IP 地址">
        <NInput
          :value="addresses[0] ?? ''"
          placeholder="输入需要封禁的 IP 地址"
          @update:value="addresses = [$event]"
        />
      </NFormItem>
    </div>
  </FormDialog>
</template>
<style scoped>
.defense-stats {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
.defense-stats > div {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 18px;
  background: var(--surface-soft);
  border-radius: 12px;
}
.defense-stats span {
  color: var(--text-muted);
}
.defense-stats strong {
  font-size: 24px;
}
.rule-card,
.ban-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  border-top: 1px solid var(--border-color);
  padding-top: 18px;
}
.rule-card p {
  margin: 10px 0 0;
}
.ban-row > div {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.port-list {
  display: grid;
  gap: 12px;
  width: 100%;
}
.port-row {
  display: flex;
  gap: 10px;
}
.port-row .n-input-number {
  flex: 1;
}
.section-heading p {
  margin: 8px 0 0;
}
@media (max-width: 700px) {
  .rule-card {
    align-items: flex-start;
    flex-direction: column;
  }
  .defense-stats {
    gap: 8px;
  }
  .defense-stats > div {
    padding: 12px;
  }
  .defense-stats strong {
    font-size: 20px;
  }
}
</style>
