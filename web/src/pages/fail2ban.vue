<route lang="json">
{
  "meta": {
    "title": "登录防护",
    "subtitle": "自动封禁多次认证失败的 IP",
    "nav": true,
    "order": 6,
    "symbol": "◈",
    "group": "网站与安全",
    "software": "fail2ban"
  }
}
</route>
<script setup lang="ts">
import FormDialog from "../components/FormDialog.vue";
import { computed, onMounted, ref } from "vue";
import { RouterLink } from "vue-router";
import {
  NAlert,
  NButton,
  NCheckbox,
  NEmpty,
  NFormItem,
  NInput,
  NInputNumber,
  NSelect,
  NTag,
} from "naive-ui";
import {
  type Fail2banContainerStatus,
  type Fail2banContainerRule,
  type Fail2banContainerConfig,
} from "../api/client";
import { useSoftwareOperations } from "../composables/software";
import { useLiveRefresh } from "../composables/live";
import { randomUUID } from "../utils/crypto";
import ValueListInput from "../components/ValueListInput.vue";
import TaskLogButton from "../components/TaskLogButton.vue";
import { fail2banRuntime, softwareStatus } from "../utils/software";
const reading = ref(false),
  readError = ref("");
const status = ref<Fail2banContainerStatus | null>(null),
  editing = ref<Fail2banContainerRule | null>(null),
  whitelist = ref<string[] | null>(null),
  addresses = ref<string[]>([]),
  banRule = ref<string | null>(null),
  showBan = ref(false);
const { api, run, busy, permitted, active, last, submit } =
  useSoftwareOperations(load);
const displayStatus = computed(() =>
  softwareStatus(
    status.value ? status.value.installed : null,
    fail2banRuntime(status.value),
  ),
);
const blocked = computed(() => busy.value || active.value);
const options = [
  { label: "SSH 登录", value: "ssh" },
  { label: "面板登录", value: "panel" },
  { label: "网站认证", value: "nginx" },
];
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
const editBase = ref<Fail2banContainerConfig | null>(null),
  banMode = ref<"ban" | "unban">("ban");
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
function editWhitelist() {
  editBase.value = copyConfig();
  whitelist.value = [...(editBase.value?.whitelist ?? [])];
}
function start(
  kind: Fail2banContainerRule["kind"] = "ssh",
  source?: Fail2banContainerRule,
) {
  editBase.value = copyConfig();
  editing.value = source
    ? { ...source, ports: [...source.ports] }
    : {
        id: randomUUID(),
        name:
          kind === "ssh"
            ? "SSH 登录"
            : kind === "panel"
              ? "面板登录"
              : "网站认证",
        kind,
        enabled: true,
        ports: kind === "ssh" ? [22] : kind === "panel" ? [] : [80, 443],
        max_retry: 5,
        find_time: 600,
        ban_time: 3600,
      };
  if (!source && (kind === "panel" || kind === "ssh"))
    void run(async () => {
      const runtime = await api.firewallRuntime();
      if (editing.value?.kind === kind)
        editing.value.ports =
          kind === "panel"
            ? runtime.shortcuts.management
            : runtime.shortcuts.ssh;
    });
}
async function save(config: Fail2banContainerConfig) {
  if (
    await submit(
      { action: "fail2ban", fail2ban: { action: "configure", config } },
      "防护规则操作日志",
    )
  ) {
    editing.value = null;
    whitelist.value = null;
  }
}
async function saveRule() {
  const rule = editing.value,
    c = editBase.value;
  if (!rule || !c) return;
  await save({
    ...c,
    rules: [
      ...c.rules.filter((r) => r.id !== rule.id),
      { ...rule, name: rule.name.trim() },
    ],
  });
}
async function removeRule(rule: Fail2banContainerRule) {
  const c = status.value?.config;
  if (!c || !window.confirm(`删除“${rule.name}”？该规则的封禁将解除。`)) return;
  await save({ ...c, rules: c.rules.filter((r) => r.id !== rule.id) });
}
async function toggle(rule: Fail2banContainerRule) {
  const c = status.value?.config;
  if (!c) return;
  await save({
    ...c,
    rules: c.rules.map((r) =>
      r.id === rule.id ? { ...r, enabled: !r.enabled } : r,
    ),
  });
}
async function unban(jail: string, address: string) {
  if (!window.confirm(`解除 ${address} 的封禁？`)) return;
  await submit(
    {
      action: "fail2ban",
      fail2ban: { action: "unban", jail_id: jail, address },
    },
    "解除封禁日志",
  );
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
    await submit(
      {
        action: "fail2ban",
        fail2ban: {
          action: banMode.value,
          jail_id: banRule.value,
          address: values[0],
        },
      },
      banMode.value === "ban" ? "封禁操作日志" : "解除封禁日志",
    )
  ) {
    showBan.value = false;
    addresses.value = [];
  }
}
useLiveRefresh(api, ["fail2ban"], load, () => reading.value);
onMounted(load);
</script>
<template>
  <div class="page-stack">
    <section class="panel page-stack">
      <div class="section-heading">
        <div>
          <h3>防护概况</h3>
          <p class="muted">
            为登录入口添加规则，超过失败次数后自动封禁来源 IP。
          </p>
        </div>
        <div class="button-row">
          <NTag :type="displayStatus.tone">{{ displayStatus.label }}</NTag
          ><NButton :disabled="blocked" @click="load">刷新</NButton
          ><RouterLink
            :to="{ path: '/components', query: { software: 'fail2ban' } }"
            ><NButton>软件管理</NButton></RouterLink
          >
        </div>
      </div>
      <NAlert v-if="status?.error" type="warning">{{ status.error }}</NAlert>
      <div class="defense-stats">
        <div>
          <span>已启用规则</span
          ><strong>{{
            status?.config.rules.filter((r) => r.enabled).length ?? 0
          }}</strong>
        </div>
        <div>
          <span>当前封禁</span><strong>{{ totalBanned }}</strong>
        </div>
        <div>
          <span>自动启动</span
          ><strong>{{
            status?.config.auto_start ? "已开启" : "已关闭"
          }}</strong>
        </div>
      </div>
    </section>
    <NAlert v-if="readError" type="error">{{ readError }}</NAlert
    ><NAlert v-if="last?.error" type="error">{{ last.error }}</NAlert>
    <div v-if="last" class="button-row">
      <span>{{
        last.state === "succeeded"
          ? "操作已完成"
          : last.state === "failed"
            ? "操作未完成"
            : "正在处理"
      }}</span
      ><TaskLogButton :task-id="last.id" />
    </div>
    <section class="panel page-stack">
      <div class="section-heading">
        <h3>防护规则</h3>
        <NButton
          type="primary"
          :disabled="!permitted || blocked"
          @click="start()"
          >添加规则</NButton
        >
      </div>
      <NEmpty
        v-if="!status?.config.rules.length"
        description="添加需要保护的登录入口"
        ><template #extra
          ><div class="button-row">
            <NButton :disabled="!permitted || blocked" @click="start('ssh')"
              >保护 SSH</NButton
            ><NButton :disabled="!permitted || blocked" @click="start('panel')"
              >保护面板</NButton
            ><NButton :disabled="!permitted || blocked" @click="start('nginx')"
              >保护网站</NButton
            >
          </div></template
        ></NEmpty
      >
      <article
        v-for="rule in status?.config.rules"
        :key="rule.id"
        class="rule-card"
      >
        <div>
          <div class="record-heading">
            <strong>{{ rule.name }}</strong
            ><NTag :type="rule.enabled ? 'success' : 'default'" size="small">{{
              rule.enabled ? "已启用" : "已停用"
            }}</NTag>
          </div>
          <p class="muted">
            {{ options.find((o) => o.value === rule.kind)?.label }} · 端口
            {{ rule.ports.join("、") }} ·
            {{ Math.round(rule.find_time / 60) }} 分钟内失败
            {{ rule.max_retry }} 次，封禁
            {{ Math.round(rule.ban_time / 60) }} 分钟
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
            :disabled="!permitted || blocked"
            @click="start(rule.kind, rule)"
            >编辑</NButton
          ><NButton
            size="small"
            :disabled="!permitted || blocked"
            @click="toggle(rule)"
            >{{ rule.enabled ? "停用" : "启用" }}</NButton
          ><NButton
            size="small"
            :disabled="!permitted || blocked"
            @click="removeRule(rule)"
            >删除</NButton
          >
        </div>
      </article>
    </section>
    <section class="panel page-stack">
      <div class="section-heading">
        <div>
          <h3>信任名单</h3>
          <p class="muted">名单中的地址不会因登录失败被自动封禁。</p>
        </div>
        <NButton :disabled="!permitted || blocked" @click="editWhitelist()"
          >编辑名单</NButton
        >
      </div>
      <div class="button-row">
        <NTag v-for="ip in status?.config.whitelist" :key="ip">{{ ip }}</NTag
        ><span v-if="!status?.config.whitelist.length" class="muted"
          >尚未添加地址</span
        >
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
          >添加封禁</NButton
        ><NButton
          :disabled="
            !permitted || blocked || !status?.ready || !ruleOptions.length
          "
          @click="
            banMode = 'unban';
            showBan = true;
            banRule = ruleOptions[0]?.value ?? null;
          "
          >解除指定地址</NButton
        >
      </div>
      <NAlert v-if="totalBanned > banned.length" type="info"
        >封禁数量较多，当前显示前 128 个地址。</NAlert
      ><NEmpty v-if="!banned.length" description="当前没有封禁地址" />
      <article
        v-for="item in banned"
        :key="item.jail + item.address"
        class="ban-row"
      >
        <div>
          <strong>{{ item.address }}</strong
          ><span class="muted">{{ item.name }}</span>
        </div>
        <NButton
          size="small"
          :disabled="!permitted || blocked"
          @click="unban(item.jail, item.address)"
          >解除封禁</NButton
        >
      </article>
    </section>
    <section class="panel page-stack">
      <h3>服务日志</h3>
      <pre v-if="status?.logs" class="service-log">{{ status.logs }}</pre>
      <NEmpty v-else description="暂无服务日志" />
    </section>
  </div>
  <FormDialog
    :show="!!editing"
    title="防护规则"
    :busy="busy"
    :draft="editing"
    :submit-disabled="
      !permitted ||
      blocked ||
      !editing ||
      !editing.name.trim() ||
      !editing.ports.length
    "
    @submit="saveRule"
    @cancel="editing = null"
    ><div v-if="editing" class="page-stack">
      <NFormItem label="规则名称"
        ><NInput v-model:value="editing.name" maxlength="40" /></NFormItem
      ><NFormItem label="保护入口"
        ><NSelect v-model:value="editing.kind" :options="options"
      /></NFormItem>
      <p v-if="editing.kind === 'nginx'" class="muted">
        保护网站登录认证，对反复返回认证失败的来源进行封禁。
      </p>
      <NFormItem label="保护端口"
        ><div class="port-list">
          <div
            v-for="(port, index) in editing.ports"
            :key="index"
            class="port-row"
          >
            <NInputNumber
              :value="port"
              @update:value="editing.ports[index] = $event ?? 0"
              :min="1"
              :max="65535"
              :precision="0"
              :show-button="false"
              :placeholder="'端口'"
            /><NButton @click="editing.ports.splice(index, 1)">移除</NButton>
          </div>
          <NButton
            dashed
            :disabled="editing.ports.length >= 15"
            @click="editing.ports.push(22)"
            >添加端口</NButton
          >
        </div></NFormItem
      >
      <div class="defense-fields">
        <NFormItem label="失败次数"
          ><NInputNumber
            v-model:value="editing.max_retry"
            :min="1"
            :max="1000"
            :precision="0" /></NFormItem
        ><NFormItem label="统计时长（秒）"
          ><NInputNumber
            v-model:value="editing.find_time"
            :min="10"
            :max="604800"
            :precision="0" /></NFormItem
        ><NFormItem label="封禁时长（秒）"
          ><NInputNumber
            v-model:value="editing.ban_time"
            :min="10"
            :max="31536000"
            :precision="0"
        /></NFormItem>
      </div>
      <NCheckbox v-model:checked="editing.enabled">启用规则</NCheckbox>
    </div></FormDialog
  >
  <FormDialog
    :show="whitelist !== null"
    title="编辑信任名单"
    :busy="busy"
    :draft="whitelist"
    :submit-disabled="!permitted || blocked || !status || !editBase"
    @submit="
      editBase &&
      whitelist &&
      save({
        ...editBase,
        whitelist: whitelist.map((a) => a.trim()).filter(Boolean),
      })
    "
    @cancel="whitelist = null"
    ><div v-if="whitelist" class="page-stack">
      <ValueListInput
        v-model:value="whitelist"
        item-label="地址"
        placeholder="例如 192.168.1.10 或 192.168.1.0/24"
        :max="128"
        :maxlength="64"
        :disabled="busy"
      /></div
  ></FormDialog>
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
    ><div class="page-stack">
      <NFormItem label="防护规则"
        ><NSelect v-model:value="banRule" :options="ruleOptions" /></NFormItem
      ><NFormItem label="IP 地址"
        ><NInput
          :value="addresses[0] ?? ''"
          placeholder="输入需要封禁的 IP 地址"
          @update:value="addresses = [$event]"
      /></NFormItem></div
  ></FormDialog>
</template>
<style scoped>
.defense-stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
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
.service-log {
  max-height: 360px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: var(--surface-soft);
  padding: 16px;
  border-radius: 10px;
}
.defense-modal {
  width: min(700px, calc(100vw - 32px));
}
.defense-fields {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
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
  .defense-fields {
    grid-template-columns: 1fr;
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
