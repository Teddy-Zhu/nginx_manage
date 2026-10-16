<route lang="json">
{
  "meta": {
    "title": "防火墙规则",
    "subtitle": "期望策略与编译预览",
    "nav": true,
    "order": 0.71,
    "symbol": "≡"
  }
}
</route>

<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, ref, toRaw, watch } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  type FirewallRule,
  type FirewallPolicy,
  type FirewallPolicyView,
  type FirewallPreview,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(),
  session = useSession(),
  dialog = useDialog();
const { run, busy } = useAction(),
  idempotency = useIdempotency();
const stored = ref<FirewallPolicyView | null>(null),
  policy = ref<FirewallPolicy>({ backend: "direct-nftables", rules: [] });
const preview = ref<FirewallPreview | null>(null),
  editing = ref<FirewallRule | null>(null);
const portsText = ref(""),
  sourcesText = ref(""),
  formError = ref("");
const controller = new AbortController();
const canWrite = computed(
  () => session.me?.scopes.includes("security.write") ?? false,
);
const dirty = computed(
  () =>
    !!stored.value &&
    JSON.stringify(policy.value) !== JSON.stringify(stored.value.policy),
);
const orderedRules = computed(() =>
  [...policy.value.rules].sort(
    (a, b) =>
      a.priority - b.priority || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  ),
);
const backends = [
  { label: "直接 nftables", value: "direct-nftables" },
  { label: "iptables-nft", value: "iptables-nft" },
  { label: "iptables-legacy", value: "iptables-legacy" },
  { label: "firewalld", value: "firewalld" },
  { label: "UFW", value: "ufw" },
];
const families = [
  { label: "IPv4", value: "ipv4" },
  { label: "IPv6", value: "ipv6" },
  { label: "IPv4 与 IPv6", value: "both" },
];
const scopes = [
  { label: "主机入站", value: "host_input" },
  { label: "Docker 发布端口", value: "docker_published" },
];
const actions = [
  { label: "允许", value: "allow" },
  { label: "丢弃", value: "deny" },
  { label: "拒绝", value: "reject" },
];
const familyName = (value: string) =>
  families.find((item) => item.value === value)?.label ?? value;
const actionName = (value: string) =>
  actions.find((item) => item.value === value)?.label ?? value;
const scopeName = (value: string) =>
  scopes.find((item) => item.value === value)?.label ?? value;
function ports(rule: FirewallRule) {
  return rule.ports
    .map((port) =>
      port.from === port.to ? String(port.from) : `${port.from}-${port.to}`,
    )
    .join(", ");
}
function localEdit(rule: FirewallRule) {
  editing.value = structuredClone(toRaw(rule));
  portsText.value = ports(rule);
  sourcesText.value = rule.sources.join("\n");
  formError.value = "";
}
function add() {
  localEdit({
    id: crypto.randomUUID(),
    name: "",
    enabled: true,
    scope: "host_input",
    family: "both",
    protocol: "tcp",
    ports: [{ from: 443, to: 443 }],
    sources: [],
    action: "allow",
    priority: Math.min(
      1_000_000,
      Math.max(0, ...policy.value.rules.map((r) => r.priority)) + 10,
    ),
    interface: "",
    comment: "",
  });
}
function commitRule() {
  if (!editing.value || !canWrite.value) return;
  const value = structuredClone(toRaw(editing.value));
  if (!value.name.trim()) {
    formError.value = "请填写规则名称";
    return;
  }
  const parts = portsText.value
    .trim()
    .split(/[,，\s]+/)
    .filter(Boolean);
  if (parts.length < 1 || parts.length > 16) {
    formError.value = "请填写 1–16 个端口或端口范围";
    return;
  }
  value.ports = [];
  for (const part of parts) {
    const match = /^([0-9]{1,5})(?:-([0-9]{1,5}))?$/.exec(part);
    if (!match) {
      formError.value = "端口格式无效，例如 80,443,8000-8010";
      return;
    }
    const from = Number(match[1]),
      to = Number(match[2] ?? match[1]);
    if (from < 1 || to > 65535 || to < from) {
      formError.value = "端口须处于 1–65535，范围起点不能大于终点";
      return;
    }
    value.ports.push({ from, to });
  }
  value.sources = sourcesText.value
    .trim()
    .split(/[,，\s]+/)
    .filter(Boolean);
  if (value.sources.length > 32) {
    formError.value = "每条规则最多 32 个来源";
    return;
  }
  const index = policy.value.rules.findIndex((r) => r.id === value.id);
  if (index < 0) {
    if (policy.value.rules.length >= 1000) {
      formError.value = "最多保存 1000 条规则";
      return;
    }
    policy.value.rules.push(value);
  } else policy.value.rules[index] = value;
  editing.value = null;
}
function remove(rule: FirewallRule) {
  dialog.warning({
    title: "删除期望规则",
    content: `移除“${rule.name}”后仍需保存策略。删除不会停止服务，也不代表端口允许或阻止。`,
    positiveText: "删除",
    negativeText: "取消",
    onPositiveClick: () => {
      policy.value.rules = policy.value.rules.filter((r) => r.id !== rule.id);
    },
  });
}
const columns: DataTableColumns<FirewallRule> = [
  {
    title: "启用",
    key: "enabled",
    width: 80,
    render: (r) =>
      h(NSwitch, {
        value: r.enabled,
        disabled: !canWrite.value || busy.value,
        "onUpdate:value": (value: boolean) => {
          r.enabled = value;
        },
      }),
  },
  { title: "名称", key: "name", minWidth: 130, ellipsis: { tooltip: true } },
  { title: "顺序", key: "priority", width: 80 },
  {
    title: "范围",
    key: "scope",
    render: (r) => scopeName(r.scope),
    width: 150,
  },
  {
    title: "地址族",
    key: "family",
    render: (r) => familyName(r.family),
    width: 140,
  },
  {
    title: "协议 / 端口",
    key: "ports",
    render: (r) => `${r.protocol.toUpperCase()} / ${ports(r)}`,
    minWidth: 160,
    ellipsis: { tooltip: true },
  },
  {
    title: "来源",
    key: "sources",
    render: (r) => r.sources.join(", ") || "任意来源",
    minWidth: 180,
    ellipsis: { tooltip: true },
  },
  {
    title: "入站接口",
    key: "interface",
    render: (r) => r.interface || "任意接口",
    width: 120,
  },
  {
    title: "动作",
    key: "action",
    render: (r) => actionName(r.action),
    width: 90,
  },
  {
    title: "操作",
    key: "actions",
    width: 150,
    render: (r) =>
      h(
        NSpace,
        { size: "small" },
        {
          default: () => [
            h(
              NButton,
              {
                size: "small",
                disabled: busy.value || !canWrite.value,
                onClick: () => localEdit(r),
              },
              { default: () => "编辑" },
            ),
            h(
              NButton,
              {
                size: "small",
                disabled: busy.value || !canWrite.value,
                onClick: () => remove(r),
              },
              { default: () => "删除" },
            ),
          ],
        },
      ),
  },
];
const previewColumns: DataTableColumns<FirewallPreview["entries"][number]> = [
  {
    title: "规则 ID",
    key: "rule_id",
    minWidth: 190,
    ellipsis: { tooltip: true },
  },
  {
    title: "地址族",
    key: "family",
    width: 100,
    render: (r) => familyName(r.family),
  },
  {
    title: "协议",
    key: "protocol",
    width: 80,
    render: (r) => r.protocol.toUpperCase(),
  },
  {
    title: "来源",
    key: "source",
    minWidth: 170,
    render: (r) => r.source || "任意来源",
  },
  {
    title: "端口",
    key: "ports",
    width: 120,
    render: (r) =>
      r.ports.from === r.ports.to
        ? String(r.ports.from)
        : `${r.ports.from}-${r.ports.to}`,
  },
  {
    title: "接口",
    key: "interface",
    width: 100,
    render: (r) => r.interface || "任意接口",
  },
  {
    title: "动作",
    key: "action",
    width: 90,
    render: (r) => actionName(r.action),
  },
];
async function load() {
  await run(async () => {
    const result = await api.firewallPolicy(controller.signal);
    stored.value = result;
    policy.value = structuredClone(result.policy);
    preview.value = null;
  });
}
function refresh() {
  if (dirty.value)
    dialog.warning({
      title: "放弃未保存修改",
      content: "将重新读取已保存的期望策略。",
      positiveText: "重新读取",
      negativeText: "取消",
      onPositiveClick: () => void load(),
    });
  else void load();
}
async function save() {
  if (!stored.value || !canWrite.value) return;
  const input = {
    base_version: stored.value.version,
    policy: structuredClone(toRaw(policy.value)),
  };
  await run(async () => {
    const result = await api.saveFirewallPolicy(input, idempotency(input));
    stored.value = result;
    policy.value = structuredClone(result.policy);
    preview.value = null;
  }, "期望策略已保存，尚未应用");
}
async function generate() {
  if (!stored.value || dirty.value) return;
  await run(async () => {
    preview.value = await api.previewFirewall(
      stored.value!.version,
      controller.signal,
    );
  });
}
watch(
  policy,
  () => {
    preview.value = null;
  },
  { deep: true },
);
onMounted(() => void load());
onUnmounted(() => controller.abort());
</script>

<template>
  <div class="page-toolbar">
    <h2>防火墙规则</h2>
    <n-space
      ><n-button :disabled="busy" @click="refresh">重新读取</n-button
      ><n-button
        :disabled="busy || !stored || !canWrite || !dirty"
        @click="save"
        >保存期望策略</n-button
      ><n-button :disabled="busy || !stored?.version || dirty" @click="generate"
        >编译预览</n-button
      ></n-space
    >
  </div>
  <n-alert type="info" :bordered="false" class="notice"
    >保存仅更新期望策略。通过“防火墙应用”生成执行计划；监听状态、本机规则和外部可达性需分别确认。</n-alert
  >
  <section v-if="stored" class="panel">
    <div class="page-toolbar">
      <h3>期望策略</h3>
      <n-tag :type="dirty ? 'warning' : 'default'">{{
        dirty
          ? "有未保存修改"
          : stored.version
            ? `已保存 · 版本 ${stored.version}`
            : "尚未保存"
      }}</n-tag>
    </div>
    <n-form-item label="目标后端"
      ><n-select
        v-model:value="policy.backend"
        :options="backends"
        :disabled="busy || !canWrite"
        style="max-width: 320px"
    /></n-form-item>
    <p class="muted">
      按顺序升序匹配；顺序相同按规则 ID
      排序。允许策略仅在本应用范围内生效；未匹配流量交回其余系统策略。选择后端不会切换系统
      alternatives 或停止现有管理器。
    </p>
    <div class="page-toolbar">
      <span>{{ policy.rules.length }} / 1000 条规则</span
      ><n-button
        :disabled="!canWrite || busy || policy.rules.length >= 1000"
        @click="add"
        >新增规则</n-button
      >
    </div>
    <n-data-table
      :columns="columns"
      :data="orderedRules"
      :row-key="(row: FirewallRule) => row.id"
      :pagination="{ pageSize: 20 }"
      :scroll-x="1400"
    />
  </section>
  <section v-if="preview" class="panel">
    <div class="page-toolbar">
      <h3>版本 {{ preview.version }} 编译预览</h3>
      <n-tag :type="preview.compiled ? 'info' : 'warning'">{{
        preview.compiled ? "编译完成 · 未应用" : "无法编译"
      }}</n-tag>
    </div>
    <n-alert
      v-for="(item, index) in preview.errors"
      :key="`error-${index}`"
      type="error"
      :bordered="false"
      class="notice"
      >{{ item }}</n-alert
    >
    <n-alert
      v-for="(item, index) in preview.warnings"
      :key="`warning-${index}`"
      type="warning"
      :bordered="false"
      class="notice"
      >{{ item }}</n-alert
    >
    <template v-if="preview.compiled">
      <dl>
        <dt>目标表 / 链</dt>
        <dd>{{ preview.table }} / {{ preview.chain }}</dd>
        <dt>挂接点</dt>
        <dd>
          {{ preview.hook }}，优先级 {{ preview.priority }}，默认
          {{ preview.default_policy }}
        </dd>
        <dt>规则数量</dt>
        <dd>
          {{ preview.logical_rules }} 条启用策略 →
          {{ preview.generated_rules }} 条内核规则，包含 2 条会话/回环保护规则
        </dd>
        <dt>编译摘要</dt>
        <dd>
          <code>{{ preview.program_hash }}</code>
        </dd>
        <dt>内核代次</dt>
        <dd>
          {{ preview.kernel.available ? preview.kernel.generation : "未知" }}
        </dd>
        <dt>目标表快照</dt>
        <dd>
          <code>{{
            preview.kernel.fingerprint || preview.kernel.reason || "未取得"
          }}</code>
        </dd>
        <template v-if="preview.transaction_hash">
          <dt>新建事务摘要</dt>
          <dd>
            <code>{{ preview.transaction_hash }}</code>
          </dd>
          <dt>事务规模</dt>
          <dd>
            {{ preview.transaction_messages }} 条消息 /
            {{ preview.transaction_bytes }} 字节，已编码、未提交
          </dd>
        </template>
        <dt>环境观测时间</dt>
        <dd>
          {{
            preview.observed_at
              ? new Date(preview.observed_at * 1000).toLocaleString()
              : "未知"
          }}
        </dd>
      </dl>
      <p v-if="preview.truncated" class="muted">
        仅展示前 128 条展开结果，全部规则已参与编译和数量检查。
      </p>
      <n-data-table
        :columns="previewColumns"
        :data="preview.entries"
        :pagination="{ pageSize: 20 }"
        :scroll-x="850"
      />
    </template>
  </section>
  <n-modal
    :show="!!editing"
    :mask-closable="false"
    preset="card"
    title="期望规则"
    style="width: min(720px, 94vw)"
    @update:show="
      (show: boolean) => {
        if (!show) editing = null;
      }
    "
  >
    <template v-if="editing">
      <n-alert v-if="formError" type="error" :bordered="false" class="notice">{{
        formError
      }}</n-alert>
      <n-form-item label="名称"
        ><n-input v-model:value="editing.name" maxlength="128"
      /></n-form-item>
      <div class="grid">
        <n-form-item label="范围"
          ><n-select
            v-model:value="editing.scope"
            :options="scopes" /></n-form-item
        ><n-form-item label="地址族"
          ><n-select v-model:value="editing.family" :options="families"
        /></n-form-item>
      </div>
      <div class="grid">
        <n-form-item label="协议"
          ><n-select
            v-model:value="editing.protocol"
            :options="[
              { label: 'TCP', value: 'tcp' },
              { label: 'UDP', value: 'udp' },
            ]" /></n-form-item
        ><n-form-item label="动作"
          ><n-select v-model:value="editing.action" :options="actions"
        /></n-form-item>
      </div>
      <n-form-item label="端口 / 范围"
        ><n-input v-model:value="portsText" placeholder="80,443,8000-8010"
      /></n-form-item>
      <n-form-item label="来源 IP / CIDR（留空表示任意来源）"
        ><n-input
          v-model:value="sourcesText"
          type="textarea"
          :rows="3"
          placeholder="每行一个地址或网络起点 CIDR；双栈规则需同时填写两种地址族"
      /></n-form-item>
      <div class="grid">
        <n-form-item label="匹配顺序"
          ><n-input-number
            :value="editing.priority"
            :min="0"
            :max="1000000"
            :precision="0"
            :clearable="false"
            @update:value="
              (value: number | null) => {
                if (editing && value !== null) editing.priority = value;
              }
            " /></n-form-item
        ><n-form-item label="入站接口（可选）"
          ><n-input
            v-model:value="editing.interface"
            maxlength="15"
            placeholder="例如 eth0，留空表示任意接口"
        /></n-form-item>
      </div>
      <n-form-item label="备注"
        ><n-input v-model:value="editing.comment" maxlength="512"
      /></n-form-item>
      <n-form-item label="启用"
        ><n-switch v-model:value="editing.enabled"
      /></n-form-item>
      <n-space justify="end"
        ><n-button @click="editing = null">取消</n-button
        ><n-button type="primary" :disabled="!canWrite" @click="commitRule"
          >更新期望规则</n-button
        ></n-space
      >
    </template>
  </n-modal>
</template>

<style scoped>
.notice {
  margin: 16px 0;
}
.panel {
  padding: 20px;
  margin-top: 16px;
  border: 1px solid var(--border, #e5eae7);
  border-radius: 12px;
  background: white;
  min-width: 0;
}
.panel h3 {
  margin-top: 0;
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
dl {
  display: grid;
  grid-template-columns: 140px minmax(0, 1fr);
  gap: 10px;
}
dt {
  color: #6d7772;
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
@media (max-width: 650px) {
  .grid {
    grid-template-columns: 1fr;
    gap: 0;
  }
  dl {
    grid-template-columns: 100px minmax(0, 1fr);
  }
}
</style>
